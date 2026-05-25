# marten-signed-id

Generates and verifies signed ID tokens for [Marten](https://martenframework.com) models — a port of Rails' `ActiveRecord::SignedId`. Use it for expiring invitation links, password-reset URLs, and anything else that needs a self-contained, tamper-resistant token referencing a record + a purpose.

Built on `Marten::Core::Signer` (HMAC-SHA256, Marten's `secret_key` by default).

## Installation

```yaml
# shard.yml
dependencies:
  marten_signed_id:
    github: stevegeek/marten-signed-id
```

```bash
shards install
```

```crystal
# src/project.cr (or wherever you wire deps)
require "marten_signed_id"
```

## Usage

Include the mixin on any model with a primary key:

```crystal
class User < Marten::Model
  include MartenSignedId::ModelMixin

  field :id, :big_int, primary_key: true, auto: true
  field :email, :email
end
```

Generate a token:

```crystal
user.signed_id(purpose: "transfer", expires_in: 4.hours)
# => "eyJpIjoi...--abc123def456..."
```

Look up by token:

```crystal
User.find_signed(token, purpose: "transfer")   # => User? (nil on miss)
User.find_signed!(token, purpose: "transfer")  # => User (raises on miss)
```

`find_signed` returns `nil` for any of: invalid signature, expired token, purpose mismatch, embedded id un-castable to the PK column type, or record no longer exists.

`find_signed!` raises `MartenSignedId::SignedRecordNotFoundError` when the signature + purpose checked out but the row is gone (or the id can't cast), and `MartenSignedId::InvalidSignedIdError` for any other miss (tamper, expiry, purpose mismatch, blank/invalid token).

## Errors

```
MartenSignedId::Error                                # umbrella — rescue this to catch everything
├── MartenSignedId::InvalidSignedIdError             # base — signature/expiry/purpose miss
│   ├── MartenSignedId::ExpiredSignedIdError         # reserved (see below)
│   ├── MartenSignedId::TamperedSignedIdError        # reserved (see below)
│   └── MartenSignedId::SignedRecordNotFoundError    # verify ok, row gone or pk un-castable
└── MartenSignedId::InsecureSecretError              # signing key too short / missing
```

`ExpiredSignedIdError` and `TamperedSignedIdError` are defined for forward compatibility but not raised today: `Marten::Core::Signer#unsign` collapses both into a single `nil` return, so this shard cannot distinguish them without bypassing the signer. They will be wired up if/when the underlying signer surfaces the difference. Until then, catch `InvalidSignedIdError` for both.

`MartenSignedId::InsecureSecretError` is raised on the first `sign`/`verify` call if the effective signing key is shorter than 32 bytes. This applies to both the default `Marten.settings.secret_key` and any caller-supplied `key:` argument — passing `key: ""` or `key: "short"` does not bypass the check. Misconfiguration fails loudly rather than silently producing forgeable tokens.

## Purpose scoping

The `purpose:` argument is mandatory, non-blank, and acts as a domain separator. A token issued for `"transfer"` cannot be redeemed with `purpose: "password_reset"`, even though both use the same underlying signing key. This prevents tokens leaked from one flow being used in another.

```crystal
token = user.signed_id(purpose: "transfer", expires_in: 4.hours)

User.find_signed(token, purpose: "transfer")       # => user
User.find_signed(token, purpose: "password_reset") # => nil
```

**Purposes are not automatically scoped to a model.** A token signed by `Widget#signed_id(purpose: "transfer")` is redeemable as `OtherModel.find_signed(token, purpose: "transfer")` if `OtherModel` has a row with the same PK — because the token does not embed the model class. If you sign IDs for multiple models with overlapping flows, namespace the purpose:

```crystal
# good
user.signed_id(purpose: "user:password_reset")
team.signed_id(purpose: "team:invite")

# risky — a leaked user reset token could be redeemed against a team
user.signed_id(purpose: "password_reset")
```

The spec suite pins this collision behaviour so it can't drift silently; see `spec/marten_signed_id_spec.cr`.

## Expiry

`expires_in:` accepts any `Time::Span`. Omit for non-expiring tokens (use sparingly).

```crystal
user.signed_id(purpose: "transfer", expires_in: 4.hours)
user.signed_id(purpose: "magic_link", expires_in: 15.minutes)
user.signed_id(purpose: "permanent_token") # no expiry
```

Zero or negative `expires_in` raises `ArgumentError`. Pre-expired tokens are a developer error, not a feature.

Recommend padding `expires_in` over your worst-case clock skew: `Marten::Core::Signer` uses a strict `Time.utc < embedded_expiry` comparison with no grace window, so tokens with sub-second remaining validity will be rejected on a verifier whose clock is a couple of seconds ahead. Adding a few seconds of buffer covers cross-host NTP drift in distributed deploys.

## Secret key

By default, the shard signs with `Marten.settings.secret_key`. This is the same key that signs Marten's session cookies and CSRF tokens — a single key rotation invalidates every signed ID at once, and any cross-feature signing-algorithm bug (e.g. an accidental `OpenSSL::Algorithm::MD5`) blast-radius includes signed IDs.

For high-stakes flows (password resets, account takeover, payment confirmations) consider per-purpose key derivation. Pass a derived `key:` to `sign` and the matching one to `verify`:

```crystal
def derived_key(purpose : String) : String
  OpenSSL::HMAC.hexdigest(
    OpenSSL::Algorithm::SHA256,
    Marten.settings.secret_key,
    "signed_id:#{purpose}",
  )
end

token = MartenSignedId.sign(user.pk, "password_reset",
  expires_in: 15.minutes,
  key: derived_key("password_reset"),
)

MartenSignedId.verify(token, "password_reset",
  key: derived_key("password_reset"),
)
```

The default behaviour is unchanged — `key:` is opt-in. Derived keys let you rotate per-feature without invalidating sessions / CSRF / other signed IDs.

## What's visible in the token

The payload is **base64-encoded, not encrypted**. Anyone holding a token can decode it and read both the primary key and the purpose string. For most use cases (password reset links, share URLs) this is fine, but be aware:

- The token reveals the resource PK to the recipient and to anyone with access to URL logs, mail-transit metadata, or `Referer` headers. If you're using non-sequential PKs specifically to prevent enumeration, signed IDs do not preserve that property.
- The token reveals the purpose verbatim. `purpose: "account_deletion_confirmation"` leaks more about intent than `purpose: "tx_4"`. Use generic purpose names when tokens will travel through untrusted channels.

If you need confidentiality, encrypt the token before sending (this shard does not).

## URL embedding

`Marten::Core::Signer` encodes tokens with standard Base64 (`+`, `/`, `=` characters), not URL-safe Base64. Tokens going into a URL must be URL-escaped by the caller:

```crystal
"/reset?token=#{URI.encode_path_segment(user.signed_id(purpose: "password_reset"))}"
```

Some downstream systems double-decode URLs and corrupt naive embeds. Always escape on the way out and the framework will decode on the way in.

## Rails comparison

| Rails | marten-signed-id |
|---|---|
| `record.signed_id(purpose: :transfer, expires_in: 4.hours)` | `record.signed_id(purpose: "transfer", expires_in: 4.hours)` |
| `Model.find_signed(token, purpose: :transfer)` | `Model.find_signed(token, purpose: "transfer")` |
| `Model.find_signed!(token, purpose: :transfer)` | `Model.find_signed!(token, purpose: "transfer")` |
| Raised: `ActiveSupport::MessageVerifier::InvalidSignature` | Raised: `MartenSignedId::InvalidSignedIdError` |
| Raised: `ActiveRecord::RecordNotFound` | Raised: `MartenSignedId::SignedRecordNotFoundError` |
| `User.active.find_signed(token, purpose: …)` (queryset-chainable) | not yet supported — `find_signed` always queries the default queryset |

Purposes are strings in Marten (symbols in Rails); the wire format is identical otherwise.

## How it works

1. `sign(id, purpose:, expires_in:)` builds a JSON payload `{"v": 1, "i": "<pk>", "p": "<purpose>"}`. The `v` field is a payload-format version; `verify` rejects unknown versions so future format changes can be introduced without breaking in-flight tokens.
2. The payload is signed via `Marten::Core::Signer#sign(value, expires:)` — HMAC-SHA256 with Marten's `secret_key` (or your derived `key:`). For tokens with no expiry, the wire form is `Base64(payload)--digest`. For tokens with expiry, the payload is wrapped in `{"_marten": {"value": Base64(payload), "expires": "<RFC3339>"}}` and that wrapper is then Base64-encoded again, so the wire form is `Base64(json-wrapper-containing-base64-payload)--digest`. Both shapes are appended with the HMAC digest after a `--` separator.
3. `verify(token, purpose:)` unsigns the token (rejecting tampered or expired ones via constant-time comparison inside the signer), parses the JSON, checks the payload version, and verifies the purpose matches before returning the embedded id string.
4. `Model.find_signed` then does a regular `get(pk: id)` to materialise the record, rescuing `Marten::DB::Errors::UnexpectedFieldValue` (the embedded id can't cast — schema rotation, etc.) and `Marten::DB::Errors::RecordNotFound` (defensive) into `nil`.

## License

MIT
