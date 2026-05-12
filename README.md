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
User.find_signed!(token, purpose: "transfer")  # => User (raises MartenSignedId::InvalidSignedIdError on miss)
```

`find_signed` returns `nil` for any of: invalid signature, expired token, purpose mismatch, or record no longer exists.

## Purpose scoping

The `purpose:` argument is mandatory and acts as a domain separator. A token issued for `"transfer"` cannot be redeemed with `purpose: "password_reset"`, even though both use the same underlying signing key. This prevents tokens leaked from one flow being used in another.

```crystal
token = user.signed_id(purpose: "transfer", expires_in: 4.hours)

User.find_signed(token, purpose: "transfer")       # => user
User.find_signed(token, purpose: "password_reset") # => nil
```

## Expiry

`expires_in:` accepts any `Time::Span`. Omit for non-expiring tokens (use sparingly).

```crystal
user.signed_id(purpose: "transfer", expires_in: 4.hours)
user.signed_id(purpose: "magic_link", expires_in: 15.minutes)
user.signed_id(purpose: "permanent_token")  # no expiry
```

## Rails comparison

| Rails | marten-signed-id |
|---|---|
| `record.signed_id(purpose: :transfer, expires_in: 4.hours)` | `record.signed_id(purpose: "transfer", expires_in: 4.hours)` |
| `Model.find_signed(token, purpose: :transfer)` | `Model.find_signed(token, purpose: "transfer")` |
| `Model.find_signed!(token, purpose: :transfer)` | `Model.find_signed!(token, purpose: "transfer")` |
| Raised: `ActiveSupport::MessageVerifier::InvalidSignature` | Raised: `MartenSignedId::InvalidSignedIdError` |

Purposes are strings in Marten (symbols in Rails); the wire format is identical otherwise.

## How it works

1. `sign(id, purpose:, expires_in:)` builds a JSON payload `{"i": "<pk>", "p": "<purpose>"}`, optionally with an absolute expiry timestamp.
2. The payload is signed via `Marten::Core::Signer#sign(value, expires:)` — HMAC-SHA256 with Marten's `secret_key`. The signer Base64-encodes the payload and appends an HMAC digest separated by `--`.
3. `verify(token, purpose:)` unsigns the token (rejecting tampered or expired ones), parses the JSON, and verifies the purpose matches before returning the embedded id.
4. `Model.find_signed` then does a regular `get(pk: id)` to materialise the record.

## License

MIT
