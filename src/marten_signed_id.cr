require "marten"
require "json"

# Generates and verifies signed ID tokens for Marten models — a port of
# Rails' `ActiveRecord::SignedId`. Use cases: expiring invitation links,
# password-reset URLs, and anything else that needs a self-contained,
# tamper-resistant token referencing a record + a purpose.
#
# Built on `Marten::Core::Signer` (HMAC-SHA256, Marten's `secret_key` by
# default). Tokens embed the record's primary key, a caller-supplied
# purpose string, and an optional expiry timestamp.
#
# Usage:
#
# ```
# class User < Marten::Model
#   include MartenSignedId::ModelMixin
# end
#
# token = user.signed_id(purpose: "transfer", expires_in: 4.hours)
#
# User.find_signed(token, purpose: "transfer")  # => User? (nil if expired/invalid/mismatched purpose)
# User.find_signed!(token, purpose: "transfer") # => User (raises InvalidSignedIdError)
# ```
#
# Purpose mismatch (a token issued for `"transfer"` used with
# `"password_reset"`) is rejected the same way as an invalid signature.
module MartenSignedId
  VERSION = "0.1.0"

  # Minimum acceptable length, in bytes, of `Marten.settings.secret_key`.
  # 32 bytes (256 bits) matches the HMAC-SHA256 block-size guidance and
  # the threshold Rails enforces on its `MessageVerifier` key.
  SECRET_KEY_MIN_BYTES = 32

  # Current on-the-wire payload version. `verify` rejects unknown
  # versions so future format changes can be introduced without breaking
  # in-flight tokens.
  #
  # Bumping this constant rejects in-flight v=1 tokens — fine for a
  # single-process restart, a footgun for rolling deploys where old and
  # new app versions run concurrently. For a zero-downtime version
  # change, first replace this with a `SUPPORTED_VERSIONS = Set{1, 2}`
  # and have `verify` accept any member, deploy the dual-accepting
  # build across all nodes, then drop v=1 from the set after the
  # longest outstanding token TTL has elapsed.
  PAYLOAD_VERSION = 1

  # Umbrella base class — every exception this shard raises descends
  # from `Error`. Callers can `rescue MartenSignedId::Error` to catch
  # both verification failures (`InvalidSignedIdError` family) and
  # misconfiguration (`InsecureSecretError`) in one clause.
  class Error < ::Exception; end

  # Base class for sign/verify failures (bad signature, expiry, purpose
  # mismatch, record gone).
  class InvalidSignedIdError < Error; end

  # Raised when `expires_in` has elapsed.
  #
  # Note: the underlying `Marten::Core::Signer#unsign` currently
  # collapses tamper and expiry into a single `nil` return, so this
  # class is reserved for callers that introduce richer signer
  # plumbing. Today, both surface as `InvalidSignedIdError` from
  # `find_signed!`.
  class ExpiredSignedIdError < InvalidSignedIdError; end

  # Raised when the digest doesn't match — signature was forged or
  # corrupted. See note on `ExpiredSignedIdError`.
  class TamperedSignedIdError < InvalidSignedIdError; end

  # Raised by `find_signed!` when the signature/expiry/purpose check
  # passed but the referenced row no longer exists in the database.
  class SignedRecordNotFoundError < InvalidSignedIdError; end

  # Raised when the signing key (either `Marten.settings.secret_key` or
  # a caller-supplied `key:`) is shorter than `SECRET_KEY_MIN_BYTES`.
  # Surfaced on the first `sign` / `verify` call so misconfiguration
  # fails loudly rather than silently producing forgeable tokens.
  class InsecureSecretError < Error; end

  # Sign the given id with a purpose + optional expiry. `id` is
  # stringified so any pk type round-trips through the token.
  #
  # Pass `key:` to override the signing key for this call (used to
  # implement per-purpose key derivation — see the README). The default
  # is `Marten.settings.secret_key`. Either way the key must be at
  # least `SECRET_KEY_MIN_BYTES`; shorter keys raise
  # `InsecureSecretError`.
  def self.sign(
    id,
    purpose : String,
    expires_in : Time::Span? = nil,
    key : String? = nil,
  ) : String
    raise ArgumentError.new("purpose must be non-blank") if purpose.blank?
    raise ArgumentError.new("expires_in must be positive") if expires_in && !expires_in.positive?
    validate_secret_key!(key)

    payload = {"v" => PAYLOAD_VERSION, "i" => id.to_s, "p" => purpose}.to_json
    expires = expires_in.try { |span| Time.utc + span }
    Marten::Core::Signer.new(key: key).sign(payload, expires: expires)
  end

  # Verify the token + purpose. Returns the original id string if the
  # token is valid (signature OK, not expired, purpose matches), or
  # `nil` otherwise.
  #
  # Pass `key:` to verify against a non-default key (paired with the
  # same option on `sign`). The same minimum-length check applies as
  # on `sign`.
  def self.verify(token : String, purpose : String, key : String? = nil) : String?
    raise ArgumentError.new("purpose must be non-blank") if purpose.blank?
    validate_secret_key!(key)

    data = Marten::Core::Signer.new(key: key).unsign(token)
    return nil if data.nil?

    # JSON parsing intentionally not rescued: at this point the
    # signature has already been verified, so a parse failure indicates
    # a bug on the signer side rather than an attack — let it surface.
    parsed = JSON.parse(data).as_h?
    return nil if parsed.nil?

    return nil unless parsed["v"]?.try(&.as_i?) == PAYLOAD_VERSION
    return nil unless parsed["p"]?.try(&.as_s?) == purpose
    parsed["i"]?.try(&.as_s?)
  end

  # Asserts that the effective signing key is at least
  # `SECRET_KEY_MIN_BYTES`. When `caller_key` is `nil`, the default
  # `Marten.settings.secret_key` is checked; when non-nil, the
  # caller-supplied key is checked. Both paths share the same length
  # bar so callers can't bypass the minimum by passing `key: ""`.
  # Called from `sign` / `verify` before any cryptographic work.
  protected def self.validate_secret_key!(caller_key : String? = nil) : Nil
    if caller_key.nil?
      key = Marten.settings.secret_key
      if key.bytesize < SECRET_KEY_MIN_BYTES
        raise InsecureSecretError.new(
          "Marten.settings.secret_key must be at least #{SECRET_KEY_MIN_BYTES} bytes " \
          "(was #{key.bytesize}). Configure a longer secret before issuing signed IDs.",
        )
      end
    else
      if caller_key.bytesize < SECRET_KEY_MIN_BYTES
        raise InsecureSecretError.new(
          "Caller-supplied key: must be at least #{SECRET_KEY_MIN_BYTES} bytes " \
          "(was #{caller_key.bytesize}). Derive a longer key (e.g. HMAC-SHA256 hex digest) " \
          "before issuing signed IDs.",
        )
      end
    end
  end

  # Mixin for Marten models. Adds:
  #
  # - `record.signed_id(purpose:, expires_in:)` — instance method
  # - `Model.find_signed(token, purpose:)` — class method, returns the
  #   record or `nil` (invalid signature, expired, purpose mismatch, or
  #   record no longer exists)
  # - `Model.find_signed!(token, purpose:)` — class method, raises
  #   `MartenSignedId::SignedRecordNotFoundError` if the row is gone
  #   and `MartenSignedId::InvalidSignedIdError` for any other miss
  module ModelMixin
    macro included
      def self.find_signed(token : ::String, purpose : ::String) : self?
        id = ::MartenSignedId.verify(token, purpose)
        return nil if id.nil?

        begin
          get(pk: id)
        rescue ::Marten::DB::Errors::UnexpectedFieldValue
          # PK shape changed (e.g. schema rotation) — token's embedded id
          # can no longer be cast to the current PK column type.
          nil
        rescue ::Marten::DB::Errors::RecordNotFound
          # Defensive: `get` is documented to return nil rather than
          # raise this, but keep the guard so a backend change can't
          # turn a documented `nil` contract into a 500.
          nil
        end
      end

      def self.find_signed!(token : ::String, purpose : ::String) : self
        id = ::MartenSignedId.verify(token, purpose)
        if id.nil?
          raise ::MartenSignedId::InvalidSignedIdError.new("Invalid or expired signed id")
        end

        record = begin
          get(pk: id)
        rescue ::Marten::DB::Errors::UnexpectedFieldValue
          nil
        rescue ::Marten::DB::Errors::RecordNotFound
          nil
        end

        record || raise ::MartenSignedId::SignedRecordNotFoundError.new(
          "No #{self.name} matching the signed id"
        )
      end
    end

    def signed_id(purpose : ::String, expires_in : ::Time::Span? = nil) : ::String
      if pk.nil?
        raise ::MartenSignedId::InvalidSignedIdError.new("Cannot sign an unpersisted record")
      end
      ::MartenSignedId.sign(pk, purpose, expires_in)
    end
  end
end
