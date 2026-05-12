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
# User.find_signed(token, purpose: "transfer")   # => User? (nil if expired/invalid/mismatched purpose)
# User.find_signed!(token, purpose: "transfer")  # => User (raises InvalidSignedIdError)
# ```
#
# Purpose mismatch (a token issued for `"transfer"` used with
# `"password_reset"`) is rejected the same way as an invalid signature.
module MartenSignedId
  VERSION = "0.1.0"

  class InvalidSignedIdError < Exception; end

  # Sign the given id with a purpose + optional expiry. `id` is
  # stringified so any pk type round-trips through the token.
  def self.sign(id, purpose : String, expires_in : Time::Span? = nil) : String
    payload = {"i" => id.to_s, "p" => purpose}.to_json
    expires = expires_in.try { |span| Time.utc + span }
    Marten::Core::Signer.new.sign(payload, expires: expires)
  end

  # Verify the token + purpose. Returns the original id string if the
  # token is valid (signature OK, not expired, purpose matches), or
  # `nil` otherwise.
  def self.verify(token : String, purpose : String) : String?
    data = Marten::Core::Signer.new.unsign(token)
    return nil if data.nil?

    parsed = begin
      JSON.parse(data).as_h?
    rescue JSON::ParseException
      nil
    end
    return nil if parsed.nil?

    return nil unless parsed["p"]?.try(&.as_s) == purpose
    parsed["i"]?.try(&.as_s)
  end

  # Mixin for Marten models. Adds:
  #
  # - `record.signed_id(purpose:, expires_in:)` — instance method
  # - `Model.find_signed(token, purpose:)` — class method, returns the
  #    record or `nil` (invalid signature, expired, purpose mismatch, or
  #    record no longer exists)
  # - `Model.find_signed!(token, purpose:)` — class method, raises
  #    `MartenSignedId::InvalidSignedIdError` on miss
  module ModelMixin
    macro included
      def self.find_signed(token : ::String, purpose : ::String) : self?
        id = ::MartenSignedId.verify(token, purpose)
        return nil if id.nil?
        get(pk: id)
      end

      def self.find_signed!(token : ::String, purpose : ::String) : self
        find_signed(token, purpose) ||
          raise ::MartenSignedId::InvalidSignedIdError.new("Invalid or expired signed id")
      end
    end

    def signed_id(purpose : ::String, expires_in : ::Time::Span? = nil) : ::String
      ::MartenSignedId.sign(pk, purpose, expires_in)
    end
  end
end
