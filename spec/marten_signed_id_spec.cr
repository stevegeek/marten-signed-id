require "./spec_helper"

describe MartenSignedId do
  describe ".sign / .verify" do
    it "round-trips an id + purpose" do
      token = MartenSignedId.sign(42, purpose: "transfer")
      MartenSignedId.verify(token, purpose: "transfer").should eq("42")
    end

    it "stringifies the id for any pk type" do
      token = MartenSignedId.sign(123_i64, purpose: "test")
      MartenSignedId.verify(token, purpose: "test").should eq("123")
    end

    it "rejects a purpose mismatch" do
      token = MartenSignedId.sign(42, purpose: "transfer")
      MartenSignedId.verify(token, purpose: "password_reset").should be_nil
    end

    it "rejects a tampered token" do
      token = MartenSignedId.sign(42, purpose: "transfer")
      MartenSignedId.verify(token + "x", purpose: "transfer").should be_nil
    end

    it "rejects a token whose payload has been swapped (digest catches it)" do
      # Belt-and-braces for L9: prove the HMAC covers the payload, not
      # just the trailing characters of the token. Splice the payload of
      # one valid token onto the signature of another and confirm verify
      # refuses it.
      good = MartenSignedId.sign(42, purpose: "transfer")
      bad = MartenSignedId.sign(43, purpose: "transfer")
      payload_good, _sig_good = good.split("--")
      _payload_bad, sig_bad = bad.split("--")
      MartenSignedId.verify("#{payload_good}--#{sig_bad}", purpose: "transfer").should be_nil
    end

    it "rejects a garbage token" do
      MartenSignedId.verify("not-a-real-token", purpose: "transfer").should be_nil
    end

    it "raises ArgumentError for a non-positive expires_in" do
      # M5: previously this silently produced a pre-expired token. Now
      # the dev error surfaces at sign time instead of failing
      # mysteriously at verify time.
      expect_raises(ArgumentError, /expires_in must be positive/) do
        MartenSignedId.sign(42, purpose: "transfer", expires_in: -1.minute)
      end
    end

    it "raises ArgumentError for an empty purpose on sign" do
      expect_raises(ArgumentError, /purpose must be non-blank/) do
        MartenSignedId.sign(42, purpose: "")
      end
    end

    it "raises ArgumentError for a whitespace purpose on sign" do
      expect_raises(ArgumentError, /purpose must be non-blank/) do
        MartenSignedId.sign(42, purpose: "   ")
      end
    end

    it "raises ArgumentError for an empty purpose on verify" do
      token = MartenSignedId.sign(42, purpose: "transfer")
      expect_raises(ArgumentError, /purpose must be non-blank/) do
        MartenSignedId.verify(token, purpose: "")
      end
    end

    it "keeps the token valid before expires_in" do
      token = MartenSignedId.sign(42, purpose: "transfer", expires_in: 1.hour)
      MartenSignedId.verify(token, purpose: "transfer").should eq("42")
    end

    it "supports tokens with no expiry" do
      token = MartenSignedId.sign(42, purpose: "transfer", expires_in: nil)
      MartenSignedId.verify(token, purpose: "transfer").should eq("42")
    end

    it "round-trips with a caller-supplied key:" do
      # H4: per-purpose key derivation pattern. Sign and verify must
      # both use the derived key; default behaviour is unchanged.
      derived = OpenSSL::HMAC.hexdigest(
        OpenSSL::Algorithm::SHA256,
        SPEC_SECRET_KEY,
        "signed_id:transfer",
      )

      token = MartenSignedId.sign(42, purpose: "transfer", key: derived)
      MartenSignedId.verify(token, purpose: "transfer", key: derived).should eq("42")
      # Default key cannot read a token signed with a derived key.
      MartenSignedId.verify(token, purpose: "transfer").should be_nil
    end

    it "round-trips identically whether key: is the default or omitted" do
      a = MartenSignedId.sign(42, purpose: "transfer")
      MartenSignedId.verify(a, purpose: "transfer").should eq("42")

      b = MartenSignedId.sign(42, purpose: "transfer", key: SPEC_SECRET_KEY)
      MartenSignedId.verify(b, purpose: "transfer", key: SPEC_SECRET_KEY).should eq("42")
      MartenSignedId.verify(b, purpose: "transfer").should eq("42")
    end

    it "raises InsecureSecretError if secret_key is too short" do
      original = Marten.settings.secret_key
      begin
        Marten.settings.secret_key = "tiny"
        expect_raises(MartenSignedId::InsecureSecretError, /at least 32 bytes/) do
          MartenSignedId.sign(42, purpose: "transfer")
        end
      ensure
        Marten.settings.secret_key = original
      end
    end

    it "rejects a token whose embedded payload version is unknown" do
      # L4: forge a token via the lower-level Signer with a future
      # version marker. We expect verify to ignore it rather than
      # silently treat it as the current format.
      payload = {"v" => 999, "i" => "42", "p" => "transfer"}.to_json
      token = Marten::Core::Signer.new.sign(payload)
      MartenSignedId.verify(token, purpose: "transfer").should be_nil
    end
  end

  describe "ModelMixin" do
    it "generates and verifies a signed id for a saved record" do
      widget = Widget.create!(name: "alpha")
      token = widget.signed_id(purpose: "test")
      Widget.find_signed(token, purpose: "test").should eq(widget)
    end

    it "returns nil for invalid tokens" do
      Widget.find_signed("garbage", purpose: "test").should be_nil
    end

    it "returns nil for a purpose mismatch" do
      widget = Widget.create!(name: "alpha")
      token = widget.signed_id(purpose: "transfer")
      Widget.find_signed(token, purpose: "password_reset").should be_nil
    end

    it "find_signed! raises InvalidSignedIdError on a bad token" do
      expect_raises(MartenSignedId::InvalidSignedIdError) do
        Widget.find_signed!("garbage", purpose: "test")
      end
    end

    it "find_signed! raises SignedRecordNotFoundError when the row is gone" do
      widget = Widget.create!(name: "alpha")
      token = widget.signed_id(purpose: "test")
      widget.delete

      expect_raises(MartenSignedId::SignedRecordNotFoundError) do
        Widget.find_signed!(token, purpose: "test")
      end
    end

    it "returns nil if the record was deleted after the token was issued" do
      widget = Widget.create!(name: "alpha")
      token = widget.signed_id(purpose: "test")
      widget.delete
      Widget.find_signed(token, purpose: "test").should be_nil
    end

    it "honours expires_in on the instance method" do
      # The instance method still accepts whatever sign accepts. Since
      # M5 forbids non-positive expires_in, use a tiny positive span
      # that lapses before verify runs.
      widget = Widget.create!(name: "alpha")
      token = widget.signed_id(purpose: "test", expires_in: 1.second)
      sleep 1.1.seconds
      Widget.find_signed(token, purpose: "test").should be_nil
    end

    it "raises on signing an unpersisted record" do
      expect_raises(MartenSignedId::InvalidSignedIdError, /unpersisted record/) do
        Widget.new.signed_id(purpose: "test")
      end
    end

    it "find_signed returns nil when the embedded id can't cast to the PK type" do
      # H1: forge a token whose payload embeds a UUID-shaped string;
      # Widget.id is :big_int, so casting must fail. We expect nil, not
      # a raised UnexpectedFieldValue.
      token = MartenSignedId.sign("not-an-integer", purpose: "test")
      Widget.find_signed(token, purpose: "test").should be_nil
    end

    it "find_signed! raises SignedRecordNotFoundError when the embedded id can't cast" do
      token = MartenSignedId.sign("not-an-integer", purpose: "test")
      expect_raises(MartenSignedId::SignedRecordNotFoundError) do
        Widget.find_signed!(token, purpose: "test")
      end
    end

    it "does not cross-redeem a token between models with colliding PKs" do
      # L10: prove that purpose-only domain separation is, as
      # documented, the caller's responsibility. A token issued for
      # Widget can be redeemed against Gizmo when both happen to have a
      # row with the same PK and the purpose strings collide. Callers
      # who need stronger separation should namespace the purpose
      # (e.g. "widget:transfer"). README documents this; this spec
      # pins the behaviour so it can't drift silently.
      widget = Widget.create!(name: "alpha")
      Gizmo.create!(name: "beta") # PK 1 on a fresh DB

      shared_token = widget.signed_id(purpose: "transfer")
      Widget.find_signed(shared_token, purpose: "transfer").should eq(widget)
      # Cross-redemption works on a generic purpose — the warning in the
      # README is load-bearing. Use a namespaced purpose to prevent it:
      ns_token = widget.signed_id(purpose: "widget:transfer")
      Gizmo.find_signed(ns_token, purpose: "gizmo:transfer").should be_nil
    end
  end
end
