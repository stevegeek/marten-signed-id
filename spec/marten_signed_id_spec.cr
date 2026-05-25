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

    it "rejects a garbage token" do
      MartenSignedId.verify("not-a-real-token", purpose: "transfer").should be_nil
    end

    it "expires the token after expires_in" do
      token = MartenSignedId.sign(42, purpose: "transfer", expires_in: -1.minute)
      MartenSignedId.verify(token, purpose: "transfer").should be_nil
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
        Marten.settings.secret_key,
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

      b = MartenSignedId.sign(42, purpose: "transfer", key: Marten.settings.secret_key)
      MartenSignedId.verify(b, purpose: "transfer", key: Marten.settings.secret_key).should eq("42")
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
      widget = Widget.create!(name: "alpha")
      token = widget.signed_id(purpose: "test", expires_in: -1.minute)
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
  end
end
