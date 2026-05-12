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

    it "find_signed! raises on miss" do
      expect_raises(MartenSignedId::InvalidSignedIdError) do
        Widget.find_signed!("garbage", purpose: "test")
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
  end
end
