# frozen_string_literal: true

require "spec_helper"

RSpec.describe "HeaderGuardSanitizer log truncation" do
  describe "sanitize_string" do
    subject(:sanitize) { Verikloak::BFF::HeaderGuardSanitizer.sanitize_string(input) }

    context "when value is within MAX_LOG_FIELD_LENGTH (256)" do
      let(:input) { "short-value" }

      it "returns the value unchanged" do
        expect(sanitize).to eq("short-value")
      end
    end

    context "when value exceeds MAX_LOG_FIELD_LENGTH" do
      let(:input) { "x" * 300 }

      it "truncates to 256 characters with ellipsis" do
        expect(sanitize.length).to eq(259) # 256 + "..."
        expect(sanitize).to end_with("...")
        expect(sanitize).to start_with("x" * 256)
      end
    end

    context "when value is exactly at the boundary" do
      let(:input) { "a" * 256 }

      it "does not truncate" do
        expect(sanitize).to eq(input)
        expect(sanitize.length).to eq(256)
      end
    end

    context "when value is 257 characters" do
      let(:input) { "b" * 257 }

      it "truncates with ellipsis" do
        expect(sanitize).to eq("#{"b" * 256}...")
      end
    end

    context "when value contains control characters" do
      let(:input) { "hello\x00world\n\t!" }

      it "strips control characters" do
        expect(sanitize).to eq("helloworld!")
      end
    end

    context "when value contains invalid UTF-8" do
      let(:input) { String.new("valid\xC0\xAFtext", encoding: 'UTF-8') }

      it "replaces invalid bytes" do
        expect(sanitize).to be_valid_encoding
        expect(sanitize).not_to be_empty
      end
    end

    context "with a very large malicious value (DoS scenario)" do
      let(:input) { "A" * 100_000 }

      it "truncates to prevent memory/log abuse" do
        expect(sanitize.length).to be <= 259 # 256 + "..."
      end
    end
  end

  describe "sanitize_log_field" do
    it "returns nil for empty strings after sanitization" do
      result = Verikloak::BFF::HeaderGuardSanitizer.sanitize_log_field("\x00\x01\x02")
      expect(result).to be_nil
    end

    it "truncates long string values" do
      result = Verikloak::BFF::HeaderGuardSanitizer.sanitize_log_field("z" * 500)
      expect(result.length).to be <= 259
    end

    it "passes through non-string values unchanged" do
      expect(Verikloak::BFF::HeaderGuardSanitizer.sanitize_log_field(42)).to eq(42)
    end

    it "sanitizes array elements" do
      result = Verikloak::BFF::HeaderGuardSanitizer.sanitize_log_field(["ok", "\x00", "fine"])
      expect(result).to eq(["ok", "fine"])
    end
  end
end
