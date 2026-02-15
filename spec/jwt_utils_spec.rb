# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Verikloak::BFF::JwtUtils do
  # A valid HS256 JWT for testing (not cryptographically meaningful — unverified decode)
  let(:valid_jwt) do
    payload = { 'sub' => 'user-1', 'aud' => 'test-client', 'exp' => Time.now.to_i + 600 }
    JWT.encode(payload, 'test-secret', 'HS256')
  end

  describe '.decode_unverified' do
    it 'decodes a valid JWT without verification' do
      payload, header = described_class.decode_unverified(valid_jwt)
      expect(payload['sub']).to eq('user-1')
      expect(payload['aud']).to eq('test-client')
      expect(header['alg']).to eq('HS256')
    end

    it 'returns [{}, {}] for nil input' do
      payload, header = described_class.decode_unverified(nil)
      expect(payload).to eq({})
      expect(header).to eq({})
    end

    it 'returns [{}, {}] for oversized token' do
      oversized = 'a' * (Verikloak::BFF::Constants::MAX_TOKEN_BYTES + 1)
      payload, header = described_class.decode_unverified(oversized)
      expect(payload).to eq({})
      expect(header).to eq({})
    end

    it 'returns [{}, {}] for malformed token' do
      payload, header = described_class.decode_unverified('not.a.jwt')
      expect(payload).to eq({})
      expect(header).to eq({})
    end
  end

  describe '.decode_claims' do
    it 'returns only the payload hash' do
      claims = described_class.decode_claims(valid_jwt)
      expect(claims['sub']).to eq('user-1')
      expect(claims).not_to have_key('alg')
    end

    it 'returns {} for nil' do
      expect(described_class.decode_claims(nil)).to eq({})
    end
  end
end
