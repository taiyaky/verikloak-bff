# frozen_string_literal: true

require 'base64'
require 'json'

RSpec.describe Verikloak::BFF::ConsistencyChecks do
  def jwt_with(payload)
    header = Base64.urlsafe_encode64({}.to_json, padding: false)
    body   = Base64.urlsafe_encode64(payload.to_json, padding: false)
    [header, body, 'sig'].join('.')
  end

  # Build two tokens: the largest token that is <= MAX, and the first token > MAX
  def boundary_tokens(max_bytes)
    under = nil
    over = nil
    pad_len = 0
    email = 'user@example.com'

    # Brute force pad length to cross the boundary
    while pad_len < max_bytes * 2
      token = jwt_with({ email: email, pad: 'x' * pad_len })
      size = token.bytesize
      if size <= max_bytes
        under = token
      else
        over = token
        break
      end
      pad_len += 1
    end
    raise 'failed to build boundary tokens' unless under && over
    [under, over, email]
  end

  describe '.decode_claims' do
    it 'decodes at or below MAX_TOKEN_BYTES and skips when exceeded' do
      max = Verikloak::BFF::Constants::MAX_TOKEN_BYTES
      token_under, token_over, email = boundary_tokens(max)

      claims_under = described_class.decode_claims(token_under)
      expect(claims_under['email']).to eq(email)

      claims_over = described_class.decode_claims(token_over)
      expect(claims_over).to eq({})
    end

    it 'returns empty hash for nil token' do
      expect(described_class.decode_claims(nil)).to eq({})
    end
  end
end

