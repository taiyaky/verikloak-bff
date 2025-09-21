# frozen_string_literal: true

RSpec.describe Verikloak::BFF::Configuration do
  describe '#initialize' do
    it 'normalizes default forwarded header and token priority' do
      config = described_class.new

      expect(config.forwarded_header_name).to eq('HTTP_X_FORWARDED_ACCESS_TOKEN')
      expect(config.token_header_priority).to eq(['HTTP_X_FORWARDED_ACCESS_TOKEN'])
    end
  end

  describe '#token_header_priority=' do
    it 'normalizes keys and strips Authorization' do
      config = described_class.new

      config.token_header_priority = [:http_x_custom, ' HTTP_AUTHORIZATION ']

      expect(config.token_header_priority).to eq(['HTTP_X_CUSTOM'])
    end

    it 'preserves explicit order after normalization' do
      config = described_class.new

      config.token_header_priority = %w[x-token x-forwarded-access-token]

      expect(config.token_header_priority).to eq([
        'HTTP_X_TOKEN',
        'HTTP_X_FORWARDED_ACCESS_TOKEN'
      ])
    end
  end

  describe '#forwarded_header_name=' do
    it 'reapplies normalization to priority list' do
      config = described_class.new
      config.token_header_priority = ['X-Token']

      config.forwarded_header_name = 'x-authz'

      expect(config.forwarded_header_name).to eq('HTTP_X_AUTHZ')
      expect(config.token_header_priority).to eq([
        'HTTP_X_TOKEN'
      ])
    end
  end
end
