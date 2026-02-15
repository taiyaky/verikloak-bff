# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Verikloak::HeaderSources do
  describe '.normalize_env_key' do
    it 'converts a plain header name to HTTP_* uppercase' do
      expect(described_class.normalize_env_key('x-forwarded-token'))
        .to eq('HTTP_X_FORWARDED_TOKEN')
    end

    it 'handles symbols' do
      expect(described_class.normalize_env_key(:x_custom_header))
        .to eq('HTTP_X_CUSTOM_HEADER')
    end

    it 'preserves existing HTTP_ prefix' do
      expect(described_class.normalize_env_key('HTTP_AUTHORIZATION'))
        .to eq('HTTP_AUTHORIZATION')
    end

    it 'returns empty string for nil' do
      expect(described_class.normalize_env_key(nil)).to eq('')
    end

    it 'returns empty string for blank' do
      expect(described_class.normalize_env_key('  ')).to eq('')
    end

    it 'strips whitespace before normalization' do
      expect(described_class.normalize_env_key('  x-custom  '))
        .to eq('HTTP_X_CUSTOM')
    end
  end

  describe '.normalize_priority' do
    it 'returns default forwarded header when priority is empty' do
      list, fwd = described_class.normalize_priority([])
      expect(list).to eq([Verikloak::HeaderSources::DEFAULT_FORWARDED_HEADER])
      expect(fwd).to eq(Verikloak::HeaderSources::DEFAULT_FORWARDED_HEADER)
    end

    it 'normalizes and deduplicates entries' do
      list, = described_class.normalize_priority(%w[x-custom x-custom x-other])
      expect(list).to eq(['HTTP_X_CUSTOM', 'HTTP_X_OTHER'])
    end

    it 'drops Authorization by default' do
      list, = described_class.normalize_priority(%w[Authorization x-custom])
      expect(list).to eq(['HTTP_X_CUSTOM'])
    end

    it 'keeps Authorization when drop_authorization is false' do
      list, = described_class.normalize_priority(%w[Authorization], drop_authorization: false)
      expect(list).to include('HTTP_AUTHORIZATION')
    end

    it 'accepts a custom forwarded_header' do
      list, fwd = described_class.normalize_priority([], forwarded_header: 'x-my-fwd')
      expect(fwd).to eq('HTTP_X_MY_FWD')
      expect(list).to eq(['HTTP_X_MY_FWD'])
    end
  end

  describe '.default_priority' do
    it 'returns the default forwarded header as priority' do
      result = described_class.default_priority
      expect(result).to eq([Verikloak::HeaderSources::DEFAULT_FORWARDED_HEADER])
    end
  end
end
