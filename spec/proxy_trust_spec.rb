# frozen_string_literal: true

require 'rspec'
require_relative '../lib/verikloak-bff'

RSpec.describe Verikloak::BFF::ProxyTrust do
  include Verikloak::BFF::ProxyTrust

  it 'returns true for trusted REMOTE_ADDR' do
    env = { 'REMOTE_ADDR' => '10.0.0.5' }
    expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0.0/8'], :rightmost)).to be true
  end

  it 'falls back to rightmost XFF when REMOTE_ADDR missing' do
    env = { 'HTTP_X_FORWARDED_FOR' => '198.51.100.10, 10.0.0.7' }
    expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0.0/8'], :rightmost)).to be true
  end

  it 'returns false for untrusted peers' do
    env = { 'REMOTE_ADDR' => '203.0.113.9' }
    expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0.0/8'], :rightmost)).to be false
  end
end

