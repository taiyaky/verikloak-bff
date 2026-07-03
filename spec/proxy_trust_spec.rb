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

  context 'peer_preference' do
    let(:env) do
      { 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.10, 10.0.0.7' }
    end

    it 'uses REMOTE_ADDR for trust decision with :remote_then_xff (default)' do
      expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0.0/8'], :rightmost)).to be false
    end

    it 'uses XFF for trust decision with :xff_only' do
      expect(
        Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0.0/8'], :rightmost, preference: :xff_only)
      ).to be true
    end

    it 'respects xff_strategy under :xff_only' do
      expect(
        Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0.0/8'], :leftmost, preference: :xff_only)
      ).to be false
    end
  end

  context 'rule isolation' do
    it 'does not let an invalid CIDR rule disable subsequent rules' do
      env = { 'REMOTE_ADDR' => '10.0.0.5' }
      expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0/8', '10.0.0.0/8'], :rightmost)).to be true
    end

    it 'does not let a raising Proc rule disable subsequent rules' do
      env = { 'REMOTE_ADDR' => '10.0.0.5' }
      raising = ->(_ip, _env) { raise 'boom' }
      expect(Verikloak::BFF::ProxyTrust.trusted?(env, [raising, '10.0.0.0/8'], :rightmost)).to be true
    end
  end

  context 'IPv4-mapped IPv6 normalisation' do
    it 'matches ::ffff:127.0.0.1 against 127.0.0.0/8' do
      env = { 'REMOTE_ADDR' => '::ffff:127.0.0.1' }
      expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['127.0.0.0/8'], :rightmost)).to be true
    end

    it 'matches ::ffff:172.17.0.1 against 172.17.0.0/16' do
      env = { 'REMOTE_ADDR' => '::ffff:172.17.0.1' }
      expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['172.17.0.0/16'], :rightmost)).to be true
    end

    it 'rejects ::ffff:203.0.113.1 against 10.0.0.0/8' do
      env = { 'REMOTE_ADDR' => '::ffff:203.0.113.1' }
      expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0.0/8'], :rightmost)).to be false
    end

    it 'normalises IPv4-mapped peer in XFF' do
      env = { 'HTTP_X_FORWARDED_FOR' => '198.51.100.10, ::ffff:10.0.0.5' }
      expect(Verikloak::BFF::ProxyTrust.trusted?(env, ['10.0.0.0/8'], :rightmost)).to be true
    end
  end
end

