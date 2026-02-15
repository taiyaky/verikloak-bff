# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Verikloak::BFF::ForwardedToken do
  let(:auth_header) { Verikloak::HeaderSources::AUTHORIZATION_HEADER }
  let(:fwd_header)  { Verikloak::HeaderSources::DEFAULT_FORWARDED_HEADER }

  describe '.extract' do
    it 'returns [auth_token, forwarded_token] from Rack env' do
      env = {
        auth_header => 'Bearer auth-token-123',
        fwd_header  => 'fwd-token-456'
      }
      auth, fwd = described_class.extract(env)
      expect(auth).to eq('auth-token-123')
      expect(fwd).to eq('fwd-token-456')
    end

    it 'returns [nil, nil] when no headers are present' do
      auth, fwd = described_class.extract({})
      expect(auth).to be_nil
      expect(fwd).to be_nil
    end

    it 'strips Bearer prefix from forwarded header' do
      env = { fwd_header => 'Bearer my-fwd-token' }
      _, fwd = described_class.extract(env)
      expect(fwd).to eq('my-fwd-token')
    end
  end

  describe '.normalize_auth' do
    it 'extracts Bearer token' do
      expect(described_class.normalize_auth('Bearer abc123')).to eq('abc123')
    end

    it 'handles case-insensitive Bearer' do
      expect(described_class.normalize_auth('bearer XYZ')).to eq('XYZ')
    end

    it 'handles Bearer without space' do
      expect(described_class.normalize_auth('BearerXYZ')).to eq('XYZ')
    end

    it 'returns nil for non-Bearer schemes' do
      expect(described_class.normalize_auth('Basic abc123')).to be_nil
    end

    it 'returns nil for nil input' do
      expect(described_class.normalize_auth(nil)).to be_nil
    end

    it 'returns nil for empty string' do
      expect(described_class.normalize_auth('')).to be_nil
    end
  end

  describe '.normalize_forwarded' do
    it 'returns bare token as-is' do
      expect(described_class.normalize_forwarded('raw-token')).to eq('raw-token')
    end

    it 'strips Bearer prefix' do
      expect(described_class.normalize_forwarded('Bearer raw-token')).to eq('raw-token')
    end

    it 'returns nil for nil input' do
      expect(described_class.normalize_forwarded(nil)).to be_nil
    end

    it 'returns nil for empty string' do
      expect(described_class.normalize_forwarded('')).to be_nil
    end

    it 'returns nil for whitespace-only input' do
      expect(described_class.normalize_forwarded('   ')).to be_nil
    end
  end

  describe '.ensure_bearer' do
    it 'returns "Bearer <token>" for a bare token' do
      expect(described_class.ensure_bearer('my-token')).to eq('Bearer my-token')
    end

    it 'normalizes existing Bearer prefix' do
      expect(described_class.ensure_bearer('Bearer my-token')).to eq('Bearer my-token')
    end

    it 'normalizes case-insensitive Bearer' do
      expect(described_class.ensure_bearer('bearer my-token')).to eq('Bearer my-token')
    end

    it 'inserts space when missing after Bearer' do
      expect(described_class.ensure_bearer('BearerXYZ')).to eq('Bearer XYZ')
    end

    it 'collapses multiple spaces after Bearer' do
      expect(described_class.ensure_bearer("Bearer   my-token")).to eq('Bearer my-token')
    end
  end

  describe '.set_authorization!' do
    it 'always overwrites Authorization header with normalized Bearer' do
      env = { auth_header => 'Bearer old-token' }
      described_class.set_authorization!(env, 'new-token')
      expect(env[auth_header]).to eq('Bearer new-token')
    end

    it 'sets Authorization when none exists' do
      env = {}
      described_class.set_authorization!(env, 'my-token')
      expect(env[auth_header]).to eq('Bearer my-token')
    end
  end

  describe '.sanitize' do
    it 'removes control characters' do
      expect(described_class.sanitize("token\r\ninjection")).to eq('tokeninjection')
    end

    it 'strips leading/trailing whitespace' do
      expect(described_class.sanitize('  token  ')).to eq('token')
    end

    it 'handles nil' do
      expect(described_class.sanitize(nil)).to eq('')
    end
  end

  describe '.strip_suspicious!' do
    it 'removes default X-Auth-Request-* headers' do
      env = {
        'HTTP_X_AUTH_REQUEST_EMAIL'  => 'forged@evil.com',
        'HTTP_X_AUTH_REQUEST_USER'   => 'forged-user',
        'HTTP_X_AUTH_REQUEST_GROUPS' => 'admin',
        'HTTP_OTHER' => 'keep-me'
      }
      described_class.strip_suspicious!(env)
      expect(env).not_to have_key('HTTP_X_AUTH_REQUEST_EMAIL')
      expect(env).not_to have_key('HTTP_X_AUTH_REQUEST_USER')
      expect(env).not_to have_key('HTTP_X_AUTH_REQUEST_GROUPS')
      expect(env['HTTP_OTHER']).to eq('keep-me')
    end

    it 'removes custom headers when hash is provided' do
      env = { 'HTTP_CUSTOM' => 'val' }
      described_class.strip_suspicious!(env, { email: 'HTTP_CUSTOM' })
      expect(env).not_to have_key('HTTP_CUSTOM')
    end
  end
end
