# frozen_string_literal: true

require_relative '../lib/verikloak-bff'
require 'logger'

logger = Logger.new($stdout)

Verikloak::BFF.configure do |c|
  c.trusted_proxies = ['127.0.0.1', '10.0.0.0/8', '192.168.0.0/16']
  c.prefer_forwarded = true
  c.require_forwarded_header = false
  c.enforce_header_consistency = true
  c.enforce_claims_consistency = { email: :email, user: :sub, groups: :realm_roles }
  c.strip_suspicious_headers = true
  c.xff_strategy = :rightmost
  c.clock_skew_leeway = 30
  c.logger = logger
end

use Verikloak::BFF::HeaderGuard

run ->(_env) { [200, { 'Content-Type' => 'text/plain' }, ['OK']] }
