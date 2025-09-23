# frozen_string_literal: true

# verikloak-bff — library entrypoint.
#
# Requiring this file loads the BFF namespace, configuration, middleware, and
# supporting utilities. Applications typically need only:
#
#   require 'verikloak-bff'
#   use Verikloak::BFF::HeaderGuard, trusted_proxies: ['127.0.0.1']
#
# @see Verikloak::BFF::HeaderGuard
# @see Verikloak::BFF::Configuration
require 'verikloak/bff'
require 'verikloak/bff/version'
require 'verikloak/bff/configuration'
require 'verikloak/bff/errors'
require 'verikloak/bff/proxy_trust'
require 'verikloak/bff/forwarded_token'
require 'verikloak/bff/consistency_checks'
require 'verikloak/bff/header_guard'
require 'verikloak/bff/rails'

if defined?(::Rails::Railtie)
  require 'verikloak/bff/railtie'
end
