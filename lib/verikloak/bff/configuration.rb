# frozen_string_literal: true

# Configuration object for verikloak-bff. Holds middleware settings such as
# proxy trust rules, header consistency policies, and logging options.
#
# @!attribute [rw] trusted_proxies
#   @return [Array<String, Regexp, Proc>] allowlist of trusted proxy peers
# @!attribute [rw] prefer_forwarded
#   @return [Boolean] prefer X-Forwarded-Access-Token over Authorization
# @!attribute [rw] require_forwarded_header
#   @return [Boolean] require X-Forwarded-Access-Token to be present
# @!attribute [rw] enforce_header_consistency
#   @return [Boolean] when both headers exist, require equality
# @!attribute [rw] enforce_claims_consistency
#   @return [Hash] mapping of header keys to claim keys (e.g., { email: :email })
# @!attribute [rw] strip_suspicious_headers
#   @return [Boolean] strip X-Auth-Request-* headers before downstream
# @!attribute [rw] xff_strategy
#   @return [Symbol] :rightmost or :leftmost peer selection from XFF
# @!attribute [rw] clock_skew_leeway
#   @return [Integer] reserved leeway (seconds) for exp/nbf (handled in core)
# @!attribute [rw] logger
#   @return [Logger, nil] optional logger for audit tags

module Verikloak
  module BFF
    # Configuration for Verikloak::BFF middleware (trusted proxies, header policies, logging, etc.).
    class Configuration
      attr_accessor :trusted_proxies, :prefer_forwarded, :require_forwarded_header,
                    :enforce_header_consistency, :enforce_claims_consistency,
                    :strip_suspicious_headers, :xff_strategy, :clock_skew_leeway,
                    :logger, :token_header_priority, :peer_preference,
                    :forwarded_header_name, :auth_request_headers, :log_with

      # enforce_claims_consistency example:
      # { email: :email, user: :sub, groups: :realm_roles }
      def initialize
        @trusted_proxies = []
        @prefer_forwarded = true
        @require_forwarded_header = false
        @enforce_header_consistency = true
        @enforce_claims_consistency = {}
        @strip_suspicious_headers = true
        @xff_strategy = :rightmost
        @peer_preference = :remote_then_xff
        @clock_skew_leeway = 30
        @logger = nil
        @log_with = nil
        @forwarded_header_name = 'HTTP_X_FORWARDED_ACCESS_TOKEN'
        @auth_request_headers = {
          email: 'HTTP_X_AUTH_REQUEST_EMAIL',
          user: 'HTTP_X_AUTH_REQUEST_USER',
          groups: 'HTTP_X_AUTH_REQUEST_GROUPS'
        }
        # When Authorization is empty and no chosen token exists, try these env headers (in order)
        # to seed Authorization, similar to verikloak-rails behavior. HTTP_AUTHORIZATION is ignored as a source.
        @token_header_priority = %w[
          HTTP_X_FORWARDED_ACCESS_TOKEN
          HTTP_AUTHORIZATION
        ]
      end
    end
  end
end
