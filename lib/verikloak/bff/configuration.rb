# frozen_string_literal: true

# Configuration object for verikloak-bff. Holds middleware settings such as
# proxy trust rules, header consistency policies, and logging options.
#
# @!attribute [rw] disabled
#   @return [Boolean] explicitly disable the middleware (pass-through mode)
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

require 'verikloak/header_sources'

module Verikloak
  module BFF
    # Configuration for Verikloak::BFF middleware (trusted proxies, header policies, logging, etc.).
    class Configuration
      attr_accessor :disabled, :trusted_proxies, :prefer_forwarded, :require_forwarded_header,
                    :enforce_header_consistency, :enforce_claims_consistency,
                    :strip_suspicious_headers, :xff_strategy, :clock_skew_leeway,
                    :logger, :peer_preference, :auth_request_headers, :log_with,
                    :claims_consistency_mode
      attr_reader :token_header_priority, :forwarded_header_name

      # enforce_claims_consistency example:
      # { email: :email, user: :sub, groups: :realm_roles }
      #
      # Initialize configuration with secure defaults for proxy trust, token
      # handling, and logging behavior.
      #
      # @return [void]
      def initialize
        @disabled = false
        @trusted_proxies = []
        @prefer_forwarded = true
        @require_forwarded_header = false
        @enforce_header_consistency = true
        @enforce_claims_consistency = {}
        @claims_consistency_mode = :enforce
        @strip_suspicious_headers = true
        @xff_strategy = :rightmost
        @peer_preference = :remote_then_xff
        @clock_skew_leeway = 30
        @logger = nil
        @log_with = nil
        self.forwarded_header_name = Verikloak::HeaderSources::DEFAULT_FORWARDED_HEADER
        @auth_request_headers = {
          email: 'HTTP_X_AUTH_REQUEST_EMAIL',
          user: 'HTTP_X_AUTH_REQUEST_USER',
          groups: 'HTTP_X_AUTH_REQUEST_GROUPS'
        }
        # When Authorization is empty and no chosen token exists, try these env headers (in order)
        # to seed Authorization, similar to verikloak-rails behavior. HTTP_AUTHORIZATION is always ignored as a source.
        self.token_header_priority = Verikloak::HeaderSources.default_priority(forwarded_header: @forwarded_header_name)
      end

      # Override forwarded header name while re-normalizing the token priority list.
      # When the forwarded header changes, downstream priority normalization must
      # be refreshed because the forwarded value participates in that list.
      #
      # @param header [String, Symbol]
      # @return [void]
      def forwarded_header_name=(header)
        @forwarded_header_name = Verikloak::HeaderSources.normalize_env_key(header)
        renormalize_token_priority!
      end

      # Assign token header priority list using shared normalization logic.
      #
      # @param priority [Array<String, Symbol>, String, Symbol, nil]
      # @return [void]
      def token_header_priority=(priority)
        normalized, = Verikloak::HeaderSources.normalize_priority(priority, forwarded_header: @forwarded_header_name)
        @token_header_priority = normalized
      end

      private

      # Re-apply token header normalization so it reflects the current forwarded header.
      #
      # @return [void]
      def renormalize_token_priority!
        # Refresh the normalized list so it reflects the new forwarded header name.
        self.token_header_priority = @token_header_priority
      end
    end
  end
end
