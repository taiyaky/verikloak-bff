# frozen_string_literal: true

# Error types emitted by verikloak-bff. These map to RFC6750-style responses
# with stable error codes for easy handling at clients and logs.

module Verikloak
  module BFF
    # Base error class with HTTP status and short code.
    #
    # @attr_reader [String] code
    # @attr_reader [Integer] http_status
    class Error < StandardError
      attr_reader :code, :http_status

      def initialize(message = nil, code: 'bff_error', http_status: 401)
        super(message || code)
        @code = code
        @http_status = http_status
      end
    end

    # Raised when a request did not pass through a trusted proxy peer.
    class UntrustedProxyError < Error
      def initialize(msg = 'request did not pass through a trusted proxy')
        super(msg, code: 'untrusted_proxy', http_status: 401)
      end
    end

    # Raised when require_forwarded_header is enabled but the forwarded token is absent.
    class MissingForwardedTokenError < Error
      def initialize(msg = 'missing X-Forwarded-Access-Token')
        super(msg, code: 'missing_forwarded_token', http_status: 401)
      end
    end

    # Raised when Authorization and X-Forwarded-Access-Token both exist and differ.
    class HeaderMismatchError < Error
      def initialize(msg = 'authorization and forwarded token mismatch')
        super(msg, code: 'header_mismatch', http_status: 401)
      end
    end

    # Raised when X-Auth-Request-* headers conflict with JWT claims.
    class ClaimsMismatchError < Error
      def initialize(field, msg = nil)
        super(msg || "claims/header mismatch for #{field}", code: 'claims_mismatch', http_status: 403)
      end
    end
  end
end
