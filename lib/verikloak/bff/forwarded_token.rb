# frozen_string_literal: true

# Utilities to extract, normalize, and manipulate forwarded/auth headers.
#
# @see .extract

module Verikloak
  module BFF
    # Helpers to extract and normalize forwarded/access token headers.
    module ForwardedToken
      module_function

      FORWARDED_HEADER = 'HTTP_X_FORWARDED_ACCESS_TOKEN'
      AUTH_HEADER      = 'HTTP_AUTHORIZATION'

      # Extract normalized tokens from the Rack env.
      #
      # @param env [Hash]
      # @return [Array(String, String)] [auth_token, forwarded_token]
      def extract(env, forwarded_header_name = FORWARDED_HEADER, auth_header_name = AUTH_HEADER)
        fwd_raw = env[forwarded_header_name]
        auth_raw = env[auth_header_name]
        [normalize_auth(auth_raw), normalize_forwarded(fwd_raw)]
      end

      # Only accept Bearer scheme for Authorization header.
      #
      # @param raw [String, nil]
      # @return [String, nil] token or nil when not Bearer
      def normalize_auth(raw)
        return nil unless raw

        token = raw.to_s.strip
        return ::Regexp.last_match(1) if token =~ /^Bearer\s+(.+)$/i
        return token[6..] if token =~ /^Bearer(?!\s)/i

        nil
      end

      # Accept either bare token or Bearer for forwarded header.
      #
      # @param raw [String, nil]
      # @return [String, nil] token or nil
      def normalize_forwarded(raw)
        return nil unless raw

        token = raw.to_s.strip
        return ::Regexp.last_match(1) if token =~ /^Bearer\s+(.+)$/i

        token.empty? ? nil : token
      end

      # Normalize to a proper 'Bearer <token>' header value.
      # - Detects scheme case-insensitively
      # - Inserts a missing space (e.g., 'BearerXYZ' => 'Bearer XYZ')
      # - Collapses multiple spaces/tabs after the scheme to a single space
      # @param token [String]
      # @return [String]
      def ensure_bearer(token)
        s = token.to_s.strip
        # Case-insensitive 'Bearer' with spaces/tabs after
        if s =~ /\ABearer[ \t]+/i
          rest = s.sub(/\ABearer[ \t]+/i, '')
          return "Bearer #{rest}"
        end

        # Case-insensitive 'Bearer' with no separator (e.g., 'BearerXYZ')
        if s =~ /\ABearer(?![ \t])/i
          rest = s[6..] || ''
          return "Bearer #{rest}"
        end

        # No scheme present; add it
        "Bearer #{s}"
      end

      # Set Authorization header to a normalized Bearer value (no overwrite when present).
      #
      # @param env [Hash]
      # @param token [String]
      def set_authorization!(env, token)
        existing = env[AUTH_HEADER].to_s
        # Overwrite only if Authorization is empty or not a valid Bearer value
        return unless existing.empty? || normalize_auth(existing).nil?

        env[AUTH_HEADER] = ensure_bearer(token)
      end

      # Remove potentially forged X-Auth-Request-* headers before passing
      # downstream when not emitted by a trusted proxy.
      #
      # @param env [Hash]
      def strip_suspicious!(env, headers = nil)
        if headers.is_a?(Hash)
          headers.each_value { |h| env.delete(h) }
          return
        end
        env.delete('HTTP_X_AUTH_REQUEST_EMAIL')
        env.delete('HTTP_X_AUTH_REQUEST_USER')
        env.delete('HTTP_X_AUTH_REQUEST_GROUPS')
      end
    end
  end
end
