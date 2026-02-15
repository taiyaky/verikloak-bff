# frozen_string_literal: true

# Helpers to compare X-Auth-Request-* headers with JWT claims according to a
# provided mapping. Intended for lightweight, unverified JWT parsing only.
#
# @see .enforce!

require 'json'
require 'verikloak/bff/constants'
require 'verikloak/bff/jwt_utils'

module Verikloak
  module BFF
    # Compares X-Auth-Request-* headers with JWT claims according to a mapping.
    module ConsistencyChecks
      module_function

      # Decode the JWT payload without verifying the signature. Intended only
      # for lightweight claim comparisons; full verification occurs downstream.
      #
      # @param token [String, nil]
      # @return [Hash] claims or empty hash on error
      def decode_claims(token)
        Verikloak::BFF::JwtUtils.decode_claims(token)
      end

      # mapping: { email: :email, user: :sub, groups: :realm_roles }
      # Enforce consistency according to the provided mapping.
      #
      # @param env [Hash]
      # @param token [String, nil]
      # @param mapping [Hash] e.g., { email: :email, user: :sub, groups: :realm_roles }
      # @param headers_map [Hash{Symbol=>String}, nil] overrides for header keys
      # @return [true, Array(:error, Symbol)] true or error tuple with failing field
      def enforce!(env, token, mapping, headers_map = nil)
        return true if mapping.nil? || mapping.empty?

        claims = decode_claims(token)
        enforce_claims(env, claims, mapping, headers_map)
      end

      # Enforce consistency using pre-decoded claims (avoids redundant JWT parsing).
      #
      # @param env [Hash]
      # @param claims [Hash] pre-decoded JWT claims
      # @param mapping [Hash]
      # @param headers_map [Hash{Symbol=>String}, nil]
      # @return [true, Array(:error, Symbol)]
      def enforce_with_claims(env, claims, mapping, headers_map = nil)
        return true if mapping.nil? || mapping.empty?

        claims = {} unless claims.is_a?(Hash)
        enforce_claims(env, claims, mapping, headers_map)
      end

      # Shared implementation for enforce! and enforce_with_claims.
      #
      # @param env [Hash]
      # @param claims [Hash]
      # @param mapping [Hash]
      # @param headers_map [Hash{Symbol=>String}, nil]
      # @return [true, Array(:error, Symbol)]
      def enforce_claims(env, claims, mapping, headers_map)
        mapping.each do |header_key, claim_key|
          hdr_val = extract_header_value(env, header_key, headers_map)
          next if hdr_val.nil? # no header → skip comparison

          case claim_key
          when :realm_roles
            roles = Array((claims['realm_access'] || {})['roles'] || [])
            hdr_list = split_list(hdr_val)
            return error(:groups) unless (hdr_list - roles).empty?
          else
            claim_val = dig_claim(claims, claim_key)
            return error(header_key) unless claim_val && hdr_val.to_s == claim_val.to_s
          end
        end
        true
      end

      # Extract an X-Auth-Request-* header value mapped from a symbolic key.
      #
      # @param env [Hash]
      # @param key [Symbol]
      # @param headers_map [Hash{Symbol=>String}, nil]
      # @return [String, nil]
      def extract_header_value(env, key, headers_map = nil)
        return env[headers_map[key]] if headers_map && headers_map[key]

        case key
        when :email
          env['HTTP_X_AUTH_REQUEST_EMAIL']
        when :user
          env['HTTP_X_AUTH_REQUEST_USER']
        when :groups
          env['HTTP_X_AUTH_REQUEST_GROUPS']
        end
      end

      # Split a comma-separated list into an array.
      #
      # @param val [String]
      # @return [Array<String>]
      def split_list(val)
        Array(val.to_s.split(',').map(&:strip).reject(&:empty?))
      end

      # Dig into JWT claims by a symbol/string key or an array path.
      #
      # @param claims [Hash]
      # @param key [Symbol, String, Array<String,Symbol>]
      # @return [Object, nil]
      def dig_claim(claims, key)
        case key
        when Symbol, String
          claims[key.to_s]
        when Array
          key.reduce(claims) { |acc, k| acc.is_a?(Hash) ? acc[k.to_s] : nil }
        end
      end

      # Build an error tuple for a failed field.
      #
      # @param field [Symbol]
      # @return [Array(:error, Symbol)]
      def error(field)
        [:error, field]
      end
    end
  end
end
