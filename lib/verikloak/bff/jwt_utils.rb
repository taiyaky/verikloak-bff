# frozen_string_literal: true

require 'jwt'
require 'verikloak/bff/constants'

module Verikloak
  module BFF
    # Lightweight helpers around JWT decoding without verification.
    module JwtUtils
      module_function

      # Decode JWT header and payload without verification, guarding against oversized input.
      #
      # @param token [String, nil]
      # @return [Array<Hash>] [payload, header]
      def decode_unverified(token)
        return [{}, {}] if token.nil? || token.bytesize > Constants::MAX_TOKEN_BYTES

        JWT.decode(token, nil, false)
      rescue StandardError
        [{}, {}]
      end

      # Return the decoded JWT payload without verification.
      #
      # @param token [String, nil]
      # @return [Hash]
      def decode_claims(token)
        decode_unverified(token).first
      end
    end
  end
end
