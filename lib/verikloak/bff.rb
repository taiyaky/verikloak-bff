# frozen_string_literal: true

# Namespace for BFF-related configuration and helpers used by verikloak-bff.
#
# @see Verikloak::BFF::Configuration

module Verikloak
  # Top-level namespace for verikloak-bff features and configuration.
  module BFF
    class << self
      # Configure global settings for the BFF middleware.
      #
      # @yieldparam config [Verikloak::BFF::Configuration]
      # @return [Verikloak::BFF::Configuration]
      def configure
        @config ||= Configuration.new
        yield @config if block_given?
        @config
      end

      # Current global configuration.
      #
      # @return [Verikloak::BFF::Configuration]
      def config
        @config ||= Configuration.new
      end
    end
  end
end
