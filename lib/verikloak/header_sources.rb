# frozen_string_literal: true

# Helpers shared across verikloak middleware for normalizing Rack env header
# names and token source priority lists. Extracted to allow other gems (such as
# verikloak-rails) to consume the same normalization logic.
module Verikloak
  # Provides normalization helpers for Rack env header keys and token priority lists.
  module HeaderSources
    module_function

    DEFAULT_FORWARDED_HEADER = 'HTTP_X_FORWARDED_ACCESS_TOKEN'
    AUTHORIZATION_HEADER     = 'HTTP_AUTHORIZATION'

    # Normalize a Rack env header key, accepting symbols, mixed case, or dash
    # separated names and returning an upper-case HTTP_* variant.
    #
    # @param header [String, Symbol, nil]
    # @return [String] normalized env key or empty string when blank
    def normalize_env_key(header)
      key = header.to_s.strip
      return '' if key.empty?

      key = key.tr('-', '_').upcase
      key = "HTTP_#{key}" unless key.start_with?('HTTP_')
      key
    end

    # Normalize a token priority list by stripping blanks, rejecting
    # Authorization as a source, and deduplicating entries while preserving
    # order.
    #
    # @param priority [Array<String, Symbol>, String, Symbol, nil]
    # @param forwarded_header [String, Symbol]
    # @param drop_authorization [Boolean]
    # @return [Array(Array<String>, String)] normalized priority and forwarded key
    def normalize_priority(priority, forwarded_header: DEFAULT_FORWARDED_HEADER, drop_authorization: true)
      forwarded_env = normalize_env_key(forwarded_header)
      items = Array(priority).flatten

      normalized = items.map { |value| normalize_env_key(value) }.reject(&:empty?)
      normalized = [forwarded_env] if normalized.empty?
      normalized = normalized.reject { |key| drop_authorization && key == AUTHORIZATION_HEADER }

      deduped = []
      normalized.each do |key|
        deduped << key unless deduped.include?(key)
      end

      [deduped.freeze, forwarded_env]
    end

    # Default priority list using the provided forwarded header name.
    #
    # @param forwarded_header [String, Symbol]
    # @return [Array<String>] normalized default priority
    def default_priority(forwarded_header: DEFAULT_FORWARDED_HEADER)
      normalize_priority([forwarded_header], forwarded_header: forwarded_header).first
    end
  end
end
