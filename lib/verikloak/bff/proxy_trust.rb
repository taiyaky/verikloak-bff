# frozen_string_literal: true

# Utilities to determine whether a request peer (via REMOTE_ADDR / XFF) is
# allow‑listed as a trusted proxy.
require 'ipaddr'

module Verikloak
  module BFF
    # Determines whether the selected peer (via XFF/REMOTE_ADDR) is a trusted proxy.
    module ProxyTrust
      module_function

      # Determine if the immediate peer (based on REMOTE_ADDR / X-Forwarded-For) is trusted.
      # strategy :rightmost (typical when proxy appends client IP to the right)
      #
      # @param env [Hash] Rack environment
      # @param trusted [Array<String, Regexp, Proc>, nil] Allowlist of proxy peers.
      #   - String: exact IP (e.g. "127.0.0.1") or CIDR (e.g. "10.0.0.0/8")
      #   - Regexp: matched against the selected peer IP
      #   - Proc: called as `->(ip, env) { ... }` and returns truthy when trusted
      # @param strategy [Symbol, String] `:rightmost` (default) or `:leftmost` for XFF parsing
      # @return [Boolean] true if the selected peer is trusted
      # @example CIDR + Regex allowlist
      #   ProxyTrust.trusted?(env, ["10.0.0.0/8", /^192\.168\./], :rightmost)
      def trusted?(env, trusted, strategy = :rightmost)
        return false if trusted.nil? || trusted.empty?

        # Rails-aligned: prefer REMOTE_ADDR; fallback to nearest XFF entry
        remote = (env['REMOTE_ADDR'] || '').to_s.strip
        remote = extract_peer_ip(env, strategy) if remote.empty?
        return false unless remote

        remote_ip = ip_or_nil(remote)
        trusted.any? { |rule| rule_trusts?(rule, remote, remote_ip, env) }
      rescue StandardError
        false
      end

      # Select the peer IP from X-Forwarded-For according to strategy or fall back to REMOTE_ADDR.
      #
      # @param env [Hash] Rack environment
      # @param strategy [Symbol, String] `:rightmost` (default) or `:leftmost`
      # @return [String, nil] Selected peer IP, or nil if not determinable
      def extract_peer_ip(env, strategy)
        mode = strategy.to_s.to_sym
        xff = env['HTTP_X_FORWARDED_FOR']
        if xff && !xff.strip.empty?
          parts = xff.split(',').map(&:strip)
          ip = mode == :leftmost ? parts.first : parts.last
          return ip
        end
        env['REMOTE_ADDR']
      end

      # Return the selected peer IP according to preference and strategy.
      #
      # @param env [Hash]
      # @param preference [Symbol] :remote_then_xff or :xff_only
      # @param strategy [Symbol] :rightmost or :leftmost
      # @return [String, nil]
      def selected_peer(env, preference, strategy)
        case preference.to_s.to_sym
        when :remote_then_xff
          ip = (env['REMOTE_ADDR'] || '').to_s.strip
          return ip unless ip.nil? || ip.empty?

          extract_peer_ip(env, :rightmost) # nearest by default
        else
          extract_peer_ip(env, strategy)
        end
      end

      # Parse string to IPAddr or nil on failure.
      #
      # @param str [String]
      # @return [IPAddr, nil]
      def ip_or_nil(str)
        IPAddr.new(str)
      rescue StandardError
        nil
      end

      # Check whether a single rule trusts the selected remote.
      #
      # @param rule [String, Regexp, Proc]
      # @param remote [String]
      # @param remote_ip [IPAddr, nil]
      # @param env [Hash]
      # @return [Boolean]
      def rule_trusts?(rule, remote, remote_ip, env)
        case rule
        when String
          if rule.include?('/') # CIDR
            cidr = IPAddr.new(rule)
            remote_ip ? cidr.include?(remote_ip) : false
          else
            remote == rule
          end
        when Regexp
          remote =~ rule
        when Proc
          rule.call(remote, env)
        else
          false
        end
      end

      # Determine if the request originates from a trusted proxy subnet.
      # Rails-aligned behavior: prefer REMOTE_ADDR, fallback to nearest (rightmost) X-Forwarded-For.
      #
      # @param env [Hash]
      # @param trusted [Array<String, Regexp, Proc>, nil]
      # @return [Boolean]
      def self.from_trusted_proxy?(env, trusted)
        return false if trusted.nil? || trusted.empty?

        ip = (env['REMOTE_ADDR'] || '').to_s.strip
        ip = env['HTTP_X_FORWARDED_FOR'].to_s.split(',').last.to_s.strip if ip.empty? && env['HTTP_X_FORWARDED_FOR']
        return false if ip.empty?

        remote_ip = ip_or_nil(ip)
        return false unless remote_ip

        trusted.any? { |rule| rule_trusts?(rule, ip, remote_ip, env) }
      rescue StandardError
        false
      end
    end
  end
end
