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
      # @param preference [Symbol] `:remote_then_xff` (default) prefers REMOTE_ADDR,
      #   `:xff_only` selects the peer from X-Forwarded-For first
      # @return [Boolean] true if the selected peer is trusted
      # @example CIDR + Regex allowlist
      #   ProxyTrust.trusted?(env, ["10.0.0.0/8", /^192\.168\./], :rightmost)
      def trusted?(env, trusted, strategy = :rightmost, preference: :remote_then_xff)
        remote = resolve_peer(env, preference, strategy)
        trusted_remote?(remote, trusted, env)
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
        resolve_peer(env, preference, strategy)
      end

      # Parse string to IPAddr or nil on failure.
      # IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) are normalised to
      # native IPv4 so that CIDR checks against plain IPv4 ranges succeed.
      #
      # @param str [String]
      # @return [IPAddr, nil]
      def ip_or_nil(str)
        addr = IPAddr.new(str)
        addr = addr.native if addr.respond_to?(:native)
        addr
      rescue StandardError
        nil
      end

      # Check whether a single rule trusts the selected remote.
      # A rule that raises (e.g. an invalid CIDR string or a failing Proc) is
      # treated as non-matching so that one bad rule cannot disable the rest
      # of the allowlist.
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
      rescue StandardError => e
        # Isolate a single failing rule without disabling the rest of the
        # allowlist, but surface it under $DEBUG so a broken Proc/CIDR rule is
        # observable instead of silently denying trust.
        warn("[verikloak-bff] trusted_proxies rule raised and was skipped: #{e.class}: #{e.message}") if $DEBUG
        false
      end

      # Resolve the peer value based on preference and strategy.
      #
      # Only `:xff_only` selects the peer from X-Forwarded-For first. Every other
      # value — the `:remote_then_xff` default, `nil`, or an unrecognized/typo'd
      # preference — falls back to the safe REMOTE_ADDR-first path so a
      # misconfiguration can never switch the trust decision onto the
      # client-controlled X-Forwarded-For header.
      #
      # @param env [Hash]
      # @param preference [Symbol]
      # @param strategy [Symbol]
      # @return [String, nil]
      def resolve_peer(env, preference, strategy)
        return extract_peer_ip(env, strategy) if preference.to_s.to_sym == :xff_only

        remote = (env['REMOTE_ADDR'] || '').to_s.strip
        return remote unless remote.empty?

        # Fall back to X-Forwarded-For when REMOTE_ADDR is empty
        extract_peer_ip(env, strategy)
      end

      # Determine whether a remote peer appears in the trusted list.
      #
      # @param remote [String, nil]
      # @param trusted [Array<String, Regexp, Proc>, nil]
      # @param env [Hash]
      # @return [Boolean]
      def trusted_remote?(remote, trusted, env)
        return false if trusted.nil? || trusted.empty?
        return false unless remote

        remote_ip = ip_or_nil(remote)
        trusted.any? { |rule| rule_trusts?(rule, remote, remote_ip, env) }
      rescue StandardError
        false
      end
    end
  end
end
