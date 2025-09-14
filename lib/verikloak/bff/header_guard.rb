# frozen_string_literal: true

# Rack middleware that hardens the BFF boundary by normalizing tokens and
# enforcing header/claims consistency before the core verifier runs.
#
# Typical usage (Rack/Rails):
#   use Verikloak::BFF::HeaderGuard, trusted_proxies: ['127.0.0.1']
#
# The middleware prefers `X-Forwarded-Access-Token` (configurable), enforces
# header equality when both tokens exist, optionally checks `X-Auth-Request-*`
# headers against JWT claims, and normalizes the request into
# `HTTP_AUTHORIZATION: Bearer <token>` for the downstream verifier.
require 'rack'
require 'json'
require 'jwt'
require 'verikloak/bff/configuration'
require 'verikloak/bff/errors'
require 'verikloak/bff/proxy_trust'
require 'verikloak/bff/forwarded_token'
require 'verikloak/bff/consistency_checks'

module Verikloak
  module BFF
    # Rack middleware that enforces BFF boundary and header/claims consistency.
    class HeaderGuard
      # Accept both Rack 2 and Rack 3 builder call styles:
      # - new(app, key: val)
      # - new(app, { key: val })
      #
      # @param app [#call]
      # @param opts [Hash, nil]
      # @param opts_kw [Hash]
      def initialize(app, opts = nil, **opts_kw)
        @app = app
        # Use a per-instance copy of global config to avoid cross-request/test side effects
        @config = Verikloak::BFF.config.dup
        combined = {}
        combined.merge!(opts) if opts.is_a?(Hash)
        combined.merge!(opts_kw) if opts_kw && !opts_kw.empty?
        apply_overrides!(combined)
      end

      # Process a Rack request.
      #
      # @param env [Hash]
      # @return [Array(Integer, Hash, Array<#to_s>)] Rack response triple
      def call(env)
        ensure_trusted_proxy!(env)
        auth_token, fwd_token = ForwardedToken.extract(env, @config.forwarded_header_name)
        ensure_forwarded_if_required!(fwd_token)
        chosen = choose_token(auth_token, fwd_token)
        chosen = seed_authorization_if_needed(env, chosen)

        enforce_header_consistency!(env, auth_token, fwd_token)
        enforce_claims_consistency!(env, chosen)
        ForwardedToken.strip_suspicious!(env, @config.auth_request_headers) if @config.strip_suspicious_headers
        normalize_authorization!(env, chosen, auth_token, fwd_token)
        expose_env_hints(env, chosen)
        @app.call(env)
      rescue Verikloak::BFF::Error => e
        respond_with_error(env, e)
      end

      private

      # Apply per-instance configuration overrides.
      #
      # @param opts [Hash]
      def apply_overrides!(opts)
        cfg = @config
        opts.each do |k, v|
          cfg.public_send("#{k}=", v) if cfg.respond_to?("#{k}=")
        end
      end

      # Choose a token based on preference and presence.
      #
      # @param auth_token [String, nil]
      # @param fwd_token [String, nil]
      # @return [String, nil]
      def choose_token(auth_token, fwd_token)
        return fwd_token if @config.prefer_forwarded && fwd_token

        auth_token || fwd_token
      end

      # Describe the source of the chosen token for logging purposes.
      #
      # @param auth_token [String, nil]
      # @param fwd_token [String, nil]
      # @return [String] "authorization" or "forwarded"
      def token_source(auth_token, fwd_token)
        return 'forwarded' if @config.prefer_forwarded && fwd_token

        if auth_token && fwd_token
          'authorization'
        else
          (auth_token ? 'authorization' : 'forwarded')
        end
      end

      # Extract selected JWT tags for audit logging (best-effort, unverified).
      #
      # @param token [String, nil]
      # @return [Hash] subset of {sub, iss, aud, kid}
      def token_tags(token)
        return {} unless token

        payload, header = decode_unverified(token)
        {
          sub: payload['sub'],
          iss: payload['iss'],
          aud: (payload['aud'].is_a?(Array) ? payload['aud'].join(' ') : payload['aud']).to_s,
          kid: header['kid']
        }.compact
      rescue StandardError
        {}
      end

      # Decode JWT header/payload without validation (for logging only).
      #
      # @param token [String]
      # @return [Array(Hash, Hash)] [payload, header]
      def decode_unverified(token)
        parts = token.to_s.split('.')
        return [{}, {}] unless parts.size >= 2

        payload = begin
          JSON.parse(::JWT::Base64.url_decode(parts[1]))
        rescue StandardError
          {}
        end
        header = begin
          JSON.parse(::JWT::Base64.url_decode(parts[0]))
        rescue StandardError
          {}
        end
        [payload, header]
      end

      # Extract request id for logging from common headers.
      #
      # @param env [Hash]
      # @return [String, nil]
      def request_id(env)
        env['HTTP_X_REQUEST_ID'] || env['action_dispatch.request_id']
      end

      # Resolve logger to use (config-provided or rack.logger).
      #
      # @param env [Hash]
      # @return [Logger, nil]
      def logger(env)
        @config.logger || env['rack.logger']
      end

      # Emit a structured log line if a logger is present.
      #
      # @param env [Hash]
      # @param kind [Symbol] :ok, :mismatch, :claims_mismatch, :error
      # @param attrs [Hash]
      def log_event(env, kind, **attrs)
        lg = logger(env)
        payload = { event: 'bff.header_guard', kind: kind, rid: request_id(env) }.merge(attrs).compact
        if @config.log_with.respond_to?(:call)
          begin
            @config.log_with.call(payload)
          rescue StandardError
            # ignore log hook failures
          end
        end
        return unless lg

        msg = payload.map { |k, v| v.nil? || v.to_s.empty? ? nil : "#{k}=#{v}" }.compact.join(' ')
        level = (kind == :ok ? :info : :warn)
        lg.public_send(level, msg)
      rescue StandardError
        # no-op on logging errors
      end

      # Raise when the request did not come through a trusted proxy.
      #
      # @param env [Hash]
      def ensure_trusted_proxy!(env)
        return if ProxyTrust.trusted?(env, @config.trusted_proxies, @config.xff_strategy)

        raise UntrustedProxyError
      end

      # Enforce presence of forwarded token when required.
      #
      # @param fwd_token [String, nil]
      def ensure_forwarded_if_required!(fwd_token)
        return unless @config.require_forwarded_header
        raise MissingForwardedTokenError if fwd_token.nil? || fwd_token.to_s.strip.empty?
      end

      # Enforce equality when both Authorization and Forwarded tokens exist.
      #
      # @param env [Hash]
      # @param auth_token [String, nil]
      # @param fwd_token [String, nil]
      def enforce_header_consistency!(env, auth_token, fwd_token)
        return unless @config.enforce_header_consistency
        return unless auth_token && fwd_token
        return if auth_token == fwd_token

        log_event(env, :mismatch, reason: 'authorization_vs_forwarded')
        raise HeaderMismatchError
      end

      # Enforce X-Auth-Request-* ↔ JWT claims mapping when configured.
      #
      # @param env [Hash]
      # @param chosen [String, nil]
      def enforce_claims_consistency!(env, chosen)
        res = ConsistencyChecks.enforce!(env, chosen, @config.enforce_claims_consistency, @config.auth_request_headers)
        return unless res.is_a?(Array) && res.first == :error

        field = res.last
        log_event(env, :claims_mismatch, field: field.to_s)
        raise ClaimsMismatchError, field
      end

      # Set normalized Authorization header and emit success log.
      #
      # @param env [Hash]
      # @param chosen [String, nil]
      # @param auth_token [String, nil]
      # @param fwd_token [String, nil]
      def normalize_authorization!(env, chosen, auth_token, fwd_token)
        return unless chosen

        ForwardedToken.set_authorization!(env, chosen)
        log_event(env, :ok, source: token_source(auth_token, fwd_token), **token_tags(chosen))
      end

      # Build a minimal RFC6750-style error response.
      #
      # @param env [Hash]
      # @param error [Verikloak::BFF::Error]
      # @return [Array(Integer, Hash, Array<String>)]
      def respond_with_error(env, error)
        log_event(env, :error, code: error.code)
        body = { error: error.code, message: error.message }.to_json
        headers = { 'Content-Type' => 'application/json',
                    'WWW-Authenticate' => %(Bearer error="#{error.code}", error_description="#{error.message}") }
        [error.http_status, headers, [body]]
      end

      # Resolve the first env header from which to source a bearer token.
      # Forwarded is considered only when the peer is trusted; HTTP_AUTHORIZATION is never a source.
      # @param env [Hash]
      # @return [String, nil]
      def resolve_first_token_header(env)
        candidates = Array(@config.token_header_priority).dup
        candidates -= ['HTTP_AUTHORIZATION']
        fwd_key = 'HTTP_X_FORWARDED_ACCESS_TOKEN'
        if candidates.include?(fwd_key) && !ProxyTrust.from_trusted_proxy?(env, @config.trusted_proxies)
          candidates -= [fwd_key]
        end
        candidates.find { |k| (v = env[k]) && !v.to_s.empty? }
      end

      # Seed Authorization from priority headers if nothing chosen and empty Authorization
      # @param env [Hash]
      # @param chosen [String, nil]
      # @return [String, nil] possibly updated chosen token
      def seed_authorization_if_needed(env, chosen)
        return chosen unless chosen.nil? && env['HTTP_AUTHORIZATION'].to_s.empty?
        return chosen unless Array(@config.token_header_priority).any?

        seeded = resolve_first_token_header(env)
        if seeded
          ForwardedToken.set_authorization!(env, env[seeded])
          return ForwardedToken.normalize_forwarded(env[seeded]) || env[seeded].to_s
        end
        chosen
      end

      # Expose hints to downstream
      # @param env [Hash]
      # @param chosen [String, nil]
      def expose_env_hints(env, chosen)
        env['verikloak.bff.token'] = chosen if chosen
        env['verikloak.bff.selected_peer'] =
          ProxyTrust.selected_peer(env, @config.peer_preference, @config.xff_strategy)
      end
    end
  end
end
