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
require 'rack/utils'
require 'json'
require 'digest'
require 'verikloak/header_sources'
require 'verikloak/bff/configuration'
require 'verikloak/bff/errors'
require 'verikloak/bff/proxy_trust'
require 'verikloak/bff/forwarded_token'
require 'verikloak/bff/consistency_checks'
require 'verikloak/bff/constants'
require 'verikloak/bff/jwt_utils'

module Verikloak
  module BFF
    # Internal helpers that sanitize tokens and log payloads for HeaderGuard.
    module HeaderGuardSanitizer
      LOG_CONTROL_CHARS    = Constants::LOG_CONTROL_CHARS
      MAX_LOG_FIELD_LENGTH = Constants::MAX_LOG_FIELD_LENGTH

      module_function

      # Generate sanitized token metadata suitable for structured logging without
      # verifying the signature.
      #
      # @param token [String, nil]
      # @return [Hash{Symbol=>Object}] sanitized tags keyed by JWT claim/header
      def token_tags(token)
        return {} unless token

        payload, header = decode_unverified(token)
        token_tags_from_decoded(payload, header)
      rescue StandardError => e
        warn("[verikloak-bff] token_tags failed: #{e.class}: #{e.message}") if $DEBUG
        {}
      end

      # Build sanitized log tags from pre-decoded JWT payload and header.
      # Avoids redundant decoding when the caller already has decoded data.
      #
      # @param payload [Hash]
      # @param header [Hash]
      # @return [Hash{Symbol=>Object}]
      def token_tags_from_decoded(payload, header)
        return {} unless payload.is_a?(Hash)

        aud = payload['aud']
        aud = aud.join(' ') if aud.is_a?(Array)
        {
          sub: sanitize_log_field(payload['sub']&.to_s),
          iss: sanitize_log_field(payload['iss']&.to_s),
          aud: sanitize_log_field(aud&.to_s),
          kid: sanitize_log_field(header&.dig('kid')&.to_s)
        }.compact
      rescue StandardError => e
        warn("[verikloak-bff] token_tags_from_decoded failed: #{e.class}: #{e.message}") if $DEBUG
        {}
      end

      # Decode a JWT without verifying the signature while guarding against
      # excessively large tokens.
      #
      # @param token [String, nil]
      # @return [Array<Hash>] payload and header hashes
      def decode_unverified(token)
        Verikloak::BFF::JwtUtils.decode_unverified(token)
      end

      # Remove unsafe characters from a structured logging payload.
      #
      # @param payload [Hash]
      # @return [Hash] sanitized payload suitable for logging
      def sanitize_payload(payload)
        payload.transform_values { |value| sanitize_log_field(value) }.compact
      end

      # Sanitize an individual value destined for logs, pruning empty results.
      #
      # @param value [Object]
      # @return [Object, nil] sanitized value or nil when the result is empty
      def sanitize_log_field(value)
        case value
        when nil
          nil
        when String
          sanitized = sanitize_string(value)
          sanitized.empty? ? nil : sanitized
        when Array
          sanitized = value.map { |item| item.is_a?(String) ? sanitize_string(item) : item }
          sanitized.reject! { |item| item.nil? || (item.is_a?(String) && item.empty?) }
          sanitized.empty? ? nil : sanitized
        else
          value
        end
      end

      # Remove control characters, invalid UTF-8, and truncate to {MAX_LOG_FIELD_LENGTH}.
      #
      # @param value [#to_s]
      # @return [String]
      def sanitize_string(value)
        sanitized = value.to_s.encode('UTF-8', invalid: :replace, undef: :replace, replace: '').gsub(LOG_CONTROL_CHARS,
                                                                                                     '')
        sanitized.length > MAX_LOG_FIELD_LENGTH ? "#{sanitized[0, MAX_LOG_FIELD_LENGTH]}..." : sanitized
      end

      # Describe the source of the chosen token for logging purposes.
      #
      # @param prefer_forwarded [Boolean]
      # @param auth_token [String, nil]
      # @param fwd_token [String, nil]
      # @return [String] "authorization" or "forwarded"
      def token_source(prefer_forwarded, auth_token, fwd_token)
        return 'forwarded' if prefer_forwarded && fwd_token

        if auth_token && fwd_token
          'authorization'
        else
          (auth_token ? 'authorization' : 'forwarded')
        end
      end

      # Extract request id for logging from common headers.
      #
      # @param env [Hash]
      # @return [String, nil]
      def request_id(env)
        env['HTTP_X_REQUEST_ID'] || env['action_dispatch.request_id']
      end

      # Emit a structured log line if a logger is present.
      #
      # @param env [Hash]
      # @param config [Configuration]
      # @param kind [Symbol] :ok, :mismatch, :claims_mismatch, :error
      # @param attrs [Hash]
      # @return [void]
      def log_event(env, config, kind, **attrs)
        payload = { event: 'bff.header_guard', kind: kind, rid: request_id(env) }.merge(attrs).compact
        sanitized = sanitize_payload(payload)
        invoke_log_hook(config, sanitized)
        emit_to_logger(config.logger || env['rack.logger'], sanitized, kind)
      rescue StandardError => e
        warn("[verikloak-bff] log_event failed: #{e.class}: #{e.message}") if $DEBUG
      end

      # @param config [Configuration]
      # @param sanitized [Hash]
      # @return [void]
      def invoke_log_hook(config, sanitized)
        return unless config.log_with.respond_to?(:call)

        config.log_with.call(sanitized)
      rescue StandardError => e
        warn("[verikloak-bff] log_with hook failed: #{e.class}: #{e.message}") if $DEBUG
      end

      # @param logger [Logger, nil]
      # @param sanitized [Hash]
      # @param kind [Symbol]
      # @return [void]
      def emit_to_logger(logger, sanitized, kind)
        return unless logger

        msg = sanitized.map { |k, v| v.nil? || v.to_s.empty? ? nil : "#{k}=#{v}" }.compact.join(' ')
        logger.public_send(kind == :ok ? :info : :warn, msg)
      end

      # Build a minimal RFC6750-style error response.
      # Delegates to {Verikloak::ErrorResponse} for consistent formatting across gems.
      #
      # @param env [Hash]
      # @param config [Configuration]
      # @param error [Verikloak::BFF::Error]
      # @return [Array(Integer, Hash, Array<String>)]
      def respond_with_error(env, config, error)
        log_event(env, config, :error, code: error.code)
        require 'verikloak/error_response'
        status, headers, body = Verikloak::ErrorResponse.build(
          code: error.code, message: error.message, status: error.http_status
        )

        # RFC 6750 §3.1: include WWW-Authenticate on 403 for client diagnostics
        if status == 403 && !headers.key?('WWW-Authenticate')
          sanitize = Verikloak::ErrorResponse.method(:sanitize_header_value)
          headers['WWW-Authenticate'] = format(
            'Bearer realm="%<realm>s", error="%<code>s", error_description="%<msg>s"',
            realm: sanitize.call('verikloak-bff'),
            code: sanitize.call(error.code),
            msg: sanitize.call(error.message)
          )
        end

        [status, headers, body]
      end
    end

    # Rack middleware that enforces BFF boundary and header/claims consistency.
    class HeaderGuard
      # Error raised when trusted_proxies is not configured and disabled is not explicitly set.
      class ConfigurationError < StandardError; end

      RequestTokens = Struct.new(:auth, :forwarded, :chosen, :decoded_payload, :decoded_header)

      # Accept both Rack 2 and Rack 3 builder call styles:
      # - new(app, key: val)
      # - new(app, { key: val })
      #
      # @param app [#call]
      # @param opts [Hash, nil]
      # @param opts_kw [Hash]
      # @raise [ConfigurationError] when trusted_proxies is not configured and disabled is false
      def initialize(app, opts = nil, **opts_kw)
        @app = app
        # Use a per-instance copy of global config to avoid cross-request/test side effects
        @config = Verikloak::BFF.config.dup
        combined = {}
        combined.merge!(opts) if opts.is_a?(Hash)
        combined.merge!(opts_kw) if opts_kw && !opts_kw.empty?
        apply_overrides!(combined)

        # Check configuration validity
        validate_configuration!
      end

      # Check if the middleware is explicitly disabled.
      #
      # @return [Boolean]
      def disabled?
        @config.disabled
      end

      # Process a Rack request through the BFF header guard pipeline.
      #
      # Pipeline stages:
      # 1. Proxy trust validation
      # 2. Token extraction and state building
      # 3. Policy enforcement (forwarded token requirements, consistency checks)
      # 4. Request finalization (Authorization header normalization)
      #
      # When `disabled: true` is set, the middleware passes through without any processing.
      #
      # @param env [Hash]
      # @return [Array(Integer, Hash, Array<#to_s>)] Rack response triple
      def call(env)
        # Pass through if middleware is explicitly disabled
        return @app.call(env) if disabled?

        # Stage 1: Validate request comes from trusted proxy
        ensure_trusted_proxy!(env)

        # Stage 2: Extract and validate tokens, build request state
        tokens = build_token_state(env)

        # Stage 3: Enforce configured policies (forwarded requirements, consistency)
        enforce_token_policies!(env, tokens)

        # Stage 4: Finalize request with normalized Authorization header
        finalize_request!(env, tokens)

        @app.call(env)
      rescue Verikloak::BFF::Error => e
        HeaderGuardSanitizer.respond_with_error(env, @config, e)
      end

      private

      # Validate that required configuration is present.
      # Raises ConfigurationError if trusted_proxies is not configured and disabled is false.
      #
      # @raise [ConfigurationError]
      # @return [void]
      def validate_configuration!
        return if @config.disabled

        proxies = @config.trusted_proxies
        return unless proxies.nil? || proxies.empty?

        raise ConfigurationError,
              'trusted_proxies must be configured for Verikloak::BFF::HeaderGuard. ' \
              'Set trusted_proxies to an array of allowed proxy addresses/CIDRs, ' \
              'or set disabled: true to explicitly skip BFF protection.'
      end

      # Build token state by extracting, validating, and selecting the active token.
      # Decodes the chosen token once (unverified) so that downstream stages
      # (claims consistency, logging) can reuse the result without re-parsing.
      #
      # @param env [Hash]
      # @return [RequestTokens]
      def build_token_state(env)
        auth_token, fwd_token = ForwardedToken.extract(env, @config.forwarded_header_name)
        ensure_forwarded_if_required!(fwd_token)

        chosen = choose_token(auth_token, fwd_token)
        chosen = seed_authorization_if_needed(env, chosen)

        payload, header = JwtUtils.decode_unverified(chosen)
        RequestTokens.new(auth_token, fwd_token, chosen, payload, header)
      end

      # Apply header and claim consistency policies for the current request.
      #
      # @param env [Hash]
      # @param tokens [RequestTokens]
      # @return [void]
      def enforce_token_policies!(env, tokens)
        enforce_header_consistency!(env, tokens.auth, tokens.forwarded)
        enforce_claims_consistency!(env, tokens)
      end

      # Mutate the Rack env with normalized headers and logging hints.
      #
      # @param env [Hash]
      # @param tokens [RequestTokens]
      # @return [void]
      def finalize_request!(env, tokens)
        ForwardedToken.strip_suspicious!(env, @config.auth_request_headers) if @config.strip_suspicious_headers
        normalize_authorization!(env, tokens)
        expose_env_hints(env, tokens.chosen)
      end

      # Apply per-instance configuration overrides.
      # Keys starting with '_' or containing '!' are rejected to prevent
      # accidental invocation of non-accessor methods.
      #
      # @param opts [Hash]
      # @return [void]
      def apply_overrides!(opts)
        cfg = @config
        opts.each do |k, v|
          key_s = k.to_s
          next if key_s.start_with?('_') || key_s.include?('!')

          writer = "#{key_s}="
          cfg.public_send(writer, v) if cfg.respond_to?(writer)
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

      # Raise when the request did not come through a trusted proxy.
      #
      # @param env [Hash]
      # @raise [UntrustedProxyError]
      def ensure_trusted_proxy!(env)
        return if ProxyTrust.trusted?(env, @config.trusted_proxies, @config.xff_strategy)

        raise UntrustedProxyError
      end

      # Enforce presence of forwarded token when required.
      #
      # @param fwd_token [String, nil]
      # @raise [MissingForwardedTokenError]
      def ensure_forwarded_if_required!(fwd_token)
        return unless @config.require_forwarded_header
        raise MissingForwardedTokenError if fwd_token.nil? || fwd_token.to_s.strip.empty?
      end

      # Enforce equality when both Authorization and Forwarded tokens exist.
      #
      # @param env [Hash]
      # @param auth_token [String, nil]
      # @param fwd_token [String, nil]
      # @raise [HeaderMismatchError]
      def enforce_header_consistency!(env, auth_token, fwd_token)
        return unless @config.enforce_header_consistency
        return unless auth_token && fwd_token

        digest_a = ::Digest::SHA256.hexdigest(auth_token)
        digest_b = ::Digest::SHA256.hexdigest(fwd_token)
        return if Rack::Utils.secure_compare(digest_a, digest_b)

        HeaderGuardSanitizer.log_event(env, @config, :mismatch, reason: 'authorization_vs_forwarded')
        raise HeaderMismatchError
      end

      # Enforce X-Auth-Request-* ↔ JWT claims mapping when configured.
      #
      # @param env [Hash]
      # @param tokens [RequestTokens]
      # @return [void]
      # @raise [ClaimsMismatchError]
      def enforce_claims_consistency!(env, tokens)
        res = ConsistencyChecks.enforce_with_claims(
          env, tokens.decoded_payload,
          @config.enforce_claims_consistency, @config.auth_request_headers
        )
        return unless res.is_a?(Array) && res.first == :error

        field = res.last
        HeaderGuardSanitizer.log_event(env, @config, :claims_mismatch, field: field.to_s)
        return if claims_consistency_log_only?

        raise ClaimsMismatchError, field
      end

      # Determine whether claims mismatches should only be logged.
      #
      # @return [Boolean]
      def claims_consistency_log_only?
        mode = @config.claims_consistency_mode || :enforce
        mode = mode.to_sym if mode.is_a?(String)
        mode = :enforce unless %i[enforce log_only].include?(mode)
        mode == :log_only
      end

      # Set normalized Authorization header and emit success log.
      # Reuses pre-decoded token payload/header from {RequestTokens} to avoid
      # redundant JWT parsing.
      #
      # @param env [Hash]
      # @param tokens [RequestTokens]
      # @return [void]
      def normalize_authorization!(env, tokens)
        return unless tokens.chosen

        ForwardedToken.set_authorization!(env, tokens.chosen)
        source = HeaderGuardSanitizer.token_source(@config.prefer_forwarded, tokens.auth, tokens.forwarded)
        tags = HeaderGuardSanitizer.token_tags_from_decoded(tokens.decoded_payload, tokens.decoded_header)
        HeaderGuardSanitizer.log_event(env, @config, :ok, source: source, **tags)
      end

      # Resolve the first env header from which to source a bearer token.
      # Forwarded is considered only when the peer is trusted; HTTP_AUTHORIZATION is never a source.
      #
      # @param env [Hash]
      # @return [String, nil]
      def resolve_first_token_header(env)
        candidates = Array(@config.token_header_priority).dup
        candidates -= [Verikloak::HeaderSources::AUTHORIZATION_HEADER]
        fwd_key = @config.forwarded_header_name || Verikloak::HeaderSources::DEFAULT_FORWARDED_HEADER
        if candidates.include?(fwd_key) && !ProxyTrust.from_trusted_proxy?(env, @config.trusted_proxies)
          candidates -= [fwd_key]
        end
        candidates.find { |k| (v = env[k]) && !v.to_s.empty? }
      end

      # Seed Authorization from priority headers if nothing chosen and empty Authorization.
      #
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

      # Expose hints to downstream middleware or apps.
      #
      # @param env [Hash]
      # @param chosen [String, nil]
      # @return [void]
      def expose_env_hints(env, chosen)
        env['verikloak.bff.token'] = chosen if chosen
        env['verikloak.bff.selected_peer'] =
          ProxyTrust.selected_peer(env, @config.peer_preference, @config.xff_strategy)
      end
    end
  end
end
