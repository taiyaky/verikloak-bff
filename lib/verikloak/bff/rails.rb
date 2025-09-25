# frozen_string_literal: true

module Verikloak
  module BFF
    # Rails-specific functionality for Verikloak BFF
    module Rails
      # Middleware management utilities for Rails applications.
      #
      # This module focuses on inserting the HeaderGuard middleware right after
      # the core Verikloak middleware while gracefully handling stacks that do
      # not contain the core component.
      module Middleware
        module_function

        CORE_MIDDLEWARE = ::Verikloak::Middleware
        HEADER_GUARD = ::Verikloak::BFF::HeaderGuard
        CORE_NAME = 'Verikloak::Middleware'
        SKIP_MESSAGE = <<~MSG.freeze
          [verikloak-bff] Skipping Verikloak::BFF::HeaderGuard insertion because Verikloak::Middleware is not present. Configure
verikloak-rails discovery settings and restart once core verification is enabled.
        MSG

        # Inserts Verikloak::BFF::HeaderGuard middleware after Verikloak::Middleware
        #
        # Attempts to insert the HeaderGuard middleware into the Rails middleware stack
        # after the core Verikloak::Middleware. If the core middleware is not present,
        # logs a warning and gracefully skips the insertion.
        #
        # @param stack [ActionDispatch::MiddlewareStack] Rails middleware stack
        # @param logger [Logger, nil] Optional logger for warning messages
        # @return [Boolean] true if insertion succeeded, false if skipped due to missing core
        # @raise [RuntimeError] Re-raises non-middleware-related runtime errors
        #
        # @example Inserting middleware in Rails configuration
        #   Verikloak::BFF::Rails::Middleware.insert_after_core(
        #     Rails.application.config.middleware,
        #     logger: Rails.logger
        #   )
        def insert_after_core(stack, logger: nil)
          return false unless auto_insert_enabled?

          unless stack && core_present?(stack)
            log_skip(logger)
            return false
          end

          stack.insert_after(CORE_MIDDLEWARE, HEADER_GUARD)
          true
        rescue RuntimeError => e
          raise unless missing_core?(e)

          log_skip(logger)
          false
        end

        # Determine whether automatic insertion is enabled via Verikloak core configuration.
        #
        # When the core gem exposes +auto_insert_bff_header_guard+, respect that flag so
        # consumers can opt out of automatic middleware wiring without triggering warnings.
        # Any failures while reading configuration default to enabling insertion in order
        # to preserve the previous behavior.
        #
        # @return [Boolean]
        def auto_insert_enabled?
          config = core_config
          return true unless config

          return config.auto_insert_bff_header_guard if config.respond_to?(:auto_insert_bff_header_guard)

          true
        rescue StandardError
          true
        end

        # Returns the Verikloak configuration object when available.
        #
        # @return [Object, nil]
        def core_config
          return nil unless defined?(::Verikloak)
          return nil unless ::Verikloak.respond_to?(:config)

          ::Verikloak.config
        rescue StandardError
          nil
        end

        # Detect whether the Verikloak core middleware is already present in the stack.
        #
        # @param stack [#include?, #each, nil]
        # @return [Boolean]
        def core_present?(stack)
          return false unless stack

          begin
            return true if stack.respond_to?(:include?) && stack.include?(CORE_MIDDLEWARE)
          rescue StandardError
            # Fall back to manual enumeration when include? is unsupported for this stack.
          end

          return false unless stack.respond_to?(:each)

          stack.each do |entry|
            candidate = unwrap_middleware(entry)
            return true if candidate == CORE_MIDDLEWARE || middleware_name(candidate) == CORE_NAME
          end

          false
        end

        # Normalize raw stack entries to a comparable object.
        #
        # @param entry [Object]
        # @return [Object]
        def unwrap_middleware(entry)
          entry = entry.first if entry.is_a?(Array)
          entry.respond_to?(:klass) ? entry.klass : entry
        end

        # Resolve a human-readable middleware name if possible.
        #
        # @param entry [Object]
        # @return [String, nil]
        def middleware_name(entry)
          return entry if entry.is_a?(String)
          return entry.to_s if entry.is_a?(Symbol)

          entry.respond_to?(:name) ? entry.name : nil
        end

        # Checks if the error indicates missing core Verikloak middleware
        #
        # Examines a RuntimeError to determine if it was caused by attempting
        # to insert middleware after a non-existent Verikloak::Middleware.
        #
        # @param error [RuntimeError] The error to examine
        # @return [Boolean] true if error indicates missing Verikloak::Middleware
        #
        # @example Checking for missing middleware error
        #   begin
        #     stack.insert_after(::Verikloak::Middleware, SomeMiddleware)
        #   rescue RuntimeError => e
        #     puts "Missing core!" if missing_core?(e)
        #   end
        def missing_core?(error)
          error.message.include?('No such middleware') &&
            error.message.include?(CORE_NAME)
        end

        # Logs a warning message about skipping middleware insertion
        #
        # Outputs a descriptive warning message explaining why the HeaderGuard
        # middleware insertion was skipped and provides guidance for resolution.
        # Uses the provided logger if available, otherwise falls back to warn().
        #
        # @param logger [Logger, nil] Optional logger instance for structured logging
        #
        # @example Logging with Rails logger
        #   log_skip(Rails.logger)
        #
        # @example Logging without logger (uses warn)
        #   log_skip(nil)
        def log_skip(logger)
          logger ? logger.warn(SKIP_MESSAGE) : warn(SKIP_MESSAGE)
        end
      end
    end
  end
end
