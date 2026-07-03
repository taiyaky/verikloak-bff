# frozen_string_literal: true

module Verikloak
  module BFF
    # Rails-specific functionality for Verikloak BFF
    module Rails
      # Middleware management utilities for Rails applications.
      #
      # This module focuses on inserting the HeaderGuard middleware right before
      # the core Verikloak middleware (so tokens are normalized before core
      # verification) while gracefully handling stacks that do not contain the
      # core component.
      #
      # NOTE: When `verikloak-rails` is installed, middleware insertion happens
      # automatically via its railtie — these helpers are only needed for manual
      # (non verikloak-rails) setups.
      module Middleware
        module_function

        CORE_NAME = 'Verikloak::Middleware'
        HEADER_GUARD_NAME = 'Verikloak::BFF::HeaderGuard'
        SKIP_MESSAGE = <<~MSG.chomp.freeze
          [verikloak-bff] Skipping Verikloak::BFF::HeaderGuard insertion because Verikloak::Middleware is not present. Configure verikloak-rails discovery settings and restart once core verification is enabled.
        MSG
        DEPRECATION_MESSAGE = <<~MSG.chomp.freeze
          [verikloak-bff] Verikloak::BFF::Rails::Middleware.insert_after_core is deprecated and will be removed in a future release. Use insert_before_core instead — HeaderGuard must run before Verikloak::Middleware so that tokens are normalized prior to verification. insert_after_core now delegates to insert_before_core.
        MSG

        # Inserts Verikloak::BFF::HeaderGuard middleware before Verikloak::Middleware
        #
        # Attempts to insert the HeaderGuard middleware into the Rails middleware stack
        # before the core Verikloak::Middleware, matching the documented stack order:
        #   [Verikloak::BFF::HeaderGuard] → [Verikloak::Middleware] → [Your App]
        # If the core middleware is not present, logs a warning and gracefully skips
        # the insertion.
        #
        # @param stack [ActionDispatch::MiddlewareStack] Rails middleware stack
        # @param logger [Logger, nil] Optional logger for warning messages
        # @return [Boolean] true if insertion succeeded, false if skipped due to missing core
        # @raise [RuntimeError] Re-raises non-middleware-related runtime errors
        #
        # @example Inserting middleware in Rails configuration
        #   Verikloak::BFF::Rails::Middleware.insert_before_core(
        #     Rails.application.config.middleware,
        #     logger: Rails.logger
        #   )
        def insert_before_core(stack, logger: nil)
          core = core_middleware
          header_guard = header_guard_middleware

          unless stack && core && header_guard && core_present?(stack, core)
            log_skip(logger)
            return false
          end

          stack.insert_before(core, header_guard)
          true
        rescue RuntimeError => e
          raise unless missing_core?(e)

          log_skip(logger)
          false
        end

        # @deprecated Use {.insert_before_core} instead. The previous behavior
        #   (inserting HeaderGuard *after* the core middleware) contradicted the
        #   documented stack order and let core verification see un-normalized
        #   tokens. This method now delegates to {.insert_before_core} and emits
        #   a deprecation warning.
        #
        # @param stack [ActionDispatch::MiddlewareStack] Rails middleware stack
        # @param logger [Logger, nil] Optional logger for warning messages
        # @return [Boolean] true if insertion succeeded, false if skipped
        def insert_after_core(stack, logger: nil)
          logger ? logger.warn(DEPRECATION_MESSAGE) : warn(DEPRECATION_MESSAGE)
          insert_before_core(stack, logger: logger)
        end

        # Detect whether the Verikloak core middleware is already present in the stack.
        #
        # @param stack [#include?, #each, nil]
        # @return [Boolean]
        def core_present?(stack, core = core_middleware)
          return false unless stack

          begin
            return true if core && stack.respond_to?(:include?) && stack.include?(core)
          rescue StandardError
            # Fall back to manual enumeration when include? is unsupported for this stack.
          end

          return false unless stack.respond_to?(:each)

          stack.each do |entry|
            candidate = unwrap_middleware(entry)
            return true if core && candidate == core
            return true if middleware_name(candidate) == CORE_NAME
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
        # to insert middleware relative to a non-existent Verikloak::Middleware.
        #
        # @param error [RuntimeError] The error to examine
        # @return [Boolean] true if error indicates missing Verikloak::Middleware
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
        def log_skip(logger)
          logger ? logger.warn(SKIP_MESSAGE) : warn(SKIP_MESSAGE)
        end

        # Safely resolves the core middleware constant when available.
        #
        # @return [Class, nil]
        def core_middleware
          safe_const_get(CORE_NAME)
        end

        # Safely resolves the HeaderGuard middleware constant when available.
        #
        # @return [Class, nil]
        def header_guard_middleware
          safe_const_get(HEADER_GUARD_NAME)
        end

        # Attempts to constantize the provided class name, returning nil when undefined.
        #
        # @param name [String]
        # @return [Module, Class, nil]
        def safe_const_get(name)
          Object.const_get(name)
        rescue NameError
          nil
        end
      end
    end
  end
end
