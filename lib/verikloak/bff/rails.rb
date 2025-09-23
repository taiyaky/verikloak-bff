# frozen_string_literal: true

module Verikloak
  module BFF
    # Rails-specific functionality for Verikloak BFF
    module Rails
      # Middleware management utilities for Rails applications
      #
      # This module provides functionality to insert Verikloak BFF middleware
      # into Rails middleware stack, with proper error handling for cases where
      # the core Verikloak middleware is not present.
      module Middleware
        module_function

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
          stack.insert_after(::Verikloak::Middleware, ::Verikloak::BFF::HeaderGuard)
          true
        rescue RuntimeError => e
          raise unless missing_core?(e)

          log_skip(logger)
          false
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
            error.message.include?('Verikloak::Middleware')
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
          message = '[verikloak-bff] Skipping Verikloak::BFF::HeaderGuard insertion because '
          message += 'Verikloak::Middleware is not present. Configure verikloak-rails discovery '
          message += 'settings and restart once core verification is enabled.'

          if logger
            logger.warn(message)
          else
            warn(message)
          end
        end
      end
    end
  end
end
