# frozen_string_literal: true

module Verikloak
  module BFF
    module Rails
      module Middleware
        module_function

        def insert_after_core(stack, logger: nil)
          stack.insert_after(::Verikloak::Middleware, ::Verikloak::BFF::HeaderGuard)
          true
        rescue RuntimeError => e
          if missing_core?(e)
            log_skip(logger)
            false
          else
            raise
          end
        end

        def missing_core?(error)
          error.message.include?('No such middleware') &&
            error.message.include?('Verikloak::Middleware')
        end

        def log_skip(logger)
          message = '[verikloak-bff] Skipping Verikloak::BFF::HeaderGuard insertion because '
          message += 'Verikloak::Middleware is not present. Configure verikloak-rails discovery '
          message += 'settings and restart once core verification is enabled.'

          if logger
            logger.warn(message)
          else
            $stderr.puts(message)
          end
        end
      end
    end
  end
end
