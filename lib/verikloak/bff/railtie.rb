# frozen_string_literal: true

require_relative 'rails'

module Verikloak
  # Module providing Verikloak BFF (Backend for Frontend) functionality
  module BFF
    # Railtie class for integrating Verikloak BFF middleware into Rails applications
    #
    # This class automatically inserts Verikloak::BFF::Rails::Middleware into the
    # Rails initialization process. The middleware is inserted after the
    # 'verikloak.middleware' initializer and configured with an appropriate logger.
    #
    # @example Automatic initialization in Rails applications
    #   # Simply adding verikloak-bff to Gemfile automatically enables it
    #   gem 'verikloak-bff'
    #
    # @see Verikloak::BFF::Rails::Middleware
    class Railtie < ::Rails::Railtie
      # Initializer that inserts Verikloak BFF middleware into Rails application
      #
      # This initializer runs after 'verikloak.middleware' and inserts
      # Verikloak::BFF::Rails::Middleware at the appropriate position.
      # Uses Rails.logger as the logger if available.
      #
      # @param app [Rails::Application] Rails application instance
      initializer 'verikloak.bff.insert_middleware', after: 'verikloak.middleware' do |app|
        logger = ::Rails.logger if defined?(::Rails.logger)

        Verikloak::BFF::Rails::Middleware.insert_after_core(app.config.middleware, logger: logger)
      end
    end
  end
end
