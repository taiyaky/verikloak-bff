# frozen_string_literal: true

require_relative 'rails'

module Verikloak
  # Module providing Verikloak BFF (Backend for Frontend) functionality
  module BFF
    # Railtie for integrating Verikloak BFF with Rails applications.
    #
    # This Railtie provides access to the BFF installation generator instead of
    # automatically inserting middleware, which could cause boot failures when
    # core Verikloak middleware is not yet configured.
    #
    # @example Installing BFF middleware
    #   rails g verikloak:bff:install
    #
    # @see Verikloak::BFF::Rails::Middleware
    class Railtie < ::Rails::Railtie
      # Loads the install generator when Rails generator infrastructure is available.
      #
      # Makes the `verikloak:bff:install` generator discoverable through `rails g`
      # while keeping generators optional for non-Rails environments.
      #
      # @return [void]
      initializer 'verikloak.bff.load_generators' do
        next unless defined?(Rails::Generators)

        require_relative '../../generators/verikloak/bff/install/install_generator'
      end
    end
  end
end
