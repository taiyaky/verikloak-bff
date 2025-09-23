# frozen_string_literal: true

require_relative 'rails'

module Verikloak
  # Module providing Verikloak BFF (Backend for Frontend) functionality
  module BFF
    # Railtie class for integrating Verikloak BFF with Rails applications.
    #
    # The Railtie no longer inserts middleware automatically because doing so
    # during `rails g verikloak:install` caused boot failures when the core
    # Verikloak middleware had not yet been configured. Applications now opt-in
    # to the HeaderGuard middleware by running `rails g verikloak:bff:install`,
    # which drops an initializer that performs the insertion during boot.
    class Railtie < ::Rails::Railtie
      # Expose the install generator when Rails generator infrastructure is
      # available. This keeps the generator optional for non-Rails consumers
      # while still making it discoverable to `rails g`.
      initializer 'verikloak.bff.load_generators' do
        next unless defined?(Rails::Generators)

        require_relative '../../generators/verikloak/bff/install/install_generator'
      end
    end
  end
end
