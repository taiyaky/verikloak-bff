# frozen_string_literal: true

require 'rails/generators/base'

module Verikloak
  module BFF
    # Namespace for Rails generators related to Verikloak BFF
    module Generators
      # Rails generator for installing Verikloak BFF middleware integration.
      #
      # This generator creates a Rails initializer that safely inserts the
      # Verikloak::BFF::HeaderGuard middleware into the Rails middleware stack.
      # It replaces automatic middleware insertion to avoid boot failures when
      # core Verikloak middleware is not yet configured.
      #
      # @example Basic usage
      #   rails g verikloak:bff:install
      #
      # @example Custom initializer path
      #   rails g verikloak:bff:install --initializer=config/initializers/custom_bff.rb
      #
      # @see Verikloak::BFF::Rails::Middleware
      class InstallGenerator < ::Rails::Generators::Base
        source_root File.expand_path('templates', __dir__)

        # Configuration option for specifying the initializer file path.
        #
        # @option options [String] :initializer ('config/initializers/verikloak_bff.rb')
        #   The path where the initializer file will be created
        class_option :initializer, type: :string,
                                   default: 'config/initializers/verikloak_bff.rb',
                                   desc: 'Path for the generated initializer'

        # Creates the Rails initializer file from template.
        #
        # Generates a Rails initializer that safely inserts the HeaderGuard
        # middleware into the middleware stack with proper error handling.
        # The initializer uses Verikloak::BFF::Rails::Middleware.insert_after_core
        # to ensure graceful handling when core middleware is missing.
        #
        # @return [void]
        def create_initializer
          template 'initializer.rb.erb', options.fetch(:initializer)
        end
      end
    end
  end
end
