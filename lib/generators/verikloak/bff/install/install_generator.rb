# frozen_string_literal: true

require 'rails/generators'

module Verikloak
  module Bff
    # Rails generators supporting verikloak-bff integration.
    module Generators
      # Generator to install the Verikloak BFF initializer into a Rails app.
      #
      # @see Verikloak::BFF::Rails::Middleware
      # @example Default usage
      #   rails g verikloak:bff:install
      class InstallGenerator < ::Rails::Generators::Base
        source_root File.expand_path('templates', __dir__)
        desc 'Creates the Verikloak BFF initializer for Rails applications.'

        # @option options [String] :initializer ('config/initializers/verikloak_bff.rb')
        #   Path for the generated initializer file.
        class_option :initializer, type: :string,
                                   default: 'config/initializers/verikloak_bff.rb',
                                   desc: 'Path for the generated initializer'

        # Copies the initializer template to the desired location.
        #
        # @return [void]
        def create_initializer
          template 'initializer.rb.erb', options.fetch(:initializer)
        end
      end
    end
  end
end

# Maintain legacy constant path for consumers referencing Verikloak::BFF::Generators.
module Verikloak
  module BFF
    Generators = Bff::Generators
  end
end
