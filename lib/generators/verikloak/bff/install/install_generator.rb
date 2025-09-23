# frozen_string_literal: true

require 'rails/generators/base'

module Verikloak
  module BFF
    module Generators
      # Generator that installs a Rails initializer responsible for
      # wiring Verikloak::BFF::HeaderGuard into the middleware stack.
      class InstallGenerator < ::Rails::Generators::Base
        source_root File.expand_path('templates', __dir__)

        class_option :initializer, type: :string,
                                   default: 'config/initializers/verikloak_bff.rb',
                                   desc: 'Path for the generated initializer'

        def create_initializer
          template 'initializer.rb.tt', initializer_path
        end

        private

        def initializer_path
          options[:initializer]
        end
      end
    end
  end
end
