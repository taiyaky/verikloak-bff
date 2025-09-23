# frozen_string_literal: true

require_relative 'rails'

module Verikloak
  module BFF
    class Railtie < ::Rails::Railtie
      initializer 'verikloak.bff.insert_middleware', after: 'verikloak.middleware' do |app|
        logger = if defined?(::Rails.logger)
                   ::Rails.logger
                 end

        Verikloak::BFF::Rails::Middleware.insert_after_core(app.config.middleware, logger: logger)
      end
    end
  end
end
