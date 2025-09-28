# frozen_string_literal: true

require 'spec_helper'
require 'fileutils'
require 'tmpdir'

RSpec.describe 'Verikloak::Bff::Generators::InstallGenerator' do
  before(:all) do
    unless defined?(Rails)
      module Rails; end
    end

    unless defined?(Rails::Generators)
      module Rails::Generators; end
    end

    unless defined?(Rails::Generators::Base) && Rails::Generators::Base.respond_to?(:source_root)
      class Rails::Generators::Base
        class << self
          def source_root(path = nil)
            @source_root = path if path
            @source_root
          end

          def desc(_); end

          def class_option(name, type:, default: nil, **)
            class_options[name.to_sym] = default
          end

          def class_options
            @class_options ||= {}
          end
        end

        def initialize(_args = [], options = {})
          @options = self.class.class_options.merge(symbolize_keys(options))
        end

        def options
          @options
        end

        def template(src, dest)
          src_path = File.join(self.class.source_root, src)
          FileUtils.mkdir_p(File.dirname(dest))
          FileUtils.cp(src_path, dest)
        end

        private

        def symbolize_keys(hash)
          hash.each_with_object({}) { |(k, v), memo| memo[k.to_sym] = v }
        end
      end
    end

    unless $LOADED_FEATURES.include?('rails/generators')
      $LOADED_FEATURES << 'rails/generators'
    end

    unless defined?(Verikloak::Bff::Generators::InstallGenerator)
      require_relative '../lib/generators/verikloak/bff/install/install_generator'
    end
  end

  after(:all) do
    $LOADED_FEATURES.delete('rails/generators')
  end

  let(:generator_class) { Verikloak::Bff::Generators::InstallGenerator }

  it 'creates the initializer at the default location' do
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        generator_class.new.create_initializer

        path = 'config/initializers/verikloak_bff.rb'
        expect(File).to exist(path)
        expect(File.read(path)).to include('Verikloak::BFF::Rails::Middleware')
      end
    end
  end

  it 'respects a custom initializer path option' do
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        generator_class.new([], initializer: 'config/custom/bff.rb').create_initializer

        expect(File).to exist('config/custom/bff.rb')
      end
    end
  end

  it 'keeps the legacy Verikloak::BFF namespace alias' do
    expect(Verikloak::BFF::Generators::InstallGenerator)
      .to be(generator_class)
  end
end
