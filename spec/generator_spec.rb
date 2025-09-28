# frozen_string_literal: true

require "spec_helper"
require "fileutils"
require "tmpdir"

RSpec.describe 'Verikloak::Bff::Generators::InstallGenerator' do
  before do
    # Provide a fake Rails::Generators base with minimal API
    stub_const('Thor::Error', Class.new(StandardError))

    base_class = Class.new do
      class << self
        def source_root(path = nil)
          @source_root = path if path
          @source_root
        end

        def desc(_description = nil); end
        
        def class_option(name, type:, default: nil, **options)
          class_options[name.to_sym] = { type: type, default: default }.merge(options)
        end

        def class_options
          @class_options ||= {}
        end
      end

      def initialize(_args = [], options = {})
        # Merge class option defaults with provided options
        defaults = self.class.class_options.transform_values { |opt| opt[:default] }
        @options = defaults.merge(symbolize_keys(options))
      end

      def options
        @options || {}
      end

      def template(src, dest)
        src_path = File.join(self.class.source_root, src)
        raise Thor::Error, "Could not find template #{src}" unless File.exist?(src_path)
        FileUtils.mkdir_p(File.dirname(dest))
        FileUtils.cp(src_path, dest)
      end

      private

      def symbolize_keys(hash)
        hash.each_with_object({}) { |(k, v), memo| memo[k.to_sym] = v }
      end
    end

    stub_const('Rails', Module.new)
    stub_const('Rails::Generators', Module.new)
    stub_const('Rails::Generators::Base', base_class)

    original_require = Kernel.instance_method(:require)
    allow_any_instance_of(Object).to receive(:require) do |instance, path|
      if path == 'rails/generators'
        true
      else
        original_require.bind(instance).call(path)
      end
    end

    # Clean up existing constants to avoid redefinition warnings
    if defined?(Verikloak::Bff::Generators::InstallGenerator)
      Verikloak::Bff::Generators.send(:remove_const, :InstallGenerator)
    end

    load File.expand_path('../lib/generators/verikloak/bff/install/install_generator.rb', __dir__)
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

  it 'creates directories recursively when needed' do
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        custom_path = 'config/deep/nested/path/verikloak_bff.rb'
        generator_class.new([], initializer: custom_path).create_initializer

        expect(File).to exist(custom_path)
        expect(File.directory?('config/deep/nested/path')).to be(true)
      end
    end
  end

  it 'keeps the legacy Verikloak::BFF namespace alias' do
    expect(Verikloak::BFF::Generators::InstallGenerator)
      .to be(generator_class)
  end
end
