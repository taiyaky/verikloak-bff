require 'bundler/setup'

# Enable SimpleCov coverage reporting when CI sets SIMPLECOV=true
if ENV['SIMPLECOV']
  begin
    require 'simplecov'
    SimpleCov.start do
      enable_coverage :branch
      add_filter %r{^/spec/}
    end
  rescue LoadError
    warn '[spec_helper] simplecov not available; skipping coverage'
  end
end

require 'rspec'
require 'rack/test'

# Load library path
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

# Project library entrypoint
begin
  require 'verikloak-bff'
rescue LoadError => e
  warn "[spec_helper] failed to load verikloak-bff: #{e.message}"
end

# Load support helpers if present (optional)
Dir[File.expand_path('support/**/*.rb', __dir__)].sort.each { |f| require f }

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.mock_with :rspec do |m|
    m.verify_partial_doubles = true
  end

  # Run specs in random order to surface order dependencies.
  config.order = :random
  Kernel.srand config.seed
end
