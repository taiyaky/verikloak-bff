# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

group :development, :test do
  gem 'rack-test'
  gem 'rake'
  gem 'rspec', '~> 3.13'
  gem 'rubocop', require: false
  gem 'rubocop-rake', require: false
  gem 'rubocop-rspec', '~> 3.9', require: false
end

# Security auditing for dependencies in development/CI
group :development do
  gem 'bundler-audit', require: false
end

# Test-only dependencies
group :test do
  gem 'rspec_junit_formatter'
  gem 'simplecov', require: false
end
