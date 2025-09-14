# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

group :development, :test do
  gem 'rack-test'
  gem 'rake'
  gem 'rspec'
  gem 'rubocop', require: false
  gem 'rubocop-rake', require: false
  gem 'rubocop-rspec', require: false
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
