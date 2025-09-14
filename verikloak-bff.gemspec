# frozen_string_literal: true

require_relative 'lib/verikloak/bff/version'

Gem::Specification.new do |spec|
  spec.name          = 'verikloak-bff'
  spec.version       = Verikloak::BFF::VERSION
  spec.authors       = ['taiyaky']

  spec.summary       = 'BFF header guard for verikloak (oauth2-proxy / auth_request integration)'
  spec.description   = 'Framework-agnostic Rack middleware that normalizes forwarded tokens, ' \
                       'enforces trust boundaries, and checks header/claims consistency before verikloak.'

  spec.homepage      = 'https://github.com/taiyaky/verikloak-bff'
  spec.license       = 'MIT'

  spec.files         = Dir['lib/**/*.rb'] + %w[README.md LICENSE CHANGELOG.md]
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 3.1'

  # Runtime dependencies
  spec.add_dependency 'jwt', '~> 2.7'
  spec.add_dependency 'rack', '>= 2.2', '< 4.0'
  spec.add_dependency 'verikloak', '>= 0.1.2', '< 0.2'

  # Metadata for RubyGems
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri']   = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['bug_tracker_uri'] = "#{spec.homepage}/issues"
  spec.metadata['documentation_uri'] = "https://rubydoc.info/gems/verikloak-bff/#{Verikloak::BFF::VERSION}"
  spec.metadata['rubygems_mfa_required'] = 'true'
end
