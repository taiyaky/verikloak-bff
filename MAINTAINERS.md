# Maintainers Guide

This document contains information for project maintainers.

## Publishing

Only maintainers are responsible for publishing new versions of verikloak-bff to RubyGems.

### Steps to Publish

1. Ensure all tests pass locally and in CI.
   ```bash
   docker compose run --rm dev rspec
   docker compose run --rm dev rubocop -a

   ```
2. Update CHANGELOG and version:
   - Update `CHANGELOG.md` with the new version and date (Keep a Changelog format).
   - Bump `lib/verikloak/bff/version.rb`.
3. Keep docs and constraints in sync (if applicable):
   - If the base gem requirement changes, update:
     - README “Compatibility” (`verikloak: >= x.y.z, < 0.2`)
   - If Ruby/Rails support changes, update README badges/Compatibility and `verikloak-bff.gemspec`.
4. Commit and tag:
   ```bash
   git commit -am "Release v<version>"
   git tag v<version>
   git push && git push --tags
   ```
5. Build the gem:
   ```bash
   gem build verikloak-bff.gemspec
   ```
6. Push to RubyGems (MFA required):
   ```bash
   gem push verikloak-bff-<version>.gem
   ```
7. Create a GitHub release for tag `v<version>` and paste the CHANGELOG entry.

### Notes
- Only maintainers should perform gem publishing.
- RubyGems MFA: this gem sets `rubygems_mfa_required = true`; ensure your account has MFA enabled (`gem signin` prompts for OTP).
- Contributors do not need to perform these steps.
- Security fixes should be prioritized for release.
