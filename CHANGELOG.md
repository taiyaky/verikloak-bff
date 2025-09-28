# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.5] - 2025-09-28

### Changed
- Align the install generator under `Verikloak::Bff::Generators` while retaining the `Verikloak::BFF::Generators` alias to avoid constant redefinition warnings during reloads.


## [0.2.4] - 2025-09-27

### Changed
- Simplify BFF install generator by inlining configuration lookups and removing unnecessary helper methods.
- Streamline generated initializer to use `Rails.configuration.middleware` and `Rails.logger` directly.
- Extract JWT decoding logic into shared `JwtUtils` module to eliminate duplication between `HeaderGuard` and `ConsistencyChecks`.
- Refactor `HeaderGuard#call` into clear pipeline stages with improved documentation.
- Enhance middleware stack detection to handle wrapped entries, string names, and complex objects.
- Remove duplicate proxy trust logic in `ProxyTrust` module by unifying `from_trusted_proxy?` and `trusted?` methods.

### Fixed
- Resolve RuboCop style violations including useless constant scoping and identical conditional branches.

## [0.2.3] - 2025-09-23

### Changed
- Stop inserting `Verikloak::BFF::HeaderGuard` automatically via the Railtie and provide a `rails g verikloak:bff:install` generator that drops an initializer to opt in when the core middleware is ready.

## [0.2.2] - 2025-09-23

### Changed
- Improved middleware class extraction logic to reduce code duplication while maintaining functionality

## [0.2.1] - 2025-09-23

### Fixed
- Skip inserting `Verikloak::BFF::HeaderGuard` in Rails when `Verikloak::Middleware` is absent (e.g., discovery not configured)
  so that generators and boot sequences no longer fail.

## [0.2.0] - 2025-09-22

### Added
- `Verikloak::HeaderSources` module for shared header normalization (consumable by verikloak-rails and other adapters).

### Changed
- `Configuration#token_header_priority=` now normalizes and deduplicates entries, reusing the shared helper and ignoring `HTTP_AUTHORIZATION` automatically.
- `forwarded_header_name` assignments trigger re-normalization of token priority lists to keep middleware aligned across gems.

## [0.1.2] - 2025-09-21

### Added
- Configuration option `claims_consistency_mode` supporting `:log_only` so deployments can record mismatches without rejecting requests.

### Changed
- Sanitize log payload strings (including JWT tags) before invoking hooks or emitting to loggers to mitigate log forging attempts.

### Documentation
- Document trusted proxy hygiene, sanitized logging hooks, and the new log-only mode in the README and Rails guide.

## [0.1.1] - 2025-09-15

### Changed
- Centralize `MAX_TOKEN_BYTES` in `Verikloak::BFF::Constants` and refactor usages in `HeaderGuard` and `ConsistencyChecks` to avoid duplication.

### Fixed
- Preserve full token content when forwarded header includes control characters (e.g., `Bearer tok\r\nmal`) by adjusting Bearer parsing in `ForwardedToken.normalize_forwarded`; combined with existing sanitization, Authorization now normalizes to `Bearer tokmal`.

### Tests
- Add boundary tests for token size limits in `ConsistencyChecks` and `HeaderGuard`.

## [0.1.0] - 2025-09-14

### Added
- Rack middleware `Verikloak::BFF::HeaderGuard`
- Bearer normalization (`ensure_bearer`), Authorization seeding (`token_header_priority`)
- Trust evaluation: REMOTE_ADDR first, XFF fallback (`peer_preference`, `xff_strategy`)
- Config keys: `forwarded_header_name`, `auth_request_headers`, `log_with`
- Claims/header consistency checks、`X-Auth-Request-*` stripping
- Env passthrough: `verikloak.bff.token`, `verikloak.bff.selected_peer`
- Docs: README、ERRORS、Rails guide (`docs/rails.md`)
- RSpec coverage for trust/consistency/seeding/env
