# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0] - 2026-02-15

### Security
- **Log value truncation**: `sanitize_string` now truncates values exceeding 256 characters (`MAX_LOG_FIELD_LENGTH`) to prevent log injection / memory abuse

### Fixed
- **`MAX_TOKEN_BYTES`**: Raised from 4096 to 8192 to match core gem — prevents behavioural inconsistency (false rejection / inspection bypass) for tokens between 4 KB and 8 KB
- **IPv4-mapped IPv6 normalisation**: `ProxyTrust.ip_or_nil` now calls `IPAddr#native` so that `::ffff:172.17.0.1` correctly matches `172.17.0.0/16` in Docker/Kubernetes environments
- **`apply_overrides!` hardening**: Rejects keys starting with `_` or containing `!` to prevent accidental invocation of non-accessor methods (consistent with verikloak-rails `BffConfigurator`)
- **`ForwardedToken::FORWARDED_HEADER`**: Now references `Verikloak::HeaderSources::DEFAULT_FORWARDED_HEADER` instead of duplicating the string, eliminating maintenance drift risk

### Changed
- Error responses now delegate to `Verikloak::ErrorResponse.build` for RFC 6750-compliant JSON output
- Error class hierarchy unified: `Verikloak::BFF::Error` now inherits from `Verikloak::Error`
- **BREAKING**: Minimum `verikloak` dependency raised to `>= 0.4.0`
- Dev dependency `rspec` pinned to `~> 3.13`, `rubocop-rspec` pinned to `~> 3.9`

### Inherited from verikloak 0.4.0
The following security improvements are provided by the core `verikloak` gem and become available through the dependency bump. They are **not implemented in verikloak-bff** itself:
- Faraday 2.14.1 security update (CVE-2026-25765)
- Header injection protection via `Verikloak::ErrorResponse.sanitize_header_value`
- JWT token size limit (`MAX_TOKEN_BYTES = 8192`)
- HTTPS enforcement and SSRF protection in OIDC discovery
- URL path-traversal normalisation

---

## [0.3.0] - 2025-01-01

### Added
- **`disabled` configuration option**: Explicitly disable the middleware in pass-through mode. When `disabled: false` (default) and `trusted_proxies` is not configured, a `ConfigurationError` is raised at startup.

### Changed
- **BREAKING**: `trusted_proxies` is now **required** when `disabled: false`. Previously, an empty `trusted_proxies` would silently disable the middleware (fail-open). Now it raises `Verikloak::BFF::HeaderGuard::ConfigurationError` to prevent unintended security gaps.

### Fixed
- **Security**: Prevent fail-open vulnerability where unset `trusted_proxies` could silently bypass proxy trust validation.

---

## [0.2.6] - 2025-12-31

### Fixed
- **Rails 8.x+ compatibility**: Remove `after_initialize` middleware insertion from generator template to avoid `FrozenError` when middleware stack is frozen.

### Changed
- Generator (`rails g verikloak:bff:install`) now creates a **configuration-only** initializer. Middleware insertion is handled automatically by `verikloak-rails`.
- Generated initializer includes comprehensive configuration options with documentation comments.
- **Breaking**: Minimum `verikloak` dependency raised from `>= 0.2.0` to `>= 0.3.0`.

### Documentation
- Add "Rails Integration" section explaining automatic middleware detection with `verikloak-rails`.
- Add warning about Rails 8.x+ middleware stack freeze in `after_initialize`.
- Add "oauth2-proxy Integration" section with header configuration reference and recommended settings.
- Document manual middleware setup option for users not using `verikloak-rails`.
- Update `docs/rails.md` with clearer setup instructions and Rails 8.x support note.

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
