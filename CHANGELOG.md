# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.1] - 2026-07-03

Maintenance release. No changes to the shipped gem's runtime code — it is identical to 1.1.0. The changes below are limited to CI and the test suite (none of the affected files ship in the gem).

### CI
- Add a non-docker RSpec compatibility matrix (Ruby 3.1–3.3) via `gemfiles/compat.gemfile`, verifying the gemspec's `required_ruby_version >= 3.1` on every supported minor Ruby; the docker-based job continues to cover the pinned 3.4 development Ruby
- Forward `SIMPLECOV` into the docker RSpec job so coverage is actually collected in CI, and enforce a 90% line-coverage floor in the suite (matching verikloak core)

---

## [1.1.0] - 2026-07-03

Verified against verikloak 1.1.0 (core) and verikloak-rails 1.2.0.

### Fixed
- **Empty Bearer Authorization**: `ForwardedToken.normalize_auth` now returns `nil` for a Bearer scheme without a token (e.g. `Authorization: Bearer`). Previously it returned an empty string, which caused a spurious `401 header_mismatch` when a valid forwarded token was present. `seed_authorization_if_needed` no longer re-inspects the raw `HTTP_AUTHORIZATION` value either, so a bare `Authorization: Bearer` no longer blocks seeding a valid token from `token_header_priority` headers
- **Multi-line Authorization hardening**: `ForwardedToken.normalize_auth` is anchored with `\A`/`\z` (previously `^`/`$`) and only accepts space/tab between the scheme and token, so a multi-line value cannot smuggle a `Bearer <token>` line past a non-Bearer first line
- **`peer_preference` honored in trust decisions**: `HeaderGuard` now passes the configured `peer_preference` (`:remote_then_xff` / `:xff_only`) to `ProxyTrust.trusted?`. Previously the preference only affected the `verikloak.bff.selected_peer` env hint and the trust decision always used `:remote_then_xff`, contradicting the documented behavior
- **`peer_preference` fail-safe**: an unrecognized or `nil` `peer_preference` now resolves to the safe `REMOTE_ADDR`-first path instead of the client-controlled `X-Forwarded-For`, and `HeaderGuard` raises `ConfigurationError` at startup for an unrecognized value so a typo cannot silently weaken the trust decision
- **Trusted proxy rule isolation**: a rule that raises (invalid CIDR string, failing Proc) no longer silently disables the remaining `trusted_proxies` rules; each rule is evaluated independently, and the failure is surfaced under `$DEBUG` instead of being swallowed without a trace
- **Fail-fast IP/CIDR validation**: `HeaderGuard` raises `ConfigurationError` at startup when a `trusted_proxies` string cannot be parsed as an IP or CIDR (previously only CIDR strings containing `/` were checked, so a malformed plain IP such as `10.0.0.999` booted and then silently rejected every request)

### Changed
- Minimum `verikloak` dependency raised to `~> 1.1` (from `~> 1.0`), matching the coordinated 1.1.0 core / 1.2.0 verikloak-rails release; `verikloak-rails` 1.2.0 already requires `verikloak ~> 1.1`
- **`Verikloak::BFF::Rails::Middleware.insert_before_core` added**: inserts HeaderGuard *before* `Verikloak::Middleware`, matching the documented stack order (`[HeaderGuard] → [Verikloak::Middleware] → [App]`) and the behavior of `verikloak-rails`
- `ForwardedToken.strip_suspicious!` and `Configuration` now share the default `X-Auth-Request-*` header list via `Constants::DEFAULT_AUTH_REQUEST_HEADERS` (previously duplicated)
- `HeaderGuard` no longer writes the `Authorization` header twice when seeding from `token_header_priority`; the header is written once during request finalization

### Deprecated
- **`Verikloak::BFF::Rails::Middleware.insert_after_core`**: deprecated in favor of `insert_before_core`. It now emits a deprecation warning and delegates to `insert_before_core`, because inserting HeaderGuard *after* the core middleware let core verification run on un-normalized tokens. The dead `auto_insert_enabled?` / `core_config` checks (which read a `Verikloak.config` that does not exist in the core gem — the real flag lives in `Verikloak::Rails.config`) were removed along the way

### Removed
- Internal helpers `HeaderGuardSanitizer.token_tags` and `HeaderGuardSanitizer.decode_unverified` (unused since token decoding was consolidated into `RequestTokens`; use `Verikloak::BFF::JwtUtils.decode_unverified` directly if needed)
- `ProxyTrust.from_trusted_proxy?` (unused thin wrapper around `ProxyTrust.trusted?`; call `ProxyTrust.trusted?(env, trusted, :rightmost, preference: ...)` directly)

---

## [1.0.0] - 2026-02-15

### Fixed
- **Token divergence**: `ForwardedToken.set_authorization!` now always overwrites `HTTP_AUTHORIZATION` with the chosen token. Previously, an existing Bearer header would prevent the overwrite, causing the downstream Verikloak middleware to verify a different token than the one selected by the BFF guard
- **BREAKING**: Minimum `verikloak` dependency raised to `~> 1.0`

### Added
- **Unit tests**: Added direct unit tests for `ForwardedToken`, `JwtUtils`, and `HeaderSources` modules

### Changed
- **v1.0.0 stable release**: Public API is now considered stable under Semantic Versioning

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
