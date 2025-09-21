# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

_No unreleased changes yet._

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
