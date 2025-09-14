# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
