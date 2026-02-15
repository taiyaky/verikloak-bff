# verikloak-bff

[![CI](https://github.com/taiyaky/verikloak-bff/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/taiyaky/verikloak-bff/actions/workflows/ci.yml)
[![Gem Version](https://img.shields.io/gem/v/verikloak-bff)](https://rubygems.org/gems/verikloak-bff)
![Ruby Version](https://img.shields.io/badge/ruby-%3E%3D%203.1-blue)
[![Downloads](https://img.shields.io/gem/dt/verikloak-bff)](https://rubygems.org/gems/verikloak-bff)


A framework-agnostic Rack middleware that hardens the **BFF / reverse-auth** boundary (oauth2-proxy, Nginx `auth_request`, etc.). It **normalizes** access tokens from `X-Forwarded-Access-Token` into `Authorization` and optionally checks **consistency** between `X-Auth-Request-*` headers and JWT claims. Signature and `iss/aud/exp` validation are performed by the core `verikloak` middleware placed after this middleware.

## Features
- Prefer / require `X-Forwarded-Access-Token` (configurable)
- Trust-boundary checking for proxy IPs (X-Forwarded-For parsing)
- Header consistency enforcement (Authorization vs Forwarded)
- Claims consistency checks (e.g., email/sub/groups) against `X-Auth-Request-*`
- Strip suspicious/forged headers before downstream
- Logging hooks for `request_id`, `sub`, `kid`, `iss/aud`

## Installation
```bash
bundle add verikloak-bff
```

## Usage

### Rack Applications
Add to your `config.ru`:
```ruby
use Verikloak::BFF::HeaderGuard, trusted_proxies: ['127.0.0.1', '10.0.0.0/8']
# Place before your core Verikloak middleware
```

### Rails Applications
Add both gems to your Gemfile:
```ruby
gem 'verikloak-rails'
gem 'verikloak-bff'
```

Run the install generator to create a configuration file:
```sh
bin/rails g verikloak:bff:install
```

The generator creates `config/initializers/verikloak_bff.rb` with BFF configuration options. **Edit this file to set `trusted_proxies`** (required unless `disabled: true`) and customize other options as needed.

**Note**: Middleware insertion is handled automatically by `verikloak-rails`. The generated initializer only contains configuration—no manual middleware setup is required.

> **Without verikloak-rails**: You can also configure middleware manually in `config/application.rb`:
> ```ruby
> config.middleware.insert_before Verikloak::Middleware, Verikloak::BFF::HeaderGuard
> ```

For detailed configuration, proxy setup examples, and troubleshooting, see [docs/rails.md](docs/rails.md).

## Consistency mapping

| Key      | Header                   | JWT claim/path          | Rule        |
|----------|---------------------------|-------------------------|-------------|
| `email`  | `X-Auth-Request-Email`   | `email`                 | equality    |
| `user`   | `X-Auth-Request-User`    | `sub`                   | equality    |
| `groups` | `X-Auth-Request-Groups`  | `realm_access.roles`    | subset      |

Use `enforce_claims_consistency: { email: :email, user: :sub, groups: :realm_roles }` to enable. Header names can be remapped via `auth_request_headers`.

See `examples/rack.ru` for a tiny Rack app demo.

## Configuration

| Key                          | Type                                 | Default      | Description |
|----------------------------- |--------------------------------------|--------------|-------------|
| `disabled`                   | Boolean                              | `false`      | Explicitly disable the middleware (pass-through mode). When `false`, `trusted_proxies` must be configured. |
| `trusted_proxies`            | Array[String/Regexp/Proc]            | *(required)* | Allowlist for proxy peers (by IP/CIDR/regex/proc). **Required** unless `disabled: true`. |
| `prefer_forwarded`           | Boolean                              | `true`       | Prefer `X-Forwarded-Access-Token` over `Authorization`. |
| `require_forwarded_header`   | Boolean                              | `false`      | Reject when no `X-Forwarded-Access-Token` (blocks direct access). |
| `enforce_header_consistency` | Boolean                              | `true`       | If both headers exist, require identical token values. |
| `enforce_claims_consistency` | Hash                                 | `{}`         | Mapping of header→claim to compare (e.g., `{ email: :email, user: :sub, groups: :realm_roles }`). |
| `claims_consistency_mode`    | Symbol (`:enforce`/`:log_only`)      | `:enforce`   | When `:log_only`, mismatches are logged but the request continues (still require downstream JWT verification). |
| `strip_suspicious_headers`   | Boolean                              | `true`       | Remove external `X-Auth-Request-*` before passing downstream. |
| `xff_strategy`               | Symbol (`:rightmost`/`:leftmost`)    | `:rightmost` | Which peer to pick from `X-Forwarded-For`. |
| `peer_preference`            | Symbol (`:remote_then_xff`/`:xff_only`) | `:remote_then_xff` | Whether to prefer `REMOTE_ADDR` before falling back to XFF. |
| `clock_skew_leeway`          | Integer (seconds)                    | `30`         | Reserved for small exp/nbf skew handled by core verifier. |
| `logger`                     | `Logger` or `nil`                    | `nil`        | Logger for audit tags (`rid`, `sub`, `kid`, `iss/aud`). |
| `token_header_priority`      | Array[String]                        | `['HTTP_X_FORWARDED_ACCESS_TOKEN']` | When Authorization is empty and no token chosen, seed it from these env headers in order. Values are normalized via `Verikloak::HeaderSources`; `HTTP_AUTHORIZATION` is ignored as a source. |
| `forwarded_header_name`      | String                               | `HTTP_X_FORWARDED_ACCESS_TOKEN` | Env key for forwarded access token. |
| `auth_request_headers`       | Hash                                 | see code     | Mapping for `X-Auth-Request-*` env keys: `{ email, user, groups }`. |

### Configuration Requirements

When `disabled: false` (the default), you **must** configure `trusted_proxies`. If it is not set, the middleware will raise a `ConfigurationError` at startup to prevent a fail-open security vulnerability.

To explicitly disable the middleware (e.g., for development or testing), set `disabled: true`:

```ruby
# Pass-through mode: no proxy trust checking
Verikloak::BFF.configure do |config|
  config.disabled = true
end
```

## Errors
This gem returns concise, RFC 6750–style error responses with stable codes. See [ERRORS.md](ERRORS.md) for details and examples.

**Note:** This middleware does not verify JWT signatures or `iss/aud/exp` itself; it normalizes and guards headers so the core `verikloak` middleware always performs final verification.

For full reverse proxy examples (Nginx auth_request / oauth2-proxy), see [docs/rails.md](docs/rails.md).

## Tips & Advanced Usage

- Peer preference: prefer `REMOTE_ADDR` before XFF
  - Set `peer_preference: :remote_then_xff` (default) to evaluate trust using the direct peer first, then fall back to the nearest (rightmost) `X-Forwarded-For` value.
  - If you run only behind a single, known proxy chain and want to rely solely on XFF ordering, use `peer_preference: :xff_only` and control position with `xff_strategy`.

- Trusted proxy hygiene
  - Keep `trusted_proxies` as specific as possible (individual IPs, tight CIDR ranges, or regexes). Review the list whenever proxy topology changes to avoid unintentionally widening the trust boundary.
  - IPv4-mapped IPv6 addresses (`::ffff:172.17.0.1`) are automatically normalised to native IPv4 so that plain IPv4 CIDR ranges (e.g. `172.17.0.0/16`) match correctly in Docker / Kubernetes environments.

- Header name customization
  - Forwarded-access-token header can be changed via:
    - `forwarded_header_name: 'HTTP_X_CUSTOM_FORWARD_TOKEN'`
  - X-Auth-Request-* header names can be remapped via:
    - `auth_request_headers: { email: 'HTTP_X_EMAIL', user: 'HTTP_X_USER', groups: 'HTTP_X_GROUPS' }`

- Authorization seeding from priority headers
  - When no token is chosen and `HTTP_AUTHORIZATION` is empty, the middleware consults `token_header_priority` to seed Authorization.
  - `HTTP_AUTHORIZATION` itself is never used as a source; forwarded headers are considered only from trusted peers.
  - Other gems can `require 'verikloak/header_sources'` to reuse the same normalization helpers when sharing configuration defaults.

- Observability helpers
  - Downstream can inspect `env['verikloak.bff.token']` (chosen token, unverified) and `env['verikloak.bff.selected_peer']` (peer IP selected for trust decisions).
  - Provide a structured log hook with `log_with: ->(payload) { logger.info(payload.to_json) }` to consume the same fields emitted to `logger`. Payload strings are sanitized (control characters removed) before hooks and loggers run to mitigate log forging.
  - Caution: avoid logging the entire Rack `env` in application logs. Treat `env['verikloak.bff.token']` as sensitive; never emit raw tokens or PII (e.g., emails) to logs.

- Claims consistency modes
  - Default `:enforce` mode rejects requests with mismatches. Switch to `claims_consistency_mode: :log_only` when you only need observability signals; downstream services must continue verifying JWT signatures, issuer, audience, and expirations.

## Rails Integration

### Recommended: Use with verikloak-rails (Auto-detection)

When both `verikloak-rails` and `verikloak-bff` are installed, the railtie automatically inserts the BFF middleware. No manual configuration is required.

```ruby
# Gemfile
gem 'verikloak-rails'
gem 'verikloak-bff'
```

The middleware stack will be configured as:
```
[Verikloak::BFF::HeaderGuard] → [Verikloak::Middleware] → [Your App]
```

### ⚠️ Rails 8.x+ Middleware Stack Freeze

In Rails 8.x and later, the middleware stack is frozen after the `after_initialize` callback. Manual middleware insertion in `after_initialize` will raise `FrozenError`:

```ruby
# ❌ This will NOT work in Rails 8.x+
Rails.application.config.after_initialize do
  Rails.application.config.middleware.insert_after(
    Verikloak::Middleware,
    Verikloak::BFF::HeaderGuard
  )
end
# => FrozenError: can't modify frozen Array
```

**Solution**: Use the automatic detection feature with `verikloak-rails`, or insert middleware in `config/application.rb` or an initializer (which runs before the stack is frozen):

```ruby
# ✅ This works - config/application.rb
module MyApp
  class Application < Rails::Application
    config.middleware.insert_before Verikloak::Middleware, Verikloak::BFF::HeaderGuard
  end
end
```

## oauth2-proxy Integration

### Header Configuration Reference

| oauth2-proxy Setting | Header Sent | HeaderGuard Behavior |
|---------------------|-------------|---------------------|
| `--pass-access-token=true` | Cookie (`_oauth2_proxy`) | Not supported (cookie-based) |
| `--pass-access-token=true` + nginx | `X-Forwarded-Access-Token` | Normalized to `Authorization` (default) |
| `--set-authorization-header=true` | `Authorization: Bearer <token>` | Used directly |
| `--set-xauthrequest=true` | `X-Auth-Request-Access-Token` | Requires `token_header_priority` config |

### Recommended oauth2-proxy Configuration

For best compatibility, configure oauth2-proxy to emit `X-Forwarded-Access-Token` via nginx:

```bash
oauth2-proxy \
  --pass-access-token=true \
  --set-authorization-header=false \
  --set-xauthrequest=true \
  --upstream=http://rails-api:3000
```

Then configure nginx to relay the token:

```nginx
proxy_set_header X-Forwarded-Access-Token $upstream_http_x_auth_request_access_token;
```

### Using X-Auth-Request-Access-Token Directly

If you prefer to use `X-Auth-Request-Access-Token` without nginx relay, configure both `forwarded_header_name` and `token_header_priority`:

```ruby
use Verikloak::BFF::HeaderGuard,
  trusted_proxies: ['10.0.0.0/8'],
  # Set the forwarded header to X-Auth-Request-Access-Token
  forwarded_header_name: 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN',
  # Also add to priority list for Authorization seeding
  token_header_priority: ['HTTP_X_AUTH_REQUEST_ACCESS_TOKEN']
```

> **Note**: If you only set `token_header_priority` without changing `forwarded_header_name`, 
> `require_forwarded_header: true` will still expect `X-Forwarded-Access-Token` and return 401 
> when it's missing.

## Development (for contributors)
Clone and install dependencies:

```bash
git clone https://github.com/taiyaky/verikloak-bff.git
cd verikloak-bff
bundle install
```
See **Testing** below to run specs and RuboCop. For releasing, see **Publishing**.

## Testing
All pull requests and pushes are automatically tested with [RSpec](https://rspec.info/) and [RuboCop](https://rubocop.org/) via GitHub Actions.
See the CI badge at the top for current build status.

To run the test suite locally:

```bash
docker compose run --rm dev rspec
docker compose run --rm dev rubocop -a
```

## Contributing
Bug reports and pull requests are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security
If you find a security vulnerability, please follow the instructions in [SECURITY.md](SECURITY.md).

## License
This project is licensed under the [MIT License](LICENSE).

## Publishing (for maintainers)
Gem release instructions are documented separately in [MAINTAINERS.md](MAINTAINERS.md).

## Changelog
See [CHANGELOG.md](CHANGELOG.md) for release history.

## References
- Verikloak (core): https://github.com/taiyaky/verikloak
- verikloak-rails (Rails integration): https://github.com/taiyaky/verikloak-rails
- verikloak-bff on RubyGems: https://rubygems.org/gems/verikloak-bff
