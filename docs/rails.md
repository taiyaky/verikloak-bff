# Rails Integration Guide

This guide explains how to use verikloak-bff together with Verikloak (core) and verikloak-rails in a Rails application.

## Prerequisites
- Ruby >= 3.1, Rails 6.1+ (7.x recommended)
- A reverse proxy acting as BFF (e.g., Nginx auth_request or oauth2-proxy) that injects:
  - `X-Forwarded-Access-Token`
  - `X-Auth-Request-*` (email/user/groups)

## 1) Gemfile
Add all three gems and bundle install.

```ruby
gem 'verikloak'
gem 'verikloak-rails'
gem 'verikloak-bff'
```

## 2) BFF configuration
Create an initializer (e.g., `config/initializers/verikloak_bff.rb`). The example below uses safe defaults for a proxy chain that appends client IP to XFF.

```ruby
Verikloak::BFF.configure do |c|
  c.trusted_proxies = ['10.0.0.0/8', '192.168.0.0/16', '127.0.0.1']

  # Trust-boundary and peer selection
  c.peer_preference = :remote_then_xff   # prefer REMOTE_ADDR, then nearest XFF (default)
  c.xff_strategy = :rightmost          # rightmost = nearest proxy (default)

  # Token selection and protection
  c.prefer_forwarded = true
  c.require_forwarded_header = true     # block direct access not going through BFF
  c.enforce_header_consistency = true   # Authorization vs X-Forwarded-Access-Token must match

  # Claim/header consistency
  c.enforce_claims_consistency = { email: :email, user: :sub, groups: :realm_roles }

  # Header names (customizable if your proxy uses different keys)
  c.forwarded_header_name = 'HTTP_X_FORWARDED_ACCESS_TOKEN'
  c.auth_request_headers  = {
    email: 'HTTP_X_AUTH_REQUEST_EMAIL',
    user:  'HTTP_X_AUTH_REQUEST_USER',
    groups:'HTTP_X_AUTH_REQUEST_GROUPS'
  }

  # Authorization seeding when empty and no chosen token exists
  c.token_header_priority = ['HTTP_X_FORWARDED_ACCESS_TOKEN']

  # Strip potentially forged identity headers before downstream
  c.strip_suspicious_headers = true

  # Structured logging hook (optional)
  c.log_with = ->(payload) { Rails.logger.info(payload.to_json) }
end
```

`trusted_proxies` must not be left empty; the middleware raises an error when no allowlist is provided.

## 3) Reverse proxy examples

Nginx auth_request:

```nginx
location / {
  auth_request /_auth;
  # Relay identity headers to the app
  proxy_set_header X-Auth-Request-Email  $upstream_http_x_auth_request_email;
  proxy_set_header X-Auth-Request-User   $upstream_http_x_auth_request_user;
  proxy_set_header X-Auth-Request-Groups $upstream_http_x_auth_request_groups;
  # Relay forwarded access token from the auth endpoint
  proxy_set_header X-Forwarded-Access-Token $upstream_http_x_forwarded_access_token;
  proxy_pass http://app;
}

location = /_auth {
  internal;
  proxy_pass http://auth-backend; # e.g., oauth2-proxy verify endpoint
  proxy_set_header X-Original-URI $request_uri;
}
```

oauth2-proxy:

```yaml
# oauth2-proxy config excerpts
set_xauthrequest: true         # emits X-Auth-Request-* headers
pass_access_token: true        # emits X-Forwarded-Access-Token
reverse_proxy: true            # trust X-Forwarded-* from your ingress/proxy
cookie_secure: true
cookie_samesite: lax
```

## 4) Consistency mapping (quick reference)

| Key      | Header                   | JWT claim/path       | Rule     |
|----------|--------------------------|----------------------|----------|
| `email`  | `X-Auth-Request-Email`   | `email`              | equality |
| `user`   | `X-Auth-Request-User`    | `sub`                | equality |
| `groups` | `X-Auth-Request-Groups`  | `realm_access.roles` | subset   |

Enable via:

```ruby
enforce_claims_consistency: { email: :email, user: :sub, groups: :realm_roles }
```

Header names can be remapped via `auth_request_headers` in the initializer.

## 5) Validation checklist
- XFF interpretation (leftmost/rightmost) matches your proxy’s behavior
- `trusted_proxies` includes proxy subnets
- `require_forwarded_header` is on when you want to block non-BFF direct access
- Authorization is seeded only when empty and no chosen token exists
- Errors are RFC6750-style; see ERRORS.md

## 6) Common pitfalls
- Leaving the Rails-side ForwardedAccessToken middleware enabled (double promotion/conflicts)
- Misconfigured `trusted_proxies` leading to `untrusted_proxy` (401)
- Missing forwarded token with `require_forwarded_header: true` (401)

