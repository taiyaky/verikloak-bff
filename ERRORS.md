# Verikloak BFF — Error Reference

This document describes the errors that can be returned by the `Verikloak::BFF::HeaderGuard` Rack middleware, their meaning, and how to address them.

## Response Shape
- Status: 401 or 403
- Body (JSON): `{ "error": <code>, "message": <human_readable> }`
- Header: `WWW-Authenticate: Bearer error="<code>", error_description="<message>"`

Example
```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer error="header_mismatch", error_description="authorization and forwarded token mismatch"

{"error":"header_mismatch","message":"authorization and forwarded token mismatch"}
```

## Error Catalog

### untrusted_proxy (401)
- Meaning: The request did not pass through an allow‑listed reverse proxy.
- Typical causes:
  - `REMOTE_ADDR` or the selected `X-Forwarded-For` peer is not in `trusted_proxies`.
  - The `xff_strategy` (`:leftmost`/`:rightmost`) does not match how your proxy appends client IPs.
- Related config: `trusted_proxies`, `xff_strategy`
- Action: Add the proxy’s source IP/CIDR/Regex/Proc to the allowlist, and ensure `xff_strategy` matches your deployment.

### missing_forwarded_token (401)
- Meaning: `require_forwarded_header: true` is enabled but `X-Forwarded-Access-Token` is missing.
- Related config: `require_forwarded_header`
- Action: Ensure the BFF/reverse proxy always forwards `X-Forwarded-Access-Token`. This is typically used to block direct access that bypasses the BFF.

### header_mismatch (401)
- Meaning: Both `Authorization` and `X-Forwarded-Access-Token` are present but do not match (double‑injection detected).
- Related config: `enforce_header_consistency` (default: enabled)
- Behavior notes:
  - `Authorization` accepts only the Bearer scheme; non‑Bearer values are ignored (not treated as tokens).
  - `X-Forwarded-Access-Token` accepts either a bare token or a `Bearer <token>` value.
- Action: Avoid injecting both headers upstream, or make their values identical.

### claims_mismatch (403)
- Meaning: Consistency checks between `X-Auth-Request-*` headers and JWT claims failed.
- Related config: `enforce_claims_consistency` (e.g., `{ email: :email, user: :sub, groups: :realm_roles }`)
- Matching details:
  - `email` → `X-Auth-Request-Email` must equal JWT `email`.
  - `user`  → `X-Auth-Request-User` must equal JWT `sub`.
  - `groups`→ `X-Auth-Request-Groups` must be contained in JWT `realm_access.roles` (no leftover when subtracting).
- Action: Verify the BFF emits correct `X-Auth-Request-*` values, and confirm the mapping matches your identity provider’s claims.

### bff_error (401)
- Meaning: A generic fallback for BFF errors not covered by the above classes.
- Action: Inspect logs (`code`/`kind`) and the HTTP response to pinpoint the cause.

## Logging & Observability
- Log tags (example): `event=bff.header_guard kind=<ok|mismatch|claims_mismatch|error> rid=<request_id> sub=<sub> kid=<kid> iss=<iss> aud=<aud>`
- PII: The middleware avoids logging PII (e.g., emails). On `claims_mismatch`, it logs only which field disagreed.
- Logger: Uses `config.logger` when set, otherwise `env['rack.logger']`. If neither is present, logging is skipped.
- Tips:
  - `from_trusted_proxy?`: Forwarded headers are considered as token sources only when the request originates from a trusted peer. Detection prefers `REMOTE_ADDR`, then falls back to the nearest (`X-Forwarded-For` rightmost) when unavailable.
  - `selected_peer`: The peer IP used for trust decisions is exposed as `env['verikloak.bff.selected_peer']` to aid debugging.

## Debugging Checklist
1) Proxy trust
   - Does `xff_strategy` match how your proxy appends to `X-Forwarded-For`?
   - Is the proxy’s peer IP/CIDR/Regex/Proc present in `trusted_proxies`?

2) Token selection & consistency
   - `X-Forwarded-Access-Token` is preferred when `prefer_forwarded` is true. If both headers exist, values must be equal when `enforce_header_consistency` is enabled.
   - `Authorization` must be Bearer; non‑Bearer values are ignored.

3) Claims consistency
   - Do `X-Auth-Request-*` values align with the corresponding JWT claims according to your mapping?
   - Is the mapping itself correct for your IdP (keys: `email|user|groups`)?

4) Stripping suspicious headers
   - With `strip_suspicious_headers` enabled, user‑supplied `X-Auth-Request-*` headers are removed before passing downstream.

## Representative cURL Examples
Mismatch (401):
```
curl -i \
  -H 'X-Forwarded-For: 127.0.0.1' \
  -H 'X-Forwarded-Access-Token: Bearer fwd' \
  -H 'Authorization: Bearer auth' \
  http://localhost:9292/
```

Missing forwarded header (401, with require_forwarded_header=true):
```
curl -i \
  -H 'X-Forwarded-For: 127.0.0.1' \
  http://localhost:9292/
```

Consistency OK (200):
```
curl -i \
  -H 'X-Forwarded-For: 127.0.0.1' \
  -H 'X-Forwarded-Access-Token: Bearer eyJ...' \
  http://localhost:9292/
```

## Notes
- This middleware does not verify JWT signatures or validate `iss`/`aud`/`exp`. It focuses on normalization and consistency checks so that the core `Verikloak::Middleware` (placed immediately after) always performs the final verification at the API edge.
# Verikloak BFF — Error Codes

Minimal list of error codes emitted by `Verikloak::BFF::HeaderGuard`. The middleware hardens the BFF boundary and normalizes headers; JWT signature and `iss/aud/exp` validation are handled by the core Verikloak middleware that follows.

## Response Shape
- Status: 401 or 403
- Body (JSON): `{ "error": <code>, "message": <text> }`
- Header: `WWW-Authenticate: Bearer error="<code>", error_description="<text>"`

## Errors

| Code                       | HTTP | Trigger (summary)                                                                           |
|----------------------------|------|----------------------------------------------------------------------------------------------|
| `untrusted_proxy`          | 401  | Request did not pass through an allow‑listed proxy                                           |
| `missing_forwarded_token`  | 401  | `require_forwarded_header: true` and `X-Forwarded-Access-Token` is missing                   |
| `header_mismatch`          | 401  | `Authorization` and `X-Forwarded-Access-Token` are both present but differ                   |
| `claims_mismatch`          | 403  | `X-Auth-Request-*` values conflict with JWT claims per mapping                               |
| `bff_error`                | 401  | Generic BFF error                                                                            |

Notes
- `Authorization`: Bearer only. Non‑Bearer values are ignored.
- `X-Forwarded-Access-Token`: accepts Bearer or bare token.
- If both headers are present and consistency is enforced, values must match.
