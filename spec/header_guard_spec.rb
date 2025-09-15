# frozen_string_literal: true

# spec_helper is auto-required via .rspec
# Only require stdlib helpers used in this spec.
require "base64"
require "json"

RSpec.describe Verikloak::BFF::HeaderGuard do
  include Rack::Test::Methods

  def build_app(opts = {})
    Rack::Builder.new do
      use Verikloak::BFF::HeaderGuard, opts
      run ->(env) { [200, { "Content-Type" => "text/plain" }, ["OK"]] }
    end
  end

  # Default app unless test overrides @app
  def app
    @app ||= build_app(
      trusted_proxies: ['127.0.0.1'],
      prefer_forwarded: true,
      enforce_header_consistency: true,
      strip_suspicious_headers: true
    )
  end

  def jwt_with(payload)
    header = Base64.urlsafe_encode64({}.to_json, padding: false)
    body   = Base64.urlsafe_encode64(payload.to_json, padding: false)
    [header, body, "sig"].join(".")
  end

  # Build two tokens: the largest token that is <= MAX, and the first token > MAX
  def boundary_tokens(max_bytes)
    under = nil
    over = nil
    pad_len = 0
    email = 'user@example.com'
    while pad_len < max_bytes * 2
      token = jwt_with({ email: email, pad: 'x' * pad_len })
      size = token.bytesize
      if size <= max_bytes
        under = token
      else
        over = token
        break
      end
      pad_len += 1
    end
    raise 'failed to build boundary tokens' unless under && over
    [under, over, email]
  end

  # Basic behavior (from original spec)
  it "promotes forwarded token to Authorization when preferred" do
    header "X-Forwarded-For", "127.0.0.1"
    header "X-Forwarded-Access-Token", "Bearer fwdtoken"
    get "/"
    expect(last_response.status).to eq 200
    expect(last_request.env["HTTP_AUTHORIZATION"]).to eq "Bearer fwdtoken"
  end

  it "sanitizes control characters before writing Authorization" do
    header "X-Forwarded-For", "127.0.0.1"
    header "X-Forwarded-Access-Token", "Bearer tok\r\nmal"
    get "/"
    expect(last_response.status).to eq 200
    expect(last_request.env["HTTP_AUTHORIZATION"]).to eq "Bearer tokmal"
  end

  context "token size boundary behavior" do
    it "enforces claims consistency at boundary size (<= MAX)" do
      max = Verikloak::BFF::Constants::MAX_TOKEN_BYTES
      token_under, _token_over, email = boundary_tokens(max)

      @app = build_app(trusted_proxies: ["127.0.0.1"], enforce_claims_consistency: { email: :email })
      header "X-Forwarded-For", "127.0.0.1"
      header "X-Forwarded-Access-Token", "Bearer #{token_under}"
      header "X-Auth-Request-Email", email
      get "/"
      expect(last_response.status).to eq 200
    end

    it "treats oversized token (> MAX) as empty claims and rejects when mapping requires match" do
      max = Verikloak::BFF::Constants::MAX_TOKEN_BYTES
      _token_under, token_over, _email = boundary_tokens(max)

      @app = build_app(trusted_proxies: ["127.0.0.1"], enforce_claims_consistency: { email: :email })
      header "X-Forwarded-For", "127.0.0.1"
      header "X-Forwarded-Access-Token", "Bearer #{token_over}"
      header "X-Auth-Request-Email", "user@example.com"
      get "/"
      expect(last_response.status).to eq 403
      expect(last_response.headers["WWW-Authenticate"]).to include("claims_mismatch")
    end
  end

  it "rejects when both headers present and mismatch" do
    header "X-Forwarded-For", "127.0.0.1"
    header "X-Forwarded-Access-Token", "Bearer fwd"
    header "Authorization", "Bearer auth"
    get "/"
    expect(last_response.status).to eq 401
    expect(last_response.headers["WWW-Authenticate"]).to include('header_mismatch')
  end

  context "trust boundary" do
    it "requires trusted_proxies configuration" do
      # Ensure the middleware is instantiated (Rack::Builder lazily builds on first call)
      expect { build_app.to_app }.to raise_error(ArgumentError)
    end

    it "rejects requests from untrusted proxy" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true)
      header "X-Forwarded-For", "203.0.113.10"
      get "/", {}, { "REMOTE_ADDR" => "" }
      expect(last_response.status).to eq 401
      expect(last_response.headers["WWW-Authenticate"]).to include("untrusted_proxy")
    end

    it "respects xff_strategy :rightmost vs :leftmost" do
      xff = "198.51.100.10, 10.0.0.1"

      @app = build_app(trusted_proxies: ["10.0.0.0/8"], xff_strategy: :rightmost)
      header "X-Forwarded-For", xff
      header "X-Forwarded-Access-Token", "Bearer t"
      get "/", {}, { "REMOTE_ADDR" => "" }
      expect(last_response.status).to eq 200

      @app = build_app(trusted_proxies: ["10.0.0.0/8"], xff_strategy: :leftmost)
      # Ensure no stale headers from previous request remain, and provide a
      # leftmost-only client IP to avoid ambiguity in header merging.
      header "X-Forwarded-For", ""
      header "X-Forwarded-For", "198.51.100.10"
      header "X-Forwarded-Access-Token", "Bearer t"
      get "/", {}, { "REMOTE_ADDR" => "" }
      expect(last_response.status).to eq 401
      expect(last_response.headers["WWW-Authenticate"]).to include("untrusted_proxy")
    end

    it "supports Regex and Proc trusted rules" do
      rule_regex = /^192\.168\./
      rule_proc = ->(ip, _env) { ip == "172.16.0.1" }
      @app = build_app(trusted_proxies: [rule_regex, rule_proc])

      header "X-Forwarded-For", "192.168.1.10"
      header "X-Forwarded-Access-Token", "Bearer t"
      get "/", {}, { "REMOTE_ADDR" => "" }
      expect(last_response.status).to eq 200

      header "X-Forwarded-For", "172.16.0.1"
      header "X-Forwarded-Access-Token", "Bearer t"
      get "/", {}, { "REMOTE_ADDR" => "" }
      expect(last_response.status).to eq 200
    end
  end

  context "require_forwarded_header" do
    it "rejects when forwarded token is missing (no tokens)" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], require_forwarded_header: true)
      header "X-Forwarded-For", "127.0.0.1"
      get "/"
      expect(last_response.status).to eq 401
      expect(last_response.headers["WWW-Authenticate"]).to include("missing_forwarded_token")
    end

    it "rejects when forwarded token is missing (Authorization only)" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], require_forwarded_header: true)
      header "X-Forwarded-For", "127.0.0.1"
      header "Authorization", "Bearer onlyauth"
      get "/"
      expect(last_response.status).to eq 401
      expect(last_response.headers["WWW-Authenticate"]).to include("missing_forwarded_token")
    end
  end

  context "claims consistency" do
    it "passes when email matches" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true, enforce_claims_consistency: { email: :email })
      header "X-Forwarded-For", "127.0.0.1"
      token = jwt_with({ email: "a@example.com" })
      header "X-Forwarded-Access-Token", "Bearer #{token}"
      header "X-Auth-Request-Email", "a@example.com"
      get "/"
      expect(last_response.status).to eq 200
    end

    it "returns 403 on claims_mismatch (email)" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true, enforce_claims_consistency: { email: :email })
      header "X-Forwarded-For", "127.0.0.1"
      token = jwt_with({ email: "a@example.com" })
      header "X-Forwarded-Access-Token", "Bearer #{token}"
      header "X-Auth-Request-Email", "b@example.com"
      get "/"
      expect(last_response.status).to eq 403
      expect(last_response.headers["WWW-Authenticate"]).to include("claims_mismatch")
    end

    it "supports user=sub mapping" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true, enforce_claims_consistency: { user: :sub })
      header "X-Forwarded-For", "127.0.0.1"
      token = jwt_with({ sub: "user-1" })
      header "X-Forwarded-Access-Token", "Bearer #{token}"
      header "X-Auth-Request-User", "user-1"
      get "/"
      expect(last_response.status).to eq 200
    end

    it "validates groups subset mapping" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true, enforce_claims_consistency: { groups: :realm_roles })
      header "X-Forwarded-For", "127.0.0.1"
      roles = { "realm_access" => { "roles" => %w[dev admin other] } }
      token = jwt_with(roles)

      header "X-Forwarded-Access-Token", "Bearer #{token}"
      header "X-Auth-Request-Groups", "dev,admin"
      get "/"
      expect(last_response.status).to eq 200

      header "X-Forwarded-Access-Token", "Bearer #{token}"
      header "X-Auth-Request-Groups", "admin,ops"
      get "/"
      expect(last_response.status).to eq 403
      expect(last_response.headers["WWW-Authenticate"]).to include("claims_mismatch")
    end

    it "skips comparison when header missing" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true, enforce_claims_consistency: { email: :email })
      header "X-Forwarded-For", "127.0.0.1"
      token = jwt_with({ email: "a@example.com" })
      header "X-Forwarded-Access-Token", "Bearer #{token}"
      get "/"
      expect(last_response.status).to eq 200
    end
  end

  context "strip suspicious headers" do
    it "removes X-Auth-Request-* before passing downstream" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], strip_suspicious_headers: true)
      header "X-Forwarded-For", "127.0.0.1"
      header "X-Forwarded-Access-Token", "Bearer fwdtoken"
      header "X-Auth-Request-Email", "evil@example.com"
      header "X-Auth-Request-User", "attacker"
      header "X-Auth-Request-Groups", "admin"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env).not_to have_key("HTTP_X_AUTH_REQUEST_EMAIL")
      expect(last_request.env).not_to have_key("HTTP_X_AUTH_REQUEST_USER")
      expect(last_request.env).not_to have_key("HTTP_X_AUTH_REQUEST_GROUPS")
    end

    it "keeps X-Auth-Request-* when stripping disabled" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], strip_suspicious_headers: false)
      header "X-Forwarded-For", "127.0.0.1"
      header "X-Forwarded-Access-Token", "Bearer fwdtoken"
      header "X-Auth-Request-Email", "user@example.com"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["HTTP_X_AUTH_REQUEST_EMAIL"]).to eq("user@example.com")
    end
  end

  context "token selection and normalization" do
    it "prefers forwarded when configured" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true, enforce_header_consistency: true)
      header "X-Forwarded-For", "127.0.0.1"
      header "Authorization", "Bearer same"
      header "X-Forwarded-Access-Token", "Bearer same"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["HTTP_AUTHORIZATION"]).to eq("Bearer same")
    end

    it "prefers Authorization when prefer_forwarded is false" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: false, enforce_header_consistency: true)
      header "X-Forwarded-For", "127.0.0.1"
      header "Authorization", "Bearer same"
      header "X-Forwarded-Access-Token", "Bearer same"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["HTTP_AUTHORIZATION"]).to eq("Bearer same")
    end

    it "ignores non-Bearer Authorization and uses forwarded" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true)
      header "X-Forwarded-For", "127.0.0.1"
      header "Authorization", "Basic abc"
      header "X-Forwarded-Access-Token", "Bearer tok"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["HTTP_AUTHORIZATION"]).to eq("Bearer tok")
    end

    it "accepts bare forwarded token" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: true)
      header "X-Forwarded-For", "127.0.0.1"
      header "X-Forwarded-Access-Token", "baretoken"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["HTTP_AUTHORIZATION"]).to eq("Bearer baretoken")
    end

    it "passes through when tokens missing and not required" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], require_forwarded_header: false)
      header "X-Forwarded-For", "127.0.0.1"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env["HTTP_AUTHORIZATION"]).to be_nil
    end

    it "treats blank forwarded as missing when required" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], require_forwarded_header: true)
      header "X-Forwarded-For", "127.0.0.1"
      header "X-Forwarded-Access-Token", "  "
      get "/"
      expect(last_response.status).to eq 401
      expect(last_response.headers["WWW-Authenticate"]).to include("missing_forwarded_token")
    end

    it "seeds Authorization from priority headers and normalizes Bearer" do
      # Configure a custom priority header
      Verikloak::BFF.configure { |c| c.token_header_priority = ['HTTP_X_SOME_TOKEN'] }
      @app = build_app(trusted_proxies: ["127.0.0.1"], prefer_forwarded: false)
      header "X-Forwarded-For", "127.0.0.1"
      header "X-Some-Token", "BearerXYZ"
      get "/"
      expect(last_response.status).to eq 200
      expect(last_request.env['HTTP_AUTHORIZATION']).to eq('Bearer XYZ')
    end
  end

  context "env passthrough" do
    it "sets bff.token and bff.selected_peer" do
      @app = build_app(trusted_proxies: ["10.0.0.0/8"], prefer_forwarded: true, xff_strategy: :rightmost)
      header "X-Forwarded-For", "198.51.100.10, 10.0.0.5"
      header "X-Forwarded-Access-Token", "Bearer tok"
      get "/", {}, { "REMOTE_ADDR" => "" }
      expect(last_response.status).to eq 200
      expect(last_request.env['verikloak.bff.token']).to eq('tok')
      expect(last_request.env['verikloak.bff.selected_peer']).to eq('10.0.0.5')
    end
  end

  context "error response format" do
    it "returns RFC6750-style body and header for header_mismatch" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], enforce_header_consistency: true)
      header "X-Forwarded-For", "127.0.0.1"
      header "Authorization", "Bearer A"
      header "X-Forwarded-Access-Token", "Bearer B"
      get "/"
      expect(last_response.status).to eq 401
      expect(last_response.headers["Content-Type"]).to eq("application/json")
      expect(last_response.headers["WWW-Authenticate"]).to include("header_mismatch")
      parsed = JSON.parse(last_response.body)
      expect(parsed["error"]).to eq("header_mismatch")
      expect(parsed["message"]).to be_a(String)
    end

    it "returns RFC6750-style for claims_mismatch" do
      @app = build_app(trusted_proxies: ["127.0.0.1"], enforce_claims_consistency: { email: :email })
      header "X-Forwarded-For", "127.0.0.1"
      token = jwt_with({ email: "x@example.com" })
      header "X-Forwarded-Access-Token", "Bearer #{token}"
      header "X-Auth-Request-Email", "y@example.com"
      get "/"
      expect(last_response.status).to eq 403
      expect(last_response.headers["Content-Type"]).to eq("application/json")
      expect(last_response.headers["WWW-Authenticate"]).to include("claims_mismatch")
      parsed = JSON.parse(last_response.body)
      expect(parsed["error"]).to eq("claims_mismatch")
      expect(parsed["message"]).to be_a(String)
    end
  end
end
