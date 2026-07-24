# Lib Auth Middleware

This repository contains an authorization middleware for the Fiber framework in Go, allowing you to check if a user is authorized to perform a specific action on a resource. The middleware sends a POST request to an authorization service, passing the user's details, resource, and desired action.

Repository: [lib-auth](https://github.com/LerianStudio/lib-auth)

## 📦 Installation

```bash
go get github.com/LerianStudio/lib-auth/v3@latest
```

## 🚀 How to Use

### 1. Set the needed environment variables:

In your environment configuration or `.env` file, set the following environment variables:

```dotenv
PLUGIN_AUTH_ADDRESS=http://localhost:4000
PLUGIN_AUTH_ENABLED=true

# Optional. When "true", the client also forwards the route product on M2M
# (application-token) authorization calls, so the auth service can isolate
# permissions by product (matching product-prefixed resources). Defaults to
# false, preserving the previous behavior of sending no product for M2M.
AUTH_M2M_PRODUCT_FORWARD_ENABLED=false

# Optional. When "true", enables the M2M/authz "inversion of responsibility"
# model: application tokens authorize under their own real sub claim and any token
# type outside {normal-user, application} fails closed with 401. Defaults to false,
# preserving the legacy pre-inversion model (non-normal-user types authorize under
# the fabricated "admin/{product}-editor-role" subject and unknown types fail open).
# Keep it false when your Casdoor seed still uses the legacy model; opt in once
# seeds are migrated.
AUTH_M2M_INVERSION_ENABLED=false

# Optional. Opt-in local JWT signature verification for the general authorization
# path. When unset, tokens are parsed without signature verification (the
# authorization service remains the trust anchor) — the previous behavior,
# unchanged. When set, the bearer token is cryptographically verified (RS256,
# expiry required, and issuer when AUTH_JWT_ISSUER is set) BEFORE its claims are
# trusted; any failure denies the request (401, fail closed).
#
# AUTH_JWT_VERIFY_CERT holds the issuer's PEM certificate(s) or RSA public key(s).
# Newline-join multiple PEMs to carry the old and new certs simultaneously across
# a key rotation (zero-downtime: a token verified by ANY listed key is accepted).
# AUTH_JWT_VERIFY_CERT_PATH points to a mounted PEM file instead (used only when
# AUTH_JWT_VERIFY_CERT is empty). A configured-but-unparseable cert is logged at
# ERROR and leaves verification disabled; it is never silently accepted.
AUTH_JWT_VERIFY_CERT=
AUTH_JWT_VERIFY_CERT_PATH=
AUTH_JWT_ISSUER=

# Optional. When "true", the middleware fails closed: if auth is disabled
# (PLUGIN_AUTH_ENABLED=false) or misconfigured (empty PLUGIN_AUTH_ADDRESS),
# every protected route refuses to serve (HTTP 503 / gRPC Unavailable) instead
# of passing through unauthenticated. Defaults to false, preserving the prior
# fail-open behavior. Set it in security-sensitive deployments so a
# missing/typo'd address cannot silently downgrade a protected service to open.
AUTH_REQUIRED=false

# Optional authorization resilience (all opt-in; defaults preserve prior behavior).
# Every fallback denies (fail closed) — no path serves a request on an outage.
#
# AUTH_TIMEOUT bounds each authorization round-trip with a per-request deadline
# (Go duration). Defaults to 30s (behavior-neutral). It also caps the retry budget.
AUTH_TIMEOUT=30s
# AUTH_CACHE_TTL enables a short-lived decision cache when > 0, keyed by
# (subject, resource, action, product, clientIp) — never the token. Empty/0
# disables it (default). Security tradeoff: a permission revocation takes up to
# the TTL to propagate, so keep it small (5–15s). It sheds load and, with the
# breaker, survives brief authz outages by serving fresh positive decisions.
# The clientIp is part of the key so an IP-dependent decision cached for one
# caller is never reused for another (see "Client IP forwarding" below).
AUTH_CACHE_TTL=
# AUTH_BREAKER_ENABLED opens a circuit breaker after sustained authz failures.
# While open it serves ONLY a fresh positive cache hit and otherwise denies;
# it never serves a stale decision. Defaults to disabled.
AUTH_BREAKER_ENABLED=false
# AUTH_RETRY_MAX retries only TRANSIENT failures (network/timeout/5xx) up to N
# times within AUTH_TIMEOUT; authoritative 401/403 are never retried. 0 disables.
AUTH_RETRY_MAX=0
```

### 2. Create a new instance of the middleware:

In your `config.go` file, configure the environment variables for the Auth Service:

```go
type Config struct {
    Address             string `env:"PLUGIN_AUTH_ADDRESS"`
    Enabled             bool   `env:"PLUGIN_AUTH_ENABLED"`
}

cfg := &Config{}

logger := zap.InitializeLogger()
```

```go
import "github.com/LerianStudio/lib-auth/v3/auth/middleware"

authClient := middleware.NewAuthClient(cfg.Address, cfg.Enabled, &logger)
```

### 2. Use the middleware in your Fiber application:

```go
func NewRoutes(auth *authMiddleware.AuthClient, [...]) *fiber.App {
    f := fiber.New(fiber.Config{
        DisableStartupMessage: true,
    })
    
    applicationName := os.Getenv("APPLICATION_NAME")
    
    // Applications routes
    f.Get("/v1/applications", auth.Authorize(applicationName, "ledger", "get"), applicationHandler.GetApplications)
}
```

## 🛠️ How It Works

The `Authorize` function:

* Receives the `sub` (user), `resource` (resource), and `action` (desired action).
* Sends a POST request to the authorization service.
* On the Fiber path, forwards the caller's client IP (`c.IP()`) as the optional `clientIp` field (see [Client IP forwarding](#-client-ip-forwarding)).
* Checks if the response indicates that the user is authorized.
* Allows the normal application flow or returns a 403 (Forbidden) error.

## 📥 Example Request to Auth

```http
POST /v1/authorize
Content-Type: application/json
Authorization: Bearer your_token_here

{
    "sub":      "lerian/userId",
    "resource": "resourceName",
    "action":   "get",
    "clientIp": "203.0.113.45"
}
```

The `clientIp` field is optional. On the Fiber path it is set automatically to `c.IP()`; the authorization service uses it to enforce the per-tenant IP allowlist.

## 🌐 Client IP forwarding

On the Fiber path, `Authorize` automatically sends `clientIp = c.IP()` to `POST /v1/authorize`, enabling the access manager to enforce a per-tenant IP allowlist downstream.

* **No code change needed.** The public `Authorize(sub, resource, action)` signature is unchanged. Consuming services get this behavior by upgrading the library — bump the version, nothing else.
* **Configure trusted proxies (Fiber v3).** For `c.IP()` to report the real client IP behind a proxy or ingress, the consuming service must configure Fiber v3's trusted-proxy settings on its `fiber.New(fiber.Config{...})`:
  * `TrustProxy: true` — enable proxy-header trust (Fiber v3 renamed the v2 `EnableTrustedProxyCheck`).
  * `TrustProxyConfig: fiber.TrustProxyConfig{Proxies: []string{"10.0.0.0/8", "<ingress-cidr>"}}` — the exact set of upstream proxy IPs/CIDRs allowed to set the forwarded header. Never leave this empty while trusting the header, or any caller can spoof its IP.
  * `ProxyHeader: fiber.HeaderXForwardedFor` — the header `c.IP()` reads the client IP from.
  * `EnableIPValidation: true` — validates that the value is a well-formed IP, so `c.IP()` cannot return a spoofable raw `X-Forwarded-For` string.

  Without this, `c.IP()` is the socket peer (the proxy), not the caller; misconfigured (trusting the header without pinning `Proxies`), it is attacker-controlled. Example:

  ```go
  f := fiber.New(fiber.Config{
      TrustProxy:         true,
      TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: []string{"10.0.0.0/8"}},
      ProxyHeader:        fiber.HeaderXForwardedFor,
      EnableIPValidation: true,
  })
  ```
* **gRPC is not IP-enforced yet.** The gRPC interceptors do not forward a client IP in this version, so gRPC-authorized calls skip IP allowlist enforcement. Peer/metadata IP extraction is a planned follow-up.
* **Cache is IP-scoped.** When `AUTH_CACHE_TTL > 0`, the decision cache key includes `clientIp`, so a decision cached for one IP is never reused for another. IP-dependent decisions stay correct under caching.

## 📡 Expected Authorization Service Response

The authorization service should return a JSON response in the following format:

```json
{
    "authorized": true,
    "timestamp": "2025-03-03T12:00:00Z"
}
```

## 🔒 gRPC usage

Secure a gRPC server with the unary interceptor using per-method policies. It reuses the same auth service and tracing used by the HTTP middleware.

```go
import (
    "context"
    "google.golang.org/grpc"
    "github.com/LerianStudio/lib-auth/v3/auth/middleware"
)

// Create the auth client once (same as HTTP)
authClient := middleware.NewAuthClient(cfg.Address, cfg.Enabled, &logger)

// Map full gRPC method names to authorization policies
policies := middleware.PolicyConfig{
    MethodPolicies: map[string]middleware.Policy{
        "/balance.BalanceProto/CreateBalance": {Resource: "balances", Action: "post"},
    },
    // Constant subject base, matching HTTP usage (e.g., "midaz")
    SubResolver: func(ctx context.Context, _ string, _ any) (string, error) { return "midaz", nil },
}

srv := grpc.NewServer(
    grpc.UnaryInterceptor(middleware.NewGRPCAuthUnaryPolicy(authClient, policies)),
)
```

Notes:
- Keys in `MethodPolicies` must be full method names in the form `/package.Service/Method`.
- When `SubResolver` returns an empty string, the subject is derived from token claims.
 - If you already use multiple interceptors, prefer `grpc.ChainUnaryInterceptor(...)` and include the auth interceptor alongside telemetry/logging.
 - The interceptors do not forward a client IP in this version, so gRPC-authorized calls are not IP-allowlist enforced yet. See [Client IP forwarding](#-client-ip-forwarding).

## 🚧 Error Handling

The middleware captures and logs the following error types:

* Failure to create the request
* Failure to send the request
* Failure to read the response body
* Failure to deserialize the response JSON
* Errors from the authorization service (e.g., 401 Unauthorized, 403 Forbidden)

## 📧 Contact

For questions or support, contact us at: [contato@lerian.studio](mailto:contato@lerian.studio).
