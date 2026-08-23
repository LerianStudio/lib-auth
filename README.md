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

# TRUSTED_PROXIES is the comma-separated list of proxy CIDRs whose forwarded hop
# (X-Forwarded-For) may be believed. It is what the library uses to derive the
# caller IP it sends as clientIp, so the per-tenant IP allowlist depends on it.
# Same variable name (and value) already used by plugin-access-manager and
# flowker — NOT to be confused with tracer's unrelated TRUSTED_PROXY_CIDRS.
#
# Entries must be CIDRs: a bare address ("10.0.0.1") is rejected, and so is an
# overly broad range (IPv4 wider than /8, IPv6 wider than /48). An IPv4 range
# written in IPv4-mapped IPv6 form ("::ffff:10.0.0.0/104") is rebased to the
# IPv4 range it denotes ("10.0.0.0/8") and measured against the IPv4 limit; if
# it cannot be rebased it is rejected, never stored in a form that would match
# nothing. An unusable entry is logged at ERROR and dropped; the valid entries
# still apply. Nothing here ever fails the boot: a missing or entirely unusable
# value logs ONE ERROR line at startup naming cause and consequence, and the
# service starts with IP policy inert.
#
# LEAVING IT UNSET DISABLES IP-BASED AUTHORIZATION. With no trusted proxies the
# derived caller IP is empty, clientIp is omitted from the authorize call, and
# the auth service denies any request under an active IP allowlist
# (deny-missing-ip). This is deliberate: falling back to the socket peer would
# forward the ingress address, which — for a tenant that happens to have the
# ingress CIDR registered — would allow EVERY caller. Set it on any deployment
# that uses tenant IP allowlists.
TRUSTED_PROXIES=10.0.0.0/8,<ingress-cidr>
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
* On the Fiber path, derives the caller's client IP from `TRUSTED_PROXIES` and the socket peer — not from `c.IP()` — and sends it as the optional `clientIp` field, omitting it when no caller IP is attributable (see [Client IP forwarding](#-client-ip-forwarding)).
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

The `clientIp` field is optional. On the Fiber path the middleware derives it from `TRUSTED_PROXIES` (see below) and omits it when no caller IP can be attributed; the authorization service uses it to enforce the per-tenant IP allowlist.

## 🌐 Client IP forwarding

On the Fiber path, `Authorize` sends `clientIp` to `POST /v1/authorize`, enabling the access manager to enforce a per-tenant IP allowlist downstream.

* **The library derives the IP itself — it does NOT call `c.IP()`.** Fiber v3 only walks the `X-Forwarded-For` chain right-to-left when the consuming service sets *all four* of `TrustProxy`, `TrustProxyConfig{Proxies}`, `ProxyHeader` and `EnableIPValidation` on the `fiber.App` it built. Miss the last one and `c.IP()` returns the **raw header** — a value the caller supplies about itself. This library cannot enforce a config it does not own, so it stops depending on it: it reads its own `TRUSTED_PROXIES` list and derives the caller IP from the forwarded header plus the real socket peer.
* **Set `TRUSTED_PROXIES`.** Comma-separated CIDRs of every proxy/ingress in front of the service, e.g. `TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12`. A bare address is rejected outright — it is *not* silently widened to a `/32` or `/128`, so write the prefix you mean. So is any range broader than `/8` (IPv4) or `/48` (IPv6) — measured on the range as stored (see the next bullet) — which includes the catch-alls `0.0.0.0/0` and `::/0`. An unusable entry is logged at ERROR and dropped; startup never fails on it, and if *every* entry is unusable the result is identical to leaving the variable unset (no trusted proxies, IP policy inert).
* **An IPv4 range written in IPv4-mapped IPv6 form is rebased to IPv4.** `::ffff:10.0.0.0/104` is stored as `10.0.0.0/8` and matches exactly what that entry matches, because hops are unmapped before comparison and the list is normalised the same way. The rebased length is what the minimum-length check is applied to, so writing a range in mapped form can never get it past a check its IPv4 form would fail: `::ffff:10.0.0.0/100` is a `/4` and is rejected. A mapped address carrying a prefix shorter than `/96` (`::ffff:10.0.0.0/95`) reaches past the mapped block, denotes no IPv4 range, and is rejected too. Plain `10.0.0.0/8` remains the clearest way to write it.
* **Unset `TRUSTED_PROXIES` means every IP-policy request is DENIED.** No trusted proxies ⇒ no derivable caller IP ⇒ `clientIp` is omitted ⇒ the auth service applies `deny-missing-ip`. There is deliberately **no fallback to the socket peer**: the peer is the ingress address, so a tenant with the ingress CIDR in its allowlist would see a *false allow* for every caller on earth. An empty value can never match by accident.
* **A missing or unusable value never fails the boot.** The service starts normally with IP policy inert — there is no `Fatal`, no `panic` and no error returned to your bootstrap. The degradation is announced instead: **one ERROR line at construction** (not per request) naming the cause and the consequence, e.g.

  ```text
  TRUSTED_PROXIES is not set; client IP will not be forwarded and the per-tenant IP allowlist will not enforce
  ```

  A value that was set but left no usable CIDR logs the same consequence with a distinct cause (`has no usable CIDR`), preceded by one ERROR per dropped entry. Alert on that line rather than waiting for a 403.
* **How the IP is chosen.** The hop list is `X-Forwarded-For` followed by the real socket peer. It is walked **right to left** (nearest hop first), skipping every hop inside a trusted CIDR; the first hop that is not a trusted proxy is the caller. If every hop is trusted (fully-internal traffic), or a hop is not a parseable bare IP, the result is empty — fail closed. IPv4-mapped IPv6 hops (`::ffff:203.0.113.7`) are normalised, so they match IPv4 CIDRs and reach the allowlist in the form it stores.
* **A hop carrying a port does not parse.** `1.2.3.4:80` is not a bare IP, so it stops the walk and no caller IP is attributed for that request. Standard `X-Forwarded-For` carries no port and nginx/ALB do not add one, but **IIS and some proxies do** — if one of those sits in front of the service, strip the port at the proxy or IP policy will never enforce.
* **No code change needed.** The public `Authorize(product, resource, action)` signature is unchanged. Consuming services get this behavior by upgrading the library and setting the environment variable.
* **Your Fiber trusted-proxy config still matters for everything else.** `c.IP()`, request logging and rate limiting in your own service continue to read it, so keep configuring all four knobs; the authorization path simply no longer depends on you getting it right:

  ```go
  f := fiber.New(fiber.Config{
      TrustProxy:         true,
      TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: []string{"10.0.0.0/8"}},
      ProxyHeader:        fiber.HeaderXForwardedFor,
      EnableIPValidation: true,
  })
  ```
* **gRPC is not IP-enforced yet.** The gRPC interceptors do not forward a client IP in this version, so gRPC-authorized calls skip IP allowlist enforcement. Peer/metadata IP extraction is a planned follow-up.
* **Cache is IP-scoped.** When `AUTH_CACHE_TTL > 0`, the decision cache key includes `clientIp`, so a decision cached for one IP is never reused for another. IP-dependent decisions stay correct under caching. When no IP is derivable the key holds an empty string, exactly as the gRPC path has always done.

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
