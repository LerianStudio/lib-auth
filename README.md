# Lib Auth Middleware

This repository contains an authorization middleware for the Fiber framework in Go, allowing you to check if a user is authorized to perform a specific action on a resource. The middleware sends a POST request to an authorization service, passing the user's details, resource, and desired action.

Repository: [lib-auth](https://github.com/LerianStudio/lib-auth)

## 📦 Installation

```bash
go get github.com/LerianStudio/lib-auth/v4@latest
```

## 🔭 Inbound trace context is not extracted by the middleware

`Authorize` and `RequireM2M` used to call `tracing.ExtractHTTPContext`
themselves, parenting their spans onto a caller-supplied `traceparent` and
replacing the context's baggage with the inbound `baggage` header. Both now
inherit the ambient request context.

Whether an inbound trace context is honored is the **application's** decision — a
caller that can set the header can otherwise choose this service's trace ID and
force its sampling decision, which is why lib-observability gates it behind
`tracing.TelemetryConfig.TrustInboundTraceContext` (default false) from `v2.1.2`
on. lib-auth cannot see that setting, so it inherits whatever parent the
application's telemetry middleware decided on: an app that trusts the inbound
trace already parented its server span to it and lib-auth joins for free; an app
that does not stays local, and so does lib-auth. Baggage sent to the
authorization service now comes from the application's context, never from the
wire — `propagation.Baggage.Extract` replaces the whole baggage value instead of
merging, so self-extraction silently discarded baggage the application seeded.
The gRPC interceptor always behaved this way; the HTTP path is now consistent
with it.

**What you will observe:** auth spans stop joining a caller-supplied
`traceparent` unless the application itself trusts it.

Note: `TrustInboundTraceContext` is an **application-level** requirement, not a
requirement of this module — lib-auth itself does not use it, and no
lib-observability type appears on lib-auth's public API, so an application is
free to be on any major of that library (see "Logging" below). Applications
that want to opt in to honoring inbound trace context must enable the flag
themselves, which requires lib-observability `v2.1.2` or later; on an earlier
version the flag does not exist and an inbound trace context is never trusted.
That is a constraint on using the FLAG, not on using lib-auth.

## 🪵 Logging

Every lib-auth entry point that takes a logger takes an `obs.Logger`, declared
in `auth/obs` from stdlib types only:

```go
type Logger interface {
	Log(ctx context.Context, level int, msg string, fields ...any)
	Enabled(level int) bool
	Sync(ctx context.Context) error
}
```

Levels are `obs.LevelError` (0), `obs.LevelWarn` (1), `obs.LevelInfo` (2),
`obs.LevelDebug` (3) — the same scale as lib-observability and lib-commons,
lower is more severe.

Nothing has to be adapted. A `lib-observability` logger (v4 or later), a
`lib-commons` `commons/obs.Logger`, and a three-method type declared in your
own package that imports no observability library at all are all accepted
directly. Pass `nil` and lib-auth builds its own default logger; it never
stores a nil logger.

The point is that lib-auth's public API names no type from a versioned
observability module, so a major bump there no longer forces one here. A CI
guard (`auth/obs/boundary`) walks the exported API with `go/ast` and fails if a
`lib-observability` type reappears in a field, parameter, return or exported
alias.

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
# value leaves the service starting with no address to forward, and announces
# that in ONE wording at two levels. At construction it is an INFO disclosure,
# in every NewAuthClient. It becomes an ERROR — once per client — only when
# Authorize is mounted on a client configured to call the authorization service
# (auth enabled and an address set), because that is the only path in this
# library that resolves a caller IP. A token-only or gRPC-only client never
# reaches it and is not paged for a feature it does not use.
#
# LEAVING IT UNSET CAN LOCK YOUR CALLERS OUT. With no trusted proxies the derived
# caller IP is empty and clientIp is omitted from the authorize call. What the
# authorization service does with a request that carries no address is ITS
# policy, not this library's, and as of 2026-08-23 that policy is conditional:
# for a tenant with an IP allowlist active on the surface being called, an
# omitted address is accepted only from a caller the authorization service
# recognises as one of the platform's own services, and DENIED otherwise. It
# recognises them by the calling service's own network address, against a range
# list configured on that service (PLATFORM_INTERNAL_CIDRS — its variable, not
# one this library reads); with that unset nothing is recognised, so every
# addressless request to such a tenant is denied. Tenants with no active
# allowlist are unaffected either way. Verify the current rule in the
# authorization service's own IP-allowlist operations documentation, which is
# the authority — it can change there without a release here.
#
# There is no fallback to the socket peer, deliberately: that would forward the
# ingress address, which — for a tenant that happens to have the ingress CIDR
# registered — would allow EVERY caller. Set it on any deployment that uses
# tenant IP allowlists.
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

logger, err := zap.New(zap.Config{Environment: zap.EnvironmentProduction})
if err != nil {
    // Do not fall through: on failure `logger` is a typed-nil *zap.Logger, not
    // a usable logger. Passing it on is a caller bug, not a "use the default"
    // signal -- pass a literal nil for that.
    log.Fatalf("failed to build logger: %v", err)
}
```

```go
import "github.com/LerianStudio/lib-auth/v4/auth/middleware"

authClient := middleware.NewAuthClient(cfg.Address, cfg.Enabled, logger)
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
* On the Fiber path, derives the caller's client IP from `TRUSTED_PROXIES` and the socket peer — not from Fiber's `c.IP()` or `c.IPs()` — and sends it as the optional `clientIp` field, omitting it when no caller IP is attributable (see [Client IP forwarding](#-client-ip-forwarding)).
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

The `clientIp` field is optional *in the schema* — the request is well-formed without it — but omitting it is not free: the authorization service uses it to enforce the per-tenant IP allowlist, and for a protected tenant an omitted address can be denied. On the Fiber path the middleware derives it from `TRUSTED_PROXIES` (see below) and omits it only when no caller IP can be attributed; see [Client IP forwarding](#-client-ip-forwarding) for what follows from that.

## 🌐 Client IP forwarding

On the Fiber path, `Authorize` sends `clientIp` to `POST /v1/authorize`, enabling the access manager to enforce a per-tenant IP allowlist downstream.

* **The library derives the IP itself — it does NOT call `c.IP()`.** Fiber v3 only walks the `X-Forwarded-For` chain right-to-left when the consuming service sets *all four* of `TrustProxy`, `TrustProxyConfig{Proxies}`, `ProxyHeader` and `EnableIPValidation` on the `fiber.App` it built. Miss the last one and `c.IP()` returns the **raw header** — a value the caller supplies about itself. This library cannot enforce a config it does not own, so it stops depending on it: it reads its own `TRUSTED_PROXIES` list and derives the caller IP from the forwarded header plus the real socket peer.
* **Set `TRUSTED_PROXIES`.** Comma-separated CIDRs of every proxy/ingress in front of the service, e.g. `TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12`. A bare address is rejected outright — it is *not* silently widened to a `/32` or `/128`, so write the prefix you mean. So is any range broader than `/8` (IPv4) or `/48` (IPv6) — measured on the range as stored (see the next bullet) — which includes the catch-alls `0.0.0.0/0` and `::/0`. An unusable entry is logged at ERROR and dropped; startup never fails on it, and if *every* entry is unusable the result is identical to leaving the variable unset (no trusted proxies, no address forwarded).
* **An IPv4 range written in IPv4-mapped IPv6 form is rebased to IPv4.** `::ffff:10.0.0.0/104` is stored as `10.0.0.0/8` and matches exactly what that entry matches, because hops are unmapped before comparison and the list is normalised the same way. The rebased length is what the minimum-length check is applied to, so writing a range in mapped form can never get it past a check its IPv4 form would fail: `::ffff:10.0.0.0/100` is a `/4` and is rejected. A mapped address carrying a prefix shorter than `/96` (`::ffff:10.0.0.0/95`) reaches past the mapped block, denotes no IPv4 range, and is rejected too. Plain `10.0.0.0/8` remains the clearest way to write it.
* **Unset `TRUSTED_PROXIES` can lock your callers out.** No trusted proxies ⇒ no derivable caller IP ⇒ `clientIp` is omitted from the authorize call. Omitting the field is all this library does; what follows is the authorization service's decision, and **as of 2026-08-23** that decision is conditional:

  | tenant | omitted `clientIp` |
  | --- | --- |
  | no IP allowlist active on the surface called | unaffected — the allowlist is not evaluated |
  | allowlist active, caller recognised as one of the platform's own services | **allowed** — the platform could not determine the address, and that must not lock the tenant out |
  | allowlist active, caller not recognised | **denied** |

  Recognition is by the *calling service's* own network address against a range list configured on the authorization service (`PLATFORM_INTERNAL_CIDRS` — **its** variable, not one this library reads). With that unset nothing is recognised, so every addressless request to a protected tenant is denied. That is the case an operator is most likely to hit. The two "allowlist active" rows describe a healthy authorization service: it fails open on its own dependency failures, which is its concern, not a behaviour to design against.

  **This table is a copy, and the copy is not the authority.** The rule belongs to the authorization service and can change there without a release here — it has already gone stale twice in this file, in both directions. Before acting on it, confirm it in that service's own IP-allowlist operations documentation. What does *not* go stale is the sentence above it: this library omits the field when no address is derivable, and takes no position on what that means.

  There is deliberately **no fallback to the socket peer**: the peer is the ingress address, so a tenant with the ingress CIDR in its allowlist would see a *false allow* for every caller on earth. Set the variable on any deployment where tenants use IP allowlists.
* **A missing or unusable value never fails the boot.** The service starts normally, forwarding no address — there is no `Fatal`, no `panic` and no error returned to your bootstrap. The degradation is announced instead, in one wording at two levels (never per request), naming the cause and the consequence:

  ```text
  TRUSTED_PROXIES is not set; client IP will not be forwarded and the per-tenant IP allowlist has nothing to match the caller against
  ```

  | when | level |
  | --- | --- |
  | at construction, in every `NewAuthClient` | **INFO** — a disclosure, visible when the consuming service logs at INFO or DEBUG |
  | the first time `Authorize` is mounted on a client configured to call the authorization service (auth enabled and an address set) | **ERROR**, once per client |

  **Alert on the ERROR.** Mounting `Authorize` is what makes the caller address load-bearing: from that point every authorized request omits `clientIp` and the conditional outcome above starts applying. A client that never mounts it — one built only to mint tokens with `GetApplicationToken`, a gRPC-only client, a service that hand-rolls its own authorize call, or one whose auth is disabled or addressless — cannot experience that outcome, so it gets the INFO and is not paged for a feature it does not use.

  A value that was set but left no usable CIDR follows the same two levels with a distinct cause (`has no usable CIDR`). Each dropped entry is still its own ERROR at construction, unconditionally: an unusable entry is a live misconfiguration whichever way the client is used.
* **How the IP is chosen.** The hop list is every `X-Forwarded-For` line on the request followed by the real socket peer. It is walked **right to left** (nearest hop first), skipping every hop inside a trusted CIDR; the first hop that is not a trusted proxy is the caller. If every hop is trusted (fully-internal traffic), or a hop cannot be read as a bare IP, no caller is attributable: the result is empty and `clientIp` is omitted — which, for a tenant with an active allowlist, is the conditional outcome described in the bullet above, not a quiet pass. IPv4-mapped IPv6 hops (`::ffff:203.0.113.7`) are normalised, so they match IPv4 CIDRs and reach the allowlist in the form it stores.

* **The chain is read off the request, not through `c.IPs()`.** `c.IPs()` reads the same header but filters it through the consuming service's app config first: with `EnableIPValidation` set, Fiber drops every token it does not recognise as an address before this library sees the chain. Dropping a token closes the gap it left, so the walk no longer stops there and carries on further left — onto text the caller wrote about itself. The same request would attribute a different caller depending only on a flag in the embedding service. So the library reads the header bytes and splits them itself: one hop per comma position, surrounding whitespace trimmed, **empty positions kept** (an empty position is a hop that cannot be vouched for, so it stops the walk like any other unreadable one). Repeated `X-Forwarded-For` lines are read and concatenated in order, as [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110#section-5.2) defines them — reading only the first line would discard the trustworthy right-hand end of the chain and stop the walk further left.
* **A hop carrying a port does not parse.** `1.2.3.4:80` is not a bare IP, so it stops the walk and no caller IP is attributed for that request. Standard `X-Forwarded-For` carries no port and nginx/ALB do not add one, but **IIS and some proxies do** — if one of those sits in front of the service, strip the port at the proxy, or every affected request reaches the authorization service addressless and takes the conditional outcome above.
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
* **gRPC forwards no client IP yet.** The gRPC interceptors send no `clientIp` in this version, so every gRPC-authorized call reaches the authorization service addressless — the same position as an unset `TRUSTED_PROXIES`, and subject to the same conditional outcome, including the deny. Peer/metadata IP extraction is a planned follow-up.
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
    "github.com/LerianStudio/lib-auth/v4/auth/middleware"
)

// Create the auth client once (same as HTTP)
authClient := middleware.NewAuthClient(cfg.Address, cfg.Enabled, logger)

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
 - The interceptors do not forward a client IP in this version, so a gRPC-authorized call carries no address for the per-tenant IP allowlist to match, and takes whatever outcome the authorization service gives an addressless request. See [Client IP forwarding](#-client-ip-forwarding).

## 🚧 Error Handling

The middleware captures and logs the following error types:

* Failure to create the request
* Failure to send the request
* Failure to read the response body
* Failure to deserialize the response JSON
* Errors from the authorization service (e.g., 401 Unauthorized, 403 Forbidden)

## 📧 Contact

For questions or support, contact us at: [contato@lerian.studio](mailto:contato@lerian.studio).
