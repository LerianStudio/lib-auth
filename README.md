# Lib Auth Middleware

This repository contains an authorization middleware for the Fiber framework in Go, allowing you to check if a user is authorized to perform a specific action on a resource. The middleware sends a POST request to an authorization service, passing the user's details, resource, and desired action.

Repository: [lib-auth](https://github.com/LerianStudio/lib-auth)

## 📦 Installation

```bash
go get github.com/LerianStudio/lib-auth/v5@latest
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

# Optional. When "true", Authorize keeps demanding a bearer token that names a
# principal even while auth is disabled (PLUGIN_AUTH_ENABLED=false or an empty
# PLUGIN_AUTH_ADDRESS): the token is extracted (401 when missing), its claims
# parsed exactly as on the enabled path, the subject derived with the same
# fail-closed token-type rules, and the Principal published on the request
# context. ONLY the authorization round-trip is skipped. Defaults to false,
# which preserves the historical pass-through. AUTH_REQUIRED still wins: with
# it set, a client that cannot authorize refuses with 503 and never gets here.
AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED=false

# Optional. Opt-in local JWT signature verification for the general authorization
# path. When unset, tokens are parsed without signature verification (the
# authorization service remains the trust anchor) — the previous behavior,
# unchanged. When set, the bearer token is cryptographically verified (RS256,
# expiry required, and issuer when AUTH_JWT_ISSUER is set) BEFORE its claims are
# trusted; any failure denies the request (401, fail closed).
#
# One path is the exception to "the authorization service remains the trust
# anchor": with AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED=true no authorization call
# is made at all, so with verification unset that path has NO trust anchor and
# the caller identity is self-asserted. Setting a cert here restores one, because
# the same claim extraction runs on both paths, and an invalid signature is then
# refused with 401 on the disabled path too.
#
# AUTH_JWT_VERIFY_CERT holds the issuer's PEM certificate(s) or RSA public key(s).
# Newline-join multiple PEMs to carry the old and new certs simultaneously across
# a key rotation (zero-downtime: a token verified by ANY listed key is accepted).
# AUTH_JWT_VERIFY_CERT_PATH points to a mounted PEM file instead (used only when
# AUTH_JWT_VERIFY_CERT is empty). A configured-but-unparseable cert is logged at
# ERROR and leaves verification disabled on the normal authorizing path, where the
# authorization service remains the trust anchor. The no-round-trip principal path
# refuses with 503 instead of accepting self-asserted claims when a configured key
# source could not be loaded.
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
# (SHA-256 digest of the bearer token, subject, resource, action, product,
# clientIp, scope attributes) — never the raw token. Empty/0 disables it
# (default). Security tradeoff: a permission revocation takes up to
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

`middleware.EnvNames()` returns every `AUTH_*` variable above, for tests that clean or audit
the client's configuration.

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
import "github.com/LerianStudio/lib-auth/v5/auth/middleware"

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
* Allows the normal application flow or refuses the request.

In v5, every `Authorize` refusal is **returned** as a `*fiber.Error`, never written
to the response by the middleware. The application's own `ErrorHandler` therefore
owns the response envelope. This is intentionally different from v4, where refusals
are written directly for compatibility with existing consumers. Migrate the module
path to `github.com/LerianStudio/lib-auth/v5` and ensure the application handler
preserves the status carried by `*fiber.Error` (`401`, `403`, `503`, or the status
returned by the authorization service). Decoded authorization-service errors also
resolve to `commons.Response` through `errors.As`.

**The HTTP status decides, never a field inside the body.** Only a `2xx` answer is
an authorization decision. A body that claims `authorized` inside any non-`2xx`
answer is never read as a grant, whatever the status.

Every non-`2xx` refuses. What the status chooses is the WORD the caller and the
operator read:

* **Refused at its own status** — the answer is about the caller, and repeating the
  request will not change it: `401` (token missing or invalid), `403` (tenant IP
  allowlist), `404` (no subject exists for the token's `sub`), and any other `4xx`
  except the four the next bullet reclassifies (`400`, `408`, `422`, `429`).
  These are never retried and never trip the circuit breaker.
* **`503 Service Unavailable`** — the authorization service did not answer the
  question: unreachable, a `5xx`, a redirect, a `2xx` that does not parse or that
  carries no decision at all, retries exhausted, the circuit breaker open, and four
  `4xx` that are not about the caller. `400` and `422` mean the request body was
  rejected, and that body is built entirely by this library, so they signal a
  contract mismatch an operator must fix. `429` is the authorization service's own
  rate limiter, whose direct caller is this service rather than the end caller.
  `408` is a timeout on the responder's side. These are retried and are
  breaker-eligible, because repeating them can succeed.

Redirects are never followed. The client returns the `3xx` itself, so the status
the decision is made on always belongs to the service at `PLUGIN_AUTH_ADDRESS` and
not to whatever a `Location` header named — otherwise a redirect to any endpoint
answering `200 {"authorized":true}` would be a grant.

The refusal message is read from both error shapes the authorization service
serves: `message` on its legacy envelope, `detail` on its RFC 9457 problem
document.

`403 Forbidden` is one of two things: a refusal this library makes locally, before
any call (a misdeclared route, or the two `RequireScope` refusals described under
Scoped access), or the authorization service answering no. The request is refused
under every rule above (fail closed), but only the 503 tells an operator an outage
apart from a policy denial, and only the 503 reaches a rail's 5xx alarms.

## 🪪 Principal on the request context

Every path where `Authorize` reads a token and then calls `c.Next()` publishes the
caller identity it derived, so a handler never has to parse the token again. Read it
back with `PrincipalFromContext`, which reports absent when no principal was
published, when the stored `Sub` is empty or whitespace-only, and when the
derivation produced no real subject (the legacy `M2MInversionEnabled=false` model,
where the subject is a fabricated role).

```go
type Principal struct {
    Type     string // token "type" claim: "normal-user" | "application"
    Owner    string // "owner" claim; empty for application tokens
    Sub      string // "sub" claim, verbatim
    Subject  string // "<owner>/<sub>" for normal-user, "<sub>" for application
    ClientID string // "azp" claim when present, else empty
    TenantID string // "tenantId" claim verbatim, else empty
}

func PrincipalFromContext(ctx context.Context) (Principal, bool)
```

A `sub` claim that is empty or whitespace-only names nobody and is refused with 401
before any principal is published; on a `normal-user` token the same applies to
`owner`, while an `application` token's `owner` is ignored and `Owner` stays empty.
Every other value is published
verbatim: `Owner` and `Sub` are the claims as the token wrote them, edge whitespace
included, with no normalization. `Subject` is the string sent to the authorization
service.

`TenantID` is the token's `tenantId` claim — the same claim the gRPC interceptors
forward as `md-tenant-id` — copied verbatim and empty when the claim is absent or
not a string. It never affects authorization or whether `PrincipalFromContext`
reports a principal, since single-tenant tokens may carry none. It is a claim, not a
tenant-isolation decision: in multi-tenant deployments the tenant-manager remains
the authority on which tenant a request belongs to.

Publication covers the authorized decision, a decision-cache hit, and the
`AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED` path below. A denied request publishes
nothing, and neither does the default disabled pass-through. The only identity attribute any of
these spans carries is `app.auth.principal.type`. The span copy of the authorization
payload omits `sub`, so `Owner`, `Sub`, `Subject`, `ClientID` and `TenantID` are recorded nowhere,
and neither the access token nor any principal identifier reaches a span attribute
or a log line written by this library — the request id is what correlates a span
with the service's own audit trail. The one caller identifier this library hands
to the service is the partner id of a scoped credential, in `c.Locals(PartnerLocalsKey)`,
for the service's own request log (see Scoped access). The body sent to the authorization service is unchanged and still carries the
subject, since it is the subject of the decision; only the telemetry copy is redacted.

### Bearer required while auth is disabled

`AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED` (field `PrincipalRequiredWhenDisabled`,
default `false`) is for services that always want a named caller, even in a
deployment that runs with the authorization service off. When it is `true` and the
client cannot authorize, `Authorize` still extracts the token (401 when missing),
parses the claims, derives the subject under the same fail-closed token-type rules,
and publishes the `Principal`. A legacy fabricated-role token without a real `sub`
is refused with 401 because it does not name a principal, as is a token whose `sub`
is empty or whitespace-only. The authorization round-trip is the only thing
skipped. The branch is taken only when the client is
disabled: a client that is enabled but has no address is an incomplete
configuration and refuses with 503 in both `Authorize` and `Check`, never the
no-round-trip path. `AUTH_REQUIRED` takes precedence: a client
that cannot authorize refuses with 503 regardless. Like
`AUTH_M2M_INVERSION_ENABLED`, the field can be pinned in code after
`NewAuthClient` instead of read from the environment.

**This is a development mode, and its trust boundary is not the usual one.** There is
no authorization round-trip on this path, so nothing external vouches for the caller.
Unless local verification is configured, with the `AUTH_JWT_VERIFY_CERT` /
`AUTH_JWT_VERIFY_CERT_PATH` PEM or a JWKS source wired through `WithKeySource`, the
published identity is **self-asserted**: anyone who can reach the route can present a
token naming any principal, and the library will publish it. The branch runs the same
claim extraction as the enabled path, so configuring keys does apply here: an invalid
signature is refused with 401 on this path too. With no keys configured the token is
parsed without verifying its signature. Do not rely on a principal published by an
unverified client on a network you do not control.

### Type guards

`RequireHuman()` and `RequireApplication()` are `fiber.Handler`s that gate a route on
the published `Principal.Type`. Mount them AFTER `Authorize`: a missing principal is
401 (nobody was identified) and a principal of the wrong kind is 403 (a known caller
of the wrong kind). Both **return** the corresponding Fiber error
(`fiber.ErrUnauthorized`, `fiber.ErrForbidden`) instead of writing a response
themselves. Under Fiber's default error handler the rendered bodies are unchanged —
plain-text `Unauthorized` and `Forbidden`, matching `Authorize` — while a service that
installs its own `ErrorHandler`, problem+json for instance, receives the error and
keeps its own response envelope.

`RequireApplication` is not `RequireM2M`. It performs no signature verification: the
authorization round-trip behind `Authorize` is the trust anchor, as it is for every
other route. `RequireM2M` stays a separate, self-verifying gate.

The two do not substitute for each other in a chain either. A route gated only by
`RequireM2M` publishes no `Principal`, because only `Authorize` publishes one, so a
`RequireApplication()` mounted behind it answers 401 for every caller, valid M2M token
included. Mount `Authorize` first whenever a type guard follows.

```go
f.Post("/v1/emissions/:id/approve",
    auth.Authorize(applicationName, "emission", "approve"),
    authMiddleware.RequireHuman(),      // 403 for a machine caller
    emissionHandler.Approve)

f.Post("/v1/operations/:id/resolution",
    auth.Authorize(applicationName, "operation", "resolve"),
    authMiddleware.RequireApplication(), // 403 for a human caller
    operationHandler.Resolve)
```

### Authorization outside the chain

When the resource or action is only known inside the handler, `Check` runs the same
decision the middleware would, with the same derivation, decision cache, breaker and
fail-closed rules:

```go
func (auth *AuthClient) Check(ctx context.Context, product, resource, action, accessToken, clientIP string) (bool, int, error)
```

It returns:

* `(true, 200, nil)` when authorized;
* `(false, 403, nil)` on a plain authoritative denial from the authorization service —
  a plain deny is an answer, not a failure;
* `(false, status, err)` when the authorization service refuses the caller — any
  `4xx` except `400`, `408`, `422` and `429` — at that status, carrying the reason
  it wrote;
* `(false, 401, err)` on a local token failure: a missing or invalid token, an
  unsupported token type, an `owner` or `sub` claim that is missing, empty or
  whitespace-only;
* `(false, 503, err)` whenever the authorization service is unavailable: a connection
  refused or other transport error, retries exhausted, or an open breaker. A client
  with `AUTH_REQUIRED` set that cannot authorize answers the same way, without
  evaluating the token.

The unavailable result stays fail-closed — never authorized — but remains
distinguishable from an authoritative denial, including when `AUTH_RETRY_MAX` or
`AUTH_BREAKER_ENABLED` is set. `Check` publishes no principal: the caller already
holds the one `Authorize` published.

`clientIP` is **caller-supplied** and reaches the authorization decision as-is, where
it feeds the per-tenant IP allowlist described in
[Client IP forwarding](#-client-ip-forwarding). Pass it empty, in which case it is
omitted from the request body exactly as on the middleware path, or pass a value you
resolved yourself through your own trusted-proxy configuration. Never pass Fiber's
`c.IP()` raw: under a misconfigured proxy chain that value is the attacker-chosen
`X-Forwarded-For` header, which lets a caller pick the address the allowlist matches
it against.

`Authorize` answers the same `503 Service Unavailable` on the wire for the same
outage (see the refusal paragraph under **How It Works** above), so a rail's alarms
can key on 503 across both surfaces.

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

## 🎯 Scoped access (declaring which instance a route addresses)

By default an authorization question says WHAT is being done — a resource and an
action. A credential that is allowed to do that on *some* instances and not others
needs the question to also say WHERE: which organization, which ledger. Only the
route knows where those identifiers sit in its own request, so the route declares
it.

```go
scope := authMiddleware.RequireScope("midaz",
    authMiddleware.Dim("organizationId", authMiddleware.FromPath).At("organization_id"),
    authMiddleware.Dim("ledgerId", authMiddleware.FromPath).At("ledger_id"),
)

f.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts",
    auth.Authorize("midaz", "accounts", "get", scope),
    accountHandler.GetAccounts)
```

* `Dim(name, source)` names the field the authorization service knows the
  dimension by, and where to read it: `FromPath`, `FromQuery`, `FromHeader`,
  `FromBody` or `FromForm` (see [Where a dimension is read](#where-a-dimension-is-read)).
  The request key defaults to the name; use `At("...")` when the route calls it
  something else, and `Optional()` when a request may leave it out.
* The values are read **only for a partner-bound credential** (a token carrying
  a `partner` claim) and sent as an additional `attributes` object on
  `POST /v1/authorize`. **Every other credential sends exactly the bytes it sends
  today**, on every route — the member is omitted, not sent empty — and its
  request is never read for a scope, so adopting this changes nothing for it.
* The accepted field names are the authorization service's, per product. Sending
  a name it does not know for that product matches nothing, and a dimension
  nobody matches never denies — which is why a declaration whose product does not
  match the route's product is refused rather than forwarded.

A partner-bound request that names no dimension — a route whose declaration or
manifest gives it none (a service whose manifest scope is not wired gives every
route none), or one whose dimensions are all optional and all left out — is still
asked, without the `attributes` member. The authorization service decides it by
the partner's own scope for the product: a partner with no scope restriction on
the product is allowed, and a partner restricted on a dimension the request does
not name is denied. The middleware answers what the service answers.

One refusal is deliberate and answers **403** before any call is made: a
required dimension the request carries no value for (header or query parameter
absent, empty path parameter). An identifier with no value cannot be matched, and
sending it absent would quietly ask a question the route did not promise.

A partner-bound request that carries a dimension malformed — an empty value, an
empty element of a list — or names different values for one dimension in two
places is answered **400** naming where, also before any call.

The scope is decided **on the way in only**, from what the request carries: the
path, the query, headers, a urlencoded form and the JSON body. Nothing is looked
up and the response is not inspected; the handler and its queries are the
product's, unchanged.

Inside the handler, `ScopeFromContext` returns what was resolved, for the checks a
route declaration cannot reach — a scope that has to be applied to the request
body, for example. It is present only for a partner-bound credential, so "no
scope" can never be read as "a partner with no restriction". The partner is also
recorded in `c.Locals("partner")` for the service's request log.

```go
if scope, ok := authMiddleware.ScopeFromContext(c.Context()); ok {
    // scope.Partner    -> "acme/partner-id"
    // scope.Attributes -> map[string]string{"organizationId": "...", "ledgerId": "..."}
}
```

### Deriving the scope from the manifest

A product that declares a `scope` section in its declaration manifest
(`permissions.yaml`) does not need to repeat it on every route:

```yaml
scope:
  dimensions:            # tree order: first = top of the funnel
    - { name: organizationId, from: path, param: organization_id, required: true,  collection: organizations, label: "Organization" }
    - { name: ledgerId,       from: path, param: ledger_id,       multi: true,     collection: ledgers,       label: "Ledger" }
    - { name: portfolioId,    from: header, param: X-Portfolio-Id,               collection: portfolios,    label: "Portfolio" }
```

A product that builds its declaration publisher with the client its routes use
needs nothing else: `declaration.New` wires the manifest's scope into the
`*middleware.AuthClient` it is given as `Auth`.

```go
auth := authMiddleware.NewAuthClient(authHost, authEnabled, logger)

pub, err := declaration.New(declaration.Config{Auth: auth, Manifest: embeddedManifest /* , ... */})
if err != nil {
    return err
}

f.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts",
    auth.Authorize("midaz", "accounts", "get"), // no RequireScope
    accountHandler.GetAccounts)
```

`declaration.New` also registers the scope process-wide under the manifest's
`service`. A route that authorizes that product with a different client, one
with no scope of its own for the product, uses the registered scope, so a
product whose publisher and routes are built with separate clients needs
nothing else either. A client with a scope of its own for the product keeps it.

Any other client takes it with `declaration.WireScope(auth, embeddedManifest)`.

* The order does not matter: a route works out its scope on its **first
  request**, not when it is registered, and again after every later wiring. A
  route registered before the publisher is built derives from the manifest as
  one registered after.
* A service that never builds a publisher (its declaration switched off) has no
  scope: every partner-bound request is asked without attributes, and nothing
  changes for any other credential.
* The scope is registered under the manifest's `service`, which must be the
  product the routes pass to `Authorize`. Routes of other products are untouched.
* A `from: path` dimension applies to a route when one **whole** path segment is
  `:<param>` — `:organization_id`, not a literal `organization_id`, not
  `:organization_id.json`. Applied dimensions are sent in manifest order, as the
  same `attributes` an explicit declaration sends.
* A `from: query` or `from: header` dimension applies to **every** route of the
  product, because a route path cannot say whether a request carries it: it is
  sent when the request carries it and left out when it does not. `param` is the
  query parameter or the header name.
* A request that ends up naming none of the dimensions behaves as on a route that
  declares nothing (a partner-bound credential is asked without attributes).
* An explicit `RequireScope` still works and wins, but may only name dimensions
  the manifest declares; one that names another is refused on every request and
  logged at ERROR on the route's first request.
* Validation: `from` must be `path`, `query` or `header`; `name`, `param` and
  `collection` are required; names are unique, and so is each `param` within its
  `from` (header names compared without regard to letter case); a `path` param is
  a bare parameter name, a `header` param a valid header name, a `query` param
  has no whitespace or reserved characters; `label` is optional.
* `from` and `param` are published and hashed with the rest of the catalog:
  moving a dimension from the path to a header is a change the access manager
  receives.

#### Authorizing in middleware (`Use`, groups, mounted apps)

A handler mounted with `Use` — on the app, on a group, or inside a mounted
sub-app — does not see the route a request is for: Fiber reports the **mount
prefix** as its route and reads no path parameter past it. `Authorize` then
resolves the request **itself**, with no product code:

```go
app.Use("/v1/organizations", auth.Authorize("midaz", "ledgers", "get"))
app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", handler)
// a partner request to /v1/organizations/org-1/ledgers/led-1 sends
// {"organizationId":"org-1","ledgerId":"led-1"}, as on the route itself
```

* The request's method and path are matched against every route the app
  registers (`Use` mounts aside) and every `scope.routes` entry of the manifest.
  The route that matches takes its scope from the manifest exactly as if the
  handler were on it, and its path parameters are read from the match.
* The **most specific** route wins, compared segment by segment from the left:
  a literal over a parameter, a parameter over an optional one, an optional one
  over a wildcard. Two routes equally specific under different paths
  (`/x/:organization_id` and `/x/:org`) leave the request **unresolved**.
* Two `scope.routes` entries of one method that are the same route under other
  parameter names are a manifest defect, refused when the manifest is wired.
* A partner-bound request that resolves to no single route — none matches, or
  two tie — is refused **403 before the round-trip**: its scope cannot be read.
  Every other credential is decided exactly as before, down to the bytes on the
  wire.
* Nothing changes for a handler on its own route (`app.Get(path, auth.Authorize(...), h)`),
  nor for a product with no scope catalog and no `RequireScope`.

#### Confining related collections (`covers`)

A dimension's `collection` is where its instances live. A partner scoped on the
dimension is confined when a request does not name it and the request's resource
is that collection. When other collections hold items that belong to the
dimension's instances, list them under `covers` so a request against them that
does not name the dimension is confined the same way:

```yaml
scope:
  dimensions:
    - { name: organizationId, from: path, param: organization_id, required: true, collection: organizations }
    - name: accountId
      from: path
      param: account_id
      multi: true
      collection: accounts
      covers: [balances, operations]   # items that belong to an account
```

* `covers` is optional. The authorization service enforces it; this library
  validates it, publishes it (also on a scope-only publication) and includes it
  in the manifest hash, so a change to `covers` alone is republished.
* Entries must be non-empty, unique within the dimension and different from the
  dimension's own `collection`; collections are compared trimmed and
  case-insensitively.
* The order of the entries is content, like the order of the dimensions.
* A manifest without `covers` publishes the same body and hash as before.

#### Declaring the hierarchy (`parent`)

The order of the dimensions does not say which one holds which. Name, on a
dimension, the dimension whose instances hold its own:

```yaml
scope:
  dimensions:
    - { name: organizationId, from: path,   param: organization_id, required: true, collection: organizations }
    - { name: ledgerId,       from: path,   param: ledger_id,       collection: ledgers,    parent: organizationId }
    - { name: portfolioId,    from: header, param: X-Portfolio-Id,  collection: portfolios, parent: ledgerId }
    - { name: accountId,      from: path,   param: account_id,      collection: accounts,   parent: ledgerId }
```

* `parent` is optional. A dimension without it is a root.
* It must name another declared dimension, and following parents from any
  dimension must end at a root: a dimension naming itself, an undeclared
  dimension, or a cycle fails validation.
* A dimension's depth is 1 for a root and its parent's depth plus 1 otherwise:
  above, `organizationId` is 1, `ledgerId` 2, and `portfolioId` and `accountId`
  are both 3 — siblings, neither narrower than the other.
* It is published (also on a scope-only publication) as the dimension's last
  member, after `covers` and `label`, and included in the manifest hash, so a
  change to `parent` alone is republished. A manifest without `parent`
  publishes the same body and hash as before.

### Where a dimension is read

Every dimension is read from one of five places, the same for an explicit
`RequireScope` and for the manifest:

| Source | `from:` | Key (`param` / `field`) | Several values | Catalog | `scope.routes` |
|---|---|---|---|---|---|
| `FromPath` | `path` | path parameter, without `:` | never — one segment is one value | yes | no (derived from the path) |
| `FromQuery` | `query` | query parameter | yes | yes | yes |
| `FromHeader` | `header` | header name, any letter case | yes | yes | yes |
| `FromBody` | `body` | path of keys in the JSON body | one per array element | no | yes |
| `FromForm` | `form` | urlencoded form field | yes | no | yes |

**Several values.** A query parameter, header or form field repeated, or a value
listing several separated by `,`, names every one of them: `?accountId=a&accountId=b`,
`?accountId=a,b` and `?accountId=a, b` all name `a` and `b`; so do two
`X-Account-Id` header lines, or one `X-Account-Id: a, b`. Spaces around an element
are trimmed and a value named twice is asked once. **Each value is its own
question and every one must be allowed**; when several dimensions name several
values, every combination is asked. An empty value or empty element (`?accountId=`,
`?accountId=a,,b`, `a,`) is refused with **400** naming the parameter. At most 100
distinct sets per request; more is refused with 400. A path segment is never
split: `/organizations/a,b` is the single value `a,b`.

**Optional.** A route dimension declared optional (`optional: true` under
`scope.routes`, `Dim(...).Optional()` in code) may be left out: when the request
does not carry it — a query parameter, header or form field absent, a body key on
its path absent or `null` — the question is asked **without that dimension**. A
value that is there must still be a non-empty string, or the request is refused
with 400 naming it. A dimension not declared optional keeps refusing absence:
403 for the path, query and headers, 400 for the body and the form. A catalog
dimension read from the query or a header is always optional, as described above.

**One dimension, several places.** A dimension may be read from more than one
place on the same request — the path and the query, a header and the body. Every
place that carries it must name **the same set of values** (in any order). When
they disagree the request is refused with **400 naming both places**, with no
authorization call and no handler call: the handler may act on either value, and
no single question checks both. A place that does not carry the value is not a
disagreement. For the body, every body value must be one the other place names,
and every value the other place names must appear in the body; a body element
that leaves an optional field out is asked with the other place's value. Reading
one dimension twice from the same place (the same header in two spellings, the
same body field twice) is a misdeclaration and refuses every request on the
route. Two **distinct** body fields are not the same place: see
[several fields of one body](#one-dimension-from-several-body-fields).

### Reading dimensions from the request body

Some routes carry the instance they address in the JSON body, not the path — for
example `POST /v1/transfers` with `{"organizationId": "...", "items": [{"ledgerId": "..."}]}`.
Declare those per route under `scope.routes`, since the same dimension comes from
the path on other routes:

```yaml
scope:
  dimensions: [ ... ]    # the catalog, unchanged
  routes:
    - method: POST
      path: /v1/transfers            # full registered path, group prefix included
      dimensions:
        - { name: organizationId, from: body, field: organizationId }
        - { name: ledgerId,       from: body, field: "items[].ledgerId" }
        - { name: portfolioId,    from: query, field: portfolioId, optional: true }
```

* `field` is a path of object keys separated by `.`; `key[]` is an array whose
  every element is read (`transactions[].legs[].ledgerId` crosses two). The last
  key holds a string — or, ending in `[]`, an array of strings
  (`accountTarget.ids[]`), every string being one value.
* **Every value must be inside the scope.** Each array element is one question to
  the authorization service (repeated sets are asked once), and the request is
  refused when any one is denied. Fields under the same element travel together;
  a field of an enclosing element (or of the top level) joins every question of
  the elements nested in it. A dimension may be read from more than one array
  (`debits[].ledgerId` and `credits[].ledgerId`), or from several fields of one
  body (see below), but each question must carry every dimension the route
  reads from the body. At most 100 distinct sets per request.
* The route still derives the dimensions its path carries. A dimension it also
  reads from the body must name the same values in both (see above).
* An optional body field may be absent or `null`; when the array an optional
  field sits in is absent or `null` and every field below it is optional, those
  fields are left out together. A present array must still be a non-empty array.
  With every body field optional, an empty body names none of them.
* **An array of strings** (`field: "accountTarget.ids[]"`):
  * every element is one value, its own question; an element that is empty or
    not a string is answered **400 naming the element** (`accountTarget.ids[1]`);
  * `optional` applies to the array as a whole: absent or `null`, the dimension
    is absent from the question;
  * an empty array (`[]`) names no value, with or without `optional`: the
    questions are asked without the dimension, and every other dimension the
    request names is still asked. A request left naming no dimension at all is
    asked without attributes, as on a route that declares nothing;
  * inside an array of objects (`targets[].ids[]`), each element's strings are
    asked with that element's other fields;
  * no other field may read inside its elements (`accountTarget.ids[].x`): the
    route fails at `WireScope`.
* The body is read **only for a partner-bound credential**, like the rest of the
  scope. Every other caller is decided as before: one authorization call without
  attributes, and the body left to the handler.
* For a partner-bound credential, a body that is not JSON, a field that is
  missing, empty or not a string, an array that is missing or empty, or a key
  repeated in another letter case is answered **400 naming the field**, with no
  authorization call and no handler call. The handler reads the body untouched.
* All the questions of one request share one timeout (`AUTH_TIMEOUT`), the
  token is verified once, and the first denial ends the request.
* Validation when the manifest is wired (`declaration.New` or `WireScope`):
  `from` must be `body`, `form`, `query` or `header`, `field` is
  required and valid for its `from`, `name` must be a catalog
  dimension, routes are unique by method and path, a route reads its body as
  JSON or as a form but not both, and the fields must fit together; any error
  fails the boot.
* `scope.routes` is read by this library only: it is never published and is not
  part of `CanonicalHash`, so adding it — `optional` and every `from` included —
  changes neither.

#### One dimension from several body fields

One body may name two **different** instances of the same dimension — an
account to credit and the accounts of a target, say. Declare each field; they
are independent references, and every value of every field is asked:

```yaml
  routes:
    - method: POST
      path: /v1/organizations/:organization_id/maintenance
      dimensions:
        - { name: accountId, from: body, field: maintenanceCreditAccount }
        - { name: accountId, from: body, field: "accountTarget.aliases[]", optional: true }
```

`{"maintenanceCreditAccount": "acc-m", "accountTarget": {"aliases": ["acc-1", "acc-2"]}}`
asks three questions — `acc-m`, `acc-1` and `acc-2`, each with the
organization from the path — and is refused when any one is denied.

* **Union.** Each value of each field is its own question and every one must
  be allowed. A value named by two fields is asked once.
* **Each value keeps its own element.** A question about one field's value
  carries, for every other body dimension, the value read in that field's own
  element, else in the nearest element enclosing it — a field of the value's
  own element wins over one of the top level — and, when no field of the
  dimension encloses it, the value read in the element closest to it. Two fields of one element naming
  the same dimension (`legs[].accountId` and `legs[].counterpartyAccountId`)
  make two questions, each with the element's other fields. When two
  dimensions are each read by several fields of the same element, every
  combination of their values is asked.
* **Per field.** `optional` applies to each field on its own: an optional field
  left out adds no value and the other fields are still asked; a required one
  left out is refused with 400 naming it. When every field of the dimension is
  left out, the questions are asked without it.
* **Same rules as any body.** The questions of every field count together
  toward the cap of 100 distinct sets per request; over it, the request is
  refused with 400 before any call.
* **Another carrier still has to agree.** This is not the
  [several-places rule](#where-a-dimension-is-read): when the path, query, a
  header or a form also names the dimension, every body value of every field
  must be one that carrier names, and every value it names must appear in the
  body, or the request is refused with 400 naming both places.
* Reading the **same** field twice — the same path, in any letter case — is
  refused at `WireScope`.
* Without a manifest, `RequireScope(product, authMiddleware.Dim("ledgerId", authMiddleware.FromBody).At("items[].ledgerId"))`
  declares the same on one route — a body field is one more source of the same
  `Dim`, next to `FromPath`, `FromHeader` and `FromQuery`. `ScopeFromContext(...).Sets` lists every set
  that was authorized; `Attributes` keeps the identifiers all sets share.

### Reading dimensions from a form body

A route that receives an `application/x-www-form-urlencoded` body declares its
fields with `from: form`, the field name as `field`:

```yaml
  routes:
    - method: POST
      path: /v1/organizations/:organization_id/payments
      dimensions:
        - { name: ledgerId,  from: form, field: ledgerId }
        - { name: accountId, from: form, field: accountId, optional: true }
```

* Only a **urlencoded** body is read, parsed by the standard library parser. For
  a partner-bound credential, a body of any other type — `multipart/form-data`
  above all — or one the parser refuses is answered **400 naming the field**,
  whether or not the dimension is optional: it may carry the field where the
  scope cannot see it. An empty body names no field.
* The form follows the JSON body's rules: it is read only for a partner-bound
  credential; an absent field is refused with 400 unless optional; a present but
  empty value always is; a field may list several values; and a field naming a
  dimension that the path, query or a header also names must agree with it.
  Note that a handler reading a form value through a helper that also looks at
  the query string may see the query's value: declare the dimension from both
  places and a disagreement is refused.
* A route reads its body either as JSON (`from: body`) or as a form
  (`from: form`), never both. The catalog reads no body.

### Publishing the scope

**Publication.** The scope section is published to the access manager whenever
the product's auth is on, independently of the permission declaration switch.
With the permission declaration on, the full manifest (scope included) is
published as before. With it off, build the publisher anyway when auth is on and
set `ScopeOnly`, which sends only `service`, `version`, `scope`, `partners` and
the permissions' `levels` (see below):

```go
pub, err := declaration.New(declaration.Config{
    // ... same fields as today ...
    ScopeOnly: !declarationEnabled,
})
```

`WireFromEnv` does this by itself: with `IDP_DECLARATION_ENABLED` off and
`PLUGIN_AUTH_ENABLED=true` it publishes the scope alone. A manifest with neither
a `scope` section nor `partners: true` publishes nothing in that mode. A scope that cannot be published
(missing configuration, access manager down) is logged and never fails the boot.

### Opting in to partners (`partners`)

A product accepts partner-bound credentials only when its manifest says so:

```yaml
service: midaz
version: 4
partners: true
```

* `partners` is optional and defaults to `false`. The access manager grants a
  partner access only to products that opted in.
* It is published with the full manifest and with the scope alone
  (`ScopeOnly`), and is part of `CanonicalHash`, after the scope. `false` is
  omitted, so a manifest that does not opt in publishes the same bytes and
  hash as before.
* A manifest may opt in with no `scope` section, or with no organization or
  ledger dimension: its partners are then granted the product tenant-wide.
  Such a manifest still has something to publish in scope-only mode — the
  opt-in itself.

### Declaring the level of a resource (`level`)

A permission may say how wide one instance of its resource is, so the access
manager can refuse to grant a partner a write on a resource wider than the
partner's scope:

```yaml
permissions:
  - { resource: organizations, action: update, effect: allow, roles: [admin], level: tenant }
  - { resource: ledgers,       action: update, effect: allow, roles: [admin], level: organizationId }
  - { resource: accounts,      action: update, effect: allow, roles: [admin], level: ledgerId }
  - { resource: balances,      action: update, effect: allow, roles: [admin], level: accountId }
```

* `level` is `tenant` (the resource spans the whole tenant) or the `name` of a
  dimension of the manifest's `scope` catalog, spelled exactly. `tenant` is
  the only built-in keyword: every narrower level is a dimension the product
  declares itself. Anything else fails validation, at boot, naming the
  permission and the allowed values:

  ```text
  permissions[1]: level "organization" must be "tenant" or the name of a scope dimension declared in scope.dimensions (organizationId, ledgerId, accountId)
  ```
* It is optional, published with the permission, and part of `CanonicalHash`:
  changing it republishes the manifest. It is the last member of a permission
  on the wire and in the hash, and a permission without it serializes exactly
  as before.
* The scope-only publication (`ScopeOnly`) carries no permissions, so it
  carries the levels apart, as its last member: one `{resource, action, level}`
  entry per permission that declares a level, in declaration order, without
  roles or effect. For the manifest above:

  ```json
  "levels": [
    {"resource": "organizations", "action": "update", "level": "tenant"},
    {"resource": "ledgers", "action": "update", "level": "organizationId"},
    {"resource": "accounts", "action": "update", "level": "ledgerId"},
    {"resource": "balances", "action": "update", "level": "accountId"}
  ]
  ```

  `levels` is part of the scope-only `CanonicalHash`, as its last member, after
  `partners`; the version is left out as in the full hash. It is omitted when no
  permission declares a level, so such a manifest publishes the same scope-only
  bytes and hash as before. The full manifest never carries `levels`: each
  level is already inside its permission.
* The access manager enforces it; this library declares, validates and
  publishes it.

## 📡 Expected Authorization Service Response

The authorization service should return a JSON response in the following format:

```json
{
    "authorized": true,
    "timestamp": "2025-03-03T12:00:00Z"
}
```

A denial may name a reason, and the reason selects the status the caller is
answered with:

```json
{
    "authorized": false,
    "timestamp": "2025-03-03T12:00:00Z",
    "reason": "suspended"
}
```

* `suspended` and `expired` mean the credential itself is finished — widening a
  permission would not help, it has to be re-issued — so the middleware answers
  **401**. The refusal carries a code of its own, recoverable with `errors.As`
  as a `commons.Response`, so it is not mistaken for an invalid token:

  | Reason | Status | Code | Message |
  |---|---|---|---|
  | `suspended` | 401 | `AUT-1009` | the partner of this credential is suspended |
  | `expired` | 401 | `AUT-1010` | the partner of this credential is outside its validity period |

  A missing, invalid or expired token is still the plain 401 it has always been,
  with no code.
* `permission`, `scope`, an unknown reason, and no reason at all stay the **403**
  every denial has always been. Which axis failed is never told apart to the end
  caller: that would turn the field into an enumeration oracle over another
  credential's identifiers.

The field is optional and additive. A service that never publishes it produces
exactly the behavior this middleware had before the field existed.

## 🔒 gRPC usage

Secure a gRPC server with the unary interceptor using per-method policies. It reuses the same auth service and tracing used by the HTTP middleware.

```go
import (
    "context"
    "google.golang.org/grpc"
    "github.com/LerianStudio/lib-auth/v5/auth/middleware"
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
