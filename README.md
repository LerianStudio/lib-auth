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
# Authorize or AuthorizeHTTP is mounted on a client configured to call the
# authorization service (auth enabled and an address set), because those are the
# only paths in this library that resolve a caller IP. A token-only or gRPC-only client never
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
* On the Fiber and `net/http` paths, derives the caller's client IP from `TRUSTED_PROXIES` and the socket peer — not from Fiber's `c.IP()` or `c.IPs()` — and sends it as the optional `clientIp` field, omitting it when no caller IP is attributable (see [Client IP forwarding](#-client-ip-forwarding)).
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

### 🧪 Testing with an authenticated principal

Package `auth/authtest` lets a service write an end-to-end test of a route that
requires a principal without contacting the authorization service. **It is
test-only: never import it from production wiring.** Every entry point takes a
`testing.TB`, there is no global switch, and lib-auth's own guard test fails if
any non-test file in the module imports it.

Pick the helper by what the test exercises:

* **The handler, not the middleware.** `authtest.Fiber(t, p)` and
  `authtest.HTTP(t, p)` publish `p` exactly as `Authorize` and `AuthorizeHTTP` do;
  mount them where those would be. `authtest.WithPrincipal(t, ctx, p)` does the
  same on a bare context. `RequireHuman`, `RequireApplication` and
  `PrincipalFromContext` behind them see an identified caller.
* **The real `Authorize` chain.** `authtest.NewIssuer(t, iss)` generates an RSA
  key inside the test process and signs RS256 tokens with it. Wire its key with
  `client.WithKeySource(issuer.KeySource())`, or set
  `t.Setenv("AUTH_JWT_VERIFY_CERT", issuer.PublicKeyPEM())` before
  `NewAuthClient`, and its tokens pass `Authorize` with signature verification
  on. A token from any other key is refused with 401. This is the required path
  when the service pins `PrincipalRequiredWhenDisabled`.

`Authorize` never reads a principal already on the request context. Whenever it
can identify a caller (an enabled client, or `PrincipalRequiredWhenDisabled`), it
refuses a request without a valid bearer token before the handler runs, and
publishes the principal it derived from that token over anything the context
held. A context-only helper therefore cannot reach a handler mounted behind the
real `Authorize`; use `Issuer` there. This library has no switch that makes
`Authorize` accept an injected principal, by design.

```go
p := authtest.User("acme-org", "user-1") // or authtest.App("acme-org/settlement-bot")
p.TenantID = "tenant-a"

// Handler test.
app.Post("/v1/emissions/:id/approve",
    authtest.Fiber(t, p),
    authMiddleware.RequireHuman(),
    emissionHandler.Approve)

// Real Authorize, auth off, bearer still required (nothing is dialled).
issuer := authtest.NewIssuer(t, "") // set iss to the client's AUTH_JWT_ISSUER, if any
client := authMiddleware.NewAuthClient("", false, nil)
client.PrincipalRequiredWhenDisabled = true
client.M2MInversionEnabled = true // needed for application principals on this path
client.WithKeySource(issuer.KeySource())

req.Header.Set("Authorization", "Bearer "+issuer.Token(t, p))
```

A principal that `PrincipalFromContext` would report as absent (a blank `Sub`, a
`normal-user` without `Owner`, a `Subject` inconsistent with `Owner` and `Sub`, an
unknown `Type`) fails the test when the helper is called, on the test goroutine.
The handlers built by `Fiber` and `HTTP` never touch `t` while serving and are
safe for concurrent requests. Tokens expire five minutes after they are issued.

`authtest` does not fake the authorization service: testing a denial (403) or an
outage (503) still needs a local stand-in for it.

To keep `authtest` out of a service's production code, add a depguard rule that
applies to non-test files only:

```yaml
linters:
  settings:
    depguard:
      rules:
        no-authtest-in-production:
          files:
            - "!$test"
          deny:
            - pkg: github.com/LerianStudio/lib-auth/v5/auth/authtest
              desc: test-only; it publishes a principal without authorization
```

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

The `clientIp` field is optional *in the schema* — the request is well-formed without it — but omitting it is not free: the authorization service uses it to enforce the per-tenant IP allowlist, and for a protected tenant an omitted address can be denied. On the Fiber and `net/http` paths the middleware derives it from `TRUSTED_PROXIES` (see below) and omits it only when no caller IP can be attributed; see [Client IP forwarding](#-client-ip-forwarding) for what follows from that.

## 🌐 Client IP forwarding

On the Fiber and `net/http` paths, `Authorize` and `AuthorizeHTTP` send `clientIp` to `POST /v1/authorize`, enabling the access manager to enforce a per-tenant IP allowlist downstream.

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
  dimension by, and where to read it: `FromPath`, `FromHeader` or `FromQuery`.
  The request key defaults to the name; use `At("...")` when the route calls it
  something else.
* The resolved values are sent as an additional `attributes` object on
  `POST /v1/authorize`. **A route that declares nothing sends exactly the bytes it
  sends today** — the member is omitted, not sent empty — so adopting this is
  route by route, with no flag day.
* The accepted field names are the authorization service's, per product. Sending
  a name it does not know for that product matches nothing, and a dimension
  nobody matches never denies — which is why a declaration whose product does not
  match the route's product is refused rather than forwarded.

Two refusals are deliberate and both answer **403**, before any call is made:

1. A credential bound to a partner reaching a route that declares no dimension.
   Such a credential is only ever allowed to reach *some* instances, and a route
   that cannot say which instance the request points at leaves the "where" with
   nothing to decide on.
2. A declared dimension the request carries no value for (header absent, empty
   path parameter). An identifier with no value cannot be matched, and sending it
   absent would quietly ask a question the route did not promise.

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
```

```go
auth := authMiddleware.NewAuthClient(authHost, authEnabled, logger)
if err := declaration.WireScope(auth, embeddedManifest); err != nil { // before registering routes
    return err
}

f.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts",
    auth.Authorize("midaz", "accounts", "get"), // no RequireScope
    accountHandler.GetAccounts)
```

* The scope is registered under the manifest's `service`, which must be the
  product the routes pass to `Authorize`. Routes of other products are untouched.
* A dimension applies to a route when one **whole** path segment is
  `:<param>` — `:organization_id`, not a literal `organization_id`, not
  `:organization_id.json`. Applied dimensions are sent in manifest order, as the
  same `attributes` an explicit declaration sends.
* A route whose path carries none of the parameters behaves as a route that
  declares nothing (a partner-bound credential is refused with 403).
* An explicit `RequireScope` still works and wins, but may only name dimensions
  the manifest declares; one that names another is refused on every request and
  logged at ERROR when the route is registered.
* Validation: `from` must be `path`; `name`, `param` and `collection` are
  required and names and params are unique; `label` is optional.

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
```

* `field` is a path of object keys separated by `.`; `key[]` is an array whose
  every element is read (`transactions[].legs[].ledgerId` crosses two). The last
  key holds a string.
* **Every value must be inside the scope.** Each array element is one question to
  the authorization service (repeated sets are asked once), and the request is
  refused when any one is denied. Fields under the same element travel together;
  a field of an enclosing element (or of the top level) joins every question of
  the elements nested in it. A dimension may be read from more than one array
  (`debits[].ledgerId` and `credits[].ledgerId`), but each question must carry
  every dimension the route reads from the body. At most 100 distinct sets per
  request.
* The route still derives the dimensions its path carries; one dimension cannot
  come from both.
* The body is read **only for a partner-bound credential**. Every other caller is
  decided as before: one authorization call carrying only the dimensions read
  from the path, headers or query, and the body left to the handler.
* For a partner-bound credential, a body that is not JSON, a field that is
  missing, empty or not a string, an array that is missing or empty, or a key
  repeated in another letter case is answered **400 naming the field**, with no
  authorization call and no handler call. The handler reads the body untouched.
* All the questions of one request share one timeout (`AUTH_TIMEOUT`), the
  token is verified once, and the first denial ends the request.
* Validation at `WireScope`: `from` must be `body`, `field` is required, `name`
  must be a catalog dimension, routes are unique by method and path, and the
  fields must fit together; any error fails the boot.
* `scope.routes` is read by this library only: it is never published and is not
  part of `CanonicalHash`, so adding it changes neither.
* Without a manifest, `RequireScope(product, authMiddleware.Dim("ledgerId", authMiddleware.FromBody).At("items[].ledgerId"))`
  declares the same on one route — a body field is one more source of the same
  `Dim`, next to `FromPath`, `FromHeader` and `FromQuery`. `ScopeFromContext(...).Sets` lists every set
  that was authorized; `Attributes` keeps the identifiers all sets share.

**Publication.** The scope section is published to the access manager whenever
the product's auth is on, independently of the permission declaration switch.
With the permission declaration on, the full manifest (scope included) is
published as before. With it off, build the publisher anyway when auth is on and
set `ScopeOnly`, which sends only `service`, `version` and `scope`:

```go
pub, err := declaration.New(declaration.Config{
    // ... same fields as today ...
    ScopeOnly: !declarationEnabled,
})
```

`WireFromEnv` does this by itself: with `IDP_DECLARATION_ENABLED` off and
`PLUGIN_AUTH_ENABLED=true` it publishes the scope alone. A manifest without a
`scope` section publishes nothing in that mode. A scope that cannot be published
(missing configuration, access manager down) is logged and never fails the boot.

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
  **401**.
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

## 🧩 net/http usage

For a service that does not run Fiber, like a plain `net/http` sidecar, mount `AuthorizeHTTP`. It runs the same authorization flow as `Authorize` and publishes the same `Principal` and `RequestScope`. It reads the same `AUTH_*` and `TRUSTED_PROXIES` settings. You do not need to parse the bearer token yourself.

```go
import (
    "errors"
    "net/http"

    "github.com/LerianStudio/lib-auth/v5/auth/middleware"
)

authClient := middleware.NewAuthClient(cfg.Address, cfg.Enabled, logger).
    // Optional: render refusals in your own envelope. Set it before serving.
    WithHTTPErrorHandler(func(w http.ResponseWriter, r *http.Request, err error) {
        var refusal *middleware.RefusalError
        if errors.As(err, &refusal) {
            writeProblem(w, refusal.Status, refusal.Message) // your renderer
        }
    })

mux := http.NewServeMux()
mux.Handle("GET /v1/organizations/{org}/accounts",
    authClient.AuthorizeHTTP("midaz", "accounts", "get",
        middleware.RequireScope("midaz", middleware.Dim("organizationId", middleware.FromPath).At("org")),
    )(accountsHandler))

// Inside accountsHandler:
//   p, ok := middleware.PrincipalFromContext(r.Context())
```

### Bearer rules

`AuthorizeHTTP` reads the credential through `auth/bearer`, a small package that uses only the standard library. You can also call `bearer.FromRequest` or `bearer.Parse` on their own. A request is accepted only when:

- It has exactly one `Authorization` header. Two header lines are refused.
- The header is `Bearer <token>`. The scheme is case-insensitive and one or more spaces may follow it. A bare token, another scheme, or two tokens are refused.
- The token is at most `bearer.MaxTokenBytes` (8 KiB). The size is checked before any decoding.
- The header has no control bytes (including TAB, CR and LF) and no bytes outside printable ASCII.
- The token has exactly three non-empty segments separated by dots, each unpadded base64url. `=` padding and the standard `+` and `/` alphabet are refused.

A missing or blank header answers `401 Missing Token`. Any other refusal answers `401 Unauthorized`. Neither calls the Access Manager.

An empty signature segment is refused too, so an unsigned (`alg=none`) token never leaves the service. This is stricter than the copy the br-sfn `slc` mqbridge carried, which accepted an empty signature and a bare token.

### What differs from `Authorize`

- **`FromPath` reads `r.PathValue`,** which only the Go 1.22+ `http.ServeMux` fills in from a `{name}` pattern. Under another router a path dimension resolves empty, and the request is refused with 403. It is never sent without the dimension. `FromHeader` and `FromQuery` work under any router.
- **Refusals go to an `HTTPErrorHandler`,** not to a returned error. `err` is always a `*middleware.RefusalError`, which carries `Status`, `Message`, and `Response`. `Response` is the Access Manager's decoded refusal body, when it sent one. `errors.As(err, &commons.Response{})` also recovers that body, as on the Fiber path. The handler must write the response. The default writes `Message` as plain text with `Status`, the same way Fiber's default handler renders the `*fiber.Error` from `Authorize`.
- **The client IP** comes from `r.RemoteAddr` and every `X-Forwarded-For` line, read in order and walked against `TRUSTED_PROXIES` exactly as on the Fiber path. If `RemoteAddr` is not an address and port, as behind a unix socket, or its address is unspecified (`0.0.0.0`, `::`), no IP is forwarded; the Fiber path forwards none either for a connection with no IP peer, which fasthttp reports as `0.0.0.0`.
- **A nil `*AuthClient`** passes every request through, as `Authorize` does. A nil `next` handler answers 500 instead of panicking.

Everything else is shared:

- `AUTH_REQUIRED`
- `AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED`
- M2M inversion (`AUTH_M2M_INVERSION_ENABLED`) and product forwarding
- the decision cache, retry, and breaker
- local JWT verification
- the 401/403/503 mapping

The Fiber `Authorize` and the gRPC interceptors keep their existing, more lenient token extraction. `Authorize`, for example, still accepts a bare token without the `Bearer` prefix. Moving them onto `auth/bearer` would refuse requests existing consumers send today, so that change would be a separate, opt-in step.

## 📣 Permission declaration publisher

`auth/declaration` publishes a plugin's own permissions manifest to the identity service at boot. It sends `PUT {IDP_HOST}/v1/declarations/{slug}` with an M2M bearer. Most plugins wire it in one line from the fixed `IDP_*` environment contract:

```go
stop, err := declaration.WireFromEnv(ctx, declaration.WireInput{
    Slug:     "plugin-fees",
    Manifest: permissionsYAML, // //go:embed permissions.yaml
    Logger:   logger,
    // Optional: your own client, e.g. for a proxy, a custom CA or mTLS.
    HTTPClient: myHTTPClient,
})
defer stop()
```

`declaration.Config.HTTPClient` is the same option when you build the publisher with `declaration.New`. If you leave it nil, the publisher uses a client with a 30s timeout.

### Redirects are never followed

The PUT carries the M2M credential and the manifest, so the publisher never follows a redirect. It refuses a redirect the same way the auth client refuses one on the token path. Following one would:

- replay the credential and the manifest to the host in `Location` on 307 and 308. Go keeps the `Authorization` header on a same-host, subdomain or https-to-http hop.
- turn the PUT into a GET on 301, 302 and 303. The redirect target's 200 would then be logged as "declaration published" when nothing was stored.

Any 3xx from the identity service fails the publish with a deterministic `*declaration.PublishError` that carries the 3xx status. It is not retried and not cached, and it is logged at ERROR. The log never includes the `Location`. The fix is configuration: point `IDP_HOST` at the identity service itself, not at a hop that redirects.

An injected client cannot turn redirect-following back on. The publisher takes a shallow copy of your client, so your client is never changed, and sets the copy's redirect policy to refuse. If your client has no `Timeout`, the copy gets the 30s default, so a `FailFast` boot cannot hang. Minting the M2M token does not use this client. It goes through the auth client, which already refuses redirects.

## 🔐 Requiring https to the Access Manager

By default the library talks to whatever address you give it, `http` included. You can make it refuse anything but `https` for every outbound call it makes to the Access Manager and the identity provider. The requirement is opt-in, and existing callers are unaffected: `NewAuthClient` behaves exactly as before.

```go
// Your service decides the posture; the library reads no ENV_NAME for it.
requireHTTPS := !isDevelopment

authClient, err := middleware.NewAuthClientWithOptions(address, enabled, logger,
    middleware.WithRequireHTTPS(requireHTTPS))
if err != nil {
    return err // *endpoint.InsecureError: the address is not https
}

stop, err := declaration.WireFromEnv(ctx, declaration.WireInput{
    Slug:         "plugin-fees",
    Manifest:     manifest,
    Logger:       logger,
    RequireHTTPS: requireHTTPS,
})
```

With the requirement on, an address passes only when it is an absolute `https` URL with a host. `http` in any letter case is refused, loopback included, and so are a missing scheme, any other scheme, a missing host and an address that does not parse. The address is checked exactly as it will be dialled, without trimming.

| Outbound call | How you turn it on | What happens to a non-https address |
|---|---|---|
| Authorization client: health check at construction | `NewAuthClientWithOptions(..., WithRequireHTTPS(true))` | Construction fails before anything is dialled. An empty address is accepted, because it never dials. |
| Authorization: Fiber `Authorize`, `AuthorizeHTTP`, `Check`, gRPC unary and stream interceptors | Same option | `Address` is re-checked on every call, because it is an exported field. A changed address is answered `503` (gRPC `Unavailable`) without a call, a retry, a breaker failure or a cache write. |
| Token minting, `GetApplicationToken` | Same option | Returns the typed error before the request is built, so the client secret never travels over `http`. |
| Declaration publisher, `IdentityAddr` | `declaration.Config.RequireHTTPS` | `New` fails. It also refuses an `Auth` that declares it allows plaintext (an `AuthClient` built without the option). A `TokenMinter` that declares no posture is accepted, and its transport is your responsibility. |
| `WireFromEnv` | `WireInput.RequireHTTPS` | Fails before anything is dialled, naming `IDP_HOST` or `PLUGIN_AUTH_HOST` (alias `PLUGIN_AUTH_ADDRESS`). There is no environment variable for the requirement. |
| JWKS key source | `JWKSConfig.RequireHTTPS` | `NewJWKSKeySource` fails, loopback `http` included. Every redirect hop must be `https` too. Setting it together with `AllowInsecureURL` is a construction error. |
| JWKS key source attached to the authorization client | `WithRequireHTTPS(true)` on the client, plus `JWKSConfig.RequireHTTPS` on the source | The client never consults a source built without `JWKSConfig.RequireHTTPS`: attaching it with `WithKeySource` is logged at ERROR, and every authorization, the no-round-trip path included, is answered `503` (gRPC `Unavailable`) with the typed error. It cannot stop a source you built from fetching on its own, so build the source with the requirement too. A source that declares no posture, such as `StaticKeySource`, fetches nothing and is accepted. |

Every refusal is an `*endpoint.InsecureError` that matches `endpoint.ErrInsecure` with `errors.Is`. It carries the component that refused, the reason, the parsed scheme and the address with any userinfo password masked and the query and fragment dropped. The address is not echoed at all when a secret could hide in it: when it does not parse, when it has no `//` (Go reads `admin:pass@am.example` as scheme `admin` followed by plain text), or when its path contains `@`.

A redirect cannot downgrade an `https` address. The authorization client and the declaration publisher never follow a redirect, and the JWKS source checks every hop against the same rule.

## 🚧 Error Handling

The middleware captures and logs the following error types:

* Failure to create the request
* Failure to send the request
* Failure to read the response body
* Failure to deserialize the response JSON
* Errors from the authorization service (e.g., 401 Unauthorized, 403 Forbidden)

## 📧 Contact

For questions or support, contact us at: [contato@lerian.studio](mailto:contato@lerian.studio).
