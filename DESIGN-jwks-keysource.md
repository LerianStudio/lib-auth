# lib-auth: dynamic JWKS key-source for M2M verification (PAM card #3755)

**Status:** design FROZEN (unanimous 3-judge panel). Implement to spec; do NOT re-derive architecture.

## Problem
M2M JWT verification today pins a single build-time RSA public key (embedded PEM in
plugin-access-manager `pkg/casdoor/certificates/token_jwt_key.pem`). Casdoor regenerates
its keypair on reseed and **republishes under the SAME `kid` = `cert-built-in`** (kid is the
cert NAME, not a content hash). So:
- a captured PEM stops matching a fresh Casdoor → `401 token signature is invalid`;
- key rotation requires rebuild+redeploy.

## Goal
Verify against JWKS fetched dynamically from a configured issuer URL, while keeping
verification **fail-CLOSED** and availability **fail-OPEN** (serve-stale).

## Non-negotiable constraints
1. **verifyToken stays authoritative on algorithm.** Keep the existing
   `verification.go:verifyToken` pinning `RS256` + `exp` + `iss`. The JWKS lib
   (`github.com/MicahParks/jwkset`) is used ONLY to fetch+parse JWKS-JSON into
   `[]*rsa.PublicKey`. Do NOT delegate alg enforcement to keyfunc/jwkset.
2. **Additive only.** Existing `NewM2MAuthenticator(certificatePEM, expectedIssuer, enabled, logger)`
   keeps its signature and behavior (static single PEM). Add a NEW constructor for the
   key-source path. Static PEM stays the default. Minor version bump (~v3.5.0-beta).
3. **THE gotcha — refresh on signature failure.** Because kid is stable, refresh-on-unknown-kid
   never fires. On a signature-verification failure, force ONE JWKS refresh (single-flight) and
   retry verifyToken once. Plus a short background TTL refresh.
4. **Fail-open availability / fail-closed verification.** Serve keys ALWAYS from an in-memory
   cache. Never block a verify on the network. If the JWKS endpoint is down, serve the last
   good (stale) keys. A bad signature/alg/exp/iss is still a hard 401.
5. **Bootstrap seed + lazy fetch.** Cache is seeded at construction from a local bootstrap PEM
   (embedded/mounted) so the process boots and verifies even if the JWKS endpoint is unreachable
   at startup. First live fetch is lazy/async.
6. **Single-flight.** Concurrent refresh requests collapse to one in-flight fetch
   (`golang.org/x/sync/singleflight` or an equivalent guard already vendored — check go.sum;
   otherwise a mutex+inflight-flag).
7. **Consume over ClusterIP, TLS + cert-pin on the fetch.** The KeySource's HTTP client must
   support TLS with an optional pinned CA/cert (config-provided). Never hairpin the ingress.

## Topology (why a generic URL)
Only PAM's `auth` and `identity` components reach Casdoor. Downstream plugins cannot; they
already reach `plugin-access-manager-auth:4000`. So:
- `auth` + `identity` KeySource JWKS URL → Casdoor `/.well-known/jwks`.
- downstream plugins KeySource JWKS URL → auth's `/internal/idp-jwks-cache` (read-through cache).
Same KeySource code, different URL. The auth endpoint (built in PAM, separate task) re-serves
auth's cached keys as standard JWKS-JSON so downstream can parse with the same code path.

## API to add (lib-auth)

```go
// KeySource yields the current set of acceptable RSA verification keys.
// Keys() NEVER blocks on the network (serve-from-cache, serve-stale on failure).
// Refresh() forces a single-flight re-fetch; used on signature-verification failure.
// Close() stops any background refresher and releases resources; idempotent and safe
// to call on a source with no background goroutine (e.g. StaticKeySource).
type KeySource interface {
    Keys(ctx context.Context) []*rsa.PublicKey
    Refresh(ctx context.Context) error
    Close() error
}
```

- `StaticKeySource(pubKeys ...*rsa.PublicKey) KeySource` — wraps today's static behavior; Refresh is a no-op. (Lets the existing constructor internally become a StaticKeySource without behavior change — optional refactor, keep back-compat.)
- `NewJWKSKeySource(cfg JWKSConfig) (KeySource, error)` where JWKSConfig carries:
  - `URL string` (JWKS endpoint), `RefreshInterval time.Duration` (short TTL, e.g. 5m),
  - `BootstrapPEM []byte` (seed), `HTTPClient *http.Client` (TLS/cert-pin injected by caller),
  - `Logger`. Seeds cache from BootstrapPEM; starts background TTL refresh; lazy first live fetch.
  - `ForcedRefreshCooldown time.Duration` — minimum interval between two forced
    (signature-failure-triggered) upstream fetches; the refresh-amplification guard.
    Defaults to 15s when zero. Only the forced `Refresh` path is throttled; the
    background TTL loop is not.
  - `Ctx context.Context` — bounds the background refresh goroutine's lifecycle;
    cancelling it stops the background refresher (graceful shutdown / leak-free tests).
    Defaults to `context.Background()`. (`Close()` also stops it regardless.)
  - `AllowInsecureURL bool` — permit a non-HTTPS, non-loopback JWKS URL. The JWKS is
    the trust root for token verification, so plaintext is rejected by default
    (fail-closed). Loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) are always
    allowed without this flag. Set true ONLY for a deliberate case (e.g. a ClusterIP
    where a service mesh terminates mTLS out-of-band); doing so emits a loud WARN at
    construction and on each refresh.
- `NewM2MAuthenticatorWithKeySource(source KeySource, expectedIssuer string, enabled bool, logger *log.Logger) (*M2MAuthenticator, error)`
  - `M2MAuthenticator` gains a `source KeySource` field (nil ⇒ legacy static `publicKey` path).
  - `verify` becomes: `keys := source.Keys(ctx)` → `verifyToken(keys,...)`; if err is a
    **signature/keys** failure AND not yet retried → `source.Refresh(ctx)` → re-`Keys()` → retry once.
    exp/iss/type/sub failures are NOT retried (they aren't key-staleness).

## Reuse in the repo
- Existing `verifyToken` (verification.go:36), `parseRSAPublicKeys` (verification.go:180) for PEM→keys.
- Check `resilience.go` and `decisioncache.go` in `auth/middleware/` for existing single-flight /
  TTL-cache / retry helpers before adding new ones — prefer reusing them.
- jwkset v0.11.0 + keyfunc/v3 v3.8.0 are already in the local mod cache (offline build OK).
  Use jwkset to unmarshal the JWKS-JSON response and enumerate keys; type-assert `*rsa.PublicKey`.

## Observability (task 1.1.8, can be a follow-up but leave hooks)
Emit: `jwks_cache_age_seconds`, `jwks_unknown_kid_total`, `jwks_verify_fail_total`,
`jwks_refresh_total{result}`. Follow lib-observability conventions already used in this package.

## Tests (TDD — write first)
- static path unchanged (existing tests green).
- JWKS happy path: token signed by fetched key verifies.
- **gotcha**: cache holds OLD key, token signed by NEW key (same kid) → first verify fails →
  forced refresh pulls NEW key → retry verifies. Assert exactly ONE refresh, one retry.
- serve-stale: JWKS endpoint 500s → Keys() still returns last-good; a token from a still-valid
  cached key verifies (fail-open availability).
- fail-closed: bad alg (HS256/none), expired exp, wrong iss, empty sub, type!=application → 401/403,
  and NO refresh loop for non-key failures.
- single-flight: N concurrent Refresh() → 1 HTTP fetch.
- bootstrap seed: construct with endpoint unreachable → Keys() returns the seeded key immediately.
