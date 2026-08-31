package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LerianStudio/lib-auth/v3/auth/obs"
	observability "github.com/LerianStudio/lib-observability/v4"
	"github.com/LerianStudio/lib-observability/v4/metrics"
	obsruntime "github.com/LerianStudio/lib-observability/v4/runtime"
	"github.com/MicahParks/jwkset"
	"golang.org/x/sync/singleflight"
)

const (
	// defaultJWKSRefreshInterval is the short background TTL after which the JWKS
	// cache is proactively re-fetched. Kept small so a key rotation propagates
	// quickly; the forced refresh-on-signature-failure is the fast path, this is
	// the steady-state backstop.
	defaultJWKSRefreshInterval = 5 * time.Minute

	// defaultJWKSFetchTimeout bounds a single JWKS HTTP fetch when the caller does
	// not inject an HTTP client with its own timeout.
	defaultJWKSFetchTimeout = 10 * time.Second

	// maxJWKSResponseBytes caps the JWKS response read so a hostile or misbehaving
	// endpoint cannot exhaust memory. A JWKS with a handful of RSA keys is a few KB.
	maxJWKSResponseBytes = 1 << 20 // 1 MiB

	// maxJWKSKeys bounds the number of RSA keys accepted from a single JWKS. verifyToken
	// tries keys until one matches, so an oversized set multiplies per-token RSA work; a
	// real rotation-overlap JWKS carries at most a few keys. A JWKS exceeding this is
	// rejected as a defensive (DoS) guard.
	maxJWKSKeys = 32

	// maxJWKSRedirects caps redirect hops on a JWKS fetch. A custom CheckRedirect
	// REPLACES net/http's default 10-hop cap, so we must re-impose one: otherwise a
	// compromised endpoint could return policy-compliant https redirects in a loop
	// and tie up the fetch for the whole timeout (CWE-400). Matches the stdlib default.
	maxJWKSRedirects = 10

	// jwksRefreshFlightKey is the fixed single-flight key: all refreshes target the
	// same JWKS URL, so concurrent forced refreshes collapse onto one in-flight fetch.
	jwksRefreshFlightKey = "refresh"

	// jwksForcedFlightKey is the single-flight key for the cooldown-gated FORCED
	// refresh wrapper (Refresh). Distinct from jwksRefreshFlightKey so the nested
	// group.Do in refreshNow does not join — and deadlock on — its own caller.
	jwksForcedFlightKey = "forced-refresh"

	// defaultForcedRefreshCooldown is the minimum interval between two forced
	// (signature-failure-triggered) upstream JWKS fetches. It caps refresh
	// amplification: a stream of DISTINCT bad-signature tokens cannot drive one
	// upstream fetch per request (single-flight only collapses CONCURRENT calls, not
	// sequential ones). Within the window a forced Refresh serves stale and returns
	// nil without hitting upstream; verification still fails closed on the retry. The
	// background TTL loop is NOT throttled by this — only the forced path is.
	defaultForcedRefreshCooldown = 15 * time.Second
)

// KeySource yields the current set of acceptable RSA verification keys.
//
// Keys NEVER blocks on the network: it serves from an in-memory cache and, on a
// backend failure, serves the last-good (stale) keys — fail-OPEN on availability.
// Refresh is the FORCED re-fetch the M2M gate calls on a signature verification
// failure to pull a rotated key (the stable-kid Casdoor case, where
// refresh-on-unknown-kid never fires); it is single-flight AND rate-limited by a
// forced-refresh cooldown so a stream of bad tokens cannot amplify into one
// upstream fetch per request — within the cooldown it serves stale and returns nil.
// Close stops any background refresher and releases resources; it is idempotent and
// safe to call on a source with no background goroutine. Verification itself stays
// fail-CLOSED: a bad signature/alg/exp/iss is always rejected by verifyToken.
type KeySource interface {
	Keys(ctx context.Context) []*rsa.PublicKey
	Refresh(ctx context.Context) error
	Close() error
}

// staticKeySource wraps a fixed key set (today's build-time single-PEM behavior).
// Refresh is a no-op: there is no backend to re-fetch from.
type staticKeySource struct {
	keys []*rsa.PublicKey
}

// StaticKeySource returns a KeySource over a fixed set of RSA public keys. It
// preserves the legacy static-PEM behavior (optionally with rotation overlap) and
// its Refresh is a no-op.
func StaticKeySource(pubKeys ...*rsa.PublicKey) KeySource {
	return &staticKeySource{keys: pubKeys}
}

func (s *staticKeySource) Keys(_ context.Context) []*rsa.PublicKey { return s.keys }

func (s *staticKeySource) Refresh(_ context.Context) error { return nil }

func (s *staticKeySource) Close() error { return nil }

// JWKSConfig configures a dynamic JWKS-backed KeySource.
type JWKSConfig struct {
	// URL is the JWKS-JSON endpoint (e.g. Casdoor's /.well-known/jwks for PAM's
	// auth/identity, or auth's read-through /internal/idp-jwks-cache for downstream
	// plugins). Required.
	URL string

	// AllowInsecureURL permits a non-HTTPS, non-loopback JWKS URL. The JWKS is the
	// trust root for token verification, so plaintext is rejected by default. Set true
	// ONLY for a deliberate case — e.g. a ClusterIP where a service mesh terminates
	// mTLS out-of-band. Loopback hosts (localhost, 127.0.0.0/8, ::1) are always allowed
	// without this flag.
	AllowInsecureURL bool

	// RefreshInterval is the short background TTL for proactive re-fetch. Defaults
	// to defaultJWKSRefreshInterval when zero.
	RefreshInterval time.Duration

	// ForcedRefreshCooldown is the minimum interval between two forced
	// (signature-failure-triggered) upstream fetches — the refresh-amplification
	// guard. Defaults to defaultForcedRefreshCooldown (15s) when zero. Only the
	// forced Refresh path is throttled; the background TTL loop is not.
	ForcedRefreshCooldown time.Duration

	// BootstrapPEM seeds the cache at construction (embedded/mounted PEM) so the
	// process boots and verifies even if the JWKS endpoint is unreachable at
	// startup. One or more concatenated PEM blocks (rotation overlap supported).
	BootstrapPEM []byte

	// HTTPClient is the caller-injected client used for the fetch; inject TLS /
	// pinned-CA transport here (consume over ClusterIP, never hairpin the ingress).
	// Defaults to a client with defaultJWKSFetchTimeout when nil.
	HTTPClient *http.Client

	// Logger records refresh outcomes. Defaults to a no-op logger when nil.
	Logger obs.Logger

	// Ctx bounds the background refresh goroutine's lifecycle: cancelling it stops
	// the background refresher (used for graceful shutdown and to avoid leaking the
	// goroutine in tests). Defaults to context.Background(). NOTE: additive to the
	// frozen DESIGN field list — see the task report.
	Ctx context.Context
}

// jwksKeySource is an HTTP JWKS-backed KeySource with an in-memory cache, a short
// background TTL refresh, and single-flight forced refresh.
type jwksKeySource struct {
	url             string
	httpClient      *http.Client
	refreshInterval time.Duration
	forcedCooldown  time.Duration
	logger          obs.Logger

	// allowInsecure mirrors JWKSConfig.AllowInsecureURL. It is retained on the source
	// so the SAME transport policy validated at construction is re-applied to every
	// redirect hop in fetch — an https JWKS URL must not be bounced to a plaintext
	// non-loopback target whose response would then be cached as a trust root (CWE-319).
	allowInsecure bool

	// warnInsecure is set when the URL is plaintext http against a non-loopback host
	// with AllowInsecureURL opted in. It drives a loud WARN at construction AND on
	// each refresh so an accidental prod enablement stays visible/alertable.
	warnInsecure bool

	// now is the clock (injectable in tests); defaults to time.Now.
	now func() time.Time

	// cancel stops the background refresher started by NewJWKSKeySource. nil for a
	// source built without a background goroutine (the internal test constructor).
	cancel context.CancelFunc

	group singleflight.Group

	// lastForcedNano is the UnixNano of the last forced refresh that was allowed to
	// hit upstream; 0 means "never". Read/written atomically to gate the forced path.
	lastForcedNano atomic.Int64

	mu        sync.RWMutex
	keys      []*rsa.PublicKey
	kids      map[string]struct{} // kids present in the current cached JWKS; feeds jwks_unknown_kid_total only. nil for bootstrap/PEM keys (which carry no kid).
	fetchedAt time.Time           // last successful LIVE fetch; zero => only the bootstrap seed

	// Observability hooks (card 1.1.8): the refreshOK/refreshFail atomics are RETAINED
	// alongside the jwks_refresh_total{result} counter so the outcome counts stay
	// directly assertable in unit tests without an OTEL reader. The four metrics
	// (jwks_refresh_total{result}, jwks_cache_age_seconds, jwks_verify_fail_total,
	// jwks_unknown_kid_total) are emitted via the lib-observability metrics factory
	// resolved from ctx — see metrics.go.
	refreshOK   atomic.Int64
	refreshFail atomic.Int64

	// cacheAgeGauge is the jwks_cache_age_seconds instrument, built ONCE per source
	// (guarded by cacheAgeGaugeOnce) so serving keys does not churn a metric builder
	// or re-WARN on a creation failure on every verify. nil => creation failed or no
	// factory was resolvable; emission is then skipped (best-effort, never blocks).
	cacheAgeGaugeOnce sync.Once
	cacheAgeGauge     *metrics.GaugeBuilder
}

// kidPresenceChecker is optionally implemented by a KeySource that tracks the kids
// of its cached JWKS. It exists ONLY to feed jwks_unknown_kid_total; verification
// never consults it (verifyToken still tries all keys). The static/PEM sources do
// not implement it — their keys carry no kid — so the metric is JWKS-only.
type kidPresenceChecker interface {
	hasKID(kid string) bool
}

// NewJWKSKeySource builds a dynamic JWKS KeySource: it seeds the cache from the
// bootstrap PEM (if any), then starts a background goroutine that performs a lazy
// first live fetch and thereafter refreshes on the short TTL. Construction never
// blocks on the network, so a slow/unreachable endpoint at startup is fine.
func NewJWKSKeySource(cfg JWKSConfig) (KeySource, error) {
	src, err := newJWKSKeySource(cfg)
	if err != nil {
		return nil, err
	}

	base := cfg.Ctx
	if base == nil {
		base = context.Background()
	}

	// Derive a cancelable context so Close() can stop the background refresher even
	// when the caller passed no cfg.Ctx (bound to context.Background()).
	ctx, cancel := context.WithCancel(base)
	src.cancel = cancel

	// Lazy first live fetch + short-TTL background refresh. Keys() never waits on
	// this. SafeGoWithContext gives panic recovery on the goroutine boundary.
	obsruntime.SafeGoWithContext(ctx, src.logger, "lib-auth.jwks-refresher", obsruntime.KeepRunning, src.refreshLoop)

	return src, nil
}

// newJWKSKeySource builds the source and seeds the bootstrap keys WITHOUT starting
// the background goroutine. Split out so tests can drive Refresh deterministically.
func newJWKSKeySource(cfg JWKSConfig) (*jwksKeySource, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("jwks key source requires a non-empty URL")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = obs.Nop()
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultJWKSFetchTimeout}
	}

	interval := cfg.RefreshInterval
	if interval <= 0 {
		interval = defaultJWKSRefreshInterval
	}

	cooldown := cfg.ForcedRefreshCooldown
	if cooldown <= 0 {
		cooldown = defaultForcedRefreshCooldown
	}

	// The JWKS is the trust root for token verification, so plaintext is rejected by
	// default (fail-closed). Loopback http is carved out (local/dev reaches Casdoor over
	// http); a non-loopback plaintext URL requires an explicit AllowInsecureURL opt-in
	// and then WARNs loudly.
	warnInsecure, err := validateJWKSURL(cfg.URL, cfg.AllowInsecureURL)
	if err != nil {
		return nil, err
	}

	if warnInsecure {
		logger.Log(context.Background(), obs.LevelWarn,
			fmt.Sprintf("JWKS is fetched over plaintext HTTP against a non-loopback host (URL=%q); the JWKS is the trust root for token verification — enable TLS in production", cfg.URL))
	}

	src := &jwksKeySource{
		url:             cfg.URL,
		httpClient:      httpClient,
		refreshInterval: interval,
		forcedCooldown:  cooldown,
		logger:          logger,
		warnInsecure:    warnInsecure,
		allowInsecure:   cfg.AllowInsecureURL,
		now:             time.Now,
	}

	if len(cfg.BootstrapPEM) > 0 {
		keys, err := parseRSAPublicKeys(cfg.BootstrapPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jwks bootstrap PEM: %w", err)
		}

		src.setKeys(keys, nil, time.Time{}) // seed only; not a live fetch (PEM keys carry no kid)
	}

	return src, nil
}

// validateJWKSURL fail-closes on an unusable JWKS URL and reports whether an insecure
// (plaintext, non-loopback, explicitly-opted-in) URL is in use so the caller can WARN.
// It rejects a parse error, an empty scheme, or any scheme other than http/https. An
// https URL is fine; an http URL is fine only for a loopback host, or for a non-loopback
// host when allowInsecure is true (then warn == true). It performs a PURE literal host
// check — never a DNS lookup — so it stays non-blocking.
func validateJWKSURL(raw string, allowInsecure bool) (warn bool, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return false, fmt.Errorf("invalid jwks url %q: %w", raw, err)
	}

	// A scheme-only URL (e.g. "https:///jwks") parses cleanly and passes the scheme
	// check, but has no host to dial: every fetch would then fail to build a usable
	// request. Reject it up front so the misconfiguration fails closed at construction.
	if u.Hostname() == "" {
		return false, fmt.Errorf("jwks url %q has no host", raw)
	}

	switch u.Scheme {
	case "https":
		return false, nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return false, nil
		}

		if !allowInsecure {
			return false, fmt.Errorf(
				"jwks url %q uses plaintext http against a non-loopback host; the JWKS is the trust root for token verification — set JWKSConfig.AllowInsecureURL to permit this deliberately",
				raw)
		}

		return true, nil
	default:
		return false, fmt.Errorf("jwks url %q has unsupported scheme %q (want https, or http for a loopback host)", raw, u.Scheme)
	}
}

// isLoopbackHost reports whether host is a loopback target by literal inspection only
// (no DNS): the name "localhost", or an IP literal in 127.0.0.0/8 or ::1.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}

	return false
}

// Keys returns the currently cached verification keys without ever touching the
// network (serve-from-cache, serve-stale). May be empty before the first
// successful fetch when no bootstrap PEM was provided; verifyToken then fails closed.
func (s *jwksKeySource) Keys(ctx context.Context) []*rsa.PublicKey {
	s.mu.RLock()
	keys := s.keys
	fetchedAt := s.fetchedAt
	s.mu.RUnlock()

	s.emitCacheAge(ctx, fetchedAt)

	return keys
}

// hasKID reports whether kid is one of the kids in the current cached JWKS. Used
// only to emit jwks_unknown_kid_total (see kidPresenceChecker); it never gates
// verification. A bootstrap/PEM-seeded source (kids == nil) reports false for every
// kid — accurate: no JWKS-published kid has been observed yet.
func (s *jwksKeySource) hasKID(kid string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.kids[kid]

	return ok
}

// emitCacheAge records jwks_cache_age_seconds for the currently-served keys. It is a
// no-op until the first successful LIVE fetch (zero fetchedAt => only a bootstrap
// seed), so a seed-only source never reports a spurious multi-decade age. The clock
// is s.now (injectable in tests). Emission is cheap and never blocks Keys.
func (s *jwksKeySource) emitCacheAge(ctx context.Context, fetchedAt time.Time) {
	if fetchedAt.IsZero() {
		return
	}

	age := int64(s.now().Sub(fetchedAt).Seconds())
	if age < 0 {
		age = 0
	}

	gauge := s.cacheAgeGaugeBuilder(ctx)
	if gauge == nil {
		return // instrument unavailable; best-effort, never block verify
	}

	if err := gauge.Set(ctx, age); err != nil {
		s.logWarn(ctx, "failed to record metric %q: %v", metricJWKSCacheAgeSeconds.Name, err)
	}
}

// cacheAgeGaugeBuilder builds the jwks_cache_age_seconds gauge builder EXACTLY once
// per source and reuses it thereafter. The lib-observability factory exposes only a
// synchronous gauge (no observable/async callback), so caching the builder here is the
// idiomatic way to avoid per-verify instrument churn and, crucially, to WARN at most
// once on a creation failure rather than on every request. Returns nil when the
// instrument cannot be created (emission is then skipped, best-effort).
func (s *jwksKeySource) cacheAgeGaugeBuilder(ctx context.Context) *metrics.GaugeBuilder {
	s.cacheAgeGaugeOnce.Do(func() {
		logger, _, _, factory := observability.NewTrackingFromContext(ctx)

		gauge, err := factory.Gauge(metricJWKSCacheAgeSeconds)
		if err != nil {
			logger.Log(ctx, obs.LevelWarn, fmt.Sprintf("failed to create metric %q: %v", metricJWKSCacheAgeSeconds.Name, err))

			return
		}

		s.cacheAgeGauge = gauge
	})

	return s.cacheAgeGauge
}

// Refresh is the FORCED, cooldown-gated re-fetch invoked by the M2M gate on a
// signature/keys failure. It caps refresh amplification: at most one upstream fetch
// per forcedCooldown window. Within the window it returns nil WITHOUT hitting
// upstream (serve-stale) — the caller's retry still verifies against the cached keys
// and fails closed if they don't match. Concurrent forced calls also collapse via
// single-flight. The stable-kid fast path is preserved: the first forced refresh
// (lastForcedNano == 0) always fires, so a real rotation refreshes promptly.
func (s *jwksKeySource) Refresh(ctx context.Context) error {
	// The cooldown decision runs INSIDE its own single-flight, so a follower that
	// arrives while the leader is fetching JOINS that fetch and shares its outcome
	// instead of being bounced by the freshly-claimed window. Bouncing it made the
	// follower's retry verify against the still-stale cache and fail 401 in the
	// middle of a real rotation. The cooldown therefore suppresses only SEQUENTIAL
	// repeats: a caller that arrives after the flight closed gets serve-stale nil.
	// The key differs from refreshNow's, or the nested Do would join itself.
	_, err, _ := s.group.Do(jwksForcedFlightKey, func() (any, error) {
		now := s.now().UnixNano()

		prev := s.lastForcedNano.Load()
		if prev != 0 && now-prev < s.forcedCooldown.Nanoseconds() {
			return nil, nil // gated: serve stale, do not hit upstream
		}

		// Single goroutine inside the flight: a plain Store claims the window.
		s.lastForcedNano.Store(now)

		err := s.refreshNow(ctx)

		// A genuinely-cancelled attempt (context.Canceled) never meaningfully reached
		// upstream, so release the window — otherwise a cancellation could stall a real
		// key rotation for the whole cooldown. Ordinary fetch failures/timeouts (e.g.
		// DeadlineExceeded, 5xx) SHOULD hold the window: that is the amplification guard.
		// CompareAndSwap only restores if no concurrent refresh has since re-claimed it.
		if err != nil && errors.Is(err, context.Canceled) {
			s.lastForcedNano.CompareAndSwap(now, prev)
		}

		return nil, err
	})

	return err
}

// refreshNow performs the single-flight re-fetch WITHOUT the cooldown gate.
// Concurrent callers collapse onto one in-flight HTTP request and share its
// outcome. On failure the cache is left untouched (serve-stale) and the error is
// returned. Used by the background TTL loop (which must not be throttled) and by
// the cooldown-gated Refresh.
func (s *jwksKeySource) refreshNow(ctx context.Context) error {
	if s.warnInsecure {
		s.logWarn(ctx, "JWKS refresh over plaintext HTTP against a non-loopback host (URL=%q); enable TLS in production", s.url)
	}

	_, err, _ := s.group.Do(jwksRefreshFlightKey, func() (any, error) {
		// Detach the fetch from the caller's (request-scoped) ctx: this fill of the
		// process-lifetime shared cache must not inherit ONE caller's cancellation —
		// a client disconnect/timeout must not abort the shared single-flight fetch and
		// fail every joined verifier. A bounded timeout still prevents a hung fetch.
		// (The background TTL loop keeps passing the source lifetime ctx; only the fetch
		// is detached here.)
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultJWKSFetchTimeout)
		defer cancel()

		keys, kids, ferr := s.fetch(fetchCtx)
		if ferr != nil {
			s.refreshFail.Add(1)
			incrJWKSCounter(ctx, metricJWKSRefreshTotal, map[string]string{"result": "fail"})

			return nil, ferr
		}

		s.setKeys(keys, kids, s.now())
		s.refreshOK.Add(1)
		incrJWKSCounter(ctx, metricJWKSRefreshTotal, map[string]string{"result": "ok"})

		return nil, nil
	})

	return err
}

// Close stops the background refresher (if any) and is idempotent. A source built
// without a background goroutine (the internal test constructor) has no cancel and
// Close is a no-op.
func (s *jwksKeySource) Close() error {
	if s.cancel != nil {
		s.cancel()
	}

	return nil
}

// refreshLoop performs the lazy first live fetch, then refreshes on the TTL until
// the context is cancelled. Failures are logged and swallowed: the cache keeps
// serving the last-good keys (fail-open availability).
func (s *jwksKeySource) refreshLoop(ctx context.Context) {
	// The background loop uses the UN-gated fetch: the periodic TTL refresh must not
	// be throttled by the forced-refresh cooldown.
	if err := s.refreshNow(ctx); err != nil {
		s.logWarn(ctx, "initial JWKS fetch failed; serving bootstrap/stale keys: %v", err)
	}

	ticker := time.NewTicker(s.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.refreshNow(ctx); err != nil {
				s.logWarn(ctx, "background JWKS refresh failed; serving stale keys: %v", err)
			}
		}
	}
}

// fetch performs one JWKS HTTP GET and parses the response into RSA public keys.
// It never mutates the cache; the caller decides whether to install the result.
func (s *jwksKeySource) fetch(ctx context.Context) ([]*rsa.PublicKey, map[string]struct{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build jwks request: %w", err)
	}

	// Enforce the transport policy on EVERY redirect hop, not just the initial URL: a
	// policy-compliant https URL must not be 302'd to a plaintext non-loopback target
	// whose response would then be cached as verification keys (CWE-319, defeating the
	// fail-closed https policy). Shallow-copy the client so CheckRedirect is overridden
	// WITHOUT mutating the caller-injected client; the copy shares the Transport (intended).
	client := *s.httpClient
	client.CheckRedirect = func(hopReq *http.Request, via []*http.Request) error {
		// A custom CheckRedirect replaces net/http's default hop cap, so re-impose one:
		// a compromised endpoint could otherwise loop policy-compliant redirects for the
		// whole fetch timeout (CWE-400).
		if len(via) >= maxJWKSRedirects {
			return fmt.Errorf("jwks fetch stopped after %d redirects", maxJWKSRedirects)
		}

		// Re-run the construction-time policy on the redirect target. A non-nil error
		// aborts the redirect (the hop is NOT followed); the warn bool is irrelevant here.
		if _, verr := validateJWKSURL(hopReq.URL.String(), s.allowInsecure); verr != nil {
			return fmt.Errorf("jwks redirect to a policy-violating target blocked: %w", verr)
		}

		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	// Read ONE byte past the cap: if the body would exceed maxJWKSResponseBytes we can
	// then report an explicit size error instead of silently truncating into a
	// misleading "malformed json" parse failure.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read jwks response: %w", err)
	}

	if len(body) > maxJWKSResponseBytes {
		return nil, nil, fmt.Errorf("jwks response exceeds %d bytes", maxJWKSResponseBytes)
	}

	keys, kids, err := parseJWKSKeysAndKIDs(body)
	if err != nil {
		return nil, nil, err
	}

	if len(keys) == 0 {
		return nil, nil, errors.New("jwks response contained no RSA public keys")
	}

	// Bound the key count: verifyToken tries keys until one matches, so an oversized
	// set multiplies per-token RSA work (a defensive DoS guard).
	if len(keys) > maxJWKSKeys {
		return nil, nil, fmt.Errorf("jwks response has %d RSA keys, exceeding the %d-key limit", len(keys), maxJWKSKeys)
	}

	return keys, kids, nil
}

// setKeys atomically replaces the cached keys and their kid set. A non-zero
// fetchedAt marks a live fetch (drives cache-age); the bootstrap seed passes the
// zero time (and a nil kid set, since PEM keys carry no kid).
func (s *jwksKeySource) setKeys(keys []*rsa.PublicKey, kids map[string]struct{}, fetchedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys = keys
	s.kids = kids

	if !fetchedAt.IsZero() {
		s.fetchedAt = fetchedAt
	}
}

// logWarn logs a refresh warning at WARN level (nil-safe), matching the package's
// logErrorf/logInfof convention. A failed refresh that serves stale is a warning,
// not an error: verification still works off the cache.
func (s *jwksKeySource) logWarn(ctx context.Context, format string, args ...any) {
	if s.logger == nil {
		return
	}

	s.logger.Log(ctx, obs.LevelWarn, fmt.Sprintf(format, args...))
}

// parseJWKSKeysAndKIDs unmarshals a JWKS-JSON document and returns its RS256 public
// keys plus the set of kids of the kept keys. jwkset is used ONLY as a JWKS-JSON ->
// keys parser here; algorithm enforcement stays authoritative in verifyToken (RS256
// pin), never delegated to the JWKS layer. Non-RSA keys are ignored (RS256-only
// verification). The kids feed jwks_unknown_kid_total ONLY (verification is unchanged:
// keys are still tried without kid lookup). A kept key that omits its kid contributes
// nothing to the set.
func parseJWKSKeysAndKIDs(data []byte) ([]*rsa.PublicKey, map[string]struct{}, error) {
	var marshal jwkset.JWKSMarshal
	if err := json.Unmarshal(data, &marshal); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal jwks json: %w", err)
	}

	jwks, err := marshal.JWKSlice()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode jwks keys: %w", err)
	}

	keys := make([]*rsa.PublicKey, 0, len(jwks))
	kids := make(map[string]struct{}, len(jwks))

	for _, jwk := range jwks {
		pub, ok := jwk.Key().(*rsa.PublicKey)
		if !ok {
			continue // non-RSA key: RS256-only verification
		}

		meta := jwk.Marshal()

		// Exclude a key only when its use is explicitly non-signature or its alg is
		// explicitly non-RS256. Keys that OMIT use/alg are kept: Casdoor may not set
		// them, and dropping those would break verification.
		if meta.USE != "" && meta.USE != jwkset.UseSig {
			continue
		}

		if meta.ALG != "" && meta.ALG != jwkset.AlgRS256 {
			continue
		}

		keys = append(keys, pub)

		if meta.KID != "" {
			kids[meta.KID] = struct{}{}
		}
	}

	return keys, kids, nil
}
