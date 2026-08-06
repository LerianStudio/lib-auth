package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LerianStudio/lib-observability/v2/log"
	obsruntime "github.com/LerianStudio/lib-observability/v2/runtime"
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

	// jwksRefreshFlightKey is the fixed single-flight key: all refreshes target the
	// same JWKS URL, so concurrent forced refreshes collapse onto one in-flight fetch.
	jwksRefreshFlightKey = "refresh"

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
	Logger log.Logger

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
	logger          log.Logger

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
	// jwks_unknown_kid_total) are emitted via the lib-observability/v2 metrics factory
	// resolved from ctx — see metrics.go.
	refreshOK   atomic.Int64
	refreshFail atomic.Int64
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
		logger = log.NewNop()
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

	// TLS is expected on the key fetch (consume over ClusterIP with a pinned CA).
	// Warn — but do NOT fail — on a non-https URL: local/dev reaches Casdoor over http.
	if u, perr := url.Parse(cfg.URL); perr == nil && u.Scheme != "" && u.Scheme != "https" {
		logger.Log(context.Background(), log.LevelWarn,
			fmt.Sprintf("JWKS URL scheme %q is not https; use https in production for the key fetch", u.Scheme))
	}

	src := &jwksKeySource{
		url:             cfg.URL,
		httpClient:      httpClient,
		refreshInterval: interval,
		forcedCooldown:  cooldown,
		logger:          logger,
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

	setJWKSGauge(ctx, metricJWKSCacheAgeSeconds, age)
}

// Refresh is the FORCED, cooldown-gated re-fetch invoked by the M2M gate on a
// signature/keys failure. It caps refresh amplification: at most one upstream fetch
// per forcedCooldown window. Within the window it returns nil WITHOUT hitting
// upstream (serve-stale) — the caller's retry still verifies against the cached keys
// and fails closed if they don't match. Concurrent forced calls also collapse via
// single-flight. The stable-kid fast path is preserved: the first forced refresh
// (lastForcedNano == 0) always fires, so a real rotation refreshes promptly.
func (s *jwksKeySource) Refresh(ctx context.Context) error {
	now := s.now().UnixNano()

	if last := s.lastForcedNano.Load(); last != 0 && now-last < s.forcedCooldown.Nanoseconds() {
		return nil // gated: serve stale, do not hit upstream
	}

	// Claim the window before fetching so a slow/failing fetch does not let a burst
	// of sequential requests each start their own upstream call.
	s.lastForcedNano.Store(now)

	return s.refreshNow(ctx)
}

// refreshNow performs the single-flight re-fetch WITHOUT the cooldown gate.
// Concurrent callers collapse onto one in-flight HTTP request and share its
// outcome. On failure the cache is left untouched (serve-stale) and the error is
// returned. Used by the background TTL loop (which must not be throttled) and by
// the cooldown-gated Refresh.
func (s *jwksKeySource) refreshNow(ctx context.Context) error {
	_, err, _ := s.group.Do(jwksRefreshFlightKey, func() (any, error) {
		keys, kids, ferr := s.fetch(ctx)
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

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSResponseBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read jwks response: %w", err)
	}

	keys, kids, err := parseJWKSKeysAndKIDs(body)
	if err != nil {
		return nil, nil, err
	}

	if len(keys) == 0 {
		return nil, nil, errors.New("jwks response contained no RSA public keys")
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

	s.logger.Log(ctx, log.LevelWarn, fmt.Sprintf(format, args...))
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
