package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/MicahParks/jwkset"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// pubKeyOf returns the RSA public half of a generated key pair (the form a
// KeySource yields).
func pubKeyOf(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()

	priv, _ := newTestRSAKeyPEM(t)

	return priv, &priv.PublicKey
}

// pubPEMOf returns the PKIX PEM encoding of a private key's public half — the
// form a bootstrap seed and NewM2MAuthenticator both accept.
func pubPEMOf(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// jwksJSON renders one or more RSA public keys as a standard JWKS-JSON document
// (RFC 7517), all sharing the given kid — mirroring how Casdoor republishes a
// regenerated keypair under the SAME kid (cert-built-in).
func jwksJSON(t *testing.T, kid string, pubs ...*rsa.PublicKey) []byte {
	t.Helper()

	marshals := make([]jwkset.JWKMarshal, 0, len(pubs))

	for _, pub := range pubs {
		jwk, err := jwkset.NewJWKFromKey(pub, jwkset.JWKOptions{
			Metadata: jwkset.JWKMetadataOptions{KID: kid, ALG: jwkset.AlgRS256, USE: jwkset.UseSig},
		})
		require.NoError(t, err)

		marshals = append(marshals, jwk.Marshal())
	}

	data, err := json.Marshal(jwkset.JWKSMarshal{Keys: marshals})
	require.NoError(t, err)

	return data
}

// fakeKeySource is a fully in-memory KeySource double for exercising the
// M2MAuthenticator retry logic deterministically (no HTTP, no goroutine). It
// records how many times Keys and Refresh were called so tests can assert the
// exact number of forced refreshes / retries.
type fakeKeySource struct {
	mu           sync.Mutex
	keys         []*rsa.PublicKey
	onRefresh    func() []*rsa.PublicKey // when set, replaces keys on Refresh
	refreshErr   error
	keysCount    int
	refreshCount int
}

func (f *fakeKeySource) Keys(_ context.Context) []*rsa.PublicKey {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.keysCount++

	return f.keys
}

func (f *fakeKeySource) Refresh(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.refreshCount++

	if f.refreshErr != nil {
		return f.refreshErr
	}

	if f.onRefresh != nil {
		f.keys = f.onRefresh()
	}

	return nil
}

func (f *fakeKeySource) Close() error { return nil }

func (f *fakeKeySource) refreshes() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.refreshCount
}

// fakeClock is a controllable monotonic clock for deterministic cooldown tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.t = c.t.Add(d)
}

func newSourceAuthenticator(t *testing.T, source KeySource, issuer string) *M2MAuthenticator {
	t.Helper()

	logger := log.Logger(&testLogger{})

	m, err := NewM2MAuthenticatorWithKeySource(source, issuer, true, &logger)
	require.NoError(t, err)

	return m
}

// ---------------------------------------------------------------------------
// StaticKeySource
// ---------------------------------------------------------------------------

func TestStaticKeySource_ReturnsKeys_RefreshNoop(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)

	src := StaticKeySource(pub)

	require.Equal(t, []*rsa.PublicKey{pub}, src.Keys(context.Background()))
	require.NoError(t, src.Refresh(context.Background()))
	require.NoError(t, src.Close())
	require.Equal(t, []*rsa.PublicKey{pub}, src.Keys(context.Background()))
}

// ---------------------------------------------------------------------------
// M2MAuthenticator with KeySource: happy path
// ---------------------------------------------------------------------------

func TestVerify_SourcePath_ValidToken_NoRefresh(t *testing.T) {
	t.Parallel()

	priv, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, "")

	token := signRS256(t, priv, applicationClaims())

	claims, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc", claims["sub"])
	assert.Equal(t, 0, source.refreshes(), "a token that verifies on the first try must not trigger a refresh")
}

// ---------------------------------------------------------------------------
// THE gotcha: stable-kid key rotation -> refresh on signature failure
// ---------------------------------------------------------------------------

func TestVerify_SourcePath_StaleKey_RefreshesOnceAndRetries(t *testing.T) {
	t.Parallel()

	// Cache holds the OLD key; the token is signed by the NEW key (same kid).
	_, oldPub := pubKeyOf(t)
	newPriv, newPub := pubKeyOf(t)

	source := &fakeKeySource{
		keys:      []*rsa.PublicKey{oldPub},
		onRefresh: func() []*rsa.PublicKey { return []*rsa.PublicKey{newPub} },
	}
	m := newSourceAuthenticator(t, source, "")

	token := signRS256(t, newPriv, applicationClaims())

	claims, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.NoError(t, err, "after the forced refresh pulls the new key, verification must succeed")
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc", claims["sub"])
	assert.Equal(t, 1, source.refreshes(), "exactly ONE forced refresh on the signature failure")
}

// A signature failure that persists after the refresh must still fail closed and
// must refresh exactly ONCE — never loop.
func TestVerify_SourcePath_PersistentBadSignature_RefreshesOnce_FailsClosed(t *testing.T) {
	t.Parallel()

	attackerPriv, _ := pubKeyOf(t)
	_, serverPub := pubKeyOf(t)

	// Refresh keeps returning the same (wrong) server key; the attacker token never verifies.
	source := &fakeKeySource{
		keys:      []*rsa.PublicKey{serverPub},
		onRefresh: func() []*rsa.PublicKey { return []*rsa.PublicKey{serverPub} },
	}
	m := newSourceAuthenticator(t, source, "")

	token := signRS256(t, attackerPriv, applicationClaims())

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 1, source.refreshes(), "retry is bounded to ONE forced refresh, never a loop")
}

// When the forced refresh itself fails, verification fails closed on the original
// signature error (never falls open).
func TestVerify_SourcePath_RefreshError_FailsClosed(t *testing.T) {
	t.Parallel()

	_, oldPub := pubKeyOf(t)
	newPriv, _ := pubKeyOf(t)

	source := &fakeKeySource{
		keys:       []*rsa.PublicKey{oldPub},
		refreshErr: assert.AnError,
	}
	m := newSourceAuthenticator(t, source, "")

	token := signRS256(t, newPriv, applicationClaims())

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 1, source.refreshes(), "one refresh was attempted; its failure must not fall open")
}

// ---------------------------------------------------------------------------
// fail-closed: non-key failures must NOT trigger a refresh loop
// ---------------------------------------------------------------------------

func TestVerify_SourcePath_AlgConfusionHS256_NoRefresh(t *testing.T) {
	t.Parallel()

	priv, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, "")

	// RS/HS confusion: forge an HS256 token. WithValidMethods reports this as
	// ErrTokenSignatureInvalid too, but its header alg is HS256, so it must NOT
	// be mistaken for key staleness and must NOT refresh.
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, applicationClaims())

	signed, err := forged.SignedString([]byte(pubPEMOf(t, priv)))
	require.NoError(t, err)

	_, statusCode, verr := m.verify(context.Background(), noopSpan(), signed)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 0, source.refreshes(), "alg-confusion is not key staleness: no refresh")
}

func TestVerify_SourcePath_AlgNone_NoRefresh(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, "")

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, applicationClaims())

	signed, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, statusCode, verr := m.verify(context.Background(), noopSpan(), signed)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 0, source.refreshes(), "alg=none is not key staleness: no refresh")
}

func TestVerify_SourcePath_Expired_NoRefresh(t *testing.T) {
	t.Parallel()

	priv, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, "")

	claims := applicationClaims()
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())

	token := signRS256(t, priv, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 0, source.refreshes(), "an expired (validly signed) token is not key staleness: no refresh")
}

func TestVerify_SourcePath_WrongIssuer_NoRefresh(t *testing.T) {
	t.Parallel()

	const issuer = "http://expected-issuer:8000"

	priv, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, issuer)

	claims := applicationClaims()
	claims["iss"] = "http://attacker-issuer:8000"

	token := signRS256(t, priv, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 0, source.refreshes(), "a wrong-issuer (validly signed) token is not key staleness: no refresh")
}

func TestVerify_SourcePath_EmptySub_NoRefresh(t *testing.T) {
	t.Parallel()

	priv, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, "")

	claims := applicationClaims()
	delete(claims, "sub")

	token := signRS256(t, priv, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 0, source.refreshes(), "signature is valid; an empty sub is an app-claim failure, not key staleness")
}

func TestVerify_SourcePath_NonApplicationType_Forbidden_NoRefresh(t *testing.T) {
	t.Parallel()

	priv, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, "")

	claims := applicationClaims()
	claims["type"] = "normal-user"

	token := signRS256(t, priv, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusForbidden, statusCode)
	assert.Equal(t, 0, source.refreshes(), "signature is valid; a wrong token type is not key staleness")
}

// ---------------------------------------------------------------------------
// JWKSKeySource: real HTTP fetch + parse
// ---------------------------------------------------------------------------

func TestJWKSKeySource_Refresh_FetchedKeyVerifies(t *testing.T) {
	t.Parallel()

	priv, pub := pubKeyOf(t)
	body := jwksJSON(t, "cert-built-in", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	require.NoError(t, source.Refresh(context.Background()))

	m := newSourceAuthenticator(t, source, "")
	token := signRS256(t, priv, applicationClaims())

	_, statusCode, verr := m.verify(context.Background(), noopSpan(), token)

	require.NoError(t, verr)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, []*rsa.PublicKey{pub}, source.Keys(context.Background()))
}

// serve-stale (fail-open availability): the endpoint is down, but the bootstrap
// seed keeps verifying.
func TestJWKSKeySource_ServeStale_EndpointDown(t *testing.T) {
	t.Parallel()

	priv, _ := pubKeyOf(t)

	// Seed from a bootstrap PEM; the live endpoint always 500s.
	bootstrapPEM := pubPEMOf(t, priv)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{
		URL:          srv.URL,
		HTTPClient:   srv.Client(),
		BootstrapPEM: []byte(bootstrapPEM),
	})
	require.NoError(t, err)

	// The forced refresh fails (500) but the seeded keys are preserved (serve-stale).
	require.Error(t, source.Refresh(context.Background()))

	keys := source.Keys(context.Background())
	require.Len(t, keys, 1, "the last-good (bootstrap) key must still be served when the endpoint is down")

	m := newSourceAuthenticator(t, source, "")
	token := signRS256(t, priv, applicationClaims())

	_, statusCode, verr := m.verify(context.Background(), noopSpan(), token)

	require.NoError(t, verr, "a token signed by the still-cached key must verify despite the endpoint being down")
	assert.Equal(t, http.StatusOK, statusCode)
}

// single-flight: N concurrent (un-gated) refreshes collapse to exactly ONE HTTP
// fetch. Deterministic via a counting barrier — the handler blocks until all N
// goroutines have entered, so the single leader cannot complete before the
// followers join its in-flight window. No timing sleeps.
func TestJWKSKeySource_SingleFlight_ConcurrentRefresh_OneFetch(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)
	body := jwksJSON(t, "cert-built-in", pub)

	const n = 24

	var hits atomic.Int64

	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		<-release // hold the (single) leader open until every goroutine has joined
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	entered := make(chan struct{}, n)

	var wg sync.WaitGroup

	wg.Add(n)

	for range n {
		go func() {
			defer wg.Done()
			entered <- struct{}{}
			_ = source.refreshNow(context.Background())
		}()
	}

	// Barrier: wait until all N goroutines are in the refresh path, THEN release the
	// leader's handler. The leader is blocked on <-release, so it cannot return and
	// let a straggler start a second fetch.
	for range n {
		<-entered
	}

	close(release)
	wg.Wait()

	assert.Equal(t, int64(1), hits.Load(), "concurrent refreshes must collapse to a single HTTP fetch")
}

// bootstrap seed: constructing with an unreachable endpoint still makes the
// seeded key available immediately (lazy first live fetch, non-blocking).
func TestJWKSKeySource_BootstrapSeed_UnreachableEndpoint(t *testing.T) {
	t.Parallel()

	priv, _ := pubKeyOf(t)
	bootstrapPEM := pubPEMOf(t, priv)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// A closed/unreachable endpoint: construction must not block and Keys() must
	// return the seed immediately.
	source, err := NewJWKSKeySource(JWKSConfig{
		URL:             "http://127.0.0.1:0/jwks",
		BootstrapPEM:    []byte(bootstrapPEM),
		RefreshInterval: time.Hour,
		Ctx:             ctx,
	})
	require.NoError(t, err)

	keys := source.Keys(context.Background())
	require.Len(t, keys, 1)

	m := newSourceAuthenticator(t, source, "")
	token := signRS256(t, priv, applicationClaims())

	_, statusCode, verr := m.verify(context.Background(), noopSpan(), token)

	require.NoError(t, verr, "the seeded bootstrap key must verify even though the endpoint is unreachable")
	assert.Equal(t, http.StatusOK, statusCode)
}

// ---------------------------------------------------------------------------
// Forced-refresh cooldown (refresh-amplification DoS guard)
// ---------------------------------------------------------------------------

// A burst of DISTINCT bad-signature RS256 tokens must not drive one upstream fetch
// per request. Single-flight only collapses CONCURRENT calls; the cooldown bounds
// the SEQUENTIAL stream to one upstream fetch per window.
func TestVerify_SourcePath_ForcedRefreshCooldown_BoundsUpstreamFetches(t *testing.T) {
	t.Parallel()

	_, serverPub := pubKeyOf(t)
	body := jwksJSON(t, "cert-built-in", serverPub)

	var hits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}

	source, err := newJWKSKeySource(JWKSConfig{
		URL:                   srv.URL,
		HTTPClient:            srv.Client(),
		ForcedRefreshCooldown: time.Minute,
	})
	require.NoError(t, err)

	source.now = clock.Now

	m := newSourceAuthenticator(t, source, "")

	const n = 20

	for range n {
		// Each token is DISTINCT (a different attacker key) so single-flight cannot
		// collapse them; only the cooldown bounds the upstream calls.
		attackerPriv, _ := pubKeyOf(t)

		token := signRS256(t, attackerPriv, applicationClaims())

		_, statusCode, verr := m.verify(context.Background(), noopSpan(), token)
		require.Error(t, verr)
		assert.Equal(t, http.StatusUnauthorized, statusCode)
	}

	assert.Equal(t, int64(1), hits.Load(), "a burst of distinct bad tokens must collapse to ONE upstream fetch within the cooldown")

	// Once the cooldown window elapses, the forced path may hit upstream again.
	clock.Advance(2 * time.Minute)

	attackerPriv, _ := pubKeyOf(t)
	_, _, _ = m.verify(context.Background(), noopSpan(), signRS256(t, attackerPriv, applicationClaims()))

	assert.Equal(t, int64(2), hits.Load(), "a bad token after the cooldown window triggers exactly one more fetch")
}

// The cooldown must NOT block a legitimate rotation: when no forced refresh has run
// recently (lastForced == 0, warmed by the background loop), the first bad token
// after a rotation refreshes promptly and verifies.
func TestVerify_SourcePath_Cooldown_DoesNotBlockLegitRotation(t *testing.T) {
	t.Parallel()

	_, oldPub := pubKeyOf(t)
	newPriv, newPub := pubKeyOf(t)

	var serveNew atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if serveNew.Load() {
			_, _ = w.Write(jwksJSON(t, "cert-built-in", newPub))

			return
		}

		_, _ = w.Write(jwksJSON(t, "cert-built-in", oldPub))
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{
		URL:                   srv.URL,
		HTTPClient:            srv.Client(),
		ForcedRefreshCooldown: time.Minute,
	})
	require.NoError(t, err)

	// Warm the cache via the UN-gated background path (does not consume a forced
	// slot), so lastForced stays 0 — mirroring real steady-state operation.
	require.NoError(t, source.refreshNow(context.Background()))

	// Rotation happens.
	serveNew.Store(true)

	m := newSourceAuthenticator(t, source, "")
	token := signRS256(t, newPriv, applicationClaims())

	_, statusCode, verr := m.verify(context.Background(), noopSpan(), token)

	require.NoError(t, verr, "a legit rotated-key token refreshes and verifies on the first attempt; cooldown must not block the good path")
	assert.Equal(t, http.StatusOK, statusCode)
}

// ---------------------------------------------------------------------------
// Lifecycle: Close stops the background refresher
// ---------------------------------------------------------------------------

func TestJWKSKeySource_Close_StopsBackgroundRefresher(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)
	body := jwksJSON(t, "cert-built-in", pub)

	var hits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	source, err := NewJWKSKeySource(JWKSConfig{
		URL:             srv.URL,
		HTTPClient:      srv.Client(),
		RefreshInterval: 15 * time.Millisecond,
	})
	require.NoError(t, err)

	// The background refresher is running: it fetches repeatedly on the TTL.
	require.Eventually(t, func() bool { return hits.Load() >= 2 }, 2*time.Second, 5*time.Millisecond)

	require.NoError(t, source.Close())

	// After Close the background loop returns on ctx cancellation, so it schedules no
	// new fetches. At most ONE fetch may already be in flight (the fetch is detached
	// from the loop ctx and completes rather than being cancelled), so allow that one
	// to settle and assert the count never advances beyond it — deterministically,
	// with no fixed sleeps.
	before := hits.Load()

	require.Never(t, func() bool { return hits.Load() > before+1 },
		200*time.Millisecond, 10*time.Millisecond,
		"no new JWKS fetches after Close: the background refresher stopped")
}

// ---------------------------------------------------------------------------
// parseJWKSKeysAndKIDs: use/alg filtering (keep omitted, drop explicit-mismatch)
// ---------------------------------------------------------------------------

func TestParseJWKSPublicKeys_UseEncKeyDropped(t *testing.T) {
	t.Parallel()

	_, rsaPub := pubKeyOf(t)

	jwk, err := jwkset.NewJWKFromKey(rsaPub, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "enc-key", USE: jwkset.UseEnc},
	})
	require.NoError(t, err)

	data, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}})
	require.NoError(t, err)

	keys, _, err := parseJWKSKeysAndKIDs(data)
	require.NoError(t, err)
	assert.Empty(t, keys, "an RSA key explicitly marked use=enc is not a signature key and must be dropped")
}

func TestParseJWKSPublicKeys_NonRS256AlgDropped(t *testing.T) {
	t.Parallel()

	_, rsaPub := pubKeyOf(t)

	jwk, err := jwkset.NewJWKFromKey(rsaPub, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "rs512", ALG: jwkset.AlgRS512},
	})
	require.NoError(t, err)

	data, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}})
	require.NoError(t, err)

	keys, _, err := parseJWKSKeysAndKIDs(data)
	require.NoError(t, err)
	assert.Empty(t, keys, "a key with an explicit non-RS256 alg must be dropped")
}

func TestParseJWKSPublicKeys_OmittedUseAndAlgKept(t *testing.T) {
	t.Parallel()

	_, rsaPub := pubKeyOf(t)

	// Casdoor may publish keys without use/alg — those MUST be kept.
	jwk, err := jwkset.NewJWKFromKey(rsaPub, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "cert-built-in"},
	})
	require.NoError(t, err)

	data, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}})
	require.NoError(t, err)

	keys, _, err := parseJWKSKeysAndKIDs(data)
	require.NoError(t, err)
	require.Len(t, keys, 1, "a key that omits use/alg must be kept")
	assert.Equal(t, rsaPub, keys[0])
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

func TestNewJWKSKeySource_EmptyURL_Errors(t *testing.T) {
	t.Parallel()

	_, err := NewJWKSKeySource(JWKSConfig{URL: "  "})
	require.Error(t, err)
}

func TestNewJWKSKeySource_BadBootstrapPEM_Errors(t *testing.T) {
	t.Parallel()

	_, err := NewJWKSKeySource(JWKSConfig{URL: "http://example/jwks", BootstrapPEM: []byte("not-a-pem")})
	require.Error(t, err)
}

func TestNewM2MAuthenticatorWithKeySource_EnabledRequiresSource(t *testing.T) {
	t.Parallel()

	logger := log.Logger(&testLogger{})

	_, err := NewM2MAuthenticatorWithKeySource(nil, "", true, &logger)
	require.Error(t, err)
}

func TestNewM2MAuthenticatorWithKeySource_DisabledAllowsNilSource(t *testing.T) {
	t.Parallel()

	logger := log.Logger(&testLogger{})

	m, err := NewM2MAuthenticatorWithKeySource(nil, "", false, &logger)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.False(t, m.enabled)
}

// ---------------------------------------------------------------------------
// parseJWKSKeysAndKIDs: JWKS-JSON -> RSA keys (error + filter branches)
// ---------------------------------------------------------------------------

func TestParseJWKSPublicKeys_InvalidJSON_Errors(t *testing.T) {
	t.Parallel()

	_, _, err := parseJWKSKeysAndKIDs([]byte("{not json"))
	require.Error(t, err)
}

func TestParseJWKSPublicKeys_EmptyKeySet_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	keys, _, err := parseJWKSKeysAndKIDs([]byte(`{"keys":[]}`))
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestParseJWKSPublicKeys_NonRSAKeyIgnored(t *testing.T) {
	t.Parallel()

	// An EC (P-256) JWK is valid JWKS-JSON but not RS256; it must be filtered out,
	// leaving only the RSA key (RS256-only verification).
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecJWK, err := jwkset.NewJWKFromKey(&ecPriv.PublicKey, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "ec-key"},
	})
	require.NoError(t, err)

	_, rsaPub := pubKeyOf(t)

	rsaJWK, err := jwkset.NewJWKFromKey(rsaPub, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "cert-built-in", ALG: jwkset.AlgRS256, USE: jwkset.UseSig},
	})
	require.NoError(t, err)

	data, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{ecJWK.Marshal(), rsaJWK.Marshal()}})
	require.NoError(t, err)

	keys, _, err := parseJWKSKeysAndKIDs(data)
	require.NoError(t, err)
	require.Len(t, keys, 1, "only the RSA key survives the filter")
	assert.Equal(t, rsaPub, keys[0])
}

// ---------------------------------------------------------------------------
// JWKSKeySource fetch error branches
// ---------------------------------------------------------------------------

func TestJWKSKeySource_Refresh_EmptyJWKS_Errors(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	err = source.Refresh(context.Background())
	require.Error(t, err, "a JWKS with no RSA keys is a refresh failure, not a silent empty key set")
}

func TestJWKSKeySource_Refresh_MalformedJSON_Errors(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not-json"))
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	require.Error(t, source.Refresh(context.Background()))
}

// ---------------------------------------------------------------------------
// source-path failure classification: malformed + empty-cache branches
// ---------------------------------------------------------------------------

func TestVerify_SourcePath_MalformedToken_NoRefresh(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, "")

	_, statusCode, err := m.verify(context.Background(), noopSpan(), "not-a-jwt")

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 0, source.refreshes(), "a malformed token is not key staleness: no refresh")
}

func TestVerify_SourcePath_EmptyCache_RefreshesOnce(t *testing.T) {
	t.Parallel()

	// Cache is empty (bootstrap absent, first fetch pending); verifyToken fails with
	// "no key". That IS a key-availability failure, so exactly one forced refresh
	// fires. Here the refresh yields nothing, so it still fails closed.
	priv, _ := pubKeyOf(t)
	source := &fakeKeySource{keys: nil}
	m := newSourceAuthenticator(t, source, "")

	token := signRS256(t, priv, applicationClaims())

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 1, source.refreshes(), "an empty key cache warrants exactly one forced refresh")
}

// ---------------------------------------------------------------------------
// FIX 1: the JWKS fetch is detached from the caller's request-scoped ctx
// ---------------------------------------------------------------------------

// capturingLogger records the level + message of every Log call so a test can
// assert that a specific WARN was emitted (e.g. the plaintext-HTTP warning).
type capturingLogger struct {
	mu   sync.Mutex
	lvls []log.Level
	msgs []string
}

func (c *capturingLogger) Log(_ context.Context, lvl log.Level, msg string, _ ...log.Field) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lvls = append(c.lvls, lvl)
	c.msgs = append(c.msgs, msg)
}

func (c *capturingLogger) With(_ ...log.Field) log.Logger { return c }
func (c *capturingLogger) WithGroup(_ string) log.Logger  { return c }
func (c *capturingLogger) Enabled(_ log.Level) bool       { return true }
func (c *capturingLogger) Sync(_ context.Context) error   { return nil }

func (c *capturingLogger) warnCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0

	for _, l := range c.lvls {
		if l == log.LevelWarn {
			n++
		}
	}

	return n
}

// cancelRoundTripper is a fake transport that always returns context.Canceled,
// so a fetch through it yields an error that errors.Is(context.Canceled).
type cancelRoundTripper struct {
	hits *atomic.Int64
}

func (rt cancelRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	rt.hits.Add(1)

	return nil, context.Canceled
}

// A caller ctx that is already cancelled must NOT abort the shared single-flight
// fetch that fills the process-lifetime cache: the fetch still completes and caches.
func TestJWKSKeySource_Refresh_CancelledCallerCtx_StillFetchesAndCaches(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)
	body := jwksJSON(t, "cert-built-in", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE the fetch: the source fetch must ignore this

	require.NoError(t, source.Refresh(ctx), "a cancelled caller ctx must not abort the shared JWKS fetch")
	assert.Equal(t, []*rsa.PublicKey{pub}, source.Keys(context.Background()),
		"the detached fetch must still populate the cache")
}

// A forced refresh that fails with context.Canceled must RELEASE the cooldown
// window (a genuinely-cancelled attempt is not the amplification case), so a
// subsequent forced Refresh within the cooldown is NOT gated.
func TestJWKSKeySource_Refresh_ContextCanceled_ReleasesCooldownWindow(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	source, err := newJWKSKeySource(JWKSConfig{
		URL:                   "https://example.com/jwks", // https: passes URL validation; transport is faked
		HTTPClient:            &http.Client{Transport: cancelRoundTripper{hits: &hits}},
		ForcedRefreshCooldown: time.Minute,
	})
	require.NoError(t, err)

	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	source.now = clock.Now

	// First forced refresh is cancelled -> releases the window.
	require.ErrorIs(t, source.Refresh(context.Background()), context.Canceled)
	require.Equal(t, int64(1), hits.Load())

	// WITHIN the cooldown (clock not advanced): a normal fetch-failure would stay
	// gated, but a released window means this attempt hits upstream again.
	require.ErrorIs(t, source.Refresh(context.Background()), context.Canceled)
	assert.Equal(t, int64(2), hits.Load(),
		"a context.Canceled forced refresh must release the cooldown window")
}

// ---------------------------------------------------------------------------
// FIX 2: require https by default, loopback http carve-out, explicit opt-in
// ---------------------------------------------------------------------------

func TestNewJWKSKeySource_HTTPSURL_OK(t *testing.T) {
	t.Parallel()

	_, err := newJWKSKeySource(JWKSConfig{URL: "https://casdoor.example.com/.well-known/jwks"})
	require.NoError(t, err)
}

func TestNewJWKSKeySource_LoopbackHTTP_OKWithoutFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
	}{
		{"ipv4_loopback", "http://127.0.0.1:8000/jwks"},
		{"ipv4_loopback_range", "http://127.0.0.5:8000/jwks"},
		{"ipv6_loopback", "http://[::1]:8000/jwks"},
		{"localhost", "http://localhost:8000/jwks"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := newJWKSKeySource(JWKSConfig{URL: tt.url})
			require.NoError(t, err, "loopback http must be allowed without AllowInsecureURL")
		})
	}
}

func TestNewJWKSKeySource_NonLoopbackHTTP_RejectedWithoutFlag(t *testing.T) {
	t.Parallel()

	_, err := newJWKSKeySource(JWKSConfig{URL: "http://casdoor.example.com/jwks"})
	require.Error(t, err, "plaintext http against a non-loopback host must fail closed without AllowInsecureURL")
}

func TestNewJWKSKeySource_NonLoopbackHTTP_AllowedWithFlag_Warns(t *testing.T) {
	t.Parallel()

	cap := &capturingLogger{}
	logger := log.Logger(cap)

	_, err := newJWKSKeySource(JWKSConfig{
		URL:              "http://casdoor.example.com/jwks",
		AllowInsecureURL: true,
		Logger:           logger,
	})
	require.NoError(t, err, "AllowInsecureURL permits plaintext http against a non-loopback host")
	assert.GreaterOrEqual(t, cap.warnCount(), 1, "an insecure-URL opt-in must emit a loud WARN at construction")
}

func TestNewJWKSKeySource_InvalidScheme_Rejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
	}{
		{"ftp", "ftp://example.com/jwks"},
		{"relative", "/relative/jwks"},
		{"no_scheme", "example.com/jwks"},
		{"unparseable", "http://[::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := newJWKSKeySource(JWKSConfig{URL: tt.url})
			require.Error(t, err, "a non-http(s) / unparseable URL must be rejected")
		})
	}
}

// ---------------------------------------------------------------------------
// FIX 4: bound the response size (detect truncation) and the key count
// ---------------------------------------------------------------------------

func TestJWKSKeySource_Fetch_ResponseTooLarge_Errors(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxJWKSResponseBytes+64)) // one chunk past the cap
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	err = source.Refresh(context.Background())
	require.Error(t, err, "an over-cap response must be an explicit size error, not a silent truncation")
	assert.Contains(t, err.Error(), "exceeds")
}

func TestJWKSKeySource_Fetch_TooManyKeys_Errors(t *testing.T) {
	t.Parallel()

	// maxJWKSKeys+1 entries (all the same key is fine: the guard bounds COUNT, and
	// verifyToken tries keys until one matches, so an oversized set multiplies work).
	_, pub := pubKeyOf(t)

	pubs := make([]*rsa.PublicKey, maxJWKSKeys+1)
	for i := range pubs {
		pubs[i] = pub
	}

	body := jwksJSON(t, "cert-built-in", pubs...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	err = source.Refresh(context.Background())
	require.Error(t, err, "a JWKS with more than maxJWKSKeys RSA keys must be rejected")
}
