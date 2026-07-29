package declaration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LerianStudio/lib-auth/v3/auth/middleware"
	liblog "github.com/LerianStudio/lib-observability/v2/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testClientID     = "f4adb14-test-client-id"
	testClientSecret = "super-secret-value-do-not-log"
	testToken        = "test-access-token-do-not-log"
)

// authServer stands in for the AUTH host: health + M2M token mint.
func newAuthServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"accessToken":%q}`, testToken)
	})

	return httptest.NewServer(mux)
}

// identityServer stands in for the IDENTITY host: PUT /v1/declarations/{slug}.
type identityServer struct {
	*httptest.Server
	mu          sync.Mutex
	putCount    int
	status      int
	body        string
	gotAuth     string
	gotBody     string
	gotPath     string
	gotRawQuery string
	puts        chan struct{}
}

func newIdentityServer(t *testing.T, status int, body string) *identityServer {
	t.Helper()

	is := &identityServer{status: status, body: body, puts: make(chan struct{}, 16)}
	is.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the request-target (escaped path + raw query) before any
		// routing check so URL-construction assertions can see a mis-routed target.
		is.mu.Lock()
		is.gotPath = r.URL.EscapedPath()
		is.gotRawQuery = r.URL.RawQuery
		is.mu.Unlock()

		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/v1/declarations/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Read the FULL body: a single Read may return a partial payload, which
		// would let wire-format assertions pass on a truncated request.
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read request body", http.StatusInternalServerError)
			return
		}

		is.mu.Lock()
		is.putCount++
		is.gotAuth = r.Header.Get("Authorization")
		is.gotBody = string(buf)
		st := is.status
		bd := is.body
		is.mu.Unlock()

		select {
		case is.puts <- struct{}{}:
		default:
		}

		w.WriteHeader(st)
		_, _ = w.Write([]byte(bd))
	}))

	return is
}

func (is *identityServer) count() int {
	is.mu.Lock()
	defer is.mu.Unlock()

	return is.putCount
}

// captureLogger records every message so tests can assert secrets never leak.
type captureLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (c *captureLogger) Log(_ context.Context, _ liblog.Level, msg string, fields ...liblog.Field) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgs = append(c.msgs, msg)
}
func (c *captureLogger) With(_ ...liblog.Field) liblog.Logger { return c }
func (c *captureLogger) WithGroup(_ string) liblog.Logger     { return c }
func (c *captureLogger) Enabled(_ liblog.Level) bool          { return true }
func (c *captureLogger) Sync(_ context.Context) error         { return nil }

func (c *captureLogger) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return strings.Join(c.msgs, "\n")
}

// fakeCache is a map-backed test double for the pluggable Cache seam.
type fakeCache struct {
	mu sync.Mutex
	m  map[string]string
}

func newFakeCache() *fakeCache { return &fakeCache{m: map[string]string{}} }

func (c *fakeCache) Get(_ context.Context, key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	v, ok := c.m[key]

	return v, ok
}

func (c *fakeCache) Set(_ context.Context, key, val string, _ time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.m[key] = val
}

func (c *fakeCache) get(key string) (string, bool) { return c.Get(context.Background(), key) }

// testConfig builds a valid Config wired to the given auth+identity servers.
func testConfig(t *testing.T, authURL, identityURL string) Config {
	t.Helper()

	l := liblog.NewNop()
	auth := middleware.NewAuthClient(authURL, true, &l)

	return Config{
		Slug:         "plugin-fees",
		Manifest:     []byte(feesJSON),
		IdentityAddr: identityURL,
		Auth:         auth,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
	}
}

// newFastPublisher builds a Publisher with tiny retry timings for fast tests.
func newFastPublisher(t *testing.T, cfg Config) *Publisher {
	t.Helper()

	p, err := New(cfg)
	require.NoError(t, err)

	p.retryInitialInterval = time.Millisecond
	p.retryMaxInterval = 2 * time.Millisecond
	p.maxTries = 3

	return p
}

func TestNew_Validation(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	base := testConfig(t, auth.URL, "http://identity.local")

	t.Run("valid", func(t *testing.T) {
		p, err := New(base)
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.NotNil(t, p.logger, "logger must default to a no-op when nil")
	})

	mutations := map[string]func(c *Config){
		"missing slug":          func(c *Config) { c.Slug = "" },
		"missing manifest":      func(c *Config) { c.Manifest = nil },
		"missing identity addr": func(c *Config) { c.IdentityAddr = "" },
		"missing auth":          func(c *Config) { c.Auth = nil },
		"missing client id":     func(c *Config) { c.ClientID = "" },
		"missing client secret": func(c *Config) { c.ClientSecret = "" },
		"bad manifest":          func(c *Config) { c.Manifest = []byte("{ not json") },
		"slug != service":       func(c *Config) { c.Slug = "mismatch" },
		"invalid manifest":      func(c *Config) { c.Manifest = []byte(`{"service":"plugin-fees","version":0}`) },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)

			_, err := New(cfg)
			require.Error(t, err)
		})
	}
}

func TestPublish_Success_CacheNil_AlwaysPUTs(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	p := newFastPublisher(t, testConfig(t, auth.URL, identity.URL))

	require.NoError(t, p.Publish(context.Background()))
	assert.Equal(t, 1, identity.count())

	// Authorization header carries the minted token; body is the wire JSON.
	identity.mu.Lock()
	defer identity.mu.Unlock()
	assert.Equal(t, "Bearer "+testToken, identity.gotAuth)
	assert.Contains(t, identity.gotBody, `"service":"plugin-fees"`)
}

func TestPublish_Success_StoresHash(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	cache := newFakeCache()
	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Cache = cache
	p := newFastPublisher(t, cfg)

	require.NoError(t, p.Publish(context.Background()))
	assert.Equal(t, 1, identity.count())

	stored, ok := cache.get("declaration:plugin-fees:hash")
	require.True(t, ok, "hash must be stored after a 200")
	assert.Equal(t, p.hash, stored)
}

func TestPublish_CacheHit_SkipsPUT(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	cache := newFakeCache()
	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Cache = cache
	p := newFastPublisher(t, cfg)

	// Pre-seed the cache with the computed hash → publish must skip the PUT.
	cache.Set(context.Background(), "declaration:plugin-fees:hash", p.hash, time.Hour)

	require.NoError(t, p.Publish(context.Background()))
	assert.Equal(t, 0, identity.count(), "cache hit must skip the PUT")
}

func TestPublish_Deterministic_NoRetry(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusUnprocessableEntity} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			auth := newAuthServer(t)
			t.Cleanup(auth.Close)

			identity := newIdentityServer(t, status, `{"message":"nope"}`)
			t.Cleanup(identity.Close)

			cache := newFakeCache()
			cfg := testConfig(t, auth.URL, identity.URL)
			cfg.Cache = cache
			p := newFastPublisher(t, cfg)

			err := p.Publish(context.Background())
			require.Error(t, err)

			var pe *PublishError
			require.ErrorAs(t, err, &pe)
			assert.True(t, pe.Deterministic, "status %d must be deterministic", status)
			assert.Equal(t, status, pe.StatusCode)
			assert.Equal(t, 1, identity.count(), "deterministic error must NOT retry")

			_, ok := cache.get("declaration:plugin-fees:hash")
			assert.False(t, ok, "deterministic failure must not write the cache")
		})
	}
}

func TestPublish_Transient_RetriesThenGivesUp(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusInternalServerError, http.StatusBadGateway} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			auth := newAuthServer(t)
			t.Cleanup(auth.Close)

			identity := newIdentityServer(t, status, `{"message":"later"}`)
			t.Cleanup(identity.Close)

			cache := newFakeCache()
			cfg := testConfig(t, auth.URL, identity.URL)
			cfg.Cache = cache
			p := newFastPublisher(t, cfg)

			err := p.Publish(context.Background())
			require.Error(t, err)

			var pe *PublishError
			require.ErrorAs(t, err, &pe)
			assert.False(t, pe.Deterministic, "status %d must be transient", status)
			assert.Equal(t, int(p.maxTries), identity.count(), "transient error must retry maxTries times")

			_, ok := cache.get("declaration:plugin-fees:hash")
			assert.False(t, ok, "transient failure must not write the cache")
		})
	}
}

func TestPublish_NetworkError_Transient(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, "{}")
	down := identity.URL
	identity.Close() // connection refused → network/transient

	cfg := testConfig(t, auth.URL, down)
	p := newFastPublisher(t, cfg)

	err := p.Publish(context.Background())
	require.Error(t, err)

	var pe *PublishError
	require.ErrorAs(t, err, &pe)
	assert.False(t, pe.Deterministic, "network failure must be transient")
}

func TestStart_FailOpen_5xx_NoFatal(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusInternalServerError, `{"message":"down"}`)
	t.Cleanup(identity.Close)

	p := newFastPublisher(t, testConfig(t, auth.URL, identity.URL))

	stop, err := p.Start(context.Background())
	require.NoError(t, err, "fail-open: a failing initial publish must NOT fatal Start")
	require.NotNil(t, stop)

	// A publish attempt was still made in the background.
	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background publish attempt")
	}

	stop()
}

func TestStart_FailFast_SurfacesError(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusInternalServerError, `{"message":"down"}`)
	t.Cleanup(identity.Close)

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.FailFast = true
	p := newFastPublisher(t, cfg)

	stop, err := p.Start(context.Background())
	require.Error(t, err, "fail-fast: initial publish failure must surface")

	if stop != nil {
		stop()
	}
}

func TestStart_Success(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	p := newFastPublisher(t, testConfig(t, auth.URL, identity.URL))

	stop, err := p.Start(context.Background())
	require.NoError(t, err)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background publish")
	}

	stop()
	assert.GreaterOrEqual(t, identity.count(), 1)
}

// TestPublish_IdentityAddrTrailingSlash_NoDoubleSlash asserts that a trailing
// slash on IdentityAddr (a common env-var footgun on PLUGIN_IDENTITY_HOST) does
// NOT produce a "//v1" request target — the base slash must be normalized.
func TestPublish_IdentityAddrTrailingSlash_NoDoubleSlash(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	// Trailing slash on the base URL.
	cfg := testConfig(t, auth.URL, identity.URL+"/")
	p := newFastPublisher(t, cfg)

	require.NoError(t, p.Publish(context.Background()))
	assert.Equal(t, 1, identity.count())

	identity.mu.Lock()
	defer identity.mu.Unlock()
	assert.Equal(t, "/v1/declarations/plugin-fees", identity.gotPath,
		"a trailing slash on IdentityAddr must not yield a double slash in the request path")
}

// TestPublish_SlugWithReservedChar_EscapedSingleSegment asserts that a slug
// carrying a reserved character is percent-escaped into a SINGLE path segment and
// does not leak into the query string (which naive fmt.Sprintf construction allows).
func TestPublish_SlugWithReservedChar_EscapedSingleSegment(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	// New enforces slug == manifest.service, so the reserved char is driven through
	// a manifest whose service carries it. Production validation is NOT weakened.
	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Slug = "a?b"
	cfg.Manifest = []byte(`{"service":"a?b","version":1}`)
	p := newFastPublisher(t, cfg)

	require.NoError(t, p.Publish(context.Background()))
	assert.Equal(t, 1, identity.count())

	identity.mu.Lock()
	defer identity.mu.Unlock()
	assert.Equal(t, "/v1/declarations/a%3Fb", identity.gotPath,
		"a reserved char in the slug must be percent-escaped as a single path segment")
	assert.Empty(t, identity.gotRawQuery,
		"a reserved char in the slug must not leak into the request query string")
}

// TestPublish_SlugWithSlash_EscapedSingleSegment asserts that a literal '/' in the
// slug is percent-escaped into a SINGLE path segment (a%2Fb) rather than being
// treated as a path separator (which would mis-route the PUT to an extra segment).
func TestPublish_SlugWithSlash_EscapedSingleSegment(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	// New enforces slug == manifest.service, so the '/' is driven through a manifest
	// whose service carries it. Production validation is NOT weakened.
	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Slug = "a/b"
	cfg.Manifest = []byte(`{"service":"a/b","version":1}`)
	p := newFastPublisher(t, cfg)

	require.NoError(t, p.Publish(context.Background()))
	assert.Equal(t, 1, identity.count())

	identity.mu.Lock()
	defer identity.mu.Unlock()
	assert.Equal(t, "/v1/declarations/a%2Fb", identity.gotPath,
		"a literal '/' in the slug must be percent-escaped into a SINGLE path segment")
	assert.Empty(t, identity.gotRawQuery,
		"the slug must not leak into the request query string")
}

func TestPublish_NeverLogsSecretOrToken(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	// 401 to exercise the error-logging path too.
	identity := newIdentityServer(t, http.StatusUnauthorized, `{"message":"bad"}`)
	t.Cleanup(identity.Close)

	cap := &captureLogger{}
	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Logger = cap
	p := newFastPublisher(t, cfg)

	_ = p.Publish(context.Background())

	logs := cap.all()
	assert.NotContains(t, logs, testClientSecret, "client secret must never be logged")
	assert.NotContains(t, logs, testToken, "minted token must never be logged")
}
