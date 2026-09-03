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
// The LEVEL of each entry is recorded alongside its text so a test can also
// assert the severity a path logs at, not only what it says.
type captureLogger struct {
	mu   sync.Mutex
	msgs []string
	lvls []liblog.Level
}

func (c *captureLogger) Log(_ context.Context, level liblog.Level, msg string, _ ...liblog.Field) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgs = append(c.msgs, msg)
	c.lvls = append(c.lvls, level)
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

// find returns the first recorded entry containing sub, together with the level
// it was logged at.
func (c *captureLogger) find(sub string) (msg string, level liblog.Level, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, m := range c.msgs {
		if strings.Contains(m, sub) {
			return m, c.lvls[i], true
		}
	}

	return "", 0, false
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

// TestNew_RejectsInvalidIdentityAddr asserts New rejects an IdentityAddr that is
// not an absolute http(s) URL (empty, scheme-less, wrong scheme, or hostless) at
// construction, instead of letting it masquerade as a retryable PUT failure, and
// accepts well-formed http/https base URLs.
func TestNew_RejectsInvalidIdentityAddr(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	rejected := map[string]string{
		"empty":        "",
		"no scheme":    "identity-host:4001",
		"wrong scheme": "ftp://host",
		"no host":      "http://",
	}
	for name, addr := range rejected {
		t.Run("reject/"+name, func(t *testing.T) {
			cfg := testConfig(t, auth.URL, addr)

			_, err := New(cfg)
			require.Error(t, err, "IdentityAddr %q must be rejected at construction", addr)
		})
	}

	accepted := map[string]string{
		"http localhost": "http://localhost:4001",
		"https host":     "https://identity.example.com",
	}
	for name, addr := range accepted {
		t.Run("accept/"+name, func(t *testing.T) {
			cfg := testConfig(t, auth.URL, addr)

			_, err := New(cfg)
			require.NoError(t, err, "IdentityAddr %q must be accepted", addr)
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
	// 501 belongs here with 401/403/422: the identity returns it when the
	// deployment is multi-tenant, where manifest materialization is the
	// tenant-manager's job. That refusal is permanent for the deployment — no
	// token, role or permission lifts it — so retrying it is pure waste.
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusUnprocessableEntity,
		http.StatusNotImplemented,
	} {
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
	for _, status := range []int{
		http.StatusConflict,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	} {
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

// TestPublish_NotImplemented_DistinctMultiTenantLog pins the OPERATOR-FACING
// half of the fix. Classifying 501 as deterministic is not enough: an operator
// reading "rejected ... (deterministic, not retrying)" would go hunting for a
// bad credential or a malformed manifest, and there is nothing wrong with
// either. The 501 message must name the real owner of multi-tenant
// materialization (the tenant-manager) and must not read as transient.
func TestPublish_NotImplemented_DistinctMultiTenantLog(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	run := func(t *testing.T, status int) (*captureLogger, *identityServer) {
		t.Helper()

		identity := newIdentityServer(t, status, `{"message":"declaration upsert is not available in multi-tenant mode"}`)
		t.Cleanup(identity.Close)

		logs := &captureLogger{}
		cfg := testConfig(t, auth.URL, identity.URL)
		cfg.Logger = logs
		p := newFastPublisher(t, cfg)

		require.Error(t, p.Publish(context.Background()))

		return logs, identity
	}

	notImplemented, identity := run(t, http.StatusNotImplemented)
	forbidden, _ := run(t, http.StatusForbidden)

	assert.Equal(t, 1, identity.count(), "501 must be attempted exactly once")

	msg, level, found := notImplemented.find("status=501")
	require.True(t, found, "the 501 path must log the status; got:\n%s", notImplemented.all())

	assert.Equal(t, liblog.LevelWarn, level,
		"501 is a correct answer from a deployment that does not serve this operation, not a plugin fault: warn, not error")
	assert.Contains(t, msg, "tenant-manager",
		"the 501 message must name who owns multi-tenant materialization")
	assert.Contains(t, msg, "multi-tenant")
	assert.NotContains(t, msg, "will retry",
		"a permanent refusal must never be described as transient")

	rejected, _, ok := forbidden.find("status=403")
	require.True(t, ok, "the 403 path must log the status; got:\n%s", forbidden.all())

	assert.NotEqual(t, rejected, msg, "501 must not reuse the 401/403/422 wording")
	assert.NotContains(t, forbidden.all(), "tenant-manager",
		"the 403 message must stay about the rejected request, not multi-tenant ownership")
}

// TestStart_Periodic_NotImplemented_KeepsTicking documents TODAY's periodic
// behavior for a deterministic refusal, which 501 deliberately shares with
// 401/403/422: runLoop logs the failure and keeps ticking. One PUT per tick (no
// in-pass retry) is the whole win here; stopping the loop on a deterministic
// class is a follow-up that must change all four statuses together, not 501
// alone.
func TestStart_Periodic_NotImplemented_KeepsTicking(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusNotImplemented, `{"message":"declaration upsert is not available in multi-tenant mode"}`)
	t.Cleanup(identity.Close)

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Interval = 10 * time.Millisecond
	p := newFastPublisher(t, cfg)

	stop, err := p.Start(context.Background())
	require.NoError(t, err, "a 501 refusal must not be fatal at boot (fail-open)")
	t.Cleanup(stop)

	for i := 1; i <= 2; i++ {
		select {
		case <-identity.puts:
		case <-time.After(5 * time.Second):
			t.Fatalf("expected PUT #%d: the periodic loop must keep ticking after a 501", i)
		}
	}
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
