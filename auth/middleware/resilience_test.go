package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LerianStudio/lib-observability/v2/log"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userToken builds a normal-user test token (HS256; this branch does not verify
// signatures, so any signing key is fine).
func userToken() string {
	return createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user-1",
	})
}

// forgedUserToken builds a token whose claims are byte-identical to userToken's but
// whose signature is not: the payload-edited / forged token an attacker replays.
func forgedUserToken() string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user-1",
	})

	signed, err := token.SignedString([]byte("attacker-secret"))
	if err != nil {
		panic("failed to sign forged test JWT: " + err.Error())
	}

	return signed
}

// countingAuthServer returns a server that records how many /v1/authorize requests
// it received and responds per the supplied handler.
func countingAuthServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, n int64)) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		handler(w, r, n)
	}))

	t.Cleanup(server.Close)

	return server, &hits
}

func writeAuthorized(w http.ResponseWriter, authorized bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(AuthResponse{Authorized: authorized})
}

// ---------------------------------------------------------------------------
// decisionCache (unit)
// ---------------------------------------------------------------------------

func TestDecisionCache_SetGetFresh(t *testing.T) {
	t.Parallel()

	c := newDecisionCache(time.Minute)
	key := cacheKey{sub: "s", resource: "r", action: "a", product: "p"}

	c.set(key, true)

	authorized, ok := c.get(key)
	require.True(t, ok)
	assert.True(t, authorized)
}

func TestDecisionCache_NegativeDecisionCached(t *testing.T) {
	t.Parallel()

	c := newDecisionCache(time.Minute)
	key := cacheKey{sub: "s", resource: "r", action: "a"}

	c.set(key, false)

	authorized, ok := c.get(key)
	require.True(t, ok)
	assert.False(t, authorized)
}

func TestDecisionCache_ExpiredEntryNotReturned(t *testing.T) {
	t.Parallel()

	c := newDecisionCache(15 * time.Millisecond)
	key := cacheKey{sub: "s", resource: "r", action: "a"}

	c.set(key, true)

	time.Sleep(40 * time.Millisecond)

	_, ok := c.get(key)
	assert.False(t, ok, "an expired entry must never be served (would be fail-open under an outage)")
}

func TestDecisionCache_KeyFieldsDoNotCollide(t *testing.T) {
	t.Parallel()

	c := newDecisionCache(time.Minute)

	c.set(cacheKey{sub: "a", resource: "b"}, true)
	c.set(cacheKey{sub: "ab", resource: ""}, false)

	got1, ok1 := c.get(cacheKey{sub: "a", resource: "b"})
	got2, ok2 := c.get(cacheKey{sub: "ab", resource: ""})

	require.True(t, ok1)
	require.True(t, ok2)
	assert.True(t, got1)
	assert.False(t, got2)
}

func TestDecisionCache_BoundedUnderManyKeys(t *testing.T) {
	t.Parallel()

	c := newDecisionCache(time.Minute)

	// Insert far more distinct keys than a single shard's cap to exercise eviction.
	total := decisionCacheShards * decisionCacheMaxPerShard * 2
	for i := 0; i < total; i++ {
		c.set(cacheKey{sub: "s", resource: "r", action: "a", product: string(rune(i)) + "-" + time.Now().String()}, true)
	}

	size := 0
	for _, shard := range c.shards {
		shard.mu.Lock()
		size += len(shard.entries)
		shard.mu.Unlock()
	}

	assert.LessOrEqual(t, size, decisionCacheShards*decisionCacheMaxPerShard, "cache must stay bounded")
}

// ---------------------------------------------------------------------------
// Cache integration via checkAuthorization
// ---------------------------------------------------------------------------

func TestCheckAuthorization_CacheHit_AvoidsSecondPost(t *testing.T) {
	t.Parallel()

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		writeAuthorized(w, true)
	})

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		cache:   newDecisionCache(time.Minute),
	}

	for i := 0; i < 3; i++ {
		authorized, statusCode, err := auth.checkAuthorization(context.Background(), "", "res", "read", userToken(), "")
		require.NoError(t, err)
		assert.True(t, authorized)
		assert.Equal(t, http.StatusOK, statusCode)
	}

	assert.Equal(t, int64(1), hits.Load(), "cache hits must avoid re-querying the authz service")
}

func TestCheckAuthorization_CacheExpiry_RequeriesAuthz(t *testing.T) {
	t.Parallel()

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		writeAuthorized(w, true)
	})

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		cache:   newDecisionCache(15 * time.Millisecond),
	}

	_, _, err := auth.checkAuthorization(context.Background(), "", "res", "read", userToken(), "")
	require.NoError(t, err)

	time.Sleep(40 * time.Millisecond)

	_, _, err = auth.checkAuthorization(context.Background(), "", "res", "read", userToken(), "")
	require.NoError(t, err)

	assert.Equal(t, int64(2), hits.Load(), "an expired cache entry must trigger a fresh authz query")
}

func TestCheckAuthorization_NegativeCache_Served(t *testing.T) {
	t.Parallel()

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		writeAuthorized(w, false)
	})

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		cache:   newDecisionCache(time.Minute),
	}

	for i := 0; i < 2; i++ {
		authorized, _, err := auth.checkAuthorization(context.Background(), "", "res", "read", userToken(), "")
		require.NoError(t, err)
		assert.False(t, authorized)
	}

	assert.Equal(t, int64(1), hits.Load(), "a cached denial is served without re-querying")
}

// TestCheckAuthorization_ForgedTokenMustNotHitCachedAllow proves the cache does not
// substitute for authentication. Local JWT verification is off (the default), so the
// authz service is the ONLY party that verifies the token signature. Two tokens carry
// identical claims but different signatures — the shape of a payload-edited or wholly
// forged token — and the authz service authorizes only the genuine one. The forged
// token must therefore reach the authz service and be denied, never be served an
// allow that was cached for the genuine token.
func TestCheckAuthorization_ForgedTokenMustNotHitCachedAllow(t *testing.T) {
	t.Parallel()

	genuine := userToken()
	forged := forgedUserToken()

	require.NotEqual(t, genuine, forged, "the two tokens must differ on the wire")

	server, _ := countingAuthServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
		// The authz service verifies the signature; only the genuine token passes.
		writeAuthorized(w, r.Header.Get("Authorization") == genuine)
	})

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		cache:   newDecisionCache(time.Minute),
	}

	authorized, _, err := auth.checkAuthorization(context.Background(), "", "res", "read", genuine, "")
	require.NoError(t, err)
	require.True(t, authorized, "the genuine token must be authorized and warm the cache")

	authorized, _, err = auth.checkAuthorization(context.Background(), "", "res", "read", forged, "")
	require.NoError(t, err)
	assert.False(t, authorized, "a forged token must never be served a decision cached for a genuine one")
}

// ---------------------------------------------------------------------------
// Retry
// ---------------------------------------------------------------------------

func TestCheckAuthorization_Retry_On5xx_EventuallySucceeds(t *testing.T) {
	t.Parallel()

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, n int64) {
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		writeAuthorized(w, true)
	})

	auth := &AuthClient{
		Address:  server.URL,
		Enabled:  true,
		Logger:   &testLogger{},
		timeout:  2 * time.Second,
		retryMax: 2,
	}

	authorized, statusCode, err := auth.checkAuthorization(context.Background(), "", "res", "read", userToken(), "")

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, int64(2), hits.Load(), "a transient 5xx must be retried")
}

func TestCheckAuthorization_Retry_NotOn403(t *testing.T) {
	t.Parallel()

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "FORBIDDEN", "message": "no"})
	})

	auth := &AuthClient{
		Address:  server.URL,
		Enabled:  true,
		Logger:   &testLogger{},
		timeout:  2 * time.Second,
		retryMax: 3,
	}

	authorized, statusCode, err := auth.checkAuthorization(context.Background(), "", "res", "write", userToken(), "")

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusForbidden, statusCode)
	assert.Equal(t, int64(1), hits.Load(), "an authoritative 403 must never be retried")
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

func TestCheckAuthorization_Breaker_OpensAfterN_AndDenies(t *testing.T) {
	t.Parallel()

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		breaker: newAuthBreaker(2, time.Minute),
	}

	// Two consecutive transient (5xx) failures trip the breaker.
	for i := 0; i < 2; i++ {
		authorized, statusCode, err := auth.checkAuthorization(context.Background(), "", "res", "read", userToken(), "")
		require.NoError(t, err, "runtime outage denies without surfacing an error")
		assert.False(t, authorized)
		assert.Equal(t, http.StatusForbidden, statusCode)
	}

	// Breaker now open: the next call is denied WITHOUT touching the authz service.
	authorized, statusCode, err := auth.checkAuthorization(context.Background(), "", "res", "read", userToken(), "")
	require.NoError(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusForbidden, statusCode)

	assert.Equal(t, int64(2), hits.Load(), "an open breaker must short-circuit, not reach the authz service")
}

func TestCheckAuthorization_BreakerOpen_ServesFreshPositiveCacheOnly(t *testing.T) {
	t.Parallel()

	var failing atomic.Bool

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		writeAuthorized(w, true)
	})

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		cache:   newDecisionCache(time.Minute),
		breaker: newAuthBreaker(2, time.Minute),
	}

	// Phase 1: prime a positive decision for "resCached" while the service is healthy.
	authorized, _, err := auth.checkAuthorization(context.Background(), "", "resCached", "read", userToken(), "")
	require.NoError(t, err)
	require.True(t, authorized)

	// Phase 2: service fails; trip the breaker via a different (uncached) key.
	failing.Store(true)

	for i := 0; i < 2; i++ {
		_, _, err = auth.checkAuthorization(context.Background(), "", "resTrip", "read", userToken(), "")
		require.NoError(t, err)
	}

	hitsAfterTrip := hits.Load()

	// Breaker open + fresh positive cache hit -> allow (served from cache, no network).
	authorized, statusCode, err := auth.checkAuthorization(context.Background(), "", "resCached", "read", userToken(), "")
	require.NoError(t, err)
	assert.True(t, authorized, "a fresh positive cache hit is served even while the breaker is open")
	assert.Equal(t, http.StatusOK, statusCode)

	// Breaker open + no cache -> deny.
	authorized, statusCode, err = auth.checkAuthorization(context.Background(), "", "resUncached", "read", userToken(), "")
	require.NoError(t, err)
	assert.False(t, authorized, "with the breaker open and no fresh cache, the request is denied")
	assert.Equal(t, http.StatusForbidden, statusCode)

	assert.Equal(t, hitsAfterTrip, hits.Load(), "neither the cache hit nor the open-breaker deny may reach the authz service")
}

// ---------------------------------------------------------------------------
// Per-request context deadline (prerequisite bug fix)
// ---------------------------------------------------------------------------

func TestCheckAuthorization_ContextTimeout_AbortsCall(t *testing.T) {
	t.Parallel()

	// Server blocks well past the client's per-request deadline.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}

		writeAuthorized(w, true)
	}))
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		timeout: 50 * time.Millisecond,
	}

	start := time.Now()
	authorized, _, err := auth.checkAuthorization(context.Background(), "", "res", "read", userToken(), "")
	elapsed := time.Since(start)

	require.Error(t, err, "the per-request deadline must abort the authz call")
	assert.False(t, authorized)
	assert.Less(t, elapsed, time.Second, "the call must abort at the deadline, not wait for the server")
}

func TestCheckAuthorization_CallerCancellation_Propagates(t *testing.T) {
	t.Parallel()

	// Proves NewRequestWithContext wiring: the CALLER's cancellation reaches the
	// HTTP call (previously the request was built without a context).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}

		writeAuthorized(w, true)
	}))
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		timeout: 5 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, _, err := auth.checkAuthorization(ctx, "", "res", "read", userToken(), "")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Less(t, elapsed, time.Second, "caller cancellation must abort the authz call")
}

// ---------------------------------------------------------------------------
// NewAuthClient - resilience config wiring
// ---------------------------------------------------------------------------

func TestNewAuthClient_ResilienceConfig(t *testing.T) {
	// Cannot use t.Parallel(): subtests use t.Setenv. enabled=false returns early
	// without any network call, exercising the config wiring in isolation.
	logger := log.Logger(&testLogger{})

	t.Run("defaults_are_behavior_neutral", func(t *testing.T) {
		t.Setenv("AUTH_TIMEOUT", "")
		t.Setenv("AUTH_CACHE_TTL", "")
		t.Setenv("AUTH_BREAKER_ENABLED", "")
		t.Setenv("AUTH_RETRY_MAX", "")

		client := NewAuthClient("", false, &logger)
		assert.Equal(t, defaultAuthTimeout, client.timeout)
		assert.Nil(t, client.cache)
		assert.Nil(t, client.breaker)
		assert.Equal(t, uint(0), client.retryMax)
	})

	t.Run("all_knobs_enabled", func(t *testing.T) {
		t.Setenv("AUTH_TIMEOUT", "5s")
		t.Setenv("AUTH_CACHE_TTL", "5s")
		t.Setenv("AUTH_BREAKER_ENABLED", "true")
		t.Setenv("AUTH_RETRY_MAX", "2")

		client := NewAuthClient("", false, &logger)
		assert.Equal(t, 5*time.Second, client.timeout)
		assert.NotNil(t, client.cache)
		assert.NotNil(t, client.breaker)
		assert.Equal(t, uint(2), client.retryMax)
	})

	t.Run("invalid_values_fall_back_to_disabled", func(t *testing.T) {
		t.Setenv("AUTH_TIMEOUT", "not-a-duration")
		t.Setenv("AUTH_CACHE_TTL", "0s")
		t.Setenv("AUTH_RETRY_MAX", "-1")

		client := NewAuthClient("", false, &logger)
		assert.Equal(t, defaultAuthTimeout, client.timeout)
		assert.Nil(t, client.cache)
		assert.Equal(t, uint(0), client.retryMax)
	})
}
