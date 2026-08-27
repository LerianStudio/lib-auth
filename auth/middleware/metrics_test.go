package middleware

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	observability "github.com/LerianStudio/lib-observability/v2"
	"github.com/LerianStudio/lib-observability/v2/log"
	obsmetrics "github.com/LerianStudio/lib-observability/v2/metrics"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// ---------------------------------------------------------------------------
// Metrics test harness: a real OTEL SDK MeterProvider with a ManualReader, wired
// into ctx exactly the way lib-observability's NewTrackingFromContext expects. This
// asserts the four card-1.1.8 metrics end-to-end through the production emit path
// (metrics.go), not just the underlying atomics.
// ---------------------------------------------------------------------------

func metricsCtx(t *testing.T) (context.Context, *sdkmetric.ManualReader) {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	factory, err := obsmetrics.NewMetricsFactory(mp.Meter("lib-auth-test"), log.NewNop())
	require.NoError(t, err)

	return observability.ContextWithMetricFactory(context.Background(), factory), reader
}

// counterValue sums the int64 counter `name`, optionally filtered to the data point
// carrying attribute attrKey=attrVal (pass "" for both to sum all points).
func counterValue(t *testing.T, reader *sdkmetric.ManualReader, name, attrKey, attrVal string) int64 {
	t.Helper()

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(context.Background(), &rm))

	var total int64

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}

			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok, "metric %q is not an int64 Sum", name)

			for _, dp := range sum.DataPoints {
				if attrKey == "" {
					total += dp.Value

					continue
				}

				if v, present := dp.Attributes.Value(attribute.Key(attrKey)); present && v.AsString() == attrVal {
					total += dp.Value
				}
			}
		}
	}

	return total
}

// gaugeValue returns the last recorded value of the int64 gauge `name`.
func gaugeValue(t *testing.T, reader *sdkmetric.ManualReader, name string) (int64, bool) {
	t.Helper()

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(context.Background(), &rm))

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}

			g, ok := m.Data.(metricdata.Gauge[int64])
			require.True(t, ok, "metric %q is not an int64 Gauge", name)

			if len(g.DataPoints) == 0 {
				return 0, false
			}

			return g.DataPoints[len(g.DataPoints)-1].Value, true
		}
	}

	return 0, false
}

// ---------------------------------------------------------------------------
// jwks_refresh_total{result=ok|fail}
// ---------------------------------------------------------------------------

func TestMetrics_JWKSRefreshTotal_OK(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)
	body := jwksJSON(t, "cert-built-in", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	ctx, reader := metricsCtx(t)

	require.NoError(t, source.Refresh(ctx))

	assert.Equal(t, int64(1), counterValue(t, reader, "jwks_refresh_total", "result", "ok"),
		"a successful upstream fetch increments jwks_refresh_total{result=ok}")
	assert.Equal(t, int64(0), counterValue(t, reader, "jwks_refresh_total", "result", "fail"))
	assert.Equal(t, int64(1), source.refreshOK.Load(), "the retained atomic tracks the same outcome")
}

func TestMetrics_JWKSRefreshTotal_Fail(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	ctx, reader := metricsCtx(t)

	require.Error(t, source.Refresh(ctx))

	assert.Equal(t, int64(1), counterValue(t, reader, "jwks_refresh_total", "result", "fail"),
		"a failed upstream fetch increments jwks_refresh_total{result=fail}")
	assert.Equal(t, int64(0), counterValue(t, reader, "jwks_refresh_total", "result", "ok"))
	assert.Equal(t, int64(1), source.refreshFail.Load(), "the retained atomic tracks the same outcome")
}

// ---------------------------------------------------------------------------
// jwks_cache_age_seconds
// ---------------------------------------------------------------------------

func TestMetrics_JWKSCacheAgeSeconds_DerivedFromFetchedAt(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)
	body := jwksJSON(t, "cert-built-in", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	source.now = clock.Now

	ctx, reader := metricsCtx(t)

	// Live fetch stamps fetchedAt at t0.
	require.NoError(t, source.Refresh(ctx))

	// 42s later, serving the keys reports their age.
	clock.Advance(42 * time.Second)

	_ = source.Keys(ctx)

	age, ok := gaugeValue(t, reader, "jwks_cache_age_seconds")
	require.True(t, ok, "serving keys after a live fetch must record jwks_cache_age_seconds")
	assert.Equal(t, int64(42), age, "cache age is now() - fetchedAt in seconds")
}

func TestMetrics_JWKSCacheAgeSeconds_BootstrapOnly_NotEmitted(t *testing.T) {
	t.Parallel()

	priv, _ := pubKeyOf(t)

	source, err := newJWKSKeySource(JWKSConfig{
		URL:          "http://127.0.0.1:0/jwks",
		BootstrapPEM: []byte(pubPEMOf(t, priv)),
	})
	require.NoError(t, err)

	ctx, reader := metricsCtx(t)

	// Only a bootstrap seed (no live fetch): fetchedAt is zero, so no age is reported
	// (a seed-only source must never emit a spurious multi-decade age).
	_ = source.Keys(ctx)

	_, ok := gaugeValue(t, reader, "jwks_cache_age_seconds")
	assert.False(t, ok, "a bootstrap-only source must not emit jwks_cache_age_seconds")
}

// ---------------------------------------------------------------------------
// jwks_verify_fail_total
// ---------------------------------------------------------------------------

func TestMetrics_JWKSVerifyFailTotal_OnSignatureFailure(t *testing.T) {
	t.Parallel()

	attackerPriv, _ := pubKeyOf(t)
	_, serverPub := pubKeyOf(t)

	source := &fakeKeySource{keys: []*rsa.PublicKey{serverPub}}
	m := newSourceAuthenticator(t, source, "")

	token := signRS256(t, attackerPriv, applicationClaims())

	ctx, reader := metricsCtx(t)

	_, statusCode, err := m.verify(ctx, noopSpan(), token)
	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)

	assert.Equal(t, int64(1), counterValue(t, reader, "jwks_verify_fail_total", "", ""),
		"a source-path signature verification failure increments jwks_verify_fail_total")
}

func TestMetrics_JWKSVerifyFailTotal_NotEmittedOnSuccess(t *testing.T) {
	t.Parallel()

	priv, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}
	m := newSourceAuthenticator(t, source, "")

	token := signRS256(t, priv, applicationClaims())

	ctx, reader := metricsCtx(t)

	_, statusCode, err := m.verify(ctx, noopSpan(), token)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)

	assert.Equal(t, int64(0), counterValue(t, reader, "jwks_verify_fail_total", "", ""),
		"a token that verifies must not increment jwks_verify_fail_total")
}

// ---------------------------------------------------------------------------
// jwks_unknown_kid_total (metric-only kid-presence probe; verification unaffected)
// ---------------------------------------------------------------------------

func TestMetrics_JWKSUnknownKIDTotal_OnUnknownKID(t *testing.T) {
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

	// A VALID token (signed by the cached key) whose header carries a kid absent from
	// the JWKS. Verification still succeeds (keys are tried without kid lookup); the
	// unknown-kid metric fires purely as a signal.
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, applicationClaims())
	tok.Header["kid"] = "totally-unknown-kid"

	signed, err := tok.SignedString(priv)
	require.NoError(t, err)

	ctx, reader := metricsCtx(t)

	_, statusCode, verr := m.verify(ctx, noopSpan(), signed)
	require.NoError(t, verr, "verification must be unaffected by the kid-presence probe")
	assert.Equal(t, http.StatusOK, statusCode)

	assert.Equal(t, int64(1), counterValue(t, reader, "jwks_unknown_kid_total", "", ""),
		"a token whose kid is absent from the cached JWKS increments jwks_unknown_kid_total")
	assert.Equal(t, int64(0), counterValue(t, reader, "jwks_verify_fail_total", "", ""),
		"the token still verified, so verify_fail must not move")
}

func TestMetrics_JWKSUnknownKIDTotal_KnownKID_NotEmitted(t *testing.T) {
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

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, applicationClaims())
	tok.Header["kid"] = "cert-built-in" // the kid the JWKS published

	signed, err := tok.SignedString(priv)
	require.NoError(t, err)

	ctx, reader := metricsCtx(t)

	_, _, verr := m.verify(ctx, noopSpan(), signed)
	require.NoError(t, verr)

	assert.Equal(t, int64(0), counterValue(t, reader, "jwks_unknown_kid_total", "", ""),
		"a token whose kid IS in the cached JWKS must not increment jwks_unknown_kid_total")
}

// ---------------------------------------------------------------------------
// hasKID: the observable state feeding jwks_unknown_kid_total
// ---------------------------------------------------------------------------

func TestJWKSKeySource_HasKID_TracksFetchedKIDs(t *testing.T) {
	t.Parallel()

	_, pub := pubKeyOf(t)
	body := jwksJSON(t, "cert-built-in", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	source, err := newJWKSKeySource(JWKSConfig{URL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	// Before any fetch, no kid is known.
	assert.False(t, source.hasKID("cert-built-in"))

	require.NoError(t, source.Refresh(context.Background()))

	assert.True(t, source.hasKID("cert-built-in"), "a fetched kid is tracked")
	assert.False(t, source.hasKID("some-other-kid"), "an unfetched kid is not tracked")
}

func TestUnverifiedKID_MalformedToken_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	// A token that cannot be parsed yields no kid (the metric probe stays silent),
	// and never influences verification.
	assert.Equal(t, "", unverifiedKID("not-a-jwt"))
	assert.Equal(t, "", unverifiedKID(""))
}
