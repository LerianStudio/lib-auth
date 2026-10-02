package middleware

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LerianStudio/lib-auth/v5/auth/endpoint"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postureKeySource is a KeySource that declares its https posture and counts
// every time the client reaches for its keys, so a test can prove a refused
// source was never consulted.
type postureKeySource struct {
	requiresHTTPS bool
	keys          []*rsa.PublicKey
	keysCalls     atomic.Int64
	refreshCalls  atomic.Int64
}

func (s *postureKeySource) Keys(context.Context) []*rsa.PublicKey {
	s.keysCalls.Add(1)

	return s.keys
}

func (s *postureKeySource) Refresh(context.Context) error {
	s.refreshCalls.Add(1)

	return nil
}

func (s *postureKeySource) Close() error { return nil }

func (s *postureKeySource) RequiresHTTPS() bool { return s.requiresHTTPS }

func (s *postureKeySource) consulted() int64 {
	return s.keysCalls.Load() + s.refreshCalls.Load()
}

func signedUserToken(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()

	return signRS256(t, key, jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user-1",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
	})
}

func requireInsecureKeySource(t *testing.T, err error) {
	t.Helper()

	require.ErrorIs(t, err, endpoint.ErrInsecure)

	var insecure *endpoint.InsecureError
	require.True(t, errors.As(err, &insecure), "want *endpoint.InsecureError, got %T", err)
	assert.Equal(t, "jwks key source", insecure.Component)
	assert.Equal(t, endpoint.ReasonPlaintextAllowed, insecure.Reason)
	assert.Contains(t, err.Error(), "RequireHTTPS")
}

// httpsClientWithSource builds a client that requires https, points at a live
// https Access Manager and verifies with source. It returns the Access Manager's
// connection count at the moment construction finished, so the health check is
// not mistaken for an authorization call. The Access Manager's certificate is not
// trusted by the client, so an authorization that passes the https guard shows up
// as a new connection whose handshake fails, never as a decision.
func httpsClientWithSource(t *testing.T, logger obs.Logger, source KeySource) (*AuthClient, *countingServer, int64) {
	t.Helper()

	am := newCountingServer(t, true)

	client, err := NewAuthClientWithOptions(am.URL, true, logger, WithRequireHTTPS(true))
	require.NoError(t, err)

	return client.WithKeySource(source), am, am.conns.Load()
}

func TestAuthClient_RequireHTTPSRefusesAKeySourceThatAllowsPlaintext(t *testing.T) {
	t.Parallel()

	key, _ := newTestRSAKeyPEM(t)
	token := signedUserToken(t, key)

	t.Run("Check answers 503 with the typed error and never consults the source", func(t *testing.T) {
		t.Parallel()

		source := &postureKeySource{requiresHTTPS: false, keys: []*rsa.PublicKey{&key.PublicKey}}
		client, am, before := httpsClientWithSource(t, &testLogger{}, source)

		authorized, code, err := client.Check(context.Background(), "midaz", "resource", "get", token, "")

		assert.False(t, authorized)
		assert.Equal(t, http.StatusServiceUnavailable, code)
		requireInsecureKeySource(t, err)
		assert.Zero(t, source.consulted(), "keys from a plaintext-allowing source must never be used")
		assert.Equal(t, before, am.conns.Load(), "the Access Manager is not dialled")
	})

	t.Run("net/http AuthorizeHTTP answers 503", func(t *testing.T) {
		t.Parallel()

		source := &postureKeySource{requiresHTTPS: false, keys: []*rsa.PublicKey{&key.PublicKey}}
		client, am, before := httpsClientWithSource(t, &testLogger{}, source)

		reached := false
		handler := client.AuthorizeHTTP("midaz", "resource", "get")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.False(t, reached)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Zero(t, source.consulted())
		assert.Equal(t, before, am.conns.Load())
	})

	t.Run("the no-round-trip path refuses too", func(t *testing.T) {
		t.Parallel()

		source := &postureKeySource{requiresHTTPS: false, keys: []*rsa.PublicKey{&key.PublicKey}}

		client, err := NewAuthClientWithOptions("", false, &testLogger{}, WithRequireHTTPS(true))
		require.NoError(t, err)

		client.PrincipalRequiredWhenDisabled = true
		client.WithKeySource(source)

		authorized, code, err := client.Check(context.Background(), "midaz", "resource", "get", token, "")

		assert.False(t, authorized)
		assert.Equal(t, http.StatusServiceUnavailable, code)
		requireInsecureKeySource(t, err)
		assert.Zero(t, source.consulted())
	})

	t.Run("attaching it is logged at ERROR", func(t *testing.T) {
		t.Parallel()

		logger := &capturingLogger{}
		source := &postureKeySource{requiresHTTPS: false}
		_, _, _ = httpsClientWithSource(t, logger, source)

		logger.mu.Lock()
		defer logger.mu.Unlock()

		found := false

		for i, msg := range logger.msgs {
			if logger.lvls[i] == obs.LevelError && strings.Contains(msg, "jwks key source") {
				found = true
			}
		}

		assert.True(t, found, "a refused key source must be reported when it is attached, got %v", logger.msgs)
	})

	t.Run("a real JWKS source on loopback http is refused", func(t *testing.T) {
		t.Parallel()

		jwks, err := NewJWKSKeySource(JWKSConfig{URL: "http://127.0.0.1:1/.well-known/jwks", RefreshInterval: time.Hour})
		require.NoError(t, err)
		t.Cleanup(func() { _ = jwks.Close() })

		client, _, _ := httpsClientWithSource(t, &testLogger{}, jwks)

		_, code, err := client.Check(context.Background(), "midaz", "resource", "get", token, "")

		assert.Equal(t, http.StatusServiceUnavailable, code)
		requireInsecureKeySource(t, err)
	})
}

func TestAuthClient_RequireHTTPSAcceptsAKeySourceThatRequiresHTTPS(t *testing.T) {
	t.Parallel()

	key, _ := newTestRSAKeyPEM(t)
	token := signedUserToken(t, key)

	for name, source := range map[string]KeySource{
		"declares https":      &postureKeySource{requiresHTTPS: true, keys: []*rsa.PublicKey{&key.PublicKey}},
		"declares no posture": StaticKeySource(&key.PublicKey),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client, am, before := httpsClientWithSource(t, &testLogger{}, source)

			_, _, err := client.Check(context.Background(), "midaz", "resource", "get", token, "")

			assert.NotErrorIs(t, err, endpoint.ErrInsecure)
			assert.Greater(t, am.conns.Load(), before, "the token verified and the Access Manager was dialled")

			if posture, ok := source.(*postureKeySource); ok {
				assert.Positive(t, posture.consulted())
			}
		})
	}
}

func TestAuthClient_RequirementOffKeepsAPlaintextKeySource(t *testing.T) {
	t.Parallel()

	key, _ := newTestRSAKeyPEM(t)
	am := newCountingServer(t, false)

	client, err := NewAuthClientWithOptions(am.URL, true, &testLogger{})
	require.NoError(t, err)

	source := &postureKeySource{requiresHTTPS: false, keys: []*rsa.PublicKey{&key.PublicKey}}
	client.WithKeySource(source)

	authorized, code, err := client.Check(context.Background(), "midaz", "resource", "get", signedUserToken(t, key), "")

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, code)
	assert.Positive(t, source.consulted())
}

func TestJWKSKeySource_DeclaresItsHTTPSPosture(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		cfg  JWKSConfig
		want bool
	}{
		"loopback http":           {JWKSConfig{URL: "http://127.0.0.1:1/jwks"}, false},
		"https without the rule":  {JWKSConfig{URL: "https://casdoor.example.com/jwks"}, false},
		"https with RequireHTTPS": {JWKSConfig{URL: "https://casdoor.example.com/jwks", RequireHTTPS: true}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			src, err := newJWKSKeySource(tc.cfg)
			require.NoError(t, err)
			assert.Equal(t, tc.want, src.RequiresHTTPS())
		})
	}
}
