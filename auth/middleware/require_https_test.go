package middleware

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LerianStudio/lib-auth/v5/auth/endpoint"
	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// countingServer counts every TCP connection it accepts, not only the requests
// that reach a handler. That is the measure of "nothing went out": a TLS
// handshake that fails, or a plaintext request that never parses, still opened a
// connection, and a refused address must not open even that.
type countingServer struct {
	*httptest.Server
	conns    atomic.Int64
	requests atomic.Int64
}

func newCountingServer(t *testing.T, useTLS bool) *countingServer {
	t.Helper()

	cs := &countingServer{}
	cs.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.requests.Add(1)

		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte("healthy"))

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorized":true,"accessToken":"minted"}`))
	}))
	cs.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			cs.conns.Add(1)
		}
	}

	if useTLS {
		cs.StartTLS()
	} else {
		cs.Start()
	}

	t.Cleanup(cs.Close)

	return cs
}

func (cs *countingServer) hostPort() string {
	return strings.TrimPrefix(strings.TrimPrefix(cs.URL, "http://"), "https://")
}

// plaintextVariants are the addresses the https requirement must refuse, all of
// them pointing at a live plaintext server so a leak would be counted.
func plaintextVariants(cs *countingServer) map[string]string {
	hp := cs.hostPort()

	return map[string]string{
		"http":           "http://" + hp,
		"uppercase HTTP": "HTTP://" + hp,
		"mixed case":     "Http://" + hp,
		"scheme-less":    hp,
		"protocol-rel":   "//" + hp,
		"ws":             "ws://" + hp,
		"ftp":            "ftp://" + hp,
	}
}

func requireInsecure(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	require.ErrorIs(t, err, endpoint.ErrInsecure)

	var insecure *endpoint.InsecureError
	require.True(t, errors.As(err, &insecure), "want *endpoint.InsecureError, got %T", err)
	assert.Equal(t, "authorization client", insecure.Component)
}

func TestNewAuthClientWithOptions_RequireHTTPSRefusesBeforeAnyConnection(t *testing.T) {
	t.Parallel()

	server := newCountingServer(t, false)

	// Serial subtests: the connection count below must be read after every one ran.
	for name, address := range plaintextVariants(server) {
		for _, enabled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/enabled=%t", name, enabled), func(t *testing.T) {
				client, err := NewAuthClientWithOptions(address, enabled, &testLogger{}, WithRequireHTTPS(true))

				requireInsecure(t, err)
				assert.Nil(t, client, "a refused address must not yield a usable client")
			})
		}
	}

	assert.Zero(t, server.conns.Load(), "a refused address must not open a single connection, health check included")
}

func TestNewAuthClientWithOptions_RequireHTTPSAcceptsHTTPS(t *testing.T) {
	t.Parallel()

	server := newCountingServer(t, true)

	client, err := NewAuthClientWithOptions(server.URL, true, &testLogger{}, WithRequireHTTPS(true))
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.True(t, client.RequiresHTTPS())
	assert.Equal(t, server.URL, client.Address)
	assert.Positive(t, server.conns.Load(), "an https address is dialled for the health check")
}

func TestNewAuthClientWithOptions_EmptyAddressIsNotValidated(t *testing.T) {
	t.Parallel()

	client, err := NewAuthClientWithOptions("", true, &testLogger{}, WithRequireHTTPS(true))
	require.NoError(t, err, "an empty address makes no outbound call, so there is nothing to refuse")
	require.NotNil(t, client)
	assert.True(t, client.RequiresHTTPS())
}

func TestNewAuthClientWithOptions_RequirementOffKeepsTodaysBehaviour(t *testing.T) {
	t.Parallel()

	for name, opts := range map[string][]ClientOption{
		"no options":         nil,
		"explicit off":       {WithRequireHTTPS(false)},
		"nil option skipped": {nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := newCountingServer(t, false)

			client, err := NewAuthClientWithOptions(server.URL, true, &testLogger{}, opts...)
			require.NoError(t, err)
			require.NotNil(t, client)
			assert.False(t, client.RequiresHTTPS())
			assert.Equal(t, int64(1), server.requests.Load(), "the plaintext health check still runs")

			legacy := NewAuthClient(server.URL, true, &testLogger{})
			assert.False(t, legacy.RequiresHTTPS())
			assert.Equal(t, int64(2), server.requests.Load(), "NewAuthClient is unchanged")
		})
	}
}

func TestNewAuthClientWithOptions_LastOptionWins(t *testing.T) {
	t.Parallel()

	client, err := NewAuthClientWithOptions("", false, &testLogger{}, WithRequireHTTPS(true), WithRequireHTTPS(false))
	require.NoError(t, err)
	assert.False(t, client.RequiresHTTPS())
}

func TestAuthClient_RequiresHTTPS_NilReceiver(t *testing.T) {
	t.Parallel()

	var client *AuthClient

	assert.NotPanics(t, func() {
		assert.False(t, client.RequiresHTTPS())
		assert.NoError(t, client.insecureAddress())
	})
}

// downgradedClient builds a client that passed the https requirement at
// construction and then had its exported Address pointed at plaintext, with the
// decision cache and the breaker on so the test can prove neither moved.
func downgradedClient(t *testing.T) (*AuthClient, *countingServer) {
	t.Helper()

	secure := newCountingServer(t, true)
	plain := newCountingServer(t, false)

	client, err := NewAuthClientWithOptions(secure.URL, true, &testLogger{}, WithRequireHTTPS(true))
	require.NoError(t, err)

	client.cache = newDecisionCache(time.Minute)
	client.breaker = newAuthBreaker(1, time.Minute)
	client.retryMax = 2
	client.Address = plain.URL

	return client, plain
}

func cacheEntries(c *decisionCache) int {
	n := 0

	for _, shard := range c.shards {
		shard.mu.Lock()
		n += len(shard.entries)
		shard.mu.Unlock()
	}

	return n
}

func assertNothingMoved(t *testing.T, client *AuthClient, plain *countingServer) {
	t.Helper()

	assert.Zero(t, plain.conns.Load(), "a downgraded address must never be dialled")
	assert.Equal(t, gobreaker.StateClosed, client.breaker.State(), "a refused address is not an outage of the Access Manager")
	assert.Zero(t, cacheEntries(client.cache), "nothing is cached from a call that never happened")
}

func TestAuthClient_DowngradedAddressIsRefusedAtCallTime(t *testing.T) {
	t.Parallel()

	t.Run("fiber Authorize answers 503", func(t *testing.T) {
		t.Parallel()

		client, plain := downgradedClient(t)
		app, capture := newCapturingApp(client)

		gatedRequest(t, app, userToken())
		requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
		assertNothingMoved(t, client, plain)
	})

	t.Run("net/http AuthorizeHTTP answers 503", func(t *testing.T) {
		t.Parallel()

		client, plain := downgradedClient(t)

		reached := false
		handler := client.AuthorizeHTTP("midaz", "resource", "get")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+userToken())

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.False(t, reached)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assertNothingMoved(t, client, plain)
	})

	t.Run("Check answers 503 with the typed error", func(t *testing.T) {
		t.Parallel()

		client, plain := downgradedClient(t)

		authorized, code, err := client.Check(context.Background(), "midaz", "resource", "get", userToken(), "")

		assert.False(t, authorized)
		assert.Equal(t, http.StatusServiceUnavailable, code)
		requireInsecure(t, err)
		assertNothingMoved(t, client, plain)
	})

	t.Run("gRPC unary answers Unavailable", func(t *testing.T) {
		t.Parallel()

		client, plain := downgradedClient(t)
		interceptor := NewGRPCAuthUnaryPolicy(client, PolicyConfig{MethodPolicies: map[string]Policy{
			"/svc/Method": {Resource: "resource", Action: "get"},
		}})

		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+userToken()))
		reached := false

		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"},
			func(context.Context, any) (any, error) {
				reached = true

				return "ok", nil
			})

		assert.False(t, reached)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assertNothingMoved(t, client, plain)
	})

	t.Run("gRPC stream answers Unavailable", func(t *testing.T) {
		t.Parallel()

		client, plain := downgradedClient(t)
		defaultPol := Policy{Resource: "resource", Action: "get"}
		interceptor := NewGRPCAuthStreamPolicy(client, PolicyConfig{DefaultPolicy: &defaultPol})

		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+userToken()))
		reached := false

		err := interceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/svc/Stream"},
			func(any, grpc.ServerStream) error {
				reached = true

				return nil
			})

		assert.False(t, reached)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assertNothingMoved(t, client, plain)
	})

	t.Run("GetApplicationToken never sends the secret", func(t *testing.T) {
		t.Parallel()

		client, plain := downgradedClient(t)

		token, err := client.GetApplicationToken(context.Background(), "client-id", "client-secret")

		assert.Empty(t, token)
		requireInsecure(t, err)
		assert.NotContains(t, err.Error(), "client-secret")
		assert.Zero(t, plain.conns.Load())
	})
}

func TestAuthClient_RequirementOffStillDialsAMutatedPlaintextAddress(t *testing.T) {
	t.Parallel()

	plain := newCountingServer(t, false)

	client, err := NewAuthClientWithOptions("", true, &testLogger{})
	require.NoError(t, err)

	client.Address = plain.URL

	authorized, code, err := client.Check(context.Background(), "midaz", "resource", "get", userToken(), "")
	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, int64(1), plain.requests.Load(), "without the requirement plaintext behaves exactly as before")
}

func TestAuthClient_RequireHTTPSUnderConcurrency(t *testing.T) {
	t.Parallel()

	client, plain := downgradedClient(t)

	var wg sync.WaitGroup

	for range 32 {
		wg.Go(func() {
			_, code, err := client.Check(context.Background(), "midaz", "resource", "get", userToken(), "")
			assert.Equal(t, http.StatusServiceUnavailable, code)
			assert.ErrorIs(t, err, endpoint.ErrInsecure)
			assert.True(t, client.RequiresHTTPS())
		})
	}

	wg.Wait()
	assertNothingMoved(t, client, plain)
}

func TestJWKSKeySource_RequireHTTPS(t *testing.T) {
	t.Parallel()

	refused := map[string]string{
		"loopback http":     "http://127.0.0.1:8000/jwks",
		"localhost http":    "http://localhost:8000/jwks",
		"uppercase HTTP":    "HTTP://127.0.0.1:8000/jwks",
		"non-loopback http": "http://casdoor.example.com/jwks",
		"scheme-less":       "casdoor.example.com/jwks",
		"other scheme":      "ftp://casdoor.example.com/jwks",
	}

	for name, raw := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			t.Parallel()

			_, err := newJWKSKeySource(JWKSConfig{URL: raw, RequireHTTPS: true})
			require.ErrorIs(t, err, endpoint.ErrInsecure)

			var insecure *endpoint.InsecureError
			require.True(t, errors.As(err, &insecure))
			assert.Equal(t, "jwks key source", insecure.Component)
		})
	}

	t.Run("accepts https", func(t *testing.T) {
		t.Parallel()

		_, err := newJWKSKeySource(JWKSConfig{URL: "https://casdoor.example.com/jwks", RequireHTTPS: true})
		require.NoError(t, err)
	})

	t.Run("refuses the contradiction with AllowInsecureURL", func(t *testing.T) {
		t.Parallel()

		_, err := newJWKSKeySource(JWKSConfig{
			URL:              "https://casdoor.example.com/jwks",
			RequireHTTPS:     true,
			AllowInsecureURL: true,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AllowInsecureURL")
	})

	t.Run("a redirect hop to loopback http is refused", func(t *testing.T) {
		t.Parallel()

		_, err := validateJWKSURL("http://127.0.0.1:8000/jwks", false, true)
		require.ErrorIs(t, err, endpoint.ErrInsecure)

		_, err = validateJWKSURL("http://127.0.0.1:8000/jwks", false, false)
		require.NoError(t, err, "without the requirement loopback http stays allowed")
	})
}
