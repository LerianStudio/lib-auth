package declaration

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/endpoint"
	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connCounter counts the TCP connections a test server accepts, so a test can
// prove a refused address was never dialled, TLS handshake included.
type connCounter struct {
	*httptest.Server
	conns atomic.Int64
}

func newConnCounter(t *testing.T, useTLS bool) *connCounter {
	t.Helper()

	cc := &connCounter{}
	cc.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cc.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			cc.conns.Add(1)
		}
	}

	if useTLS {
		cc.StartTLS()
	} else {
		cc.Start()
	}

	t.Cleanup(cc.Close)

	return cc
}

func httpsConfig(identityAddr string, auth TokenMinter) Config {
	return Config{
		Slug:         "plugin-fees",
		Manifest:     []byte(feesJSON),
		IdentityAddr: identityAddr,
		Auth:         auth,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RequireHTTPS: true,
	}
}

func TestNew_RequireHTTPSRefusesPlaintextIdentity(t *testing.T) {
	t.Parallel()

	for name, addr := range map[string]string{
		"http":           "http://identity.example",
		"uppercase HTTP": "HTTP://identity.example",
		"loopback http":  "http://127.0.0.1:4001",
		"scheme-less":    "identity.example:4001",
		"other scheme":   "ws://identity.example",
		"hostless":       "https:///v1",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := New(httpsConfig(addr, &fakeMinter{token: "token"}))
			require.ErrorIs(t, err, endpoint.ErrInsecure)

			var insecure *endpoint.InsecureError
			require.True(t, errors.As(err, &insecure))
			assert.Equal(t, "declaration publisher", insecure.Component)
		})
	}
}

func TestNew_RequireHTTPSAcceptsHTTPSIdentity(t *testing.T) {
	t.Parallel()

	for _, addr := range []string{"https://identity.example", "HTTPS://identity.example:8443/base"} {
		_, err := New(httpsConfig(addr, &fakeMinter{token: "token"}))
		require.NoError(t, err, addr)
	}
}

func TestNew_RequireHTTPSChecksTheMinterPosture(t *testing.T) {
	t.Parallel()

	t.Run("an auth client that allows plaintext is refused", func(t *testing.T) {
		t.Parallel()

		_, err := New(httpsConfig("https://identity.example", middleware.NewAuthClient("", true, obs.Nop())))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "WithRequireHTTPS")
	})

	t.Run("a nil auth client is refused", func(t *testing.T) {
		t.Parallel()

		var auth *middleware.AuthClient

		_, err := New(httpsConfig("https://identity.example", auth))
		require.Error(t, err)
	})

	t.Run("an auth client that requires https is accepted", func(t *testing.T) {
		t.Parallel()

		auth, err := middleware.NewAuthClientWithOptions("", true, obs.Nop(), middleware.WithRequireHTTPS(true))
		require.NoError(t, err)

		_, err = New(httpsConfig("https://identity.example", auth))
		require.NoError(t, err)
	})

	t.Run("a minter that declares no posture is accepted", func(t *testing.T) {
		t.Parallel()

		_, err := New(httpsConfig("https://identity.example", &fakeMinter{token: "token"}))
		require.NoError(t, err)
	})
}

func TestNew_RequirementOffKeepsPlaintextIdentity(t *testing.T) {
	t.Parallel()

	cfg := httpsConfig("http://identity.example", middleware.NewAuthClient("", true, obs.Nop()))
	cfg.RequireHTTPS = false

	_, err := New(cfg)
	require.NoError(t, err)
}

func wireInputRequiringHTTPS() WireInput {
	in := wireInput()
	in.RequireHTTPS = true

	return in
}

func TestWireFromEnv_RequireHTTPSRefusesPlaintextIdentityHost(t *testing.T) {
	auth := newConnCounter(t, true)
	identity := newConnCounter(t, false)

	setWireEnvCanonical(t, identity.URL, auth.URL, true)

	stop, err := WireFromEnv(context.Background(), wireInputRequiringHTTPS())
	require.NotNil(t, stop, "every error path returns a non-nil stop")
	require.ErrorIs(t, err, endpoint.ErrInsecure)
	assert.True(t, strings.HasPrefix(err.Error(), "IDP_HOST"), "the error names the variable: %v", err)
	assert.Zero(t, identity.conns.Load())
	assert.Zero(t, auth.conns.Load(), "a refused identity host stops the boot before the auth client dials")
}

func TestWireFromEnv_RequireHTTPSRefusesPlaintextAuthHost(t *testing.T) {
	for name, set := range map[string]func(t *testing.T, identity, auth string){
		"canonical": func(t *testing.T, identity, auth string) {
			t.Helper()
			setWireEnvCanonical(t, identity, auth, true)
			t.Setenv("PLUGIN_AUTH_ADDRESS", "")
		},
		"alias": func(t *testing.T, identity, auth string) {
			t.Helper()
			setWireEnvCanonical(t, identity, "", true)
			t.Setenv("PLUGIN_AUTH_ADDRESS", auth)
		},
	} {
		t.Run(name, func(t *testing.T) {
			auth := newConnCounter(t, false)
			identity := newConnCounter(t, true)

			set(t, identity.URL, auth.URL)

			stop, err := WireFromEnv(context.Background(), wireInputRequiringHTTPS())
			require.NotNil(t, stop)
			require.ErrorIs(t, err, endpoint.ErrInsecure)
			assert.True(t, strings.HasPrefix(err.Error(), "PLUGIN_AUTH_HOST"), "the error names the variable: %v", err)
			assert.Contains(t, err.Error(), "PLUGIN_AUTH_ADDRESS")
			assert.Zero(t, auth.conns.Load(), "the plaintext auth host is never dialled, health check included")
			assert.Zero(t, identity.conns.Load())
		})
	}
}

func TestWireFromEnv_RequireHTTPSAcceptsHTTPSHosts(t *testing.T) {
	auth := newConnCounter(t, true)
	identity := newConnCounter(t, true)

	setWireEnvCanonical(t, identity.URL, auth.URL, true)

	stop, err := WireFromEnv(context.Background(), wireInputRequiringHTTPS())
	require.NoError(t, err)
	require.NotNil(t, stop)
	stop()
}

func TestWireFromEnv_RequirementOffKeepsPlaintextHosts(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newConnCounter(t, false)

	setWireEnvCanonical(t, identity.URL, auth.URL, true)

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err)
	require.NotNil(t, stop)
	stop()
}
