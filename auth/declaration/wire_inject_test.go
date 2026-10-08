package declaration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countAuthClientBuilds swaps the package's AuthClient constructor for one that
// counts its calls, so a test can prove whether WireFromEnv built a client of its
// own. The original constructor is restored on cleanup.
func countAuthClientBuilds(t *testing.T) *int {
	t.Helper()

	orig := newAuthClient
	builds := 0

	newAuthClient = func(address string, enabled bool, logger obs.Logger) *middleware.AuthClient {
		builds++

		return orig(address, enabled, logger)
	}

	t.Cleanup(func() { newAuthClient = orig })

	return &builds
}

// failIfCalled stands in for an auth host that must never be contacted: the env
// one, when the service injects its own client.
func failIfCalled(t *testing.T, why string) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error(why)
	}))
	t.Cleanup(srv.Close)

	return srv
}

// With no client injected, WireFromEnv builds exactly one from the env auth
// host, as it always has.
func TestWireFromEnv_NilAuthClient_BuildsOneFromEnv(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	setWireEnvCanonical(t, identity.URL, auth.URL, true)

	builds := countAuthClientBuilds(t)

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err)
	require.NotNil(t, stop)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background declaration PUT")
	}

	assert.Equal(t, 1, *builds, "without an injected client WireFromEnv builds its own from the env")
}

// An injected client mints the token, no second client is built, and the env
// auth host and switch are not read: PLUGIN_AUTH_HOST points at a server that
// fails the test if contacted, and PLUGIN_AUTH_ENABLED is off.
func TestWireFromEnv_InjectedAuthClient_IsTheOneUsed(t *testing.T) {
	auth := newCapturingAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	envAuth := failIfCalled(t, "the env auth host must not be used when a client is injected")

	setWireEnvCanonical(t, identity.URL, envAuth.URL, false)
	t.Setenv("PLUGIN_AUTH_ADDRESS", envAuth.URL)

	injected := middleware.NewAuthClient(auth.URL, true, obs.Nop())
	builds := countAuthClientBuilds(t)

	in := wireInput()
	in.AuthClient = injected

	stop, err := WireFromEnv(context.Background(), in)
	require.NoError(t, err, "the injected client replaces PLUGIN_AUTH_HOST and PLUGIN_AUTH_ENABLED")
	require.NotNil(t, stop)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background declaration PUT")
	}

	auth.mu.Lock()
	mints, gotClientID := auth.gotMintCount, auth.gotClientID
	auth.mu.Unlock()

	assert.GreaterOrEqual(t, mints, 1, "the injected client must mint the publisher's token")
	assert.Equal(t, testClientID, gotClientID)
	assert.Zero(t, *builds, "WireFromEnv must not build a second client")
}

// The injected client replaces only the auth pair: the identity host and the M2M
// credentials stay required, each with the error naming its variable.
func TestWireFromEnv_InjectedAuthClient_StillRequiresIdentityConfig(t *testing.T) {
	cases := map[string]string{
		"IDP_HOST":              "IDP_HOST",
		"IDP_M2M_CLIENT_ID":     "IDP_M2M_CLIENT_ID",
		"IDP_M2M_CLIENT_SECRET": "IDP_M2M_CLIENT_SECRET",
	}

	for blank, wantName := range cases {
		t.Run(blank, func(t *testing.T) {
			setWireEnvCanonical(t, "http://identity.local:4001", "", false)

			for _, alias := range []string{"PLUGIN_IDENTITY_HOST", "M2M_CLIENT_ID", "M2M_CLIENT_SECRET"} {
				t.Setenv(alias, "")
			}

			t.Setenv(blank, " ")

			in := wireInput()
			in.AuthClient = &middleware.AuthClient{Address: "http://auth.local:4000", Enabled: true}

			stop, err := WireFromEnv(context.Background(), in)
			require.Error(t, err)
			require.NotNil(t, stop)
			assert.Contains(t, err.Error(), wantName)
			assert.NotPanics(t, func() { stop() })
		})
	}
}

// An injected client that cannot mint a token is the same permanent
// misconfiguration the env pair guards against, and fails closed by name.
func TestWireFromEnv_InjectedAuthClient_UnusableFailsClosed(t *testing.T) {
	cases := map[string]struct {
		client   *middleware.AuthClient
		wantText string
	}{
		"disabled":      {&middleware.AuthClient{Address: "http://auth.local:4000", Enabled: false}, "WireInput.AuthClient.Enabled"},
		"empty address": {&middleware.AuthClient{Address: "  ", Enabled: true}, "WireInput.AuthClient.Address"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			setWireEnvCanonical(t, "http://identity.local:4001", "http://auth.local:4000", true)

			builds := countAuthClientBuilds(t)

			in := wireInput()
			in.AuthClient = tc.client

			stop, err := WireFromEnv(context.Background(), in)
			require.Error(t, err, "an injected client that cannot mint must not fall back to the env")
			require.NotNil(t, stop)
			assert.Contains(t, err.Error(), tc.wantText)
			assert.Contains(t, err.Error(), "IDP_DECLARATION_ENABLED")
			assert.Zero(t, *builds)
			assert.NotPanics(t, func() { stop() })
		})
	}
}

// Flag off and no scope: the injected client changes nothing, even a disabled
// one. WireFromEnv validates nothing and returns a no-op.
func TestWireFromEnv_InjectedAuthClient_DisabledFlagIsNoop(t *testing.T) {
	clearCanonicalIDPEnv(t)
	t.Setenv("DECLARATION_ENABLED", "")
	t.Setenv("PLUGIN_AUTH_ENABLED", "")

	in := wireInput()
	in.AuthClient = &middleware.AuthClient{}

	stop, err := WireFromEnv(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, stop)
	assert.NotPanics(t, func() { stop() })
}

// Declaration off, scope declared: the injected client publishes the scope
// alone. Whether auth is on is the client's own Enabled, not PLUGIN_AUTH_ENABLED.
func TestWireFromEnv_InjectedAuthClient_PublishesScopeOnly(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	envAuth := failIfCalled(t, "the env auth host must not be used when a client is injected")

	setScopeOnlyEnv(t, identity.URL, envAuth.URL)
	t.Setenv("PLUGIN_AUTH_ENABLED", "")

	injected := middleware.NewAuthClient(auth.URL, true, obs.Nop())
	builds := countAuthClientBuilds(t)

	in := scopedWireInput(obs.Nop())
	in.AuthClient = injected

	stop, err := WireFromEnv(context.Background(), in)
	require.NoError(t, err)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background scope-only PUT")
	}

	assert.Zero(t, *builds, "the scope-only path must not build a second client either")
}

// Declaration off, scope declared, injected client disabled: auth is off for
// this service, so nothing is published and the boot is unchanged.
func TestWireFromEnv_InjectedAuthClient_DisabledSkipsScopeOnly(t *testing.T) {
	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	setScopeOnlyEnv(t, identity.URL, "http://auth.local:4000")

	logger := &errorLogger{}
	in := scopedWireInput(logger)
	in.AuthClient = &middleware.AuthClient{Address: "http://auth.local:4000", Enabled: false}

	stop, err := WireFromEnv(context.Background(), in)
	require.NoError(t, err)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
		t.Fatal("a disabled injected client must not publish the scope")
	case <-time.After(200 * time.Millisecond):
	}

	logger.mu.Lock()
	defer logger.mu.Unlock()
	assert.Empty(t, logger.errors, "auth off is not an error")
}
