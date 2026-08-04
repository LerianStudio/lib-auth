package declaration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	liblog "github.com/LerianStudio/lib-observability/v2/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setWireEnv seeds the FIXED, un-prefixed env contract WireFromEnv consumes so
// each test can then mutate a single knob. It intentionally sets EVERY variable
// (via t.Setenv) so a leftover value from the host env can never bleed into a
// case — t.Setenv also forbids t.Parallel, which is why these tests are serial.
func setWireEnv(t *testing.T, identityHost, authHost string, authEnabled bool) {
	t.Helper()

	t.Setenv("DECLARATION_ENABLED", "true")
	t.Setenv("PLUGIN_IDENTITY_HOST", identityHost)
	t.Setenv("M2M_CLIENT_ID", testClientID)
	t.Setenv("M2M_CLIENT_SECRET", testClientSecret)
	t.Setenv("PLUGIN_AUTH_HOST", authHost)

	if authEnabled {
		t.Setenv("PLUGIN_AUTH_ENABLED", "true")
	} else {
		t.Setenv("PLUGIN_AUTH_ENABLED", "false")
	}
}

// wireInput builds a valid WireInput matching the feesJSON fixture (Slug ==
// manifest.service, so New's BOLA check passes).
func wireInput() WireInput {
	return WireInput{
		Slug:     "plugin-fees",
		Manifest: []byte(feesJSON),
		Logger:   liblog.NewNop(),
	}
}

// TestWireFromEnv_Disabled asserts the default-off path: when DECLARATION_ENABLED
// is not "true", WireFromEnv reads/validates NOTHING else (no identity host, no
// creds set), returns a non-nil no-op stop and a nil error, and stop() is safe.
func TestWireFromEnv_Disabled(t *testing.T) {
	cases := map[string]string{
		"unset":       "",
		"explicit-no": "false",
		"garbage":     "1",
	}

	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			// Only the flag is set (to a non-"true" value, or empty). NO other
			// env is provided — proving the disabled path validates nothing.
			if val == "" {
				t.Setenv("DECLARATION_ENABLED", "")
			} else {
				t.Setenv("DECLARATION_ENABLED", val)
			}

			stop, err := WireFromEnv(context.Background(), wireInput())
			require.NoError(t, err, "disabled path must never error")
			require.NotNil(t, stop, "disabled path must return a non-nil no-op stop")

			assert.NotPanics(t, func() { stop() }, "stop() must be safe to call")
		})
	}
}

// TestWireFromEnv_MissingRequired asserts that, when enabled, each required env
// var — when blank — yields a clear error that NAMES the missing variable, and
// that the returned stop is always non-nil (deferred stop() must never nil-panic).
func TestWireFromEnv_MissingRequired(t *testing.T) {
	cases := map[string]struct {
		blankVar string
		wantName string
	}{
		"missing identity host": {"PLUGIN_IDENTITY_HOST", "PLUGIN_IDENTITY_HOST"},
		"missing client id":     {"M2M_CLIENT_ID", "M2M_CLIENT_ID"},
		"missing client secret": {"M2M_CLIENT_SECRET", "M2M_CLIENT_SECRET"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			setWireEnv(t, "http://identity.local:4001", "http://auth.local:4000", false)
			t.Setenv(tc.blankVar, "   ") // whitespace-only == blank after trim

			stop, err := WireFromEnv(context.Background(), wireInput())
			require.Error(t, err, "a blank required var must error")
			require.NotNil(t, stop, "error path must still return a non-nil no-op stop")
			assert.Contains(t, err.Error(), tc.wantName,
				"the error must name the missing env var")

			assert.NotPanics(t, func() { stop() }, "stop() must be safe on the error path")
		})
	}
}

// capturingAuthServer stands in for the AUTH host and records the credentials it
// receives on the M2M token-mint call, so a test can prove the TRIMMED values
// reached the wire (not merely that WireFromEnv returned no error).
type capturingAuthServer struct {
	*httptest.Server
	mu           sync.Mutex
	gotClientID  string
	gotSecret    string
	gotMintCount int
}

// newCapturingAuthServer builds an auth server that captures the JSON
// {clientId, clientSecret} body of the token-mint request (the exact shape
// middleware.AuthClient.GetApplicationToken POSTs) and returns a token.
func newCapturingAuthServer(t *testing.T) *capturingAuthServer {
	t.Helper()

	cas := &capturingAuthServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ClientID     string `json:"clientId"`
			ClientSecret string `json:"clientSecret"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		cas.mu.Lock()
		cas.gotClientID = body.ClientID
		cas.gotSecret = body.ClientSecret
		cas.gotMintCount++
		cas.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"accessToken":%q}`, testToken)
	})

	cas.Server = httptest.NewServer(mux)

	return cas
}

// TestWireFromEnv_TrimsWhitespace asserts the env values are trimmed BEFORE they
// reach the wire. It does not settle for a nil error (FailFast is false, so a
// no-op could pass): it waits for the background PUT, then asserts the auth host
// received the TRIMMED M2M client id/secret and the identity host received the
// TRIMMED base URL (a clean /v1/declarations/<slug> path, no stray whitespace).
func TestWireFromEnv_TrimsWhitespace(t *testing.T) {
	auth := newCapturingAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	// Pad identity host, client id and secret with surrounding whitespace.
	setWireEnv(t, "   "+identity.URL+"   ", auth.URL, true)
	t.Setenv("M2M_CLIENT_ID", "  "+testClientID+"  ")
	t.Setenv("M2M_CLIENT_SECRET", "  "+testClientSecret+"  ")

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err,
		"padded-but-present values must be trimmed (untrimmed IdentityHost would be an invalid URL)")
	require.NotNil(t, stop)
	t.Cleanup(stop)

	// Block until the background publisher actually PUTs, so the assertions below
	// observe a real request rather than a no-op that returned before publishing.
	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background declaration PUT")
	}

	// The auth host must have minted a token with the TRIMMED credentials.
	auth.mu.Lock()
	gotClientID, gotSecret, mintCount := auth.gotClientID, auth.gotSecret, auth.gotMintCount
	auth.mu.Unlock()

	require.GreaterOrEqual(t, mintCount, 1, "the publisher must have minted a token")
	assert.Equal(t, testClientID, gotClientID,
		"the auth host must receive the TRIMMED M2M_CLIENT_ID")
	assert.Equal(t, testClientSecret, gotSecret,
		"the auth host must receive the TRIMMED M2M_CLIENT_SECRET")

	// The identity host must see a clean, trimmed path (no leaked whitespace).
	identity.mu.Lock()
	gotPath := identity.gotPath
	identity.mu.Unlock()
	assert.Equal(t, "/v1/declarations/plugin-fees", gotPath,
		"the TRIMMED identity host must yield a clean request path")
}

// TestWireFromEnv_HappyPath asserts the full wiring: valid env + auth/identity
// test hosts produce a non-nil stop and a nil error (Start fail-opens, so it
// never blocks on identity reachability), and a background PUT is attempted.
func TestWireFromEnv_HappyPath(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	setWireEnv(t, identity.URL, auth.URL, true)

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err)
	require.NotNil(t, stop)
	t.Cleanup(stop)

	// The background publisher must attempt a PUT against identity.
	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background declaration PUT")
	}
}

// TestWireFromEnv_HappyPath_IdentityUnreachable asserts Start's fail-open contract
// survives the wire: even with an unreachable identity host, WireFromEnv returns a
// non-nil stop and nil error (serving is never blocked by the access-manager).
func TestWireFromEnv_HappyPath_IdentityUnreachable(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	// A syntactically valid but unreachable identity host.
	setWireEnv(t, "http://127.0.0.1:1", auth.URL, true)

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err, "fail-open: an unreachable identity must NOT fatal WireFromEnv")
	require.NotNil(t, stop)

	assert.NotPanics(t, func() { stop() })
}
