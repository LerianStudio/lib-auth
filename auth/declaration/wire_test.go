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

	"github.com/LerianStudio/lib-auth/v4/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setWireEnv seeds the DEPRECATED, un-prefixed env aliases WireFromEnv still
// honors so each test can then mutate a single knob. It intentionally sets EVERY
// variable (via t.Setenv) so a leftover value from the host env can never bleed
// into a case — t.Setenv also forbids t.Parallel, which is why these tests are
// serial.
//
// The canonical IDP_* names are explicitly BLANKED first: lookupWithDeprecatedAlias
// prefers a non-empty canonical value, so an ambient IDP_* in the host/CI env would
// otherwise win over the alias this fixture is exercising — silently testing the
// wrong path (and pointing the publisher's background request at the host IDP_HOST).
func setWireEnv(t *testing.T, identityHost, authHost string, authEnabled bool) {
	t.Helper()

	clearCanonicalIDPEnv(t)

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

// clearCanonicalIDPEnv blanks the four canonical IDP_* variables so an ambient
// value from the host or CI environment cannot override the deprecated aliases a
// test fixture sets. Blank (not unset) is sufficient and is what t.Setenv offers:
// lookupWithDeprecatedAlias trims before testing for emptiness, so a blank
// canonical falls through to the alias exactly as an unset one would.
func clearCanonicalIDPEnv(t *testing.T) {
	t.Helper()

	for _, name := range []string{
		"IDP_DECLARATION_ENABLED",
		"IDP_HOST",
		"IDP_M2M_CLIENT_ID",
		"IDP_M2M_CLIENT_SECRET",
	} {
		t.Setenv(name, "")
	}
}

// wireInput builds a valid WireInput matching the feesJSON fixture (Slug ==
// manifest.service, so New's BOLA check passes).
func wireInput() WireInput {
	return WireInput{
		Slug:     "plugin-fees",
		Manifest: []byte(feesJSON),
		Logger:   obs.Nop(),
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
			// The canonical IDP_* names are blanked so an ambient
			// IDP_DECLARATION_ENABLED=true in the host/CI env cannot win over the
			// alias and flip this case onto the ENABLED path — which would still
			// satisfy every assertion below (a wired publisher also returns a
			// non-nil stop and a nil error) while silently testing the opposite
			// branch and firing a background publish at the host IDP_HOST.
			clearCanonicalIDPEnv(t)

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
		// setWireEnv seeds the deprecated aliases; blanking the alias leaves the
		// (unset) canonical value empty too, so validation fires and names the
		// canonical IDP_ var — the post-#4232 error contract.
		"missing identity host": {"PLUGIN_IDENTITY_HOST", "IDP_HOST"},
		"missing client id":     {"M2M_CLIENT_ID", "IDP_M2M_CLIENT_ID"},
		"missing client secret": {"M2M_CLIENT_SECRET", "IDP_M2M_CLIENT_SECRET"},
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

// recordingLogger is a minimal obs.Logger spy that records the messages
// emitted at LevelWarn, so a test can assert the deprecated-alias warning fires
// exactly once and never carries a secret value.
type recordingLogger struct {
	mu    sync.Mutex
	warns []string
}

func (l *recordingLogger) Log(_ context.Context, level int, msg string, _ ...any) {
	if level != obs.LevelWarn {
		return
	}

	l.mu.Lock()
	l.warns = append(l.warns, msg)
	l.mu.Unlock()
}

func (l *recordingLogger) Enabled(_ int) bool           { return true }
func (l *recordingLogger) Sync(_ context.Context) error { return nil }

func (l *recordingLogger) warnCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.warns)
}

// TestLookupWithDeprecatedAlias exercises the canonical-wins / deprecated-fallback
// resolver directly: canonical set (regardless of the alias) wins silently; only
// the alias set returns its TRIMMED value and warns exactly once (naming both
// vars, never a value); neither set returns "".
func TestLookupWithDeprecatedAlias(t *testing.T) {
	const (
		canonicalKey  = "IDP_TEST_CANONICAL"
		deprecatedKey = "TEST_DEPRECATED"
	)

	cases := map[string]struct {
		canonical  string
		deprecated string
		want       string
		wantWarns  int
	}{
		"canonical wins over alias":  {canonical: "  canon  ", deprecated: "legacy", want: "canon", wantWarns: 0},
		"canonical only":             {canonical: "canon", deprecated: "", want: "canon", wantWarns: 0},
		"alias only warns once":      {canonical: "", deprecated: "  legacy  ", want: "legacy", wantWarns: 1},
		"canonical blank falls back": {canonical: "   ", deprecated: "legacy", want: "legacy", wantWarns: 1},
		"neither set":                {canonical: "", deprecated: "", want: "", wantWarns: 0},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(canonicalKey, tc.canonical)
			t.Setenv(deprecatedKey, tc.deprecated)

			rec := &recordingLogger{}
			got := lookupWithDeprecatedAlias(canonicalKey, deprecatedKey, rec)

			assert.Equal(t, tc.want, got, "resolved value")
			assert.Equal(t, tc.wantWarns, rec.warnCount(), "warn count")

			for _, msg := range rec.warns {
				assert.Contains(t, msg, deprecatedKey, "warn must name the deprecated var")
				assert.Contains(t, msg, canonicalKey, "warn must name the canonical var")
				assert.NotContains(t, msg, "legacy", "warn must NEVER log the value")
			}
		})
	}
}

// TestLookupWithDeprecatedAlias_NilLogger asserts the resolver tolerates a nil
// logger on the deprecated-alias path (it must resolve the value, not nil-panic).
func TestLookupWithDeprecatedAlias_NilLogger(t *testing.T) {
	t.Setenv("IDP_TEST_CANONICAL", "")
	t.Setenv("TEST_DEPRECATED", "legacy")

	var got string
	assert.NotPanics(t, func() {
		got = lookupWithDeprecatedAlias("IDP_TEST_CANONICAL", "TEST_DEPRECATED", nil)
	})
	assert.Equal(t, "legacy", got)
}

// setWireEnvCanonical seeds ONLY the canonical IDP_ contract (no deprecated
// aliases), proving WireFromEnv reads the new names.
func setWireEnvCanonical(t *testing.T, identityHost, authHost string, authEnabled bool) {
	t.Helper()

	t.Setenv("IDP_DECLARATION_ENABLED", "true")
	t.Setenv("IDP_HOST", identityHost)
	t.Setenv("IDP_M2M_CLIENT_ID", testClientID)
	t.Setenv("IDP_M2M_CLIENT_SECRET", testClientSecret)
	t.Setenv("PLUGIN_AUTH_HOST", authHost)

	if authEnabled {
		t.Setenv("PLUGIN_AUTH_ENABLED", "true")
	} else {
		t.Setenv("PLUGIN_AUTH_ENABLED", "false")
	}
}

// TestWireFromEnv_CanonicalNames asserts the canonical IDP_ contract drives the
// full wiring end-to-end (a background PUT is attempted against identity).
func TestWireFromEnv_CanonicalNames(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	setWireEnvCanonical(t, identity.URL, auth.URL, true)

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err)
	require.NotNil(t, stop)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background declaration PUT from the canonical IDP_ contract")
	}
}

// TestWireFromEnv_CanonicalWinsOverDeprecated asserts that when BOTH the canonical
// and the deprecated identity host are set, the canonical IDP_HOST wins: the PUT
// lands on the canonical identity server, and the deprecated one is never hit.
func TestWireFromEnv_CanonicalWinsOverDeprecated(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	canonical := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(canonical.Close)

	deprecated := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(deprecated.Close)

	setWireEnvCanonical(t, canonical.URL, auth.URL, true)
	// Also set the deprecated identity host to a DIFFERENT server.
	t.Setenv("PLUGIN_IDENTITY_HOST", deprecated.URL)

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err)
	require.NotNil(t, stop)
	t.Cleanup(stop)

	select {
	case <-canonical.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the PUT on the CANONICAL identity host")
	}

	select {
	case <-deprecated.puts:
		t.Fatal("the deprecated identity host must NOT be used when canonical is set")
	case <-time.After(200 * time.Millisecond):
		// expected: no PUT on the deprecated server.
	}
}

// TestWireFromEnv_DeprecatedAliasesStillWork asserts the one-release compat window:
// with ONLY the deprecated aliases set (no IDP_ names), WireFromEnv still wires up
// and attempts a background PUT.
func TestWireFromEnv_DeprecatedAliasesStillWork(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	// Deprecated names only (this is exactly what setWireEnv seeds).
	setWireEnv(t, identity.URL, auth.URL, true)

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err)
	require.NotNil(t, stop)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background declaration PUT from the deprecated-alias contract")
	}
}
