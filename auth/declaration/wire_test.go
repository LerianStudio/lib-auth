package declaration

import (
	"context"
	"net/http"
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

// TestWireFromEnv_TrimsWhitespace asserts the env values are trimmed before use:
// a padded-but-present identity host is accepted (it would be an INVALID URL if
// the surrounding spaces were not trimmed, so a nil error proves trimming ran).
func TestWireFromEnv_TrimsWhitespace(t *testing.T) {
	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	// Pad identity host, client id and secret with surrounding whitespace.
	setWireEnv(t, "   "+identity.URL+"   ", "", false)
	t.Setenv("M2M_CLIENT_ID", "  "+testClientID+"  ")
	t.Setenv("M2M_CLIENT_SECRET", "  "+testClientSecret+"  ")

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err,
		"padded-but-present values must be trimmed (untrimmed IdentityHost would be an invalid URL)")
	require.NotNil(t, stop)

	stop()
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
