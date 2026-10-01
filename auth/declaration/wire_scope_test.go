package declaration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setScopeOnlyEnv seeds a deployment whose permission declaration is OFF while
// its auth is ON: the configuration in which only the scope is published.
func setScopeOnlyEnv(t *testing.T, identityHost, authHost string) {
	t.Helper()

	setWireEnvCanonical(t, identityHost, authHost, true)
	t.Setenv("IDP_DECLARATION_ENABLED", "false")

	// Blank the deprecated aliases so an ambient value cannot stand in for a
	// canonical variable a case blanks.
	for _, alias := range []string{"DECLARATION_ENABLED", "PLUGIN_IDENTITY_HOST", "M2M_CLIENT_ID", "M2M_CLIENT_SECRET", "PLUGIN_AUTH_ADDRESS"} {
		t.Setenv(alias, "")
	}
}

func scopedWireInput(logger obs.Logger) WireInput {
	return WireInput{Slug: "plugin-fees", Manifest: []byte(scopedJSON), Logger: logger}
}

// errorLogger records the messages logged at ERROR.
type errorLogger struct {
	recordingLogger
	errors []string
}

func (l *errorLogger) Log(ctx context.Context, level int, msg string, args ...any) {
	if level == obs.LevelError {
		l.mu.Lock()
		l.errors = append(l.errors, msg)
		l.mu.Unlock()
	}

	l.recordingLogger.Log(ctx, level, msg, args...)
}

func TestWireFromEnv_DeclarationOff_AuthOn_PublishesScopeOnly(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	setScopeOnlyEnv(t, identity.URL, auth.URL)

	stop, err := WireFromEnv(context.Background(), scopedWireInput(obs.Nop()))
	require.NoError(t, err)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background scope-only PUT")
	}

	identity.mu.Lock()
	body := identity.gotBody
	identity.mu.Unlock()

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.ElementsMatch(t, []string{"service", "version", "scope"}, keys(got),
		"with the permission declaration off only the scope is published")
}

// Declaration ON: the full manifest goes out, scope included.
func TestWireFromEnv_DeclarationOn_PublishesScopeWithPermissions(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	setWireEnvCanonical(t, identity.URL, auth.URL, true)

	stop, err := WireFromEnv(context.Background(), scopedWireInput(obs.Nop()))
	require.NoError(t, err)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background PUT")
	}

	identity.mu.Lock()
	body := identity.gotBody
	identity.mu.Unlock()

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Subset(t, keys(got), []string{"permissions", "roles", "scope"})
}

// A manifest without a scope keeps the declaration-off boot exactly as before:
// nothing is validated, nothing is called, even with auth on.
func TestWireFromEnv_DeclarationOff_AuthOn_NoScope_IsNoop(t *testing.T) {
	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	clearCanonicalIDPEnv(t)
	t.Setenv("DECLARATION_ENABLED", "")
	t.Setenv("PLUGIN_AUTH_ENABLED", "true")
	t.Setenv("PLUGIN_AUTH_HOST", "")

	stop, err := WireFromEnv(context.Background(), wireInput())
	require.NoError(t, err)
	require.NotNil(t, stop)
	stop()

	assert.Equal(t, 0, identity.count())
}

// Auth off: the scope is not published either — there is no M2M token to
// publish it with, and the product is not enforcing anything.
func TestWireFromEnv_DeclarationOff_AuthOff_IsNoop(t *testing.T) {
	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	setScopeOnlyEnv(t, identity.URL, "http://127.0.0.1:1")
	t.Setenv("PLUGIN_AUTH_ENABLED", "false")

	stop, err := WireFromEnv(context.Background(), scopedWireInput(obs.Nop()))
	require.NoError(t, err)
	stop()

	assert.Equal(t, 0, identity.count())
}

// A scope that cannot be published for lack of configuration is logged at ERROR
// naming the variable, and never fails the boot: the product keeps serving.
func TestWireFromEnv_ScopeOnly_MissingConfig_LogsAndServes(t *testing.T) {
	for _, blank := range []string{"IDP_HOST", "IDP_M2M_CLIENT_ID", "IDP_M2M_CLIENT_SECRET", "PLUGIN_AUTH_HOST"} {
		t.Run(blank, func(t *testing.T) {
			setScopeOnlyEnv(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
			t.Setenv(blank, "")

			logger := &errorLogger{}

			stop, err := WireFromEnv(context.Background(), scopedWireInput(logger))
			require.NoError(t, err, "a scope that cannot be published must not fail the boot")
			require.NotNil(t, stop)
			stop()

			logger.mu.Lock()
			defer logger.mu.Unlock()

			require.Len(t, logger.errors, 1)
			assert.Contains(t, logger.errors[0], blank)
		})
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	return out
}
