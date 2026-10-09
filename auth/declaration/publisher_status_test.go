package declaration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func waitState(t *testing.T, st *Status, want State) {
	t.Helper()

	require.Eventually(t, func() bool { return st.State() == want },
		5*time.Second, time.Millisecond, "status never reached %s (last %s)", want, st.State())
}

func TestStatus_ZeroValueIsIdle(t *testing.T) {
	var st Status

	assert.Equal(t, StateIdle, st.State())
	assert.Equal(t, "idle", st.State().String())
}

// A refusal is permanent: one PUT, reported failed, logged at ERROR, never retried.
func TestStart_DeterministicRefusalStopsAndReportsFailed(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusForbidden, `{"message":"nope"}`)
	t.Cleanup(identity.Close)

	var st Status

	logs := &captureLogger{}
	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Status = &st
	cfg.Logger = logs
	p := newFastPublisher(t, cfg)

	stop, err := p.Start(context.Background())
	require.NoError(t, err)

	waitState(t, &st, StateFailed)
	stop()

	assert.Equal(t, 1, identity.count(), "a refusal must not be retried")

	_, level, found := logs.find("status=403")
	require.True(t, found, "the refusal must be logged; got:\n%s", logs.all())
	assert.Equal(t, obs.LevelError, level)
}

func TestWireFromEnv_ReportsStatus(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	setWireEnv(t, identity.URL, auth.URL, true)

	var st Status

	in := wireInput()
	in.Status = &st

	stop, err := WireFromEnv(context.Background(), in)
	require.NoError(t, err)
	t.Cleanup(stop)

	waitState(t, &st, StatePublished)
}

func TestWireFromEnv_Off_LeavesStatusIdle(t *testing.T) {
	clearCanonicalIDPEnv(t)
	t.Setenv("DECLARATION_ENABLED", "")
	t.Setenv("PLUGIN_AUTH_ENABLED", "false")

	var st Status

	in := wireInput()
	in.Status = &st

	stop, err := WireFromEnv(context.Background(), in)
	require.NoError(t, err)
	stop()

	assert.Equal(t, StateIdle, st.State())
}

// A scope that cannot be published for lack of configuration reads failed, not idle.
func TestWireFromEnv_ScopeOnly_MissingConfig_ReportsFailed(t *testing.T) {
	setScopeOnlyEnv(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
	t.Setenv("IDP_HOST", "")

	var st Status

	in := scopedWireInput(obs.Nop())
	in.Status = &st

	stop, err := WireFromEnv(context.Background(), in)
	require.NoError(t, err)
	stop()

	assert.Equal(t, StateFailed, st.State())
}
