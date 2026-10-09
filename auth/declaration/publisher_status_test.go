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

func (is *identityServer) setStatus(status int) {
	is.mu.Lock()
	defer is.mu.Unlock()

	is.status = status
}

func waitPuts(t *testing.T, is *identityServer, n int) {
	t.Helper()

	for i := 1; i <= n; i++ {
		select {
		case <-is.puts:
		case <-time.After(5 * time.Second):
			t.Fatalf("expected PUT #%d", i)
		}
	}
}

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

// An access manager that comes up after the budget of a single Publish call is
// spent still receives the declaration: the background publish keeps retrying.
func TestStart_RetriesTransientPastTheBudgetUntilAccepted(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusServiceUnavailable, `{}`)
	t.Cleanup(identity.Close)

	var st Status

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Status = &st
	p := newFastPublisher(t, cfg)

	stop, err := p.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(stop)

	assert.Equal(t, StatePending, st.State(), "pending from Start until the access manager answers")

	waitPuts(t, identity, int(p.maxTries)+1)
	assert.Equal(t, StatePending, st.State())

	identity.setStatus(http.StatusOK)
	waitState(t, &st, StatePublished)
	assert.Equal(t, "published", st.State().String())
	assert.Greater(t, identity.count(), int(p.maxTries))
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

// stop ends a retry that would otherwise run for as long as the outage lasts.
func TestStart_StopEndsTheRetry(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusServiceUnavailable, `{}`)
	t.Cleanup(identity.Close)

	var st Status

	logs := &captureLogger{}
	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Status = &st
	cfg.Logger = logs
	p := newFastPublisher(t, cfg)

	stop, err := p.Start(context.Background())
	require.NoError(t, err)

	waitPuts(t, identity, 2)

	stopped := make(chan struct{})

	go func() {
		stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop must end the retry")
	}

	assert.Equal(t, StatePending, st.State(), "never accepted, never refused")

	_, _, found := logs.find("initial declaration publish failed")
	assert.False(t, found, "a shutdown is not a failed publish")
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
