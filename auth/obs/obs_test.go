package obs_test

import (
	"context"
	"testing"

	"github.com/LerianStudio/lib-auth/v4/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localLogger is declared here with universal types only and imports nothing
// from lib-observability. That it satisfies obs.Logger is the entire point of
// the package: a consumer can supply a logger without taking a dependency on
// any observability library, let alone a specific major of one.
type localLogger struct {
	levels []int
	msgs   []string
}

func (l *localLogger) Log(_ context.Context, level int, msg string, _ ...any) {
	l.levels = append(l.levels, level)
	l.msgs = append(l.msgs, msg)
}

func (l *localLogger) Enabled(int) bool           { return true }
func (l *localLogger) Sync(context.Context) error { return nil }

var _ obs.Logger = (*localLogger)(nil)

func TestLevelScaleIsSeverityDescending(t *testing.T) {
	t.Parallel()

	// Lower is more severe, matching lib-observability's log.Level and
	// lib-commons' commons/obs. An adapter that silently inverted this would
	// turn every error into a debug line.
	assert.Equal(t, 0, obs.LevelError)
	assert.Equal(t, 1, obs.LevelWarn)
	assert.Equal(t, 2, obs.LevelInfo)
	assert.Equal(t, 3, obs.LevelDebug)
}

func TestNop_IsUsableAndSilent(t *testing.T) {
	t.Parallel()

	l := obs.Nop()
	require.NotNil(t, l, "Nop must never hand back a nil Logger")

	assert.False(t, l.Enabled(obs.LevelError), "the no-op logger enables nothing")
	assert.NoError(t, l.Sync(context.Background()))
	assert.NotPanics(t, func() {
		l.Log(context.Background(), obs.LevelError, "dropped", "key", "value")
	})
}

func TestLocalLoggerSatisfiesTheContract(t *testing.T) {
	t.Parallel()

	var l obs.Logger = &localLogger{}

	l.Log(context.Background(), obs.LevelWarn, "hello", "k", 1)

	spy, ok := l.(*localLogger)
	require.True(t, ok)
	assert.Equal(t, []int{obs.LevelWarn}, spy.levels)
	assert.Equal(t, []string{"hello"}, spy.msgs)
}
