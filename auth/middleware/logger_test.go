package middleware

import (
	"context"
	"testing"

	"github.com/LerianStudio/lib-auth/v4/auth/obs"
	liblog "github.com/LerianStudio/lib-observability/v4/log"
	libzap "github.com/LerianStudio/lib-observability/v4/zap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The logger parameters of this package are declared as obs.Logger, an
// interface built from stdlib types only. These assertions pin the other half
// of the bargain: the loggers lib-observability actually produces satisfy it
// as they are, with no adapter, so the decoupling costs consumers nothing.
var (
	_ obs.Logger = liblog.NewNop()
	_ obs.Logger = (*libzap.Logger)(nil)
	_ obs.Logger = (*testLogger)(nil)
)

// countingLogger is an obs.Logger that counts what it is handed. It is a
// concrete POINTER type: the previous *log.Logger parameter could not hold one
// without the caller first storing it in an interface variable and taking that
// variable's address.
type countingLogger struct {
	calls int
}

func (l *countingLogger) Log(context.Context, int, string, ...any) { l.calls++ }
func (l *countingLogger) Enabled(int) bool                         { return true }
func (l *countingLogger) Sync(context.Context) error               { return nil }

func TestResolveLogger_NilYieldsUsableLogger(t *testing.T) {
	l := resolveLogger(nil)

	require.NotNil(t, l, "a nil logger must resolve to a usable one, never to nil")
	assert.NotPanics(t, func() {
		l.Log(context.Background(), obs.LevelInfo, "resolved")
		_ = l.Enabled(obs.LevelInfo)
		_ = l.Sync(context.Background())
	})
}

func TestResolveLogger_PassesTheCallerLoggerThrough(t *testing.T) {
	want := &countingLogger{}

	got := resolveLogger(want)

	assert.Same(t, want, got, "the caller's logger must be stored as given, not copied or wrapped")
}

func TestNewAuthClient_NilLoggerNeverStoresNil(t *testing.T) {
	c := NewAuthClient("", false, nil)

	require.NotNil(t, c)
	require.NotNil(t, c.Logger, "AuthClient.Logger must be usable even when the caller supplies none")

	// Every internal log helper must survive the default-resolved logger.
	assert.NotPanics(t, func() {
		logInfof(context.Background(), c.Logger, "info %d", 1)
		logErrorf(context.Background(), c.Logger, "error %d", 2)
	})
}

func TestNewAuthClient_AcceptsAConcretePointerLogger(t *testing.T) {
	spy := &countingLogger{}

	c := NewAuthClient("", false, spy)

	require.NotNil(t, c)
	assert.Same(t, spy, c.Logger)

	// NewAuthClient already logs through the injected logger during
	// construction (the TRUSTED_PROXIES warning), so count the delta.
	before := spy.calls
	logInfof(context.Background(), c.Logger, "hello")
	assert.Equal(t, before+1, spy.calls, "the client must log through the injected logger")
}

func TestNewM2MAuthenticator_NilLoggerNeverStoresNil(t *testing.T) {
	m, err := NewM2MAuthenticator("", "", false, nil)

	require.NoError(t, err)
	require.NotNil(t, m)
	require.NotNil(t, m.logger)
	assert.NotPanics(t, func() { m.logger.Log(context.Background(), obs.LevelWarn, "ok") })
}

func TestNewM2MAuthenticatorWithKeySource_NilLoggerNeverStoresNil(t *testing.T) {
	m, err := NewM2MAuthenticatorWithKeySource(nil, "", false, nil)

	require.NoError(t, err)
	require.NotNil(t, m)
	require.NotNil(t, m.logger)
	assert.NotPanics(t, func() { m.logger.Log(context.Background(), obs.LevelWarn, "ok") })
}

func TestNewJWKSKeySource_NilLoggerNeverStoresNil(t *testing.T) {
	src, err := newJWKSKeySource(JWKSConfig{URL: "https://example.test/jwks", Logger: nil})

	require.NoError(t, err)
	require.NotNil(t, src.logger, "JWKSConfig.Logger defaults to a no-op logger, never nil")
	assert.NotPanics(t, func() { src.logWarn(context.Background(), "ok") })
}

// logErrorf and logInfof guard a nil logger themselves; the guard is the last
// line of defence for a caller that sets AuthClient.Logger directly.
func TestLogHelpers_TolerateANilLogger(t *testing.T) {
	assert.NotPanics(t, func() {
		logInfof(context.Background(), nil, "no logger")
		logErrorf(context.Background(), nil, "no logger")
	})
}
