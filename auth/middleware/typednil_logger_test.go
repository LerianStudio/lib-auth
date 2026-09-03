package middleware

import (
	"context"
	"testing"

	"github.com/LerianStudio/lib-auth/v4/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// derefLogger is an ordinary implementation of the contract: its methods
// dereference the receiver, so a typed nil panics on first use. The universal
// contract invites exactly this kind of implementation, so lib-auth must never
// hand one back out of a resolution path.
type derefLogger struct{ calls int }

func (d *derefLogger) Log(context.Context, int, string, ...any) { d.calls++ }
func (d *derefLogger) Enabled(int) bool                         { return true }
func (d *derefLogger) Sync(context.Context) error               { return nil }

func TestResolveLogger_TypedNilIsTreatedAsUnset(t *testing.T) {
	var typedNil *derefLogger

	got := resolveLogger(typedNil)

	require.NotNil(t, got)
	assert.NotSame(t, obs.Logger(typedNil), got, "typed nil must not be handed back")
	assert.NotPanics(t, func() {
		got.Log(context.Background(), obs.LevelError, "must not panic")
	})
}

func TestNewAuthClient_TypedNilLoggerIsUsable(t *testing.T) {
	var typedNil *derefLogger

	client := NewAuthClient("", false, typedNil)

	require.NotNil(t, client)
	require.NotNil(t, client.Logger)
	assert.NotPanics(t, func() {
		client.Logger.Log(context.Background(), obs.LevelError, "must not panic")
	})
}

func TestNewM2MAuthenticator_TypedNilLoggerIsUsable(t *testing.T) {
	var typedNil *derefLogger

	m, err := NewM2MAuthenticator("", "", false, typedNil)

	require.NoError(t, err)
	require.NotNil(t, m)
	assert.NotPanics(t, func() {
		m.logger.Log(context.Background(), obs.LevelError, "must not panic")
	})
}

func TestNewJWKSKeySource_TypedNilLoggerIsUsable(t *testing.T) {
	var typedNil *derefLogger

	src, err := newJWKSKeySource(JWKSConfig{URL: "https://example.test/jwks", Logger: typedNil})

	require.NoError(t, err)
	require.NotNil(t, src)
	assert.NotPanics(t, func() {
		src.logger.Log(context.Background(), obs.LevelError, "must not panic")
	})
}
