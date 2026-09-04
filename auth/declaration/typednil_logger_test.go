package declaration

import (
	"context"
	"testing"

	"github.com/LerianStudio/lib-auth/v4/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// derefLogger dereferences its receiver, as an ordinary implementation of the
// universal contract does. A typed nil of this type panics on first use.
type derefLogger struct{ calls int }

func (d *derefLogger) Log(context.Context, int, string, ...any) { d.calls++ }
func (d *derefLogger) Enabled(int) bool                         { return true }
func (d *derefLogger) Sync(context.Context) error               { return nil }

func TestNew_TypedNilLoggerIsUsable(t *testing.T) {
	var typedNil *derefLogger

	cfg := testConfig(t, "http://auth.test", "http://identity.test")
	cfg.Logger = typedNil

	p, err := New(cfg)

	require.NoError(t, err)
	require.NotNil(t, p)
	assert.NotPanics(t, func() {
		p.logger.Log(context.Background(), obs.LevelError, "must not panic")
	})
}

func TestLookupWithDeprecatedAlias_TypedNilLoggerDoesNotPanic(t *testing.T) {
	var typedNil *derefLogger

	t.Setenv("IDP_TYPEDNIL_CANARY", "")
	t.Setenv("TYPEDNIL_CANARY_DEPRECATED", "from-alias")

	var got string

	assert.NotPanics(t, func() {
		got = lookupWithDeprecatedAlias("IDP_TYPEDNIL_CANARY", "TYPEDNIL_CANARY_DEPRECATED", typedNil)
	})
	assert.Equal(t, "from-alias", got)
}
