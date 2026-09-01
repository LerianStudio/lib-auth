package obs_test

import (
	"context"
	"testing"

	"github.com/LerianStudio/lib-auth/v3/auth/obs"
	"github.com/stretchr/testify/assert"
)

type ptrLogger struct{ n int }

func (p *ptrLogger) Log(context.Context, int, string, ...any) { p.n++ }
func (p *ptrLogger) Enabled(int) bool                         { return true }
func (p *ptrLogger) Sync(context.Context) error               { return nil }

type valueLogger struct{}

func (valueLogger) Log(context.Context, int, string, ...any) {}
func (valueLogger) Enabled(int) bool                         { return true }
func (valueLogger) Sync(context.Context) error               { return nil }

func TestIsNil(t *testing.T) {
	t.Parallel()

	var typedNil *ptrLogger

	tests := []struct {
		name   string
		logger obs.Logger
		want   bool
	}{
		{"untyped nil interface", nil, true},
		{"typed-nil pointer", typedNil, true},
		{"live pointer", &ptrLogger{}, false},
		{"value implementation", valueLogger{}, false},
		{"nop", obs.Nop(), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, obs.IsNil(tc.logger))
		})
	}
}
