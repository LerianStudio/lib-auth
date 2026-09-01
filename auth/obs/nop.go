package obs

import "context"

// nopLogger discards everything it is given.
type nopLogger struct{}

func (nopLogger) Log(context.Context, int, string, ...any) {}

func (nopLogger) Enabled(int) bool { return false }

func (nopLogger) Sync(context.Context) error { return nil }

// Nop returns a Logger that discards every event.
//
// It is the value lib-auth falls back to when a caller supplies no logger and
// no default can be built, so no code path in this library holds a nil Logger.
// Callers can use it too, and it costs them no import of lib-observability.
func Nop() Logger { return nopLogger{} }
