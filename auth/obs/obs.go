// Package obs declares the minimal observability contract that lib-auth
// exposes on its public API.
//
// The interface here is expressed with stdlib types only. lib-auth MUST NOT
// import github.com/LerianStudio/lib-observability from this package: Go
// matches the types inside a method signature NOMINALLY, so an interface that
// names a type defined by a versioned module stays bound to that module's
// major. That binding is exactly what this package exists to remove — while
// lib-auth named lib-observability's log.Logger on its own signatures, every
// major of that library crossed the boundary and forced a major here, and no
// consumer could move alone.
//
// Because the contract mentions nothing but stdlib types, an adapter written
// against ANY major of lib-observability satisfies it, and so does a logger
// declared in a package that has never imported lib-observability at all.
//
// Since lib-observability v4 no adapter is needed in either direction: the
// loggers that library produces (log.NewNop, *log.GoLogger, the zap adapter,
// the value returned by NewLoggerFromContext) satisfy Logger as they are, and
// every lib-observability entry point that takes a logger accepts a Logger
// declared here. The same holds for lib-commons' commons/obs.Logger, which is
// this same shape.
package obs

import "context"

// Log severity levels.
//
// The numeric scale is identical to lib-observability's log.Level and to
// lib-commons' commons/obs: lower values are MORE severe. A logger configured
// at LevelInfo (2) emits Error, Warn and Info and suppresses Debug.
const (
	// LevelError reports failures. Most severe.
	LevelError = 0
	// LevelWarn reports recoverable anomalies.
	LevelWarn = 1
	// LevelInfo reports normal operational events.
	LevelInfo = 2
	// LevelDebug reports diagnostic detail. Least severe.
	LevelDebug = 3
)

// Logger is the logging contract required by lib-auth.
//
// Structured attributes travel as alternating key/value pairs in fields; a
// lib-observability log.Field passed positionally is recognized on arrival by
// that library. Implementations must be safe for concurrent use and must never
// panic on malformed fields.
//
// Note the absence of a With/WithGroup method: a method that returns the
// interface it is declared on cannot be satisfied from outside the declaring
// package, because a foreign implementation has no way to name the return
// type. That is the mistake this contract is built to avoid.
type Logger interface {
	// Log emits msg at the given level with the fields attached.
	Log(ctx context.Context, level int, msg string, fields ...any)
	// Enabled reports whether events at level would be emitted.
	Enabled(level int) bool
	// Sync flushes any buffered log entries.
	Sync(ctx context.Context) error
}
