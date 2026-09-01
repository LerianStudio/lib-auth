# lib-auth v4 — migration guide

v4 removes every `github.com/LerianStudio/lib-observability` type from the
public API of lib-auth, and moves the library's own internal use of that
dependency to **lib-observability v4**.

There is no compatibility layer and nothing is deprecated. Types were replaced
in place and the old ones deleted.

## Why

Go types have **nominal identity**. `lib-observability/v2/log.Logger` and
`lib-observability/v4/log.Logger` are distinct types even though the code is
byte-for-byte identical. While lib-auth named `log.Logger` on its own
signatures, that library's major crossed the boundary and forced a major here
every time it moved — and consumers could not move alone. That is what stalled
the fleet: midaz could not adopt lib-observability v4 because lib-auth,
lib-streaming and lib-service-discovery did not compile against it.

`auth/obs` declares the same capability with **stdlib types only**, so an
implementation written against *any* major of lib-observability satisfies it —
and so does a type declared in a package that has never imported an
observability library at all.

The same change shipped in lib-commons v7 (`commons/obs`); the interfaces are
identical, so a `commons/obs.Logger` is accepted here directly.

## 1. The new contract — `auth/obs`

```go
package obs

const (
	LevelError = 0
	LevelWarn  = 1
	LevelInfo  = 2
	LevelDebug = 3
)

type Logger interface {
	Log(ctx context.Context, level int, msg string, fields ...any)
	Enabled(level int) bool
	Sync(ctx context.Context) error
}

func Nop() Logger
```

Lower level is more severe — the same scale as lib-observability's `log.Level`
and lib-commons' `commons/obs`.

There is deliberately no `With`/`WithGroup` method: a method that returns the
interface it is declared on cannot be satisfied from outside the declaring
package, which is the trap that made the previous design unavoidable.

lib-auth exposes no metrics type on its public API, so there is no
`MetricsRecorder` here. `*metrics.MetricsFactory` is used only inside
unexported code (the JWKS instruments in `auth/middleware/metrics.go` and
`keysource.go`), resolved from the ambient context.

## 2. Getting an `obs.Logger`

There is nothing to get.

- **lib-observability v4+** — `log.NewNop()`, `*log.GoLogger`, the zap adapter
  and the value returned by `NewLoggerFromContext` all carry
  `Log(ctx, int, string, ...any)`, `Enabled(int)` and `Sync(ctx)`. Pass them
  straight in.
- **lib-commons v7+** — `commons/obs.Logger` is this same shape. Pass it
  straight in.
- **your own type** — three methods over stdlib types, no imports.

## 3. What broke — symbol by symbol

| Before | After |
| --- | --- |
| `middleware.NewAuthClient(address string, enabled bool, logger *log.Logger)` | `middleware.NewAuthClient(address string, enabled bool, logger obs.Logger)` |
| `middleware.AuthClient.Logger log.Logger` | `middleware.AuthClient.Logger obs.Logger` |
| `middleware.NewM2MAuthenticator(cert, issuer string, enabled bool, logger *log.Logger)` | `… logger obs.Logger` |
| `middleware.NewM2MAuthenticatorWithKeySource(src KeySource, issuer string, enabled bool, logger *log.Logger)` | `… logger obs.Logger` |
| `middleware.JWKSConfig.Logger log.Logger` | `middleware.JWKSConfig.Logger obs.Logger` |
| `declaration.Config.Logger log.Logger` | `declaration.Config.Logger obs.Logger` |
| `declaration.WireInput.Logger log.Logger` | `declaration.WireInput.Logger obs.Logger` |

### The pointer-to-interface, fixed in passing

The three constructors took a `*log.Logger` — a **pointer to an interface**.
That is almost never what anyone wants: it cannot hold a concrete pointer
implementation without the caller first parking it in an interface variable
and taking that variable's address, it needs a dereference before any method
call, and it has two distinct empty values (a nil `*Logger` and a non-nil
`*Logger` addressing a nil `Logger`) that behaved differently. It is now an
interface value. `nil` still means "build me the default logger", which is the
only thing the pointer was ever expressing.

```go
// BEFORE
logger, _ := zap.New(zap.Config{Environment: zap.EnvironmentProduction})
client := middleware.NewAuthClient(addr, enabled, &logger)

// AFTER
logger, _ := zap.New(zap.Config{Environment: zap.EnvironmentProduction})
client := middleware.NewAuthClient(addr, enabled, logger)

// AFTER — also legal now, and was not before
client := middleware.NewAuthClient(addr, enabled, &myConcreteLogger{})
client := middleware.NewAuthClient(addr, enabled, nil) // default logger
```

### Implementing the interface

A logger implementation written against lib-observability v2/v3 does not
satisfy the new contract: Go requires the signature to match exactly. Move it
to the universal shape (this is the same edit lib-observability v4 asks for —
see `MIGRATION-v4.md` there):

```go
// BEFORE
func (l *myLogger) Log(ctx context.Context, level log.Level, msg string, fields ...log.Field)
func (l *myLogger) With(...log.Field) log.Logger
func (l *myLogger) WithGroup(string) log.Logger
func (l *myLogger) Enabled(log.Level) bool

// AFTER
func (l *myLogger) Log(ctx context.Context, level int, msg string, fields ...any)
func (l *myLogger) Enabled(level int) bool
// With/WithGroup are not part of the contract; drop them or keep them for
// your own use.
```

## 4. The mechanical step in a consumer

```bash
# 1. the constructors no longer take an address
grep -rl 'NewAuthClient(\|NewM2MAuthenticator' --include='*.go' . \
  | xargs sed -i -E 's#(New(AuthClient|M2MAuthenticator(WithKeySource)?)\([^)]*), &([A-Za-z0-9_.]+)\)#\1, \4)#g'

# 2. bump the module requirement
go get github.com/LerianStudio/lib-auth/v4@latest
go mod tidy

# 3. let the compiler find the residue
go build ./... && go vet ./...
```

## 5. The module-path bump

The major bump is **not applied in this branch** — the module path is still
`github.com/LerianStudio/lib-auth/v3`. Apply it as the release step, on its
own commit:

```bash
cd /path/to/lib-auth

go mod edit -module github.com/LerianStudio/lib-auth/v4

grep -rl 'LerianStudio/lib-auth/v3' --include='*.go' . \
  | grep -v '/vendor/' \
  | xargs sed -i -E 's#(LerianStudio/lib-auth)/v3#\1/v4#g'

grep -rl 'LerianStudio/lib-auth/v3' --include='*.md' . \
  | xargs sed -i -E 's#(LerianStudio/lib-auth)/v3#\1/v4#g'

# gofmt -l lists unformatted files but still exits 0, so check its OUTPUT is
# empty rather than its status, or the chain below runs on unformatted code.
test -z "$(gofmt -l .)" && go build ./... && go test -count=1 ./...
```

## 6. The regression guard

`auth/obs/boundary` walks every non-test `.go` file under `auth/` with
`go/ast` and fails if an exported field, parameter, return type or type alias
names a `github.com/LerianStudio/lib-observability` type. Its allowlist is
empty and is meant to stay empty. If it fires, the coupling this release
removed is coming back.
