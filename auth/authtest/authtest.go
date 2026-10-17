package authtest

import (
	"context"
	"net/http"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/internal/principalctx"
	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/gofiber/fiber/v3"
)

const (
	normalUser  = "normal-user"
	application = "application"
)

// User returns a normal-user principal as Authorize derives it from a token
// whose owner and sub claims are owner and sub: Subject is owner+"/"+sub. Set
// TenantID and ClientID on the returned value when the test needs them.
func User(owner, sub string) middleware.Principal {
	return middleware.Principal{Type: normalUser, Owner: owner, Sub: sub, Subject: owner + "/" + sub}
}

// App returns an application principal as Authorize derives it under
// M2MInversionEnabled: no Owner, Subject equal to sub. Set TenantID and
// ClientID on the returned value when the test needs them.
func App(sub string) middleware.Principal {
	return middleware.Principal{Type: application, Sub: sub, Subject: sub}
}

// WithPrincipal returns ctx carrying p exactly as Authorize publishes it, so
// middleware.PrincipalFromContext reads p back. It fails the test with
// tb.Fatalf when ctx is nil or when p is a principal PrincipalFromContext would
// report as absent (empty or whitespace-only Sub, a normal-user without Owner, a
// Subject inconsistent with Owner and Sub, an unknown Type); ctx is then
// returned unchanged. A nil tb panics.
//
//nolint:thelper // a nil tb must panic with a message naming authtest before tb.Helper() dereferences it.
func WithPrincipal(tb testing.TB, ctx context.Context, p middleware.Principal) context.Context {
	requireTB(tb, "WithPrincipal")
	tb.Helper()

	if ctx == nil {
		tb.Fatalf("authtest: WithPrincipal called with a nil context")

		return ctx
	}

	if !validPrincipal(tb, "WithPrincipal", p) {
		return ctx
	}

	return publish(ctx, p)
}

// Fiber returns a fiber.Handler that publishes p on the request context and
// calls c.Next(); mount it where Authorize would be. p is validated once, here,
// with the rules of WithPrincipal: an invalid p fails the test, and the handler
// returned after a Fatalf that did not stop the goroutine answers every request
// with fiber.ErrUnauthorized without calling c.Next(). The handler never touches
// tb and is safe for concurrent requests. A nil tb panics.
//
//nolint:thelper // a nil tb must panic with a message naming authtest before tb.Helper() dereferences it.
func Fiber(tb testing.TB, p middleware.Principal) fiber.Handler {
	requireTB(tb, "Fiber")
	tb.Helper()

	if !validPrincipal(tb, "Fiber", p) {
		return func(fiber.Ctx) error { return fiber.ErrUnauthorized }
	}

	return func(c fiber.Ctx) error {
		c.SetContext(publish(c.Context(), p))

		return c.Next()
	}
}

// HTTP returns net/http middleware that publishes p on the request context and
// serves next; mount it where AuthorizeHTTP would be. A nil next answers 500, as
// AuthorizeHTTP does. p is validated once, here, with the rules of
// WithPrincipal: an invalid p fails the test, and the middleware returned after a
// Fatalf that did not stop the goroutine answers every request with 401 without
// serving next. The middleware never touches tb and is safe for concurrent
// requests. A nil tb panics.
//
//nolint:thelper // a nil tb must panic with a message naming authtest before tb.Helper() dereferences it.
func HTTP(tb testing.TB, p middleware.Principal) func(http.Handler) http.Handler {
	requireTB(tb, "HTTP")
	tb.Helper()

	valid := validPrincipal(tb, "HTTP", p)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case !valid:
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			case next == nil:
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			default:
				next.ServeHTTP(w, r.WithContext(publish(r.Context(), p)))
			}
		})
	}
}

// publish stores p under the key Authorize uses.
func publish(ctx context.Context, p middleware.Principal) context.Context {
	return context.WithValue(ctx, principalctx.Key{}, p)
}

// validPrincipal reports whether PrincipalFromContext would read p back, and
// fails the test when it would not. It applies the middleware's own rules, by
// round-tripping p through them, so the two can never drift apart.
func validPrincipal(tb testing.TB, helper string, p middleware.Principal) bool {
	tb.Helper()

	if _, ok := middleware.PrincipalFromContext(publish(context.Background(), p)); !ok {
		tb.Fatalf("authtest: %s: principal %+v is not one Authorize publishes "+
			"(needs a non-blank Sub; Type normal-user with Owner and Subject Owner/Sub, "+
			"or Type application with no Owner and Subject Sub)", helper, p)

		return false
	}

	return true
}

// requireTB panics with a message naming the helper when tb is nil, before any
// call on tb would panic with a bare nil dereference.
//
//nolint:thelper // a nil tb must panic with a message naming authtest before tb.Helper() dereferences it.
func requireTB(tb testing.TB, helper string) {
	if tb == nil {
		panic("authtest: " + helper + " called with a nil testing.TB")
	}
}
