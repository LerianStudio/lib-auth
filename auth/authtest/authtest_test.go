package authtest_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/authtest"
	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTB stands in for *testing.T where a helper is expected to fail the
// test: it records every Fatalf instead of stopping the goroutine, so the test
// can assert the refusal and what the helper returned afterwards. Every method
// it does not override panics on the nil embedded TB, which pins that the
// helpers use nothing but Helper and Fatalf.
type recordingTB struct {
	testing.TB

	mu     sync.Mutex
	fatals []string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Cleanup(func()) {}

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

func (r *recordingTB) failures() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.fatals...)
}

func tenantUser() middleware.Principal {
	p := authtest.User("acme-org", "user-1")
	p.TenantID = "tenant-a"
	p.ClientID = "client-x"

	return p
}

func tenantApp() middleware.Principal {
	p := authtest.App("acme-org/settlement-bot")
	p.TenantID = "tenant-a"
	p.ClientID = "client-y"

	return p
}

func TestUserAndApp_BuildTheShapeAuthorizePublishes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, middleware.Principal{
		Type: "normal-user", Owner: "acme-org", Sub: "user-1", Subject: "acme-org/user-1",
	}, authtest.User("acme-org", "user-1"))

	assert.Equal(t, middleware.Principal{
		Type: "application", Sub: "acme-org/bot", Subject: "acme-org/bot",
	}, authtest.App("acme-org/bot"))
}

func TestWithPrincipal_PublishesWhatPrincipalFromContextReads(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]middleware.Principal{
		"user":        tenantUser(),
		"application": tenantApp(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := authtest.WithPrincipal(t, context.Background(), want)

			got, ok := middleware.PrincipalFromContext(ctx)
			require.True(t, ok)
			assert.Equal(t, want, got)
		})
	}
}

// invalidPrincipals are the principals PrincipalFromContext would report as
// absent; a helper that published one would hand the handler nobody.
func invalidPrincipals() map[string]middleware.Principal {
	user := authtest.User("acme-org", "user-1")

	mismatched := user
	mismatched.Subject = "other-org/user-1"

	appWithOwner := authtest.App("bot")
	appWithOwner.Owner = "acme-org"

	unknownType := user
	unknownType.Type = "service"

	return map[string]middleware.Principal{
		"zero":                  {},
		"empty sub":             authtest.User("acme-org", ""),
		"whitespace sub":        authtest.User("acme-org", "  "),
		"user without owner":    authtest.User("", "user-1"),
		"user subject mismatch": mismatched,
		"app with owner":        appWithOwner,
		"app empty sub":         authtest.App(""),
		"unknown type":          unknownType,
	}
}

func TestWithPrincipal_RefusesAnInvalidPrincipal(t *testing.T) {
	t.Parallel()

	for name, p := range invalidPrincipals() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &recordingTB{}
			ctx := authtest.WithPrincipal(rec, context.Background(), p)

			assert.Len(t, rec.failures(), 1, "an invalid principal must fail the test")

			_, ok := middleware.PrincipalFromContext(ctx)
			assert.False(t, ok, "a refused principal must never be published")
		})
	}
}

func TestWithPrincipal_RefusesANilContext(t *testing.T) {
	t.Parallel()

	rec := &recordingTB{}

	//nolint:staticcheck // SA1012: the nil context is the input under test.
	ctx := authtest.WithPrincipal(rec, nil, authtest.User("acme-org", "user-1"))

	assert.Len(t, rec.failures(), 1)
	assert.Nil(t, ctx)
}

func TestHelpers_PanicOnANilTB(t *testing.T) {
	t.Parallel()

	p := authtest.User("acme-org", "user-1")

	for name, call := range map[string]func(){
		"WithPrincipal": func() { authtest.WithPrincipal(nil, context.Background(), p) },
		"Fiber":         func() { authtest.Fiber(nil, p) },
		"HTTP":          func() { authtest.HTTP(nil, p) },
		"NewIssuer":     func() { authtest.NewIssuer(nil, "") },
	} {
		assert.PanicsWithValue(t, "authtest: "+name+" called with a nil testing.TB", call, name)
	}
}

// fiberApp mounts guard behind authtest.Fiber and records the principal the
// handler saw.
func fiberApp(t *testing.T, p middleware.Principal, guard fiber.Handler) (*fiber.App, *sync.Map) {
	t.Helper()

	seen := &sync.Map{}
	app := fiber.New()
	app.Get("/r/:id", authtest.Fiber(t, p), guard, func(c fiber.Ctx) error {
		got, ok := middleware.PrincipalFromContext(c.Context())
		if !ok {
			return fiber.ErrTeapot
		}

		// Fiber reuses the buffer behind Params once the handler returns.
		seen.Store(strings.Clone(c.Params("id")), got)

		return c.SendStatus(http.StatusOK)
	})

	return app, seen
}

func fiberStatus(t *testing.T, app *fiber.App, path string) int {
	t.Helper()

	resp, err := app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	require.NoError(t, err)

	defer resp.Body.Close()

	return resp.StatusCode
}

func TestFiber_StandsInForAuthorizeAheadOfTheTypeGuards(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		p     middleware.Principal
		guard fiber.Handler
		want  int
	}{
		{"human route, user", tenantUser(), middleware.RequireHuman(), http.StatusOK},
		{"human route, application", tenantApp(), middleware.RequireHuman(), http.StatusForbidden},
		{"application route, application", tenantApp(), middleware.RequireApplication(), http.StatusOK},
		{"application route, user", tenantUser(), middleware.RequireApplication(), http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			app, seen := fiberApp(t, tc.p, tc.guard)

			require.Equal(t, tc.want, fiberStatus(t, app, "/r/1"))

			got, ok := seen.Load("1")
			if tc.want != http.StatusOK {
				assert.False(t, ok, "a refused request must not reach the handler")

				return
			}

			require.True(t, ok)
			assert.Equal(t, tc.p, got)
		})
	}
}

func TestFiber_InvalidPrincipalFailsTheTestAndRefusesEveryRequest(t *testing.T) {
	t.Parallel()

	rec := &recordingTB{}
	handler := authtest.Fiber(rec, middleware.Principal{})

	require.Len(t, rec.failures(), 1)

	reached := false
	app := fiber.New()
	app.Get("/", handler, func(c fiber.Ctx) error {
		reached = true

		return c.SendStatus(http.StatusOK)
	})

	assert.Equal(t, http.StatusUnauthorized, fiberStatus(t, app, "/"))
	assert.False(t, reached)
}

func TestFiber_ServesConcurrentRequests(t *testing.T) {
	t.Parallel()

	want := tenantUser()
	app, seen := fiberApp(t, want, middleware.RequireHuman())

	const requests = 20

	statuses := make([]int, requests)
	errs := make([]error, requests)

	var wg sync.WaitGroup

	for i := range requests {
		wg.Go(func() {
			resp, err := app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("/r/%d", i), nil))
			if err != nil {
				errs[i] = err

				return
			}

			defer resp.Body.Close()

			statuses[i] = resp.StatusCode
		})
	}

	wg.Wait()

	for i := range requests {
		require.NoError(t, errs[i], "request %d", i)
		assert.Equal(t, http.StatusOK, statuses[i], "request %d", i)

		got, ok := seen.Load(fmt.Sprint(i))
		require.True(t, ok, "request %d", i)
		assert.Equal(t, want, got, "request %d", i)
	}
}

func TestHTTP_StandsInForAuthorizeHTTP(t *testing.T) {
	t.Parallel()

	want := tenantApp()

	var got middleware.Principal

	handler := authtest.HTTP(t, want)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := middleware.PrincipalFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusTeapot)

			return
		}

		got = p

		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, want, got)
}

func TestHTTP_NilNextAnswers500(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	authtest.HTTP(t, tenantUser())(nil).ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestHTTP_InvalidPrincipalFailsTheTestAndRefusesEveryRequest(t *testing.T) {
	t.Parallel()

	rec := &recordingTB{}
	mw := authtest.HTTP(rec, authtest.User("", "user-1"))

	require.Len(t, rec.failures(), 1)

	reached := false
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).
		ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.False(t, reached)

	body, err := io.ReadAll(rr.Body)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
}
