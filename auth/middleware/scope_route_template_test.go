package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// warnCapturingLogger records every message logged at WARN.
type warnCapturingLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *warnCapturingLogger) Log(_ context.Context, level int, msg string, _ ...any) {
	if level != obs.LevelWarn {
		return
	}

	l.mu.Lock()
	l.msgs = append(l.msgs, msg)
	l.mu.Unlock()
}

func (l *warnCapturingLogger) Enabled(_ int) bool           { return true }
func (l *warnCapturingLogger) Sync(_ context.Context) error { return nil }

func (l *warnCapturingLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.msgs)
}

// prefixMountedApp mounts handler the way a product authorizes inside prefix
// middleware: on app.Use, where Fiber reports the route as "USE <prefix>" with
// no path parameters.
func prefixMountedApp(handler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Use("/v1/organizations", handler)
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", ok)
	app.Post("/v1/organizations/:organization_id/transfers", ok)

	return app
}

// A handler mounted on a prefix sees no route of its own: told the route the
// request is for, it sends the dimensions that route's path carries, read from
// the request path, whichever template syntax the caller states it in.
func TestAuthorize_ForRoute_PrefixMountReadsTheStatedRoute(t *testing.T) {
	t.Parallel()

	for name, template := range map[string]string{
		"huma_template":  "/v1/organizations/{organization_id}/ledgers/{ledger_id}",
		"fiber_template": "/v1/organizations/:organization_id/ledgers/:ledger_id",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := scopedClient(t, rec)

			app := prefixMountedApp(auth.Authorize("midaz", "ledgers", "get", ForRoute("midaz", http.MethodGet, template)))

			assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1", partnerToken("acme/p1")))
			assert.JSONEq(t,
				`{"action":"get","product":"midaz","resource":"ledgers","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1"}}`,
				rec.lastBody(t))
		})
	}
}

// The stated route takes the dimensions the manifest declares for it outside
// the path too (scope.routes), exactly as the route itself would.
func TestAuthorize_ForRoute_TakesTheManifestRouteScope(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, "/v1/organizations/:organization_id/transfers",
		Dim("ledgerId", FromBody).At("ledger_id")))

	app := prefixMountedApp(auth.Authorize("midaz", "transfers", "post",
		ForRoute("midaz", http.MethodPost, "/v1/organizations/{organization_id}/transfers")))

	assert.Equal(t, http.StatusOK, doPost(t, app, "/v1/organizations/org-1/transfers", partnerToken("acme/p1"), `{"ledger_id":"led-9"}`).status)
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-9"}`, attributesOf(t, rec.lastBody(t)))

	// A declared body dimension the request does not carry is refused 400
	// before the round-trip, as on the route itself.
	calls := rec.hits.Load()
	assert.Equal(t, http.StatusBadRequest, doPost(t, app, "/v1/organizations/org-1/transfers", partnerToken("acme/p1"), `{}`).status)
	assert.Equal(t, calls, rec.hits.Load(), "refused without asking")
}

// A request the stated route does not describe — another path or another
// method — cannot be read on that route's scope: a partner is refused before
// the round-trip, and every other caller is decided as before.
func TestAuthorize_ForRoute_RequestOutsideTheStatedRouteIsRefusedForAPartner(t *testing.T) {
	t.Parallel()

	const ledgerRoute = "/v1/organizations/{organization_id}/ledgers/{ledger_id}"

	tests := []struct {
		name     string
		template string
		method   string
		target   string
	}{
		{name: "other_path", template: ledgerRoute, method: http.MethodGet, target: "/v1/organizations/org-1/ledgers/led-1/accounts"},
		{name: "shorter_path", template: ledgerRoute, method: http.MethodGet, target: "/v1/organizations/org-1"},
		{name: "other_literal", template: ledgerRoute, method: http.MethodGet, target: "/v1/organizations/org-1/portfolios/led-1"},
		{name: "other_method", template: ledgerRoute, method: http.MethodPost, target: "/v1/organizations/org-1/ledgers/led-1"},
		// The route reads no dimension, so nothing else would refuse it.
		{name: "route_without_dimensions", template: "/v1/organizations", method: http.MethodGet, target: "/v1/organizations/org-1/ledgers/led-1"},
		// An empty segment is no parameter, even one the catalog does not read.
		{name: "empty_parameter", template: "/v1/organizations/{organization_id}/things/{thing_id}/ledgers/{ledger_id}", method: http.MethodGet, target: "/v1/organizations/org-1/things//ledgers/led-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := scopedClient(t, rec)

			app := fiber.New()
			app.Use("/v1/organizations", auth.Authorize("midaz", "ledgers", "get",
				ForRoute("midaz", http.MethodGet, tt.template)))
			app.All("/v1/organizations/*", ok)

			req := httptest.NewRequest(tt.method, tt.target, nil)
			req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Zero(t, rec.hits.Load(), "refused without asking")

			// Positive control: same route, same handler, a non-partner caller.
			req = httptest.NewRequest(tt.method, tt.target, nil)
			req.Header.Set("Authorization", "Bearer "+userToken())
			resp, err = app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, `{"action":"get","product":"midaz","resource":"ledgers","sub":"acme-org/user-1"}`, rec.lastBody(t))
		})
	}
}

// A trailing slash and a literal in another letter case still reach the route
// under Fiber's default routing, so they still match the stated route.
func TestAuthorize_ForRoute_MatchesLikeTheDefaultRouter(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := prefixMountedApp(auth.Authorize("midaz", "ledgers", "get",
		ForRoute("midaz", "get", "/v1/organizations/{organization_id}/ledgers/{ledger_id}")))

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/Organizations/org-1/ledgers/led-1/", partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-1"}`, attributesOf(t, rec.lastBody(t)))
}

// A non-partner credential on a stated route puts the same bytes on the wire as
// on the route itself.
func TestAuthorize_ForRoute_NonPartnerIsByteIdentical(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	direct := fiber.New()
	direct.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", auth.Authorize("midaz", "ledgers", "get"), ok)
	assert.Equal(t, http.StatusOK, doGet(t, direct, "/v1/organizations/org-1/ledgers/led-1", userToken()))
	want := rec.lastBody(t)

	app := prefixMountedApp(auth.Authorize("midaz", "ledgers", "get",
		ForRoute("midaz", http.MethodGet, "/v1/organizations/{organization_id}/ledgers/{ledger_id}")))
	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1", userToken()))
	assert.Equal(t, want, rec.lastBody(t))
}

// A stated route that cannot be read is a programming error: every request is
// refused, whatever the caller, as for any misdeclared route.
func TestAuthorize_ForRoute_MisdeclaredRefusesEveryRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope ScopeDeclaration
	}{
		{name: "empty_method", scope: ForRoute("midaz", " ", "/v1/organizations/{organization_id}")},
		{name: "relative_template", scope: ForRoute("midaz", http.MethodGet, "v1/organizations/{organization_id}")},
		{name: "unclosed_param", scope: ForRoute("midaz", http.MethodGet, "/v1/organizations/{organization_id")},
		{name: "partial_segment_param", scope: ForRoute("midaz", http.MethodGet, "/v1/organizations/{organization_id}.json")},
		{name: "empty_param", scope: ForRoute("midaz", http.MethodGet, "/v1/organizations/{}")},
		{name: "optional_param", scope: ForRoute("midaz", http.MethodGet, "/v1/organizations/:organization_id?")},
		{name: "wildcard", scope: ForRoute("midaz", http.MethodGet, "/v1/organizations/*")},
		{name: "repeated_param", scope: ForRoute("midaz", http.MethodGet, "/v1/{id}/x/{id}")},
		{name: "other_product", scope: ForRoute("tracer", http.MethodGet, "/v1/organizations/{organization_id}")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := scopedClient(t, rec)

			app := fiber.New()
			app.Use("/v1", auth.Authorize("midaz", "organizations", "get", tt.scope))
			app.Get("/v1/*", ok)

			assert.Equal(t, http.StatusForbidden, doGet(t, app, "/v1/organizations/org-1", userToken()))
			assert.Equal(t, http.StatusForbidden, doGet(t, app, "/v1/organizations/org-1", partnerToken("acme/p1")))
			assert.Zero(t, rec.hits.Load())
		})
	}
}

// Authorizing on a prefix without stating the route is how a scoped route goes
// silently unscoped: the request is still decided as before, and the service is
// told once.
func TestAuthorize_PrefixMountWithoutRoute_WarnsOnce(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	logger := &warnCapturingLogger{}
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: logger, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	app := prefixMountedApp(auth.Authorize("midaz", "ledgers", "get"))

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1", partnerToken("acme/p1")))
	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-2/ledgers/led-2", partnerToken("acme/p1")))
	assert.Equal(t, 1, logger.count(), "warned once")
	assert.Contains(t, logger.msgs[0], "ForRoute")
}

// Controls for the warning: the route stated, a route mounted on its own path,
// and a product with no catalog say nothing.
func TestAuthorize_PrefixMountWarning_Controls(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		catalog bool
		mount   func(*AuthClient) *fiber.App
	}{
		{name: "route_stated", catalog: true, mount: func(auth *AuthClient) *fiber.App {
			return prefixMountedApp(auth.Authorize("midaz", "ledgers", "get",
				ForRoute("midaz", http.MethodGet, "/v1/organizations/{organization_id}/ledgers/{ledger_id}")))
		}},
		{name: "own_route", catalog: true, mount: func(auth *AuthClient) *fiber.App {
			app := fiber.New()
			app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", auth.Authorize("midaz", "ledgers", "get"), ok)

			return app
		}},
		{name: "no_catalog", catalog: false, mount: func(auth *AuthClient) *fiber.App {
			return prefixMountedApp(auth.Authorize("midaz", "ledgers", "get"))
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			logger := &warnCapturingLogger{}
			// A product no other test registers process-wide, so "no_catalog"
			// really has none.
			auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: logger, M2MInversionEnabled: true}

			if tt.catalog {
				require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))
			}

			assert.Equal(t, http.StatusOK, doGet(t, tt.mount(auth), "/v1/organizations/org-1/ledgers/led-1", partnerToken("acme/p1")))
			assert.Zero(t, logger.count())
		})
	}
}

func TestParseRouteTemplate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		template string
		want     string
		params   []string
	}{
		{name: "huma", template: "/v1/organizations/{organization_id}/ledgers/{ledger_id}", want: "/v1/organizations/:organization_id/ledgers/:ledger_id", params: []string{"organization_id", "ledger_id"}},
		{name: "fiber", template: "/v1/organizations/:organization_id", want: "/v1/organizations/:organization_id", params: []string{"organization_id"}},
		{name: "mixed", template: "/v1/{a}/x/:b", want: "/v1/:a/x/:b", params: []string{"a", "b"}},
		{name: "literal_only", template: "/v1/health", want: "/v1/health", params: nil},
		{name: "root", template: "/", want: "/", params: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rt, problem := parseRouteTemplate(http.MethodGet, tt.template)
			require.Empty(t, problem)
			assert.Equal(t, tt.want, rt.path)

			var params []string

			for _, segment := range rt.segments {
				if segment.param {
					params = append(params, segment.text)
				}
			}

			assert.Equal(t, tt.params, params)
		})
	}
}

func TestServedByPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		route   string
		request string
		want    bool
	}{
		{name: "prefix_mount", route: "/v1/organizations", request: "/v1/organizations/org-1/ledgers", want: true},
		{name: "global_mount", route: "/", request: "/v1/health", want: true},
		{name: "own_route", route: "/v1/organizations/:organization_id", request: "/v1/organizations/org-1", want: false},
		{name: "own_route_trailing_slash", route: "/v1/organizations/:organization_id", request: "/v1/organizations/org-1/", want: false},
		{name: "wildcard_route", route: "/v1/*", request: "/v1/organizations/org-1", want: false},
		{name: "plus_route", route: "/v1/+", request: "/v1/organizations/org-1", want: false},
		{name: "optional_route", route: "/v1/:a?", request: "/v1/x", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, servedByPrefix(tt.route, tt.request))
		})
	}
}

// Fiber serves a HEAD request with the GET route, so a stated GET route
// describes it.
func TestAuthorize_ForRoute_HeadIsServedByTheGetRoute(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := prefixMountedApp(auth.Authorize("midaz", "ledgers", "get",
		ForRoute("midaz", http.MethodGet, "/v1/organizations/{organization_id}/ledgers/{ledger_id}")))

	req := httptest.NewRequest(http.MethodHead, "/v1/organizations/org-1/ledgers/led-1", nil)
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-1"}`, attributesOf(t, rec.lastBody(t)))
}
