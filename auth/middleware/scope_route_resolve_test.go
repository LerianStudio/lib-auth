package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ledgerPath = "/v1/organizations/org-1/ledgers/led-1"

// mountedApps are the ways a product authorizes in middleware, each guarding
// GET /v1/organizations/:organization_id/ledgers/:ledger_id. In every one
// Fiber reports a mount prefix as the handler's route and reads no parameter
// past it.
func mountedApps(handler fiber.Handler) map[string]*fiber.App {
	prefix := fiber.New()
	prefix.Use("/v1/organizations", handler)
	prefix.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", ok)

	group := fiber.New()
	orgs := group.Group("/v1/organizations/:organization_id")
	orgs.Use(handler)
	orgs.Get("/ledgers/:ledger_id", ok)

	sub := fiber.New()
	sub.Use(handler)
	sub.Get("/organizations/:organization_id/ledgers/:ledger_id", ok)

	mounted := fiber.New()
	mounted.Use("/v1", sub)

	global := fiber.New()
	global.Use(handler)
	global.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", ok)

	return map[string]*fiber.App{
		"prefix_use":    prefix,
		"group_use":     group,
		"mounted_app":   mounted,
		"global_use":    global,
		"own_route":     ownRouteApp(handler),
		"own_route_grp": ownRouteGroupApp(handler),
	}
}

// mountNames names every app mountedApps builds.
var mountNames = []string{"prefix_use", "group_use", "mounted_app", "global_use", "own_route", "own_route_grp"}

func ownRouteApp(handler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", handler, ok)

	return app
}

func ownRouteGroupApp(handler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Group("/v1/organizations/:organization_id").Get("/ledgers/:ledger_id", handler, ok)

	return app
}

// Wherever the handler is mounted, a partner-bound request sends the
// dimensions of the route that serves it — the same attributes as a handler on
// the route itself — with no product code.
func TestAuthorize_MountedHandler_ResolvesTheServingRoute(t *testing.T) {
	t.Parallel()

	for _, name := range mountNames {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := scopedClient(t, rec)
			app := mountedApps(auth.Authorize("midaz", "ledgers", "get"))[name]

			assert.Equal(t, http.StatusOK, doGet(t, app, ledgerPath, partnerToken("acme/p1")))
			assert.JSONEq(t,
				`{"action":"get","product":"midaz","resource":"ledgers","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1"}}`,
				rec.lastBody(t))
		})
	}
}

// A non-partner credential puts the same bytes on the wire wherever the
// handler is mounted.
func TestAuthorize_MountedHandler_NonPartnerIsByteIdentical(t *testing.T) {
	t.Parallel()

	for _, name := range mountNames {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := scopedClient(t, rec)
			app := mountedApps(auth.Authorize("midaz", "ledgers", "get"))[name]

			assert.Equal(t, http.StatusOK, doGet(t, app, ledgerPath, userToken()))
			assert.Equal(t, `{"action":"get","product":"midaz","resource":"ledgers","sub":"acme-org/user-1"}`, rec.lastBody(t))
		})
	}
}

// The route a request resolves to takes the dimensions the manifest declares
// for it outside the path (scope.routes), and a declared dimension the request
// does not carry is refused before the round-trip, as on the route itself.
func TestAuthorize_MountedHandler_TakesTheManifestRouteScope(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, "/v1/organizations/:organization_id/transfers",
		Dim("ledgerId", FromBody).At("ledger_id")))

	app := fiber.New()
	app.Use("/v1/organizations", auth.Authorize("midaz", "transfers", "post"))
	app.Post("/v1/organizations/:organization_id/transfers", ok)

	assert.Equal(t, http.StatusOK, doPost(t, app, "/v1/organizations/org-1/transfers", partnerToken("acme/p1"), `{"ledger_id":"led-9"}`).status)
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-9"}`, attributesOf(t, rec.lastBody(t)))

	calls := rec.hits.Load()
	assert.Equal(t, http.StatusBadRequest, doPost(t, app, "/v1/organizations/org-1/transfers", partnerToken("acme/p1"), `{}`).status)
	assert.Equal(t, calls, rec.hits.Load(), "refused without asking")
}

// A route the manifest declares is a candidate even when the app serves it
// through a route the handler cannot name (a wildcard here).
func TestAuthorize_MountedHandler_ResolvesADeclaredRoute(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, "/v1/organizations/:organization_id/transfers",
		Dim("ledgerId", FromBody).At("ledger_id")))

	app := fiber.New()
	app.Use("/v1/organizations", auth.Authorize("midaz", "transfers", "post"))
	app.Post("/v1/organizations/*", ok)

	assert.Equal(t, http.StatusOK, doPost(t, app, "/v1/organizations/org-1/transfers", partnerToken("acme/p1"), `{"ledger_id":"led-9"}`).status)
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-9"}`, attributesOf(t, rec.lastBody(t)))
}

// An explicit declaration on a mounted handler reads its path dimensions on
// the route that serves the request.
func TestAuthorize_MountedHandler_ExplicitDeclarationReadsTheServingRoute(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Use("/v1/organizations", auth.Authorize("midaz", "ledgers", "get",
		RequireScope("midaz", Dim("ledgerId", FromPath).At("ledger_id"))))
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, ledgerPath, partnerToken("acme/p1")))
	assert.JSONEq(t, `{"ledgerId":"led-1"}`, attributesOf(t, rec.lastBody(t)))
}

// The most specific route wins: a literal segment over a parameter, a
// parameter over a wildcard — whatever order the routes are registered in.
func TestAuthorize_MountedHandler_MostSpecificRouteWins(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := fiber.New()
	app.Use("/v1/organizations", auth.Authorize("midaz", "ledgers", "get"))
	app.Get("/v1/organizations/*", ok)
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", ok)
	app.Get("/v1/organizations/:organization_id/ledgers/summary", ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/summary", partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1"}`, attributesOf(t, rec.lastBody(t)))

	assert.Equal(t, http.StatusOK, doGet(t, app, ledgerPath, partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-1"}`, attributesOf(t, rec.lastBody(t)))
}

// A request no single route describes cannot have its scope read: a partner
// is refused before the round-trip, and every other credential is decided as
// before.
func TestAuthorize_MountedHandler_UnresolvedIsRefusedForAPartner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		routes []string
		target string
	}{
		// Two routes, equally specific, naming the same place differently.
		{name: "ambiguous", routes: []string{
			"/v1/organizations/:organization_id/ledgers/:ledger_id",
			"/v1/organizations/:org/ledgers/:ledger_id",
		}, target: ledgerPath},
		// No route serves the request at all.
		{name: "no_route", routes: []string{"/v1/organizations/:organization_id"}, target: ledgerPath},
		// An empty segment is no parameter.
		{name: "empty_parameter", routes: []string{"/v1/organizations/:organization_id/things/:thing_id/ledgers/:ledger_id"},
			target: "/v1/organizations/org-1/things//ledgers/led-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := scopedClient(t, rec)

			app := fiber.New()
			app.Use("/v1/organizations", auth.Authorize("midaz", "ledgers", "get"))

			for _, route := range tt.routes {
				app.Get(route, ok)
			}

			assert.Equal(t, http.StatusForbidden, doGet(t, app, tt.target, partnerToken("acme/p1")))
			assert.Zero(t, rec.hits.Load(), "refused without asking")

			// Positive control: the same request, a non-partner caller.
			doGet(t, app, tt.target, userToken())
			assert.Equal(t, `{"action":"get","product":"midaz","resource":"ledgers","sub":"acme-org/user-1"}`, rec.lastBody(t))
		})
	}
}

// A product with no catalog has no scope to resolve: a partner on a mounted
// handler is asked without attributes, as before — even for a request no
// route serves, which a resolution would refuse.
func TestAuthorize_MountedHandler_NoCatalogIsUnchanged(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Use("/v1/organizations", auth.Authorize("no-catalog-product", "ledgers", "get"))

	assert.Equal(t, http.StatusNotFound, doGet(t, app, ledgerPath, partnerToken("acme/p1")))
	assert.Equal(t, `{"action":"get","product":"no-catalog-product","resource":"ledgers","sub":"acme/app"}`, rec.lastBody(t))
}

// A catalog registered process-wide is resolved like the client's own.
func TestAuthorize_MountedHandler_ProcessWideCatalog(t *testing.T) {
	t.Parallel()

	const product = "resolve-process-wide"

	require.NoError(t, SetProductManifestScope(product, manifestDims()...))
	t.Cleanup(func() { _ = SetProductManifestScope(product) })

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Use("/v1/organizations", auth.Authorize(product, "ledgers", "get"))
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, ledgerPath, partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-1"}`, attributesOf(t, rec.lastBody(t)))
}

// A handler on its own route keeps that route's scope, exactly as before, even
// when its path is one the resolution could not read.
func TestAuthorize_OwnRoute_IsNeverResolved(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/files/:name.:ext", auth.Authorize("midaz", "files", "get"), ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/files/report.pdf", partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1"}`, attributesOf(t, rec.lastBody(t)))
}

// Only a route of the request's method describes it.
func TestAuthorize_MountedHandler_ResolvesOnTheRequestMethod(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, "/v1/organizations/:organization_id/transfers",
		Dim("ledgerId", FromBody).At("ledger_id")))

	app := fiber.New()
	app.Use("/v1/organizations", auth.Authorize("midaz", "transfers", "get"))
	app.Get("/v1/organizations/*", ok)

	// The declared POST route is more specific, but it is not this request's.
	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/transfers", partnerToken("acme/p1")))
	assert.Equal(t, `{"action":"get","product":"midaz","resource":"transfers","sub":"acme/app"}`, rec.lastBody(t))
}

// A Use mount is not a route a request is for: only the routes that serve
// requests are candidates.
func TestAuthorize_MountedHandler_UseMountsAreNotCandidates(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := fiber.New()
	app.Use("/v1", auth.Authorize("midaz", "organizations", "get"))
	app.Group("/v1/organizations/:org").Use(func(c fiber.Ctx) error { return c.Next() })
	app.Get("/v1/organizations/:organization_id", ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1", partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1"}`, attributesOf(t, rec.lastBody(t)))
}

// Routes registered after the first request are resolved too.
func TestAuthorize_MountedHandler_SeesRoutesAddedLater(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := fiber.New()
	app.Use("/v1/organizations", auth.Authorize("midaz", "ledgers", "get"))
	app.Get("/v1/organizations/:organization_id", ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1", partnerToken("acme/p1")))
	assert.Equal(t, http.StatusForbidden, doGet(t, app, ledgerPath, partnerToken("acme/p1")))

	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, ledgerPath, partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-1"}`, attributesOf(t, rec.lastBody(t)))
}

// Two manifest routes that are one route under different parameter names are
// a manifest defect, refused when the manifest is wired.
func TestSetManifestRouteScope_SameRouteUnderAnotherNameIsRefused(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, "/v1/organizations/:organization_id/transfers",
		Dim("ledgerId", FromBody).At("ledger_id")))

	err := auth.SetManifestRouteScope("midaz", http.MethodPost, "/v1/organizations/:org/transfers",
		Dim("ledgerId", FromBody).At("ledger"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name the same route")

	// Controls: another method, another literal, and a more specific route are
	// distinct routes.
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPut, "/v1/organizations/:org/transfers",
		Dim("ledgerId", FromBody).At("ledger_id")))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, "/v1/organizations/:org/payouts",
		Dim("ledgerId", FromBody).At("ledger_id")))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, "/v1/organizations/main/transfers",
		Dim("ledgerId", FromBody).At("ledger_id")))
}

func TestRouteTemplate_Match(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		template string
		path     string
		want     map[string]string
	}{
		{name: "params", template: "/v1/:a/x/:b", path: "/v1/1/x/2", want: map[string]string{"a": "1", "b": "2"}},
		{name: "literal_case", template: "/v1/Things/:a", path: "/V1/things/1", want: map[string]string{"a": "1"}},
		{name: "trailing_slash", template: "/v1/:a", path: "/v1/1/", want: map[string]string{"a": "1"}},
		{name: "constraint", template: "/v1/:a<int>", path: "/v1/7", want: map[string]string{"a": "7"}},
		{name: "optional_present", template: "/v1/:a?", path: "/v1/1", want: map[string]string{"a": "1"}},
		{name: "optional_absent", template: "/v1/:a?", path: "/v1", want: map[string]string{}},
		{name: "wildcard", template: "/v1/*", path: "/v1/a/b", want: map[string]string{}},
		{name: "wildcard_empty", template: "/v1/*", path: "/v1", want: map[string]string{}},
		{name: "plus", template: "/v1/+", path: "/v1/a", want: map[string]string{}},
		{name: "plus_empty", template: "/v1/+", path: "/v1", want: nil},
		{name: "plus_only_empty_segments", template: "/v1/+", path: "/v1//", want: nil},
		{name: "longer", template: "/v1/:a", path: "/v1/1/2", want: nil},
		{name: "shorter", template: "/v1/:a/x", path: "/v1/1", want: nil},
		{name: "other_literal", template: "/v1/x/:a", path: "/v1/y/1", want: nil},
		{name: "empty_param", template: "/v1/:a/x", path: "/v1//x", want: nil},
		{name: "root", template: "/", path: "/", want: map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			route, ok := parseRouteTemplate(http.MethodGet, tt.template)
			require.True(t, ok)

			params, matched := route.match(pathSegments(tt.path))
			assert.Equal(t, tt.want != nil, matched)

			if tt.want != nil {
				assert.Equal(t, tt.want, params)
			}
		})
	}
}

func TestParseRouteTemplate_RefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	for _, template := range []string{
		"/v1/:a-:b",
		"/v1/:a.:b",
		"/v1/file.:ext",
		"/v1/*/x",
		"/v1/:a?/x",
		"/v1/:",
	} {
		_, ok := parseRouteTemplate(http.MethodGet, template)
		assert.False(t, ok, template)
	}
}

func TestCompareSpecificity(t *testing.T) {
	t.Parallel()

	parse := func(path string) routeTemplate {
		route, ok := parseRouteTemplate(http.MethodGet, path)
		require.True(t, ok, path)

		return route
	}

	tests := []struct {
		more, less string
	}{
		{more: "/v1/x/summary", less: "/v1/x/:id"},
		{more: "/v1/x/:id", less: "/v1/x/:id?"},
		{more: "/v1/x/:id?", less: "/v1/x/*"},
		{more: "/v1/main/:id", less: "/v1/:org/summary"},
		{more: "/v1/x", less: "/v1/x/*"},
	}

	for _, tt := range tests {
		assert.Positive(t, compareSpecificity(parse(tt.more), parse(tt.less)), tt.more+" over "+tt.less)
		assert.Negative(t, compareSpecificity(parse(tt.less), parse(tt.more)), tt.less+" under "+tt.more)
	}

	assert.Zero(t, compareSpecificity(parse("/v1/:a/x"), parse("/v1/:b/x")))
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
		{name: "mounted_app", route: "/v1/", request: "/v1/organizations/org-1", want: true},
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

// A HEAD request is resolved like any other, on the route Fiber serves it with.
func TestAuthorize_MountedHandler_Head(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := mountedApps(auth.Authorize("midaz", "ledgers", "get"))["prefix_use"]

	req := httptest.NewRequest(http.MethodHead, ledgerPath, nil)
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-1"}`, attributesOf(t, rec.lastBody(t)))
}

func TestSegmentCount(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]int{
		"":                       0,
		"/":                      0,
		"/v1":                    1,
		"/v1/":                   1,
		"/v1/organizations/org1": 3,
		"//v1//x/":               2,
		"/:organization_id/abc":  2,
	} {
		assert.Equal(t, want, segmentCount(path), path)
	}
}
