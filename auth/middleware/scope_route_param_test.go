package middleware

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// A route maps its own path parameter to a catalog dimension
// ---------------------------------------------------------------------------

const (
	genericAccountRoute  = "/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:id"
	genericAccountTarget = "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1"
	namedAccountRoute    = "/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id/balances"
	namedAccountTarget   = "/v1/organizations/org-1/ledgers/led-1/accounts/acc-9/balances"
	genericLedgerRoute   = "/v1/organizations/:organization_id/ledgers/:id"
	genericLedgerTarget  = "/v1/organizations/org-1/ledgers/led-7"
)

// genericParamApp serves the generic account route, mapped, next to a route
// that names the catalog's own parameter and a generic route left unmapped.
func genericParamApp(t *testing.T, srv *fakeAuthServer, catalog []Dimension) *fiber.App {
	t.Helper()

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", catalog...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodGet, genericAccountRoute, Dim("accountId", FromPath).At("id")))

	app := fiber.New()
	app.Get(genericAccountRoute, auth.Authorize("midaz", "accounts", "get"), ok)
	app.Get(namedAccountRoute, auth.Authorize("midaz", "balances", "get"), ok)
	app.Get(genericLedgerRoute, auth.Authorize("midaz", "ledgers", "get"), ok)

	return app
}

// The route's ":id" is asked as the dimension the route maps it to, with the
// dimensions the catalog derives from the rest of its path.
func TestAuthorize_RouteParam_GenericIDIsAskedAsTheMappedDimension(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "acc-denied")
	app := genericParamApp(t, srv, accountCatalog())

	assert.Equal(t, http.StatusOK, doGet(t, app, genericAccountTarget, partnerToken("acme/p1")))
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"}}, srv.attributeCalls())

	// The value is checked: one outside the scope is refused.
	assert.Equal(t, http.StatusForbidden, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1/accounts/acc-denied", partnerToken("acme/p1")))
}

// The mapping is the route's alone: a route naming the catalog's own parameter
// derives it from the catalog, and another route with a generic ":id" does not
// read it as the account.
func TestAuthorize_RouteParam_MappingIsForThatRouteOnly(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	app := genericParamApp(t, srv, accountCatalog())

	assert.Equal(t, http.StatusOK, doGet(t, app, namedAccountTarget, partnerToken("acme/p1")))
	assert.Equal(t, http.StatusOK, doGet(t, app, genericLedgerTarget, partnerToken("acme/p1")))

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-9"},
		{"organizationId": "org-1"},
	}, srv.attributeCalls())
}

// The route's mapping wins over the catalog for the parameter it maps: a
// catalog dimension that reads the same parameter is not derived on that
// route, so one value never answers for two dimensions.
func TestAuthorize_RouteParam_MappingWinsOverTheCatalogParameter(t *testing.T) {
	t.Parallel()

	catalog := append(accountCatalog(), Dim("holderId", FromPath).At("id"))

	srv := newDecidingAuthServer(t)
	app := genericParamApp(t, srv, catalog)

	assert.Equal(t, http.StatusOK, doGet(t, app, genericAccountTarget, partnerToken("acme/p1")))
	assert.Equal(t, http.StatusOK, doGet(t, app, genericLedgerTarget, partnerToken("acme/p1")))

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		// Positive control: an unmapped route still derives the catalog's own
		// reading of the parameter.
		{"organizationId": "org-1", "holderId": "led-7"},
	}, srv.attributeCalls())
}

// One generic parameter name maps to different dimensions on different routes.
func TestAuthorize_RouteParam_SameParameterMapsPerRoute(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", accountCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodGet, genericAccountRoute, Dim("accountId", FromPath).At("id")))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodGet, genericLedgerRoute, Dim("ledgerId", FromPath).At("id")))

	app := fiber.New()
	app.Get(genericAccountRoute, auth.Authorize("midaz", "accounts", "get"), ok)
	app.Get(genericLedgerRoute, auth.Authorize("midaz", "ledgers", "get"), ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, genericAccountTarget, partnerToken("acme/p1")))
	assert.Equal(t, http.StatusOK, doGet(t, app, genericLedgerTarget, partnerToken("acme/p1")))

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "ledgerId": "led-7"},
	}, srv.attributeCalls())
}

// A credential that is not partner-bound is asked without attributes on a
// mapped route, as everywhere.
func TestAuthorize_RouteParam_NonPartnerIsAskedWithout(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	app := genericParamApp(t, srv, accountCatalog())

	assert.Equal(t, http.StatusOK, doGet(t, app, genericAccountTarget, userToken()))
	assert.Equal(t, []map[string]string{nil}, srv.attributeCalls())
}

func TestSetManifestRouteScope_PathParameterMustBeOnTheRoute(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}
	require.NoError(t, auth.SetManifestScope("midaz", accountCatalog()...))

	err := auth.SetManifestRouteScope("midaz", http.MethodGet, genericAccountRoute, Dim("accountId", FromPath).At("account_id"))
	require.ErrorContains(t, err, `reads path parameter "account_id", which the route path does not carry`)

	// A segment that merely contains the parameter is a different one.
	err = auth.SetManifestRouteScope("midaz", http.MethodGet, "/v1/accounts/:id.json", Dim("accountId", FromPath).At("id"))
	require.ErrorContains(t, err, `reads path parameter "id", which the route path does not carry`)

	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodGet, genericAccountRoute, Dim("accountId", FromPath).At("id")),
		"positive control: the parameter the route carries is accepted")
}
