package middleware

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// A partner on a route its manifest gives no scope, and wiring order
// ---------------------------------------------------------------------------

// A partner-bound credential on a route whose manifest declares no scope —
// no catalog at all, or a catalog none of whose dimensions the route carries —
// is refused before any call, with the same 403 a denied partner gets. A
// credential that is not partner-bound is decided as always.
func TestAuthorize_UnscopedRoute_DeniesOnlyThePartner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		catalog []Dimension
	}{
		{name: "no_catalog"},
		{name: "route_carries_no_dimension", catalog: manifestDims()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t, "org-denied")
			auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

			if tt.catalog != nil {
				require.NoError(t, auth.SetManifestScope("midaz", tt.catalog...))
			}

			app := fiber.New()
			app.Get("/v1/settings", auth.Authorize("midaz", "settings", "get"), ok)
			app.Get("/v1/organizations/:organization_id", auth.Authorize("midaz", "organizations", "get"), ok)

			unscoped := doCarrier(t, app, carrierRequest{method: http.MethodGet, target: "/v1/settings", token: partnerToken("acme/p1")})
			assert.Equal(t, http.StatusForbidden, unscoped.status)
			assert.Equal(t, int64(0), srv.hits.Load(), "refused before any call")

			assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/settings", userToken()))
			assert.Equal(t, []map[string]string{nil}, srv.attributeCalls(), "a credential that is not partner-bound is asked as always")

			if tt.catalog == nil {
				return
			}

			// The refusal is the one a partner denied by the service gets.
			denied := doCarrier(t, app, carrierRequest{method: http.MethodGet, target: "/v1/organizations/org-denied", token: partnerToken("acme/p1")})
			assert.Equal(t, http.StatusForbidden, denied.status)
			assert.Equal(t, denied.body, unscoped.body, "uniform refusal")

			// Positive control: a scoped route of the same catalog is allowed.
			assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1", partnerToken("acme/p1")))
		})
	}
}

// A route works out its scope on its first request, so a catalog wired after
// the route is registered reaches it as one wired before.
func TestAuthorize_ManifestScope_WiredAfterTheRoutes(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", auth.Authorize("midaz", "ledgers", "get"), ok)

	require.NoError(t, auth.SetManifestScope("midaz", accountCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, legsRoute, Dim("accountId", FromBody).At("accountId")))

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1", partnerToken("acme/p1")))
	assert.Equal(t, http.StatusOK, doPost(t, app, legsPath, partnerToken("acme/p1"), `{"accountId":"acc-1"}`).status)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
	}, srv.attributeCalls())
}

// A route that has served requests before its catalog was wired picks the
// catalog up on its next request.
func TestAuthorize_ManifestScope_WiredAfterTheFirstRequest(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id", auth.Authorize("midaz", "organizations", "get"), ok)

	assert.Equal(t, http.StatusForbidden, doGet(t, app, "/v1/organizations/org-1", partnerToken("acme/p1")), "no catalog yet: unscopeable")
	assert.Equal(t, int64(0), srv.hits.Load())

	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1", partnerToken("acme/p1")))
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
}
