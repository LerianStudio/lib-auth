package declaration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// separateGuardManifest is wireCompatManifest under a service no other test
// publishes, so what the process-wide registry holds for it is this file's.
func separateGuardManifest(t *testing.T, product string) string {
	t.Helper()

	t.Cleanup(func() { require.NoError(t, middleware.SetProductManifestScope(product)) })

	return strings.Replace(wireCompatManifest, "service: midaz", "service: "+product, 1)
}

// A product may hand declaration.New one client and authorize its routes with
// another. New registers the manifest's scope under its service, and the routes
// of the other client, which has no catalog of its own, derive their scope from
// it: partner-bound requests are scoped, and the rest are decided as always.
func TestNew_ScopesRoutesOfAnotherClient(t *testing.T) {
	t.Parallel()

	const product = "separate-guard"

	manifest := separateGuardManifest(t, product)

	rec := newScopeRecorder(t, "acc-denied")
	minter := &middleware.AuthClient{Logger: obs.Nop()}
	guard := &middleware.AuthClient{Address: rec.URL, Enabled: true, Logger: obs.Nop(), M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id", guard.Authorize(product, "accounts", "get"), compatOK)
	app.Post("/v1/organizations/:organization_id/ledgers/:ledger_id/transactions", guard.Authorize(product, "transactions", "post"), compatOK)

	target := "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1"

	// Before New, nothing is registered: the partner is refused before any call.
	assert.Equal(t, http.StatusForbidden, status(t, app, http.MethodGet, target, compatPartner))
	assert.Empty(t, rec.questions(), "refused before any call")

	newPublisherFor(t, product, minter, manifest)

	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, target, compatPartner))
	assert.Equal(t, http.StatusForbidden, status(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts/acc-denied", compatPartner))

	req := newBodyRequest(http.MethodPost, "/v1/organizations/org-1/ledgers/led-1/transactions",
		`{"send":{"source":{"from":[{"accountId":"acc-1"}]}}}`, compatPartner)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode, "the manifest's body route reaches the other client too")

	user := compatToken(jwt.MapClaims{"type": "normal-user", "owner": "acme-org", "sub": "user-1"})
	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, target, user))

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-denied"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		nil,
	}, rec.questions())
}

// A client with a catalog of its own for the product keeps it: the registered
// one is only the fallback.
func TestNew_ClientCatalogWinsOverTheRegisteredOne(t *testing.T) {
	t.Parallel()

	const product = "own-catalog"

	newPublisherFor(t, product, &middleware.AuthClient{Logger: obs.Nop()}, separateGuardManifest(t, product))

	rec := newScopeRecorder(t, "")
	guard := &middleware.AuthClient{Address: rec.URL, Enabled: true, Logger: obs.Nop(), M2MInversionEnabled: true}
	require.NoError(t, guard.SetManifestScope(product, middleware.Dim("organizationId", middleware.FromPath).At("organization_id")))

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id", guard.Authorize(product, "accounts", "get"), compatOK)

	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1", compatPartner))
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, rec.questions())
}

// A later New for the product replaces what is registered, and routes that
// already served a request follow it.
func TestNew_ReregisteringReachesRoutesAlreadyServed(t *testing.T) {
	t.Parallel()

	const product = "reregistered"

	manifest := separateGuardManifest(t, product)

	rec := newScopeRecorder(t, "")
	guard := &middleware.AuthClient{Address: rec.URL, Enabled: true, Logger: obs.Nop(), M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id", guard.Authorize(product, "accounts", "get"), compatOK)

	target := "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1"

	newPublisherFor(t, product, &middleware.AuthClient{Logger: obs.Nop()}, manifest)
	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, target, compatPartner))

	unscoped := manifest[:strings.Index(manifest, "scope:")]
	newPublisherFor(t, product, &middleware.AuthClient{Logger: obs.Nop()}, unscoped)
	assert.Equal(t, http.StatusForbidden, status(t, app, http.MethodGet, target, compatPartner))

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
	}, rec.questions(), "the second request is refused before any call")
}

func newBodyRequest(method, target, body, token string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	return req
}

// Registering while another client's routes serve requests is safe: run with
// -race.
func TestNew_RegisteringWhileServingIsRaceFree(t *testing.T) {
	t.Parallel()

	const product = "concurrent"

	manifest := separateGuardManifest(t, product)

	rec := newScopeRecorder(t, "")
	guard := &middleware.AuthClient{Address: rec.URL, Enabled: true, Logger: obs.Nop(), M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id", guard.Authorize(product, "accounts", "get"), compatOK)

	done := make(chan struct{})

	go func() {
		defer close(done)

		for range 20 {
			_, err := New(Config{
				Slug: product, Manifest: []byte(manifest), IdentityAddr: "http://identity.invalid",
				Auth: &middleware.AuthClient{Logger: obs.Nop()}, ClientID: "id", ClientSecret: "secret",
			})
			if err != nil {
				t.Errorf("New: %v", err)

				return
			}
		}
	}()

	for range 20 {
		code := status(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1", compatPartner)
		assert.Contains(t, []int{http.StatusOK, http.StatusForbidden}, code)
	}

	<-done

	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1", compatPartner),
		"once registered, the route is scoped")
}
