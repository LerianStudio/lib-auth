package declaration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scopeRecorder is an authorization service that records the attributes of
// every question and refuses those naming a denied value.
type scopeRecorder struct {
	*httptest.Server

	mu    sync.Mutex
	asked []map[string]string
}

func newScopeRecorder(t *testing.T, denied string) *scopeRecorder {
	t.Helper()

	rec := &scopeRecorder{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("scope recorder: failed to read body: %v", err)
			http.Error(w, `{"code":"unreadable_body"}`, http.StatusBadRequest)

			return
		}

		var body struct {
			Attributes map[string]string `json:"attributes"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("scope recorder: failed to decode body: %v", err)
			http.Error(w, `{"code":"undecodable_body"}`, http.StatusBadRequest)

			return
		}

		rec.mu.Lock()
		rec.asked = append(rec.asked, body.Attributes)
		rec.mu.Unlock()

		authorized := true

		for _, v := range body.Attributes {
			if v == denied {
				authorized = false
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"authorized": authorized})
	}))
	t.Cleanup(rec.Close)

	return rec
}

func (r *scopeRecorder) questions() []map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]map[string]string(nil), r.asked...)
}

var compatPartner = compatToken(jwt.MapClaims{"type": "application", "sub": "acme/app", "partner": "acme/p1"})

func status(t *testing.T, app *fiber.App, method, target, token string) int {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	return resp.StatusCode
}

func newPublisher(t *testing.T, auth TokenMinter, manifest string) {
	t.Helper()

	_, err := New(Config{
		Slug: "midaz", Manifest: []byte(manifest), IdentityAddr: "http://identity.invalid",
		Auth: auth, ClientID: "id", ClientSecret: "secret",
	})
	require.NoError(t, err)
}

// New gives the client it mints with the manifest's scope, so the routes that
// client authorizes derive their scope from it — routes registered before New
// as well as after.
func TestNew_WiresTheManifestScopeIntoTheClient(t *testing.T) {
	t.Parallel()

	rec := newScopeRecorder(t, "acc-denied")
	auth := &middleware.AuthClient{Address: rec.URL, Enabled: true, Logger: obs.Nop(), M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id", auth.Authorize("midaz", "accounts", "get"), compatOK)

	newPublisher(t, auth, wireCompatManifest)

	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/balances/:account_id", auth.Authorize("midaz", "balances", "get"), compatOK)

	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1", compatPartner))
	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/balances/acc-2", compatPartner))
	assert.Equal(t, http.StatusForbidden, status(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/balances/acc-denied", compatPartner))

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-2"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-denied"},
	}, rec.questions())
}

// A service whose declaration is off never builds a publisher, so its client
// has no scope: a partner-bound credential is refused before any call, and any
// other credential is decided as always.
func TestNew_NotCalledLeavesPartnersDenied(t *testing.T) {
	t.Parallel()

	rec := newScopeRecorder(t, "")
	auth := &middleware.AuthClient{Address: rec.URL, Enabled: true, Logger: obs.Nop(), M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id", auth.Authorize("midaz", "accounts", "get"), compatOK)

	target := "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1"
	user := compatToken(jwt.MapClaims{"type": "normal-user", "owner": "acme-org", "sub": "user-1"})

	assert.Equal(t, http.StatusForbidden, status(t, app, http.MethodGet, target, compatPartner))
	assert.Empty(t, rec.questions(), "refused before any call")

	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, target, user))
	assert.Equal(t, []map[string]string{nil}, rec.questions())

	// Positive control: once New wires the manifest, the same partner request
	// is asked and allowed.
	newPublisher(t, auth, wireCompatManifest)
	assert.Equal(t, http.StatusOK, status(t, app, http.MethodGet, target, compatPartner))
}

// A minter that is not an AuthClient has no routes to scope: New takes it as
// before.
func TestNew_OtherMinterIsLeftAlone(t *testing.T) {
	t.Parallel()

	newPublisher(t, minterFunc(func(context.Context, string, string) (string, error) { return "token", nil }), wireCompatManifest)
}

// A manifest route the middleware cannot honour fails New, as it fails
// WireScope.
func TestNew_RouteTheMiddlewareRefusesFailsNew(t *testing.T) {
	t.Parallel()

	auth := &middleware.AuthClient{Logger: obs.Nop()}

	_, err := New(Config{
		Slug: "midaz", Manifest: []byte(wireCompatManifest + `
    - method: POST
      path: /v1/organizations/:organization_id/ledgers/:ledger_id/transfers
      dimensions:
        - name: accountId
          from: body
          field: "items[]."
`), IdentityAddr: "http://identity.invalid", Auth: auth, ClientID: "id", ClientSecret: "secret",
	})
	require.ErrorContains(t, err, `"items[]."`)
}

type minterFunc func(ctx context.Context, clientID, clientSecret string) (string, error)

func (f minterFunc) GetApplicationToken(ctx context.Context, clientID, clientSecret string) (string, error) {
	return f(ctx, clientID, clientSecret)
}

func compatOK(c fiber.Ctx) error { return c.SendString("ok") }
