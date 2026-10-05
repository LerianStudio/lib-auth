package declaration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wireCompatManifest is a product manifest with a scope catalog and a body
// route, valid on every release that knows scope.routes.
const wireCompatManifest = `
service: midaz
version: 1
permissions:
  - resource: accounts
    action: get
    effect: allow
    roles: [midaz/viewer]
roles:
  - name: midaz/viewer
scope:
  dimensions:
    - name: organizationId
      from: path
      param: organization_id
      collection: organizations
    - name: ledgerId
      from: path
      param: ledger_id
      collection: ledgers
    - name: accountId
      from: path
      param: account_id
      collection: accounts
  routes:
    - method: POST
      path: /v1/organizations/:organization_id/ledgers/:ledger_id/transactions
      dimensions:
        - name: accountId
          from: body
          field: "send.source.from[].accountId"
`

// wireCompatGolden holds the authorize bodies the develop line sends for the
// requests of nonPartnerAuthorizeBodies, captured from a build of it. They are
// literal bytes, so an added member, a reordered key or a changed encoding on a
// call that is not partner-bound fails the comparison.
const wireCompatGolden = "testdata/nonpartner_authorize_bodies.json"

func compatToken(claims jwt.MapClaims) string {
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("compat-secret"))
	if err != nil {
		panic("sign compat token: " + err.Error())
	}

	return signed
}

// nonPartnerAuthorizeBodies builds the product the way a service does — one
// client for its routes and its publisher, declaration.New given that client —
// and returns the raw /v1/authorize body of each request a credential that is
// not partner-bound makes on it: a user and an application, on a route the
// catalog scopes, a body route, and a route the catalog gives no account.
func nonPartnerAuthorizeBodies(t *testing.T, manifest string) []string {
	t.Helper()

	var (
		mu     sync.Mutex
		bodies []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		mu.Lock()
		bodies = append(bodies, r.Method+" "+r.URL.Path+" "+string(raw))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorized":true}`))
	}))
	t.Cleanup(srv.Close)

	auth := &middleware.AuthClient{Address: srv.URL, Enabled: true, Logger: obs.Nop(), M2MInversionEnabled: true}

	_, err := New(Config{
		Slug: "midaz", Manifest: []byte(manifest), IdentityAddr: "http://identity.invalid",
		Auth: auth, ClientID: "id", ClientSecret: "secret",
	})
	require.NoError(t, err)

	ok := func(c fiber.Ctx) error { return c.SendString("ok") }

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id", auth.Authorize("midaz", "accounts", "get"), ok)
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/balances/:id", auth.Authorize("midaz", "balances", "get"), ok)
	app.Post("/v1/organizations/:organization_id/ledgers/:ledger_id/transactions", auth.Authorize("midaz", "transactions", "post"), ok)

	user := compatToken(jwt.MapClaims{"type": "normal-user", "owner": "acme-org", "sub": "user-1"})
	application := compatToken(jwt.MapClaims{"type": "application", "sub": "acme/app"})

	for _, token := range []string{user, application} {
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1", nil),
			httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1?organizationId=org-2", nil),
			httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/balances/bal-1", nil),
			httptest.NewRequest(http.MethodPost, "/v1/organizations/org-1/ledgers/led-1/transactions",
				strings.NewReader(`{"send":{"source":{"from":[{"accountId":"acc-1"},{"accountId":"acc-2"}]}}}`)),
			httptest.NewRequest(http.MethodPost, "/v1/organizations/org-1/ledgers/led-1/transactions", strings.NewReader(`not json`)),
		} {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s %s", req.Method, req.URL)
			require.NoError(t, resp.Body.Close())
		}
	}

	mu.Lock()
	defer mu.Unlock()

	return append([]string(nil), bodies...)
}

// A credential that is not partner-bound sends, on a product whose manifest
// declaration.New wired into its client, exactly the authorize bodies the
// develop line sends — where the same wiring attached no scope: no attributes,
// no other member, the same bytes.
func TestNew_NonPartnerAuthorizeBodiesMatchTheDevelopLine(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(wireCompatGolden)
	require.NoError(t, err)

	var golden []string
	require.NoError(t, json.Unmarshal(raw, &golden))
	require.Len(t, golden, 10, "the golden file holds one body per request")

	got := nonPartnerAuthorizeBodies(t, wireCompatManifest)
	assert.Equal(t, golden, got)

	for _, body := range got {
		assert.NotContains(t, body, "attributes")
	}
}
