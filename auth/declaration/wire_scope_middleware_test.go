package declaration

import (
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

// authorizeRecorder stands in for POST /v1/authorize and records the last body.
type authorizeRecorder struct {
	*httptest.Server
	mu   sync.Mutex
	last string
}

func newAuthorizeRecorder(t *testing.T) *authorizeRecorder {
	t.Helper()

	rec := &authorizeRecorder{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		rec.mu.Lock()
		rec.last = string(raw)
		rec.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorized":true}`))
	}))
	t.Cleanup(rec.Close)

	return rec
}

func partnerBearer(t *testing.T) string {
	t.Helper()

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type": "application", "sub": "acme/app", "partner": "acme/p1",
	}).SignedString([]byte("test"))
	require.NoError(t, err)

	return "Bearer " + signed
}

// WireScope is the one call a product makes: the route below declares nothing,
// and the request carries the manifest's dimensions as attributes.
func TestWireScope_RoutesDeriveTheManifestDimensions(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	rec := newAuthorizeRecorder(t)
	auth := middleware.NewAuthClient(rec.URL, true, obs.Nop())

	require.NoError(t, WireScope(auth, []byte(scopedYAML)))

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id",
		auth.Authorize("plugin-fees", "ledgers", "get"),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/ledgers/led-1", nil)
	req.Header.Set("Authorization", partnerBearer(t))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	rec.mu.Lock()
	body := rec.last
	rec.mu.Unlock()

	var got struct {
		Attributes map[string]string `json:"attributes"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1"}, got.Attributes)
}

func TestWireScope_ManifestWithoutScopeIsANoop(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	rec := newAuthorizeRecorder(t)
	auth := middleware.NewAuthClient(rec.URL, true, obs.Nop())

	require.NoError(t, WireScope(auth, []byte(feesJSON)))

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id",
		auth.Authorize("plugin-fees", "ledgers", "get"),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1", nil)
	req.Header.Set("Authorization", partnerBearer(t))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"without a catalog the route declares nothing, and a partner credential is refused as before")
}

func TestWireScope_Errors(t *testing.T) {
	t.Parallel()

	auth := &middleware.AuthClient{Logger: obs.Nop()}

	require.Error(t, WireScope(nil, []byte(scopedYAML)), "nil client")
	require.Error(t, WireScope(auth, nil), "empty manifest")
	require.Error(t, WireScope(auth, []byte("service: x\nversion: 1\nscope:\n  dimensions:\n    - name: a\n      from: body\n      param: a\n      collection: c\n")),
		"invalid scope")
}
