package declaration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// optionalRoutesSection declares a route whose ledger is optional in its body.
const optionalRoutesSection = `
  routes:
    - method: POST
      path: /v2/transactions/direct
      dimensions:
        - name: organizationId
          from: body
          field: organizationId
        - name: ledgerId
          from: body
          field: ledgerId
          optional: true
`

const optionalRoutedYAML = scopedYAML + optionalRoutesSection

func TestParseManifest_RouteDimensionOptional(t *testing.T) {
	t.Parallel()

	fromYAML, err := parseManifest([]byte(optionalRoutedYAML))
	require.NoError(t, err)
	require.NoError(t, fromYAML.Validate())

	fromJSON, err := parseManifest([]byte(`{"service":"plugin-fees","version":3,"scope":{"routes":[{"method":"POST","path":"/x","dimensions":[
		{"name":"ledgerId","from":"body","field":"ledgerId","optional":true}]}]}}`))
	require.NoError(t, err)

	assert.Equal(t, []DeclarationRouteDimension{
		{Name: "organizationId", From: "body", Field: "organizationId"},
		{Name: "ledgerId", From: "body", Field: "ledgerId", Optional: true},
	}, fromYAML.Scope.Routes[0].Dimensions)
	assert.True(t, fromJSON.Scope.Routes[0].Dimensions[0].Optional)
}

// optional lives in scope.routes, which only this library reads: declaring it
// moves neither the wire body nor the hash.
func TestRouteDimensionOptional_StaysOutOfTheWireAndTheHash(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(optionalRoutedYAML))
	require.NoError(t, err)
	require.True(t, m.Scope.Routes[0].Dimensions[1].Optional, "the fixture must declare optional")

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, scopedYAMLHash, hash)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, scopedYAMLWire, string(wire))
	assert.NotContains(t, string(wire), "optional")
}

// WireScope carries optional into the middleware: the body may leave the field
// out, and may not give it an empty value.
func TestWireScope_OptionalRouteDimension(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	rec := newAuthorizeRecorder(t)
	auth := middleware.NewAuthClient(rec.URL, true, obs.Nop())

	require.NoError(t, WireScope(auth, []byte(optionalRoutedYAML)))

	app := fiber.New()
	app.Post("/v2/transactions/direct", auth.Authorize("plugin-fees", "transactions", "post"),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/v2/transactions/direct", strings.NewReader(body))
		req.Header.Set("Authorization", partnerBearer(t))

		resp, err := app.Test(req)
		require.NoError(t, err)

		return resp.StatusCode
	}

	lastAttributes := func() map[string]string {
		rec.mu.Lock()
		body := rec.last
		rec.mu.Unlock()

		var got struct {
			Attributes map[string]string `json:"attributes"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &got))

		return got.Attributes
	}

	assert.Equal(t, http.StatusOK, post(`{"organizationId":"org-1"}`))
	assert.Equal(t, map[string]string{"organizationId": "org-1"}, lastAttributes())

	assert.Equal(t, http.StatusOK, post(`{"organizationId":"org-1","ledgerId":"led-1"}`))
	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1"}, lastAttributes())

	assert.Equal(t, http.StatusBadRequest, post(`{"organizationId":"org-1","ledgerId":""}`))
	assert.Equal(t, http.StatusBadRequest, post(`{"ledgerId":"led-1"}`), "a dimension not declared optional stays required")
}
