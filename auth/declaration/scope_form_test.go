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

// formRoutesSection declares a route reading its ledger from a urlencoded form.
const formRoutesSection = `
  routes:
    - method: POST
      path: /v1/organizations/:organization_id/ledgers
      dimensions:
        - name: ledgerId
          from: form
          field: ledgerId
        - name: organizationId
          from: form
          field: organizationId
          optional: true
`

const formRoutedYAML = scopedYAML + formRoutesSection

func TestValidate_FormRouteDimension(t *testing.T) {
	t.Parallel()

	valid := func() *DeclarationManifest {
		m, err := parseManifest([]byte(formRoutedYAML))
		require.NoError(t, err)

		return m
	}

	require.NoError(t, valid().Validate(), "positive control")

	m := valid()
	m.Scope.Routes[0].Dimensions[0].Field = "ledger id"
	assert.ErrorContains(t, m.Validate(), `scope.routes[0].dimensions[0]: field "ledger id" must be a form field name`)

	m = valid()
	m.Scope.Routes[0].Dimensions[1].From = "body"
	assert.ErrorContains(t, m.Validate(), "scope.routes[0]: reads the request body both as JSON (from: body) and as a form (from: form)")

	m = valid()
	m.Scope.Dimensions[0].From = "form"
	assert.ErrorContains(t, m.Validate(), `scope.dimensions[0]: from must be one of "path", "query", "header", got "form"`,
		"the catalog applies to every route and reads no body")
}

// form lives in scope.routes: it moves neither the wire body nor the hash.
func TestFormRouteDimension_StaysOutOfTheWireAndTheHash(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(formRoutedYAML))
	require.NoError(t, err)

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, scopedYAMLHash, hash)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, scopedYAMLWire, string(wire))
}

func TestWireScope_FormRouteDimension(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	rec := newAuthorizeRecorder(t)
	auth := middleware.NewAuthClient(rec.URL, true, obs.Nop())

	require.NoError(t, WireScope(auth, []byte(formRoutedYAML)))

	app := fiber.New()
	app.Post("/v1/organizations/:organization_id/ledgers", auth.Authorize("plugin-fees", "ledgers", "post"),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	post := func(ctype, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/organizations/org-1/ledgers", strings.NewReader(body))
		req.Header.Set("Authorization", partnerBearer(t))
		req.Header.Set("Content-Type", ctype)

		resp, err := app.Test(req)
		require.NoError(t, err)

		return resp.StatusCode
	}

	assert.Equal(t, http.StatusOK, post("application/x-www-form-urlencoded", "ledgerId=led-1"))

	rec.mu.Lock()
	body := rec.last
	rec.mu.Unlock()

	var got struct {
		Attributes map[string]string `json:"attributes"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1"}, got.Attributes)

	assert.Equal(t, http.StatusBadRequest, post("application/x-www-form-urlencoded", "ledgerId=led-1&organizationId=org-2"),
		"the form disagrees with the path")
	assert.Equal(t, http.StatusBadRequest, post("multipart/form-data; boundary=x", "--x--\r\n"), "only a urlencoded form is read")
}
