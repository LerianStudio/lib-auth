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

// scopedYAMLHash and scopedYAMLWire are the canonical hash and the wire body of
// scopedYAML as computed before scope.routes existed. They are literals, not a
// recomputation, so any drift in the bytes a deployed manifest publishes fails.
const (
	scopedYAMLHash = "ec9654111747e39b05330cee152db445382adae6bd5a5e7a7a7e6442fd7adb9d"
	scopedYAMLWire = `{"service":"plugin-fees","version":3,"permissions":[{"resource":"billing-packages","action":"read","effect":"allow","roles":["fees/viewer"]}],"roles":[{"name":"fees/viewer"}],"scope":{"dimensions":[{"name":"organizationId","from":"path","param":"organization_id","required":true,"collection":"organizations","label":"Organization"},{"name":"ledgerId","from":"path","param":"ledger_id","multi":true,"collection":"ledgers","label":"ledger"}]}}`
)

// routesSection is a scope.routes section declaring two body routes.
const routesSection = `
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
    - method: post
      path: /v2/transactions/batch
      dimensions:
        - name: organizationId
          from: body
          field: organizationId
        - name: ledgerId
          from: body
          field: "items[].ledgerId"
`

const routedYAML = scopedYAML + routesSection

const routedJSON = `{
  "service": "plugin-fees",
  "version": 3,
  "permissions": [
    { "resource": "billing-packages", "action": "read", "effect": "allow", "roles": ["fees/viewer"] }
  ],
  "roles": [ { "name": "fees/viewer" } ],
  "scope": {
    "dimensions": [
      { "name": "organizationId", "from": "path", "param": "organization_id", "required": true, "collection": "organizations", "label": "Organization" },
      { "name": "ledgerId", "from": "path", "param": "ledger_id", "multi": true, "collection": "ledgers", "label": "ledger" }
    ],
    "routes": [
      { "method": "POST", "path": "/v2/transactions/direct", "dimensions": [
        { "name": "organizationId", "from": "body", "field": "organizationId" },
        { "name": "ledgerId", "from": "body", "field": "ledgerId" } ] },
      { "method": "post", "path": "/v2/transactions/batch", "dimensions": [
        { "name": "organizationId", "from": "body", "field": "organizationId" },
        { "name": "ledgerId", "from": "body", "field": "items[].ledgerId" } ] }
    ]
  }
}`

func TestParseManifest_ScopeRoutes_YAMLAndJSONAgree(t *testing.T) {
	t.Parallel()

	fromYAML, err := parseManifest([]byte(routedYAML))
	require.NoError(t, err)

	fromJSON, err := parseManifest([]byte(routedJSON))
	require.NoError(t, err)

	assert.Equal(t, fromJSON, fromYAML)

	require.NotNil(t, fromYAML.Scope)
	require.Len(t, fromYAML.Scope.Routes, 2)
	assert.Equal(t, DeclarationScopeRoute{
		Method: "post",
		Path:   "/v2/transactions/batch",
		Dimensions: []DeclarationRouteDimension{
			{Name: "organizationId", From: "body", Field: "organizationId"},
			{Name: "ledgerId", From: "body", Field: "items[].ledgerId"},
		},
	}, fromYAML.Scope.Routes[1])

	require.NoError(t, fromYAML.Validate())
}

// The routes are read by this library alone: the published catalog, its wire
// body and its hash are the ones the manifest had before declaring them.
func TestScopeRoutes_StayOutOfTheWireAndTheHash(t *testing.T) {
	t.Parallel()

	without, err := parseManifest([]byte(scopedYAML))
	require.NoError(t, err)

	with, err := parseManifest([]byte(routedYAML))
	require.NoError(t, err)

	for name, m := range map[string]*DeclarationManifest{"without_routes": without, "with_routes": with} {
		hash, err := m.CanonicalHash()
		require.NoError(t, err)
		assert.Equal(t, scopedYAMLHash, hash, name)

		wire, err := m.wireJSON()
		require.NoError(t, err)
		assert.Equal(t, scopedYAMLWire, string(wire), name)

		scopeWire, err := m.scopeOnly().wireJSON()
		require.NoError(t, err)
		assert.NotContains(t, string(scopeWire), "routes", name)

		scopeHash, err := m.scopeOnly().CanonicalHash()
		require.NoError(t, err)

		withoutScopeHash, err := without.scopeOnly().CanonicalHash()
		require.NoError(t, err)
		assert.Equal(t, withoutScopeHash, scopeHash, name)
	}

	// Projecting the manifest must not drop the routes from the manifest itself.
	assert.Len(t, with.Scope.Routes, 2)
}

func TestValidate_ScopeRoutes(t *testing.T) {
	t.Parallel()

	valid := func() *DeclarationManifest {
		m, err := parseManifest([]byte(routedYAML))
		require.NoError(t, err)

		return m
	}

	tests := []struct {
		name    string
		mutate  func(m *DeclarationManifest)
		wantErr string
	}{
		{name: "from_missing", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].From = "" }, wantErr: `scope.routes[0].dimensions[0]: from must be one of "body", "form", "query", "header", got ""`},
		{name: "from_unknown", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].From = "cookie" }, wantErr: `got "cookie"`},
		{name: "from_path", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].From = "path" }, wantErr: `got "path"`},
		{name: "field_missing", mutate: func(m *DeclarationManifest) { m.Scope.Routes[1].Dimensions[1].Field = " " }, wantErr: "scope.routes[1].dimensions[1]: field must not be empty"},
		{name: "name_missing", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].Name = "" }, wantErr: "scope.routes[0].dimensions[0]: name must not be empty"},
		{name: "name_outside_catalog", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].Name = "portfolioId" }, wantErr: `"portfolioId" is not a scope dimension`},
		{name: "method_missing", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Method = "" }, wantErr: "scope.routes[0]: method must not be empty"},
		{name: "path_relative", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Path = "v2/x" }, wantErr: "scope.routes[0]: path"},
		{name: "no_dimensions", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions = nil }, wantErr: "scope.routes[0]: must declare at least one dimension"},
		{name: "duplicate_route", mutate: func(m *DeclarationManifest) { m.Scope.Routes[1].Path = m.Scope.Routes[0].Path }, wantErr: "scope.routes[1]: duplicate route"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := valid()
			tt.mutate(m)

			err := m.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}

	require.NoError(t, valid().Validate(), "positive control")
}

// WireScope wires the routes too: a route reading its organization and ledger
// from the body sends them, with no declaration at the route.
func TestWireScope_RoutesReadTheBody(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	rec := newAuthorizeRecorder(t)
	auth := middleware.NewAuthClient(rec.URL, true, obs.Nop())

	require.NoError(t, WireScope(auth, []byte(routedYAML)))

	app := fiber.New()
	v2 := app.Group("/v2")
	v2.Post("/transactions/batch", auth.Authorize("plugin-fees", "transactions", "post"),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest(http.MethodPost, "/v2/transactions/batch",
		strings.NewReader(`{"organizationId":"org-1","items":[{"ledgerId":"led-1"}]}`))
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

	req = httptest.NewRequest(http.MethodPost, "/v2/transactions/batch", strings.NewReader(`{"organizationId":"org-1"}`))
	req.Header.Set("Authorization", partnerBearer(t))

	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// A route the middleware cannot honour fails the boot, as any other manifest
// error does.
func TestWireScope_RouteErrorsFailTheBoot(t *testing.T) {
	t.Parallel()

	auth := &middleware.AuthClient{Logger: obs.Nop()}

	unknownFrom := strings.Replace(routedYAML, "from: body\n          field: ledgerId", "from: path\n          field: ledgerId", 1)
	require.NotEqual(t, routedYAML, unknownFrom)
	require.ErrorContains(t, WireScope(auth, []byte(unknownFrom)), `got "path"`)

	badField := strings.Replace(routedYAML, `"items[].ledgerId"`, `"items[]."`, 1)
	require.NotEqual(t, routedYAML, badField)
	require.ErrorContains(t, WireScope(auth, []byte(badField)), `"items[]."`)

	// A field ending in "[]" is an array of strings: wired.
	stringArray := strings.Replace(routedYAML, `"items[].ledgerId"`, `"ledgerIds[]"`, 1)
	require.NotEqual(t, routedYAML, stringArray)
	require.NoError(t, WireScope(&middleware.AuthClient{Logger: obs.Nop()}, []byte(stringArray)))

	require.NoError(t, WireScope(auth, []byte(routedYAML)), "positive control")
}
