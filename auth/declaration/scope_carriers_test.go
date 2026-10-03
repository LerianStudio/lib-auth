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

// carriersYAML reads the organization from a header, the ledger from the path
// and the account from the query; one route reads the ledger from the query
// too, and the organization from the body.
const carriersYAML = `
service: plugin-fees
version: 3
scope:
  dimensions:
    - name: organizationId
      from: header
      param: X-Organization-Id
      collection: organizations
    - name: ledgerId
      from: path
      param: ledger_id
      collection: ledgers
    - name: accountId
      from: query
      param: accountId
      multi: true
      collection: accounts
  routes:
    - method: POST
      path: /v1/ledgers/:ledger_id/transfers
      dimensions:
        - name: organizationId
          from: body
          field: organizationId
        - name: ledgerId
          from: query
          field: ledgerId
          optional: true
        - name: accountId
          from: header
          field: X-Account-Id
          optional: true
`

func TestValidate_ScopeCarriers(t *testing.T) {
	t.Parallel()

	valid := func() *DeclarationManifest {
		m, err := parseManifest([]byte(carriersYAML))
		require.NoError(t, err)

		return m
	}

	require.NoError(t, valid().Validate(), "positive control")

	tests := []struct {
		name    string
		mutate  func(m *DeclarationManifest)
		wantErr string
	}{
		{name: "header_param_not_a_token", mutate: func(m *DeclarationManifest) { m.Scope.Dimensions[0].Param = "X Organization" }, wantErr: `scope.dimensions[0]: param "X Organization" must be a header name`},
		{name: "header_param_with_colon", mutate: func(m *DeclarationManifest) { m.Scope.Dimensions[0].Param = "X-Org:" }, wantErr: "scope.dimensions[0]: param"},
		{name: "query_param_with_space", mutate: func(m *DeclarationManifest) { m.Scope.Dimensions[2].Param = "account id" }, wantErr: `scope.dimensions[2]: param "account id" must be a query parameter name`},
		{name: "query_param_with_ampersand", mutate: func(m *DeclarationManifest) { m.Scope.Dimensions[2].Param = "a&b" }, wantErr: "scope.dimensions[2]: param"},
		{name: "same_header_any_case", mutate: func(m *DeclarationManifest) {
			m.Scope.Dimensions[2].From = "header"
			m.Scope.Dimensions[2].Param = "x-organization-id"
		}, wantErr: `scope.dimensions[2]: duplicate param "x-organization-id"`},
		{name: "same_query", mutate: func(m *DeclarationManifest) {
			m.Scope.Dimensions[1].From = "query"
			m.Scope.Dimensions[1].Param = "accountId"
		}, wantErr: `scope.dimensions[2]: duplicate param "accountId"`},
		{name: "route_header_field_not_a_token", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[2].Field = "X Account" }, wantErr: `scope.routes[0].dimensions[2]: field "X Account" must be a header name`},
		{name: "route_query_field_with_space", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[1].Field = "ledger id" }, wantErr: `scope.routes[0].dimensions[1]: field "ledger id" must be a query parameter name`},
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

	// A path parameter and a query parameter spelled alike are two places.
	m := valid()
	m.Scope.Dimensions[1].Param = "accountId"
	require.NoError(t, m.Validate())
}

// The catalog's carriers are content: they go on the wire and into the hash,
// so moving a dimension from the path to a header is published.
func TestScopeCarriers_AreContent(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(carriersYAML))
	require.NoError(t, err)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Contains(t, string(wire), `{"name":"organizationId","from":"header","param":"X-Organization-Id","collection":"organizations"}`)
	assert.Contains(t, string(wire), `{"name":"accountId","from":"query","param":"accountId","multi":true,"collection":"accounts"}`)
	assert.NotContains(t, string(wire), "routes")

	hash, err := m.CanonicalHash()
	require.NoError(t, err)

	moved := *m
	moved.Scope = &DeclarationScope{Dimensions: append([]DeclarationDimension(nil), m.Scope.Dimensions...)}
	moved.Scope.Dimensions[0].From = "query"

	movedHash, err := moved.CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, hash, movedHash)
}

// WireScope reads each dimension where the manifest says: a catalog header and
// query on every route, the route's own carriers on its route, and refuses a
// request whose carriers disagree.
func TestWireScope_Carriers(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	rec := newAuthorizeRecorder(t)
	auth := middleware.NewAuthClient(rec.URL, true, obs.Nop())

	require.NoError(t, WireScope(auth, []byte(carriersYAML)))

	app := fiber.New()
	app.Post("/v1/ledgers/:ledger_id/transfers", auth.Authorize("plugin-fees", "transfers", "post"),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	post := func(target, body string, headers map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		req.Header.Set("Authorization", partnerBearer(t))

		for k, v := range headers {
			req.Header.Set(k, v)
		}

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

	assert.Equal(t, http.StatusOK, post("/v1/ledgers/led-1/transfers?ledgerId=led-1&accountId=acc-1",
		`{"organizationId":"org-1"}`, map[string]string{"x-organization-id": "org-1", "X-Account-Id": "acc-1"}))
	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"}, lastAttributes())

	assert.Equal(t, http.StatusBadRequest, post("/v1/ledgers/led-1/transfers?ledgerId=led-2",
		`{"organizationId":"org-1"}`, nil), "path and query disagree on the ledger")
	assert.Equal(t, http.StatusBadRequest, post("/v1/ledgers/led-1/transfers",
		`{"organizationId":"org-2"}`, map[string]string{"X-Organization-Id": "org-1"}), "header and body disagree on the organization")
	assert.Equal(t, http.StatusBadRequest, post("/v1/ledgers/led-1/transfers?accountId=acc-1",
		`{"organizationId":"org-1"}`, map[string]string{"X-Account-Id": "acc-2"}), "query and header disagree on the account")
}
