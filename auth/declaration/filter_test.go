package declaration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// filteredYAML is scopedYAML with an account dimension and a list route that
// filters on it, declaring no dimension of its own.
const filteredYAML = scopedYAML + `    - { name: accountId, from: query, param: accountId, collection: accounts }
  routes:
    - method: GET
      path: /v1/organizations/:organization_id/ledgers/:ledger_id/accounts
      filter: [accountId]
`

func TestParseManifest_ScopeRouteFilter(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(filteredYAML))
	require.NoError(t, err)
	require.NoError(t, m.Validate())

	require.Len(t, m.Scope.Routes, 1)
	assert.Equal(t, []string{"accountId"}, m.Scope.Routes[0].Filter)
	assert.Empty(t, m.Scope.Routes[0].Dimensions)
}

// The filter is a route's, and routes are never published: the wire body and
// the hash are those of the catalog alone.
func TestScopeRouteFilter_StaysOutOfTheWireAndTheHash(t *testing.T) {
	t.Parallel()

	filtered, err := parseManifest([]byte(filteredYAML))
	require.NoError(t, err)

	catalogOnly := *filtered
	catalogOnly.Scope = &DeclarationScope{Dimensions: filtered.Scope.Dimensions}

	for name, m := range map[string]*DeclarationManifest{"filtered": filtered, "catalog_only": &catalogOnly} {
		wire, err := m.wireJSON()
		require.NoError(t, err)
		assert.NotContains(t, string(wire), "filter", name)
		assert.NotContains(t, string(wire), "routes", name)
	}

	filteredHash, err := filtered.CanonicalHash()
	require.NoError(t, err)

	catalogHash, err := catalogOnly.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, catalogHash, filteredHash)
}

func TestValidate_ScopeRouteFilter(t *testing.T) {
	t.Parallel()

	valid := func() *DeclarationManifest {
		m, err := parseManifest([]byte(filteredYAML))
		require.NoError(t, err)

		return m
	}

	tests := []struct {
		name    string
		mutate  func(m *DeclarationManifest)
		wantErr string
	}{
		{name: "empty_entry", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Filter = []string{""} }, wantErr: "scope.routes[0].filter[0]: must not be empty"},
		{name: "outside_catalog", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Filter = []string{"portfolioId"} }, wantErr: `scope.routes[0].filter[0]: "portfolioId" is not a scope dimension of the catalog`},
		{name: "duplicate", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Filter = []string{"accountId", "accountId"} }, wantErr: `scope.routes[0].filter[1]: duplicate dimension "accountId"`},
		{name: "neither", mutate: func(m *DeclarationManifest) { m.Scope.Routes[0].Filter = nil }, wantErr: "scope.routes[0]: must declare at least one dimension or a filter"},
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

// WireScope wires the filter: a partner listing accounts without naming one
// asks to filter on it.
func TestWireScope_RouteFilter(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	var (
		mu   sync.Mutex
		last string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		mu.Lock()
		last = string(raw)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorized":true,"allowed":{"accountId":["acc-1"]}}`))
	}))
	t.Cleanup(srv.Close)

	auth := middleware.NewAuthClient(srv.URL, true, obs.Nop())
	require.NoError(t, WireScope(auth, []byte(filteredYAML)))

	var (
		values []string
		ok     bool
	)

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts",
		auth.Authorize("plugin-fees", "accounts", "get"),
		func(c fiber.Ctx) error {
			if scope, present := middleware.ScopeFromContext(c.Context()); present {
				values, ok = scope.Allowed("accountId")
			}

			return c.SendString("ok")
		})

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts", nil)
	req.Header.Set("Authorization", partnerBearer(t))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mu.Lock()
	body := last
	mu.Unlock()

	assert.JSONEq(t,
		`{"action":"get","product":"plugin-fees","resource":"accounts","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1"},"filter":["accountId"]}`,
		body)
	assert.True(t, ok)
	assert.Equal(t, []string{"acc-1"}, values)
}
