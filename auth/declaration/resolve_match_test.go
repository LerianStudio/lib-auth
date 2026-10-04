package declaration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// matchYAML is unresolvedYAML with the account dimension resolved and matched
// on any of its values, and a route resolving a holder into its ledgers.
const matchYAML = `
service: plugin-fees
version: 3
permissions:
  - resource: billing-packages
    action: read
    effect: allow
    roles: [fees/viewer]
roles:
  - name: fees/viewer
scope:
  dimensions:
    - { name: organizationId, from: path, param: organization_id, required: true, collection: organizations, label: "Organization" }
    - { name: ledgerId, from: path, param: ledger_id, multi: true, collection: ledgers, label: "ledger" }
    - { name: accountId, from: header, param: X-Account-Alias, collection: accounts, resolve: alias, match: any }
  routes:
    - method: GET
      path: /v1/organizations/:organization_id/holders/:holder_id
      dimensions:
        - { name: ledgerId, from: path, field: holder_id, resolve: holderLedgers, match: any }
`

func TestParseManifest_Match(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(matchYAML))
	require.NoError(t, err)
	require.NoError(t, m.Validate())

	assert.Equal(t, "any", m.Scope.Dimensions[2].Match)
	assert.Empty(t, m.Scope.Dimensions[0].Match)
	assert.Equal(t, "any", m.Scope.Routes[0].Dimensions[0].Match)
}

// match is read by this library only: the wire body, the scope-only body and
// the hash are those of the manifest without it.
func TestMatch_StaysOutOfTheWireAndTheHash(t *testing.T) {
	t.Parallel()

	matched, err := parseManifest([]byte(matchYAML))
	require.NoError(t, err)

	plain, err := parseManifest([]byte(unresolvedYAML))
	require.NoError(t, err)

	matchedHash, err := matched.CanonicalHash()
	require.NoError(t, err)

	plainHash, err := plain.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, plainHash, matchedHash)

	matchedWire, err := matched.wireJSON()
	require.NoError(t, err)

	plainWire, err := plain.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, string(plainWire), string(matchedWire))

	matchedScope, err := matched.scopeOnly().wireJSON()
	require.NoError(t, err)

	plainScope, err := plain.scopeOnly().wireJSON()
	require.NoError(t, err)
	assert.Equal(t, string(plainScope), string(matchedScope))

	for _, leaked := range []string{"match", "holder_id", "routes"} {
		assert.NotContains(t, string(matchedWire), leaked)
		assert.NotContains(t, string(matchedScope), leaked)
	}

	assert.Equal(t, "any", matched.Scope.Dimensions[2].Match, "projecting does not modify the manifest")

	// A catalog match stays out on its own, with no route declared and no
	// resolve left to project away.
	catalogOnly := *matched
	catalogOnly.Scope = &DeclarationScope{Dimensions: append([]DeclarationDimension(nil), matched.Scope.Dimensions...)}
	catalogOnly.Scope.Dimensions[2].Resolve = ""

	catalogOnlyHash, err := catalogOnly.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, plainHash, catalogOnlyHash)

	catalogOnlyWire, err := catalogOnly.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, string(plainWire), string(catalogOnlyWire))
}

func TestValidate_Match(t *testing.T) {
	t.Parallel()

	valid := func() *DeclarationManifest {
		m, err := parseManifest([]byte(matchYAML))
		require.NoError(t, err)

		return m
	}

	tests := []struct {
		name    string
		mutate  func(m *DeclarationManifest)
		wantErr string
	}{
		{
			name:    "catalog_unknown",
			mutate:  func(m *DeclarationManifest) { m.Scope.Dimensions[2].Match = "some" },
			wantErr: `scope.dimensions[2]: match must be "all" or "any", got "some"`,
		},
		{
			name:    "catalog_without_resolve",
			mutate:  func(m *DeclarationManifest) { m.Scope.Dimensions[2].Resolve = "" },
			wantErr: `scope.dimensions[2]: match requires resolve`,
		},
		{
			name:    "route_unknown",
			mutate:  func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].Match = "ANY" },
			wantErr: `scope.routes[0].dimensions[0]: match must be "all" or "any", got "ANY"`,
		},
		{
			name: "route_without_resolve",
			mutate: func(m *DeclarationManifest) {
				m.Scope.Routes[0].Dimensions[0] = DeclarationRouteDimension{Name: "accountId", From: "query", Field: "account", Match: "any"}
			},
			wantErr: `scope.routes[0].dimensions[0]: match requires resolve`,
		},
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

	explicit := valid()
	explicit.Scope.Dimensions[2].Match = "all"
	explicit.Scope.Routes[0].Dimensions[0].Match = "all"
	require.NoError(t, explicit.Validate(), "all is the default, and may be written")
}

// WireScope wires match: a holder in two ledgers is allowed to a partner
// allowed on one of them with match: any, and refused with match: all.
func TestWireScope_MatchAny(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	for match, want := range map[string]int{"any": http.StatusOK, "all": http.StatusForbidden, "": http.StatusForbidden} {
		srv := newDenyingServer(t, "led-1")
		auth := middleware.NewAuthClient(srv.URL, true, obs.Nop())

		require.NoError(t, auth.RegisterScopeResolver("alias", noResolve))
		require.NoError(t, auth.RegisterScopeResolver("holderLedgers", func(_ context.Context, in middleware.ResolveInput) ([][]string, error) {
			return [][]string{{"led-1", "led-2"}}, nil
		}))

		m, err := parseManifest([]byte(matchYAML))
		require.NoError(t, err)

		m.Scope.Routes[0].Dimensions[0].Match = match

		raw, err := json.Marshal(m)
		require.NoError(t, err)
		require.NoError(t, WireScope(auth, raw))

		app := fiber.New()
		app.Get("/v1/organizations/:organization_id/holders/:holder_id",
			auth.Authorize("plugin-fees", "holders", "get"),
			func(c fiber.Ctx) error { return c.SendString("ok") })

		req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/holders/h-1", nil)
		req.Header.Set("Authorization", partnerBearer(t))

		resp, err := app.Test(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, want, resp.StatusCode, "match %q", match)
	}
}

// newDenyingServer is an authorization service refusing every question naming
// one of the denied values.
func newDenyingServer(t *testing.T, denied ...string) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		var body struct {
			Attributes map[string]string `json:"attributes"`
		}

		_ = json.Unmarshal(raw, &body)

		authorized := true

		for _, value := range denied {
			for _, attribute := range body.Attributes {
				if attribute == value {
					authorized = false
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"authorized": authorized})
	}))
	t.Cleanup(srv.Close)

	return srv
}

// A catalog dimension wires match too: an alias resolving to two accounts is
// allowed on one of them with match: any, and refused with match: all.
func TestWireScope_CatalogMatchAny(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	for match, want := range map[string]int{"any": http.StatusOK, "all": http.StatusForbidden} {
		srv := newDenyingServer(t, "acc-1")
		auth := middleware.NewAuthClient(srv.URL, true, obs.Nop())

		require.NoError(t, auth.RegisterScopeResolver("holderLedgers", noResolve))
		require.NoError(t, auth.RegisterScopeResolver("alias", func(_ context.Context, in middleware.ResolveInput) ([][]string, error) {
			return [][]string{{"acc-1", "acc-2"}}, nil
		}))

		m, err := parseManifest([]byte(matchYAML))
		require.NoError(t, err)

		m.Scope.Dimensions[2].Match = match

		raw, err := json.Marshal(m)
		require.NoError(t, err)
		require.NoError(t, WireScope(auth, raw))

		app := fiber.New()
		app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id",
			auth.Authorize("plugin-fees", "ledgers", "get"),
			func(c fiber.Ctx) error { return c.SendString("ok") })

		req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/ledgers/led-1", nil)
		req.Header.Set("Authorization", partnerBearer(t))
		req.Header.Set("X-Account-Alias", "@a")

		resp, err := app.Test(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, want, resp.StatusCode, "match %q", match)
	}
}
