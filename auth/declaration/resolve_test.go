package declaration

import (
	"context"
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

// resolvedYAML is scopedYAML with an account dimension read from an alias
// header and resolved, and a route resolving a transaction id from its path.
const resolvedYAML = `
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
    - { name: accountId, from: header, param: X-Account-Alias, collection: accounts, resolve: alias }
  routes:
    - method: GET
      path: /v1/organizations/:organization_id/ledgers/:ledger_id/transactions/:transaction_id
      dimensions:
        - { name: accountId, from: path, field: transaction_id, resolve: legs }
`

// The same manifest without any resolve: what is published.
const unresolvedYAML = `
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
    - { name: accountId, from: header, param: X-Account-Alias, collection: accounts }
`

func TestParseManifest_Resolve(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(resolvedYAML))
	require.NoError(t, err)
	require.NoError(t, m.Validate())

	assert.Equal(t, "alias", m.Scope.Dimensions[2].Resolve)
	assert.Empty(t, m.Scope.Dimensions[0].Resolve)
	assert.Equal(t, "legs", m.Scope.Routes[0].Dimensions[0].Resolve)
}

// resolve is read by this library only: the wire body, the scope-only body
// and the hash are those of the manifest without it.
func TestResolve_StaysOutOfTheWireAndTheHash(t *testing.T) {
	t.Parallel()

	resolved, err := parseManifest([]byte(resolvedYAML))
	require.NoError(t, err)

	plain, err := parseManifest([]byte(unresolvedYAML))
	require.NoError(t, err)

	resolvedHash, err := resolved.CanonicalHash()
	require.NoError(t, err)

	plainHash, err := plain.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, plainHash, resolvedHash)

	resolvedWire, err := resolved.wireJSON()
	require.NoError(t, err)

	plainWire, err := plain.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, string(plainWire), string(resolvedWire))
	assert.NotContains(t, string(resolvedWire), "resolve")

	scopeWire, err := resolved.scopeOnly().wireJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(scopeWire), "resolve")

	assert.Equal(t, "alias", resolved.Scope.Dimensions[2].Resolve, "projecting does not modify the manifest")

	// A catalog resolve stays out on its own, with no route declared.
	catalogOnly := *resolved
	catalogOnly.Scope = &DeclarationScope{Dimensions: resolved.Scope.Dimensions}

	catalogOnlyHash, err := catalogOnly.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, plainHash, catalogOnlyHash)

	catalogOnlyWire, err := catalogOnly.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, string(plainWire), string(catalogOnlyWire))
}

func TestValidate_Resolve(t *testing.T) {
	t.Parallel()

	valid := func() *DeclarationManifest {
		m, err := parseManifest([]byte(resolvedYAML))
		require.NoError(t, err)

		return m
	}

	tests := []struct {
		name    string
		mutate  func(m *DeclarationManifest)
		wantErr string
	}{
		{
			name:    "catalog_padded",
			mutate:  func(m *DeclarationManifest) { m.Scope.Dimensions[2].Resolve = " alias" },
			wantErr: `scope.dimensions[2]: resolve " alias" must be a resolver name with no surrounding whitespace`,
		},
		{
			name:    "catalog_blank",
			mutate:  func(m *DeclarationManifest) { m.Scope.Dimensions[2].Resolve = "  " },
			wantErr: `scope.dimensions[2]: resolve "  " must be`,
		},
		{
			name:    "route_padded",
			mutate:  func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].Resolve = "legs " },
			wantErr: `scope.routes[0].dimensions[0]: resolve "legs " must be`,
		},
		{
			name:    "route_path_without_resolve",
			mutate:  func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].Resolve = "" },
			wantErr: `scope.routes[0].dimensions[0]: from must be one of "body", "form", "query", "header", got "path"`,
		},
		{
			name:    "route_path_param_invalid",
			mutate:  func(m *DeclarationManifest) { m.Scope.Routes[0].Dimensions[0].Field = ":transaction_id" },
			wantErr: `scope.routes[0].dimensions[0]: field ":transaction_id" must be a bare path parameter name`,
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
}

// A manifest naming a resolver the client does not have fails the boot.
func TestWireScope_UnregisteredResolverFailsTheBoot(t *testing.T) {
	t.Parallel()

	auth := &middleware.AuthClient{Logger: obs.Nop()}

	err := WireScope(auth, []byte(resolvedYAML))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"alias"`)

	require.NoError(t, auth.RegisterScopeResolver("alias", noResolve))

	err = WireScope(auth, []byte(resolvedYAML))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"legs"`)

	require.NoError(t, auth.RegisterScopeResolver("legs", noResolve))
	require.NoError(t, WireScope(auth, []byte(resolvedYAML)), "positive control")
}

func noResolve(context.Context, middleware.ResolveInput) ([][]string, error) {
	return nil, nil
}

// WireScope wires the resolution: a partner request to the route asks about
// the accounts the transaction resolves to.
func TestWireScope_RouteResolvesThePath(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	rec := newAuthorizeRecorder(t)
	auth := middleware.NewAuthClient(rec.URL, true, obs.Nop())

	require.NoError(t, auth.RegisterScopeResolver("alias", noResolve))
	require.NoError(t, auth.RegisterScopeResolver("legs", func(_ context.Context, in middleware.ResolveInput) ([][]string, error) {
		if in.Known["organizationId"][0] != "org-1" || in.Items[0].Value != "tx-1" {
			return make([][]string, len(in.Items)), nil
		}

		return [][]string{{"acc-1"}}, nil
	}))
	require.NoError(t, WireScope(auth, []byte(resolvedYAML)))

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/transactions/:transaction_id",
		auth.Authorize("plugin-fees", "transactions", "get"),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/transactions/tx-1", nil)
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
	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"}, got.Attributes)

	// The same transaction under another organization does not resolve.
	req = httptest.NewRequest(http.MethodGet, "/v1/organizations/org-2/ledgers/led-1/transactions/tx-1", nil)
	req.Header.Set("Authorization", partnerBearer(t))

	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	rec.mu.Lock()
	last := rec.last
	rec.mu.Unlock()
	assert.False(t, strings.Contains(last, "org-2"), "an unresolved request is never asked")
}

// siblingsYAML is unresolvedYAML plus a route whose body resolves aliases with
// the fields of their element, and an array of aliases.
const siblingsYAML = unresolvedYAML + `
  routes:
    - method: POST
      path: /v1/organizations/:organization_id/transfers
      dimensions:
        - { name: ledgerId,  from: body, field: "debits[].ledgerId" }
        - { name: accountId, from: body, field: "debits[].alias", resolve: alias }
    - method: POST
      path: /v1/organizations/:organization_id/ledgers/:ledger_id/rules
      dimensions:
        - { name: accountId, from: body, field: "accountTarget.aliases[]", optional: true, resolve: alias }
`

// scope.routes — string arrays and resolved body fields included — are read
// by this library only: the wire body, the scope-only body and the hash are
// those of the manifest without them.
func TestScopeRoutes_StringArraysAndSiblingsStayOutOfTheWireAndTheHash(t *testing.T) {
	t.Parallel()

	routed, err := parseManifest([]byte(siblingsYAML))
	require.NoError(t, err)
	require.NoError(t, routed.Validate())
	require.Len(t, routed.Scope.Routes, 2, "the routes are parsed")

	plain, err := parseManifest([]byte(unresolvedYAML))
	require.NoError(t, err)

	routedHash, err := routed.CanonicalHash()
	require.NoError(t, err)

	plainHash, err := plain.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, plainHash, routedHash)

	routedWire, err := routed.wireJSON()
	require.NoError(t, err)

	plainWire, err := plain.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, string(plainWire), string(routedWire))

	routedScope, err := routed.scopeOnly().wireJSON()
	require.NoError(t, err)

	plainScope, err := plain.scopeOnly().wireJSON()
	require.NoError(t, err)
	assert.Equal(t, string(plainScope), string(routedScope))

	for _, leaked := range []string{"routes", "aliases[]", "debits[]", "resolve"} {
		assert.NotContains(t, string(routedWire), leaked)
		assert.NotContains(t, string(routedScope), leaked)
	}
}

// WireScope wires the siblings: the resolver confines each alias to the ledger
// its own element names.
func TestWireScope_ResolverReceivesTheElementsSiblings(t *testing.T) {
	t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

	rec := newAuthorizeRecorder(t)
	auth := middleware.NewAuthClient(rec.URL, true, obs.Nop())

	var got []middleware.ResolveItem

	require.NoError(t, auth.RegisterScopeResolver("alias", func(_ context.Context, in middleware.ResolveInput) ([][]string, error) {
		got = in.Items

		out := make([][]string, len(in.Items))
		for i, item := range in.Items {
			out[i] = []string{item.Siblings["ledgerId"] + ":" + item.Value}
		}

		return out, nil
	}))
	require.NoError(t, WireScope(auth, []byte(siblingsYAML)))

	app := fiber.New()
	app.Post("/v1/organizations/:organization_id/transfers",
		auth.Authorize("plugin-fees", "transfers", "post"),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/org-1/transfers",
		strings.NewReader(`{"debits":[{"ledgerId":"led-2","alias":"@a"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", partnerBearer(t))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, []middleware.ResolveItem{{Value: "@a", Siblings: map[string]string{"ledgerId": "led-2"}}}, got)

	rec.mu.Lock()
	body := rec.last
	rec.mu.Unlock()

	var sent struct {
		Attributes map[string]string `json:"attributes"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &sent))
	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "led-2:@a"}, sent.Attributes)
}
