package declaration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// canonicalHashExplicitGolden is the CanonicalHash of
// testdata/canonical_hash_explicit.json. It is the SHA-256 of
// canonicalExplicitBytes, which fixes where explicit sits in a dimension: the
// last member, after parent. The literal is the contract the authorization
// service mirrors: it is not recomputed here.
const canonicalHashExplicitGolden = "f6ce6625cb4d03351caf8e442a31139988dd202ac07a7d16b7a765da769254b3"

// canonicalExplicitBytes is the canonical serialization of the same fixture: the
// manifest without its version.
const canonicalExplicitBytes = `{"service":"midaz","permissions":[{"resource":"transaction-routes","action":"get","effect":"allow","roles":["viewer"]}],"roles":[{"name":"viewer","granted_to":[{"group":"midaz-viewer-group"}]}],"scope":{"dimensions":[{"name":"organizationId","from":"path","param":"organization_id","required":true,"collection":"organizations","label":"organization"},{"name":"ledgerId","from":"path","param":"ledger_id","collection":"ledgers","label":"ledger","parent":"organizationId"},{"name":"transactionRouteId","from":"path","param":"transaction_route_id","multi":true,"collection":"transaction-routes","label":"transaction route","parent":"ledgerId","explicit":true},{"name":"operationRouteId","from":"path","param":"operation_route_id","multi":true,"collection":"operation-routes","explicit":true}]}}`

func explicitFixture(t *testing.T) *DeclarationManifest {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "canonical_hash_explicit.json"))
	require.NoError(t, err)

	m, err := parseManifest(raw)
	require.NoError(t, err)
	require.NoError(t, m.Validate())
	require.True(t, m.Scope.Dimensions[2].Explicit,
		"the fixture must carry explicit, or the golden proves nothing about it")
	require.False(t, m.Scope.Dimensions[1].Explicit)

	return m
}

func TestCanonicalHash_GoldenWithExplicit(t *testing.T) {
	t.Parallel()

	m := explicitFixture(t)

	published := m.serverProjection()
	canonical, err := json.Marshal(canonicalManifest{
		Service:     published.Service,
		Permissions: published.Permissions,
		Roles:       published.Roles,
		M2M:         published.M2M,
		Scope:       published.Scope,
		Partners:    published.Partners,
	})
	require.NoError(t, err)
	assert.Equal(t, canonicalExplicitBytes, string(canonical), "explicit is the last member of a dimension")

	sum := sha256.Sum256([]byte(canonicalExplicitBytes))
	require.Equal(t, canonicalHashExplicitGolden, hex.EncodeToString(sum[:]), "the golden is the hash of the canonical bytes")

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, canonicalHashExplicitGolden, hash)
}

// Turning explicit on or off changes the hash, so an explicit-only change
// reaches the service. A manifest without it hashes as before: the covers and
// parent goldens pin those bytes.
func TestCanonicalHash_IncludesExplicit(t *testing.T) {
	t.Parallel()

	base := explicitFixture(t)

	baseHash, err := base.CanonicalHash()
	require.NoError(t, err)

	cp := *base
	cp.Scope = &DeclarationScope{Dimensions: append([]DeclarationDimension(nil), base.Scope.Dimensions...)}
	cp.Scope.Dimensions[2].Explicit = false

	offHash, err := cp.CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, offHash, "an explicit-only change must change the hash")
}

func TestParseManifest_Explicit_YAMLAndJSONAgree(t *testing.T) {
	t.Parallel()

	fromJSON := explicitFixture(t)

	fromYAML, err := parseManifest([]byte(`
service: midaz
version: 1
permissions:
  - { resource: transaction-routes, action: get, effect: allow, roles: [viewer] }
roles:
  - name: viewer
    granted_to: [{ group: midaz-viewer-group }]
scope:
  dimensions:
    - { name: organizationId, from: path, param: organization_id, required: true, collection: organizations, label: organization }
    - { name: ledgerId, from: path, param: ledger_id, collection: ledgers, label: ledger, parent: organizationId }
    - { name: transactionRouteId, from: path, param: transaction_route_id, multi: true, collection: transaction-routes, label: transaction route, parent: ledgerId, explicit: true }
    - { name: operationRouteId, from: path, param: operation_route_id, multi: true, collection: operation-routes, explicit: true }
`))
	require.NoError(t, err)

	assert.Equal(t, fromJSON, fromYAML)
}

// The full declaration carries explicit, and a dimension without it sends no
// explicit key.
func TestWireJSON_Explicit(t *testing.T) {
	t.Parallel()

	wire, err := explicitFixture(t).wireJSON()
	require.NoError(t, err)

	assert.Contains(t, string(wire), `"parent":"ledgerId","explicit":true}`)
	assert.Contains(t, string(wire), `"collection":"operation-routes","explicit":true}`)
	assert.Contains(t, string(wire), `"label":"ledger","parent":"organizationId"}`, "a dimension that is not explicit sends no explicit key")
	assert.Equal(t, 2, strings.Count(string(wire), `"explicit"`))
}

// A scope-only publication carries the dimensions' explicit flag.
func TestPublish_ScopeOnly_CarriesExplicit(t *testing.T) {
	t.Parallel()

	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	raw, err := os.ReadFile(filepath.Join("testdata", "canonical_hash_explicit.json"))
	require.NoError(t, err)

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Slug = "midaz"
	cfg.Manifest = raw
	cfg.ScopeOnly = true

	p := newFastPublisher(t, cfg)
	require.NoError(t, p.Publish(context.Background()))

	identity.mu.Lock()
	body := identity.gotBody
	identity.mu.Unlock()

	assert.JSONEq(t, `{
	  "service": "midaz",
	  "version": 1,
	  "scope": {"dimensions": [
	    {"name": "organizationId", "from": "path", "param": "organization_id", "required": true, "collection": "organizations", "label": "organization"},
	    {"name": "ledgerId", "from": "path", "param": "ledger_id", "collection": "ledgers", "label": "ledger", "parent": "organizationId"},
	    {"name": "transactionRouteId", "from": "path", "param": "transaction_route_id", "multi": true, "collection": "transaction-routes", "label": "transaction route", "parent": "ledgerId", "explicit": true},
	    {"name": "operationRouteId", "from": "path", "param": "operation_route_id", "multi": true, "collection": "operation-routes", "explicit": true}
	  ]}
	}`, body)
}

func TestValidate_ScopeExplicit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dim      DeclarationDimension
		wantErrs []string
	}{
		{
			name: "valid",
			dim:  DeclarationDimension{Name: "operationRouteId", From: "path", Param: "operation_route_id", Collection: "operation-routes", Explicit: true},
		},
		{
			name: "valid_required_without_explicit",
			dim:  DeclarationDimension{Name: "operationRouteId", From: "path", Param: "operation_route_id", Collection: "operation-routes", Required: true},
		},
		{
			name:     "explicit_without_collection",
			dim:      DeclarationDimension{Name: "operationRouteId", From: "path", Param: "operation_route_id", Explicit: true},
			wantErrs: []string{`scope.dimensions[1]: explicit dimension "operationRouteId" must name its collection`},
		},
		{
			name:     "explicit_with_blank_collection",
			dim:      DeclarationDimension{Name: "operationRouteId", From: "path", Param: "operation_route_id", Collection: "  ", Explicit: true},
			wantErrs: []string{`scope.dimensions[1]: explicit dimension "operationRouteId" must name its collection`},
		},
		{
			name:     "explicit_and_required",
			dim:      DeclarationDimension{Name: "operationRouteId", From: "path", Param: "operation_route_id", Collection: "operation-routes", Required: true, Explicit: true},
			wantErrs: []string{`scope.dimensions[1]: dimension "operationRouteId" must not be both explicit and required`},
		},
		{
			name: "explicit_required_and_no_collection",
			dim:  DeclarationDimension{Name: "operationRouteId", From: "path", Param: "operation_route_id", Required: true, Explicit: true},
			wantErrs: []string{
				`scope.dimensions[1]: explicit dimension "operationRouteId" must name its collection`,
				`scope.dimensions[1]: dimension "operationRouteId" must not be both explicit and required`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := parseManifest([]byte(feesJSON))
			require.NoError(t, err)

			m.Scope = &DeclarationScope{Dimensions: []DeclarationDimension{
				{Name: "ledgerId", From: "path", Param: "ledger_id", Collection: "ledgers"},
				tt.dim,
			}}

			err = m.Validate()
			if len(tt.wantErrs) == 0 {
				require.NoError(t, err)

				return
			}

			var me *ManifestError

			require.ErrorAs(t, err, &me)

			for _, want := range tt.wantErrs {
				assert.Contains(t, me.Reason, want)
			}

			assert.Equal(t, len(tt.wantErrs), strings.Count(me.Reason, "explicit"), "each defect is reported once: %s", me.Reason)
		})
	}
}
