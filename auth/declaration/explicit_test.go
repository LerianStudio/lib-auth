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
const canonicalHashExplicitGolden = "cb6735c8b8c7e34d3ef9e1291bb1790c008724ea1a272082cbd483c4e4a820b4"

// canonicalExplicitBytes is the canonical serialization of the same fixture: the
// manifest without its version.
const canonicalExplicitBytes = `{"service":"example","permissions":[{"resource":"items","action":"get","effect":"allow","roles":["viewer"]}],"roles":[{"name":"viewer","granted_to":[{"group":"example-viewer-group"}]}],"scope":{"dimensions":[{"name":"tenantGroupId","from":"path","param":"tenant_group_id","required":true,"collection":"tenant-groups","label":"tenant group"},{"name":"containerId","from":"path","param":"container_id","collection":"containers","label":"container","parent":"tenantGroupId"},{"name":"itemId","from":"path","param":"item_id","multi":true,"collection":"items","label":"item","parent":"containerId","explicit":true},{"name":"widgetId","from":"path","param":"widget_id","multi":true,"collection":"widgets","explicit":true}]}}`

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
service: example
version: 1
permissions:
  - { resource: items, action: get, effect: allow, roles: [viewer] }
roles:
  - name: viewer
    granted_to: [{ group: example-viewer-group }]
scope:
  dimensions:
    - { name: tenantGroupId, from: path, param: tenant_group_id, required: true, collection: tenant-groups, label: tenant group }
    - { name: containerId, from: path, param: container_id, collection: containers, label: container, parent: tenantGroupId }
    - { name: itemId, from: path, param: item_id, multi: true, collection: items, label: item, parent: containerId, explicit: true }
    - { name: widgetId, from: path, param: widget_id, multi: true, collection: widgets, explicit: true }
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

	assert.Contains(t, string(wire), `"parent":"containerId","explicit":true}`)
	assert.Contains(t, string(wire), `"collection":"widgets","explicit":true}`)
	assert.Contains(t, string(wire), `"label":"container","parent":"tenantGroupId"}`, "a dimension that is not explicit sends no explicit key")
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
	cfg.Slug = "example"
	cfg.Manifest = raw
	cfg.ScopeOnly = true

	p := newFastPublisher(t, cfg)
	require.NoError(t, p.Publish(context.Background()))

	identity.mu.Lock()
	body := identity.gotBody
	identity.mu.Unlock()

	assert.JSONEq(t, `{
	  "service": "example",
	  "version": 1,
	  "scope": {"dimensions": [
	    {"name": "tenantGroupId", "from": "path", "param": "tenant_group_id", "required": true, "collection": "tenant-groups", "label": "tenant group"},
	    {"name": "containerId", "from": "path", "param": "container_id", "collection": "containers", "label": "container", "parent": "tenantGroupId"},
	    {"name": "itemId", "from": "path", "param": "item_id", "multi": true, "collection": "items", "label": "item", "parent": "containerId", "explicit": true},
	    {"name": "widgetId", "from": "path", "param": "widget_id", "multi": true, "collection": "widgets", "explicit": true}
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
			dim:  DeclarationDimension{Name: "widgetId", From: "path", Param: "widget_id", Collection: "widgets", Explicit: true},
		},
		{
			name: "valid_required_without_explicit",
			dim:  DeclarationDimension{Name: "widgetId", From: "path", Param: "widget_id", Collection: "widgets", Required: true},
		},
		{
			name:     "explicit_without_collection",
			dim:      DeclarationDimension{Name: "widgetId", From: "path", Param: "widget_id", Explicit: true},
			wantErrs: []string{`scope.dimensions[1]: explicit dimension "widgetId" must name its collection`},
		},
		{
			name:     "explicit_with_blank_collection",
			dim:      DeclarationDimension{Name: "widgetId", From: "path", Param: "widget_id", Collection: "  ", Explicit: true},
			wantErrs: []string{`scope.dimensions[1]: explicit dimension "widgetId" must name its collection`},
		},
		{
			name:     "explicit_and_required",
			dim:      DeclarationDimension{Name: "widgetId", From: "path", Param: "widget_id", Collection: "widgets", Required: true, Explicit: true},
			wantErrs: []string{`scope.dimensions[1]: dimension "widgetId" must not be both explicit and required`},
		},
		{
			name: "explicit_required_and_no_collection",
			dim:  DeclarationDimension{Name: "widgetId", From: "path", Param: "widget_id", Required: true, Explicit: true},
			wantErrs: []string{
				`scope.dimensions[1]: explicit dimension "widgetId" must name its collection`,
				`scope.dimensions[1]: dimension "widgetId" must not be both explicit and required`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := explicitFixture(t)
			m.Scope = &DeclarationScope{Dimensions: []DeclarationDimension{
				{Name: "containerId", From: "path", Param: "container_id", Collection: "containers"},
				tt.dim,
			}}

			err := m.Validate()
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
