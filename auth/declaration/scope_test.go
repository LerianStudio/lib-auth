package declaration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scopedYAML is a manifest carrying the scope section in its authored form: two
// dimensions in tree order, the first the top of the funnel.
const scopedYAML = `
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
    - name: organizationId
      from: path
      param: organization_id
      required: true
      multi: false
      collection: organizations
      label: "Organization"
    - name: ledgerId
      from: path
      param: ledger_id
      required: false
      multi: true
      collection: ledgers
      label: "ledger"
`

// scopedJSON is the wire form of the SAME manifest.
const scopedJSON = `{
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
    ]
  }
}`

func TestParseManifest_Scope_YAMLAndJSONAgree(t *testing.T) {
	t.Parallel()

	fromYAML, err := parseManifest([]byte(scopedYAML))
	require.NoError(t, err)

	fromJSON, err := parseManifest([]byte(scopedJSON))
	require.NoError(t, err)

	assert.Equal(t, fromJSON, fromYAML)

	require.NotNil(t, fromYAML.Scope)
	assert.Equal(t, []DeclarationDimension{
		{Name: "organizationId", From: "path", Param: "organization_id", Required: true, Collection: "organizations", Label: "Organization"},
		{Name: "ledgerId", From: "path", Param: "ledger_id", Multi: true, Collection: "ledgers", Label: "ledger"},
	}, fromYAML.Scope.Dimensions, "dimensions keep their authored (tree) order")

	require.NoError(t, fromYAML.Validate())
}

// The wire tags are the contract the access manager and the identity provider
// read: a renamed tag would arrive as an unknown member and the catalog would be
// published empty.
func TestWireJSON_Scope_UsesTheContractTags(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(scopedYAML))
	require.NoError(t, err)

	wire, err := m.wireJSON()
	require.NoError(t, err)

	var got struct {
		Scope struct {
			Dimensions []map[string]any `json:"dimensions"`
		} `json:"scope"`
	}
	require.NoError(t, json.Unmarshal(wire, &got))

	require.Len(t, got.Scope.Dimensions, 2)
	assert.Equal(t, map[string]any{
		"name": "organizationId", "from": "path", "param": "organization_id",
		"required": true, "collection": "organizations", "label": "Organization",
	}, got.Scope.Dimensions[0])
	assert.Equal(t, map[string]any{
		"name": "ledgerId", "from": "path", "param": "ledger_id",
		"multi": true, "collection": "ledgers", "label": "ledger",
	}, got.Scope.Dimensions[1])
}

// A manifest without a scope section must put the same bytes on the wire and
// hash to the same value as before the section existed.
func TestManifestWithoutScope_WireAndHashUnchanged(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(feesJSON))
	require.NoError(t, err)
	assert.Nil(t, m.Scope)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(wire), "scope")

	hash, err := m.CanonicalHash()
	require.NoError(t, err)

	// Golden: the hash of feesJSON as computed before the scope section existed.
	legacy, err := json.Marshal(struct {
		Service     string                  `json:"service"`
		Permissions []DeclarationPermission `json:"permissions,omitempty"`
		Roles       []DeclarationRole       `json:"roles,omitempty"`
		M2M         *DeclarationM2M         `json:"m2m,omitempty"`
	}{m.Service, m.Permissions, m.Roles, m.M2M})
	require.NoError(t, err)
	assert.Equal(t, sha256Hex(legacy), hash)
}

// The scope is content: a catalog change must change the hash, or a hash-based
// no-op on either side would swallow it.
func TestCanonicalHash_IncludesScope(t *testing.T) {
	t.Parallel()

	base, err := parseManifest([]byte(scopedJSON))
	require.NoError(t, err)

	baseHash, err := base.CanonicalHash()
	require.NoError(t, err)

	noScope := *base
	noScope.Scope = nil

	noScopeHash, err := noScope.CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, noScopeHash, "adding a scope must change the hash")

	reordered := *base
	reordered.Scope = &DeclarationScope{Dimensions: []DeclarationDimension{
		base.Scope.Dimensions[1], base.Scope.Dimensions[0],
	}}

	reorderedHash, err := reordered.CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, reorderedHash, "dimension order is the tree order and is content")
}

func TestValidate_Scope(t *testing.T) {
	t.Parallel()

	valid := func() DeclarationDimension {
		return DeclarationDimension{Name: "organizationId", From: "path", Param: "organization_id", Collection: "organizations"}
	}

	tests := []struct {
		name    string
		dims    []DeclarationDimension
		wantErr string
	}{
		{name: "valid_without_label", dims: []DeclarationDimension{valid()}},
		{name: "valid_empty_dimensions", dims: []DeclarationDimension{}},
		{
			name:    "empty_name",
			dims:    []DeclarationDimension{func() DeclarationDimension { d := valid(); d.Name = " "; return d }()},
			wantErr: "scope.dimensions[0]: name must not be empty",
		},
		{
			name:    "from_body",
			dims:    []DeclarationDimension{func() DeclarationDimension { d := valid(); d.From = "body"; return d }()},
			wantErr: `scope.dimensions[0]: from must be one of "path", "query", "header", got "body"`,
		},
		{
			name:    "from_missing",
			dims:    []DeclarationDimension{func() DeclarationDimension { d := valid(); d.From = ""; return d }()},
			wantErr: `scope.dimensions[0]: from must be one of "path", "query", "header", got ""`,
		},
		{
			name:    "empty_param",
			dims:    []DeclarationDimension{func() DeclarationDimension { d := valid(); d.Param = ""; return d }()},
			wantErr: "scope.dimensions[0]: param must not be empty",
		},
		{
			name:    "param_with_colon_marker",
			dims:    []DeclarationDimension{func() DeclarationDimension { d := valid(); d.Param = ":organization_id"; return d }()},
			wantErr: "scope.dimensions[0]: param",
		},
		{
			name:    "param_with_slash",
			dims:    []DeclarationDimension{func() DeclarationDimension { d := valid(); d.Param = "a/b"; return d }()},
			wantErr: "scope.dimensions[0]: param",
		},
		{
			name:    "empty_collection",
			dims:    []DeclarationDimension{func() DeclarationDimension { d := valid(); d.Collection = ""; return d }()},
			wantErr: "scope.dimensions[0]: collection must not be empty",
		},
		{
			name: "duplicate_name",
			dims: []DeclarationDimension{
				valid(),
				func() DeclarationDimension { d := valid(); d.Param = "other_id"; return d }(),
			},
			wantErr: `scope.dimensions[1]: duplicate name "organizationId"`,
		},
		{
			name: "duplicate_param",
			dims: []DeclarationDimension{
				valid(),
				func() DeclarationDimension { d := valid(); d.Name = "otherId"; return d }(),
			},
			wantErr: `scope.dimensions[1]: duplicate param "organization_id"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := parseManifest([]byte(feesJSON))
			require.NoError(t, err)

			m.Scope = &DeclarationScope{Dimensions: tt.dims}

			err = m.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			var me *ManifestError

			require.ErrorAs(t, err, &me)
			assert.Contains(t, me.Reason, tt.wantErr)
		})
	}
}

// Parsing rejects nothing by itself; an invalid scope surfaces through Validate,
// which New runs eagerly — so a broken scope fails the boot, not the first PUT.
func TestNew_RejectsInvalidScope(t *testing.T) {
	t.Parallel()

	raw := strings.Replace(scopedYAML, "from: path\n      param: ledger_id", "from: body\n      param: ledger_id", 1)
	require.NotEqual(t, scopedYAML, raw)

	cfg := testConfig(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
	cfg.Manifest = []byte(raw)

	_, err := New(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `scope.dimensions[1]: from must be one of "path", "query", "header", got "body"`)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// The full publication carries the scope section alongside the permissions.
func TestPublish_FullManifest_IncludesScope(t *testing.T) {
	t.Parallel()

	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Manifest = []byte(scopedJSON)

	p := newFastPublisher(t, cfg)
	require.NoError(t, p.Publish(context.Background()))

	identity.mu.Lock()
	body := identity.gotBody
	identity.mu.Unlock()

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Contains(t, got, "permissions")
	assert.Contains(t, got, "roles")
	assert.Contains(t, got, "scope")
}

// A scope-only publication carries service, version and scope and NOTHING else:
// the access manager replaces only the sections present, so an extra
// permissions member would overwrite what the permission switch governs.
func TestPublish_ScopeOnly_BodyShape(t *testing.T) {
	t.Parallel()

	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Manifest = []byte(scopedJSON)
	cfg.ScopeOnly = true

	p := newFastPublisher(t, cfg)
	require.NoError(t, p.Publish(context.Background()))

	identity.mu.Lock()
	body, path := identity.gotBody, identity.gotPath
	identity.mu.Unlock()

	assert.Equal(t, "/v1/declarations/plugin-fees", path)
	assert.JSONEq(t, `{
	  "service": "plugin-fees",
	  "version": 3,
	  "scope": {"dimensions": [
	    {"name": "organizationId", "from": "path", "param": "organization_id", "required": true, "collection": "organizations", "label": "Organization"},
	    {"name": "ledgerId", "from": "path", "param": "ledger_id", "multi": true, "collection": "ledgers", "label": "ledger"}
	  ]}
	}`, body)
}

// A scope-only publisher over a manifest that declares no scope has nothing to
// say: it must not PUT (an empty body would read as "nothing changed" at best).
func TestStart_ScopeOnly_WithoutScope_NeverPuts(t *testing.T) {
	t.Parallel()

	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	var st Status

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.ScopeOnly = true
	cfg.Status = &st

	p := newFastPublisher(t, cfg)
	require.NoError(t, p.Publish(context.Background()))

	stop, err := p.Start(context.Background())
	require.NoError(t, err)
	stop()

	assert.Equal(t, 0, identity.count())
	assert.Equal(t, StateIdle, st.State(), "nothing was published")
}

// The scope-only and the full publication are different bodies: they must not
// share a dedup entry, or publishing one would suppress the other.
func TestPublish_ScopeOnly_DoesNotShareTheFullCacheEntry(t *testing.T) {
	t.Parallel()

	full, err := New(func() Config {
		c := testConfig(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
		c.Manifest = []byte(scopedJSON)

		return c
	}())
	require.NoError(t, err)

	scopeOnly, err := New(func() Config {
		c := testConfig(t, "http://127.0.0.1:1", "http://127.0.0.1:1")
		c.Manifest = []byte(scopedJSON)
		c.ScopeOnly = true

		return c
	}())
	require.NoError(t, err)

	assert.NotEqual(t, full.cacheKey(), scopeOnly.cacheKey())
	assert.NotEqual(t, full.hash, scopeOnly.hash)
}

// Transient failures of the scope publication are retried with backoff, like
// the full one; a deterministic refusal is not.
func TestPublish_ScopeOnly_RetriesTransient(t *testing.T) {
	t.Parallel()

	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusServiceUnavailable, `{}`)
	t.Cleanup(identity.Close)

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Manifest = []byte(scopedJSON)
	cfg.ScopeOnly = true

	p := newFastPublisher(t, cfg)

	err := p.Publish(context.Background())
	require.Error(t, err)
	assert.Equal(t, 3, identity.count(), "every attempt of the budget is spent")
}
