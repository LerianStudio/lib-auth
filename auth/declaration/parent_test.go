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

// canonicalHashParentGolden is the CanonicalHash of
// testdata/canonical_hash_parent.json. It is the SHA-256 of
// canonicalParentBytes, which fixes where parent sits in a dimension: the last
// member, after covers and label. The literal is the contract the authorization
// service mirrors: it is not recomputed here.
const canonicalHashParentGolden = "7f5fe35126dc706aeaaad0682fb1890aaf589d32393aeb6d8afadc16f6a74beb"

// canonicalParentBytes is the canonical serialization of the same fixture: the
// manifest without its version.
const canonicalParentBytes = `{"service":"midaz","permissions":[{"resource":"accounts","action":"get","effect":"allow","roles":["viewer"]}],"roles":[{"name":"viewer","granted_to":[{"group":"midaz-viewer-group"}]}],"scope":{"dimensions":[{"name":"organizationId","from":"path","param":"organization_id","required":true,"collection":"organizations","label":"organization"},{"name":"ledgerId","from":"path","param":"ledger_id","collection":"ledgers","label":"ledger","parent":"organizationId"},{"name":"portfolioId","from":"header","param":"X-Portfolio-Id","collection":"portfolios","parent":"ledgerId"},{"name":"accountId","from":"path","param":"account_id","multi":true,"collection":"accounts","covers":["balances","operations"],"label":"account","parent":"ledgerId"}]}}`

func parentFixture(t *testing.T) *DeclarationManifest {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "canonical_hash_parent.json"))
	require.NoError(t, err)

	m, err := parseManifest(raw)
	require.NoError(t, err)
	require.NoError(t, m.Validate())
	require.Equal(t, "ledgerId", m.Scope.Dimensions[3].Parent,
		"the fixture must carry parent, or the golden proves nothing about it")

	return m
}

func TestCanonicalHash_GoldenWithParent(t *testing.T) {
	t.Parallel()

	m := parentFixture(t)

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
	assert.Equal(t, canonicalParentBytes, string(canonical), "parent is the last member of a dimension")

	sum := sha256.Sum256([]byte(canonicalParentBytes))
	require.Equal(t, canonicalHashParentGolden, hex.EncodeToString(sum[:]), "the golden is the hash of the canonical bytes")

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, canonicalHashParentGolden, hash)
}

// Adding, removing or changing a parent changes the hash; a manifest without
// one hashes as before (TestCanonicalHash_GoldenWithCovers and
// TestManifestWithoutCovers_WireAndHashUnchanged pin those bytes).
func TestCanonicalHash_IncludesParent(t *testing.T) {
	t.Parallel()

	base := parentFixture(t)

	baseHash, err := base.CanonicalHash()
	require.NoError(t, err)

	withParent := func(parent string) *DeclarationManifest {
		cp := *base
		cp.Scope = &DeclarationScope{Dimensions: append([]DeclarationDimension(nil), base.Scope.Dimensions...)}
		cp.Scope.Dimensions[2].Parent = parent

		return &cp
	}

	noneHash, err := withParent("").CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, noneHash)

	movedHash, err := withParent("organizationId").CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, movedHash, "a parent-only change must change the hash")
}

func TestParseManifest_Parent_YAMLAndJSONAgree(t *testing.T) {
	t.Parallel()

	fromJSON := parentFixture(t)

	fromYAML, err := parseManifest([]byte(`
service: midaz
version: 1
permissions:
  - { resource: accounts, action: get, effect: allow, roles: [viewer] }
roles:
  - name: viewer
    granted_to: [{ group: midaz-viewer-group }]
scope:
  dimensions:
    - { name: organizationId, from: path, param: organization_id, required: true, collection: organizations, label: organization }
    - { name: ledgerId, from: path, param: ledger_id, collection: ledgers, label: ledger, parent: organizationId }
    - { name: portfolioId, from: header, param: X-Portfolio-Id, collection: portfolios, parent: ledgerId }
    - { name: accountId, from: path, param: account_id, multi: true, collection: accounts, covers: [balances, operations], label: account, parent: ledgerId }
`))
	require.NoError(t, err)

	assert.Equal(t, fromJSON, fromYAML)
}

// A scope-only publication carries the dimensions' parent.
func TestPublish_ScopeOnly_CarriesParent(t *testing.T) {
	t.Parallel()

	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	raw, err := os.ReadFile(filepath.Join("testdata", "canonical_hash_parent.json"))
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
	    {"name": "portfolioId", "from": "header", "param": "X-Portfolio-Id", "collection": "portfolios", "parent": "ledgerId"},
	    {"name": "accountId", "from": "path", "param": "account_id", "multi": true, "collection": "accounts", "covers": ["balances", "operations"], "label": "account", "parent": "ledgerId"}
	  ]}
	}`, body)
}

// The full declaration carries parent too, and a dimension without one sends
// no parent key.
func TestWireJSON_Parent(t *testing.T) {
	t.Parallel()

	wire, err := parentFixture(t).wireJSON()
	require.NoError(t, err)

	assert.Contains(t, string(wire), `"label":"account","parent":"ledgerId"}`)
	assert.Contains(t, string(wire), `"label":"organization"}`, "a root dimension sends no parent key")
}

func TestValidate_ScopeParent(t *testing.T) {
	t.Parallel()

	dim := func(name, parent string) DeclarationDimension {
		return DeclarationDimension{Name: name, From: "path", Param: strings.ToLower(name), Collection: name + "s", Parent: parent}
	}

	tests := []struct {
		name     string
		dims     []DeclarationDimension
		wantErrs []string
	}{
		{name: "valid_tree", dims: []DeclarationDimension{dim("org", ""), dim("ledger", "org"), dim("portfolio", "ledger"), dim("account", "ledger")}},
		{name: "valid_child_declared_first", dims: []DeclarationDimension{dim("account", "ledger"), dim("ledger", "")}},
		{name: "valid_none", dims: []DeclarationDimension{dim("org", ""), dim("ledger", "")}},
		{
			name:     "unknown",
			dims:     []DeclarationDimension{dim("org", ""), dim("ledger", "organization")},
			wantErrs: []string{`scope.dimensions[1]: parent "organization" is not a declared dimension`},
		},
		{
			name:     "self",
			dims:     []DeclarationDimension{dim("org", "org")},
			wantErrs: []string{`scope.dimensions[0]: parent "org" must not be the dimension itself`},
		},
		{
			name:     "cycle_of_two",
			dims:     []DeclarationDimension{dim("org", "ledger"), dim("ledger", "org")},
			wantErrs: []string{`scope.dimensions[0]: parent "ledger" makes a cycle: org -> ledger -> org`},
		},
		{
			name:     "cycle_of_three",
			dims:     []DeclarationDimension{dim("org", ""), dim("a", "c"), dim("b", "a"), dim("c", "b")},
			wantErrs: []string{`scope.dimensions[1]: parent "c" makes a cycle: a -> c -> b -> a`},
		},
		{
			name:     "padded",
			dims:     []DeclarationDimension{dim("org", ""), dim("ledger", " org")},
			wantErrs: []string{`scope.dimensions[1]: parent " org" is not a declared dimension`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := parseManifest([]byte(feesJSON))
			require.NoError(t, err)

			m.Scope = &DeclarationScope{Dimensions: tt.dims}

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

			assert.Equal(t, len(tt.wantErrs), strings.Count(me.Reason, "parent "), "each defect is reported once: %s", me.Reason)
		})
	}
}
