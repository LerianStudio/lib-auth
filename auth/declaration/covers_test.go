package declaration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// coveredYAML is scopedYAML with a dimension that confines related collections.
const coveredYAML = `
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
      collection: organizations
      label: "Organization"
    - name: accountId
      from: path
      param: account_id
      multi: true
      collection: accounts
      covers: [balances, operations]
      label: "Account"
`

// coveredJSON is the wire form of the SAME manifest.
const coveredJSON = `{
  "service": "plugin-fees",
  "version": 3,
  "permissions": [
    { "resource": "billing-packages", "action": "read", "effect": "allow", "roles": ["fees/viewer"] }
  ],
  "roles": [ { "name": "fees/viewer" } ],
  "scope": {
    "dimensions": [
      { "name": "organizationId", "from": "path", "param": "organization_id", "required": true, "collection": "organizations", "label": "Organization" },
      { "name": "accountId", "from": "path", "param": "account_id", "multi": true, "collection": "accounts", "covers": ["balances", "operations"], "label": "Account" }
    ]
  }
}`

// The hash and the wire bytes of scopedJSON as computed by the release before
// covers existed. A manifest that declares no covers must publish the same bytes
// and hash to the same value, so upgrading the library republishes nothing.
const (
	scopedJSONPreviousHash = "ec9654111747e39b05330cee152db445382adae6bd5a5e7a7a7e6442fd7adb9d"
	scopedJSONPreviousWire = `{"service":"plugin-fees","version":3,"permissions":[{"resource":"billing-packages","action":"read","effect":"allow","roles":["fees/viewer"]}],"roles":[{"name":"fees/viewer"}],"scope":{"dimensions":[{"name":"organizationId","from":"path","param":"organization_id","required":true,"collection":"organizations","label":"Organization"},{"name":"ledgerId","from":"path","param":"ledger_id","multi":true,"collection":"ledgers","label":"ledger"}]}}`
)

func TestManifestWithoutCovers_WireAndHashUnchanged(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(scopedJSON))
	require.NoError(t, err)

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, scopedJSONPreviousHash, hash)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, scopedJSONPreviousWire, string(wire))

	// An explicitly empty list is the same as none.
	empty := *m
	empty.Scope = &DeclarationScope{Dimensions: append([]DeclarationDimension(nil), m.Scope.Dimensions...)}
	empty.Scope.Dimensions[1].Covers = []string{}

	emptyHash, err := empty.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, scopedJSONPreviousHash, emptyHash)

	emptyWire, err := empty.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, scopedJSONPreviousWire, string(emptyWire))
}

func TestParseManifest_Covers_YAMLAndJSONAgree(t *testing.T) {
	t.Parallel()

	fromYAML, err := parseManifest([]byte(coveredYAML))
	require.NoError(t, err)

	fromJSON, err := parseManifest([]byte(coveredJSON))
	require.NoError(t, err)

	assert.Equal(t, fromJSON, fromYAML)

	require.NotNil(t, fromYAML.Scope)
	require.Len(t, fromYAML.Scope.Dimensions, 2)
	assert.Nil(t, fromYAML.Scope.Dimensions[0].Covers)
	assert.Equal(t, []string{"balances", "operations"}, fromYAML.Scope.Dimensions[1].Covers)

	require.NoError(t, fromYAML.Validate())
}

func TestWireJSON_Covers(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(coveredYAML))
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

	assert.NotContains(t, got.Scope.Dimensions[0], "covers", "a dimension without covers sends no covers key")
	assert.Equal(t, []any{"balances", "operations"}, got.Scope.Dimensions[1]["covers"])
}

func TestCanonicalHash_IncludesCovers(t *testing.T) {
	t.Parallel()

	base, err := parseManifest([]byte(coveredJSON))
	require.NoError(t, err)

	baseHash, err := base.CanonicalHash()
	require.NoError(t, err)

	withCovers := func(covers []string) *DeclarationManifest {
		cp := *base
		cp.Scope = &DeclarationScope{Dimensions: append([]DeclarationDimension(nil), base.Scope.Dimensions...)}
		cp.Scope.Dimensions[1].Covers = covers

		return &cp
	}

	noCoversHash, err := withCovers(nil).CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, noCoversHash, "adding covers must change the hash")

	moreHash, err := withCovers([]string{"balances", "operations", "holds"}).CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, moreHash, "a covers-only change must change the hash")

	reorderedHash, err := withCovers([]string{"operations", "balances"}).CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, baseHash, reorderedHash, "covers order is content")

	// scope.routes are projected out of the hash; covers must survive that projection.
	routed := withCovers([]string{"balances", "operations"})
	routed.Scope.Routes = []DeclarationScopeRoute{{
		Method: "POST", Path: "/v1/transfers",
		Dimensions: []DeclarationRouteDimension{{Name: "accountId", From: "body", Field: "accountId"}},
	}}

	routedHash, err := routed.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, baseHash, routedHash)
}

// A scope-only publication carries the dimensions' covers.
func TestPublish_ScopeOnly_CarriesCovers(t *testing.T) {
	t.Parallel()

	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Manifest = []byte(coveredJSON)
	cfg.ScopeOnly = true

	p := newFastPublisher(t, cfg)
	require.NoError(t, p.Publish(context.Background()))

	identity.mu.Lock()
	body := identity.gotBody
	identity.mu.Unlock()

	assert.JSONEq(t, `{
	  "service": "plugin-fees",
	  "version": 3,
	  "scope": {"dimensions": [
	    {"name": "organizationId", "from": "path", "param": "organization_id", "required": true, "collection": "organizations", "label": "Organization"},
	    {"name": "accountId", "from": "path", "param": "account_id", "multi": true, "collection": "accounts", "covers": ["balances", "operations"], "label": "Account"}
	  ]}
	}`, body)
}

func TestValidate_ScopeCovers(t *testing.T) {
	t.Parallel()

	dim := func(collection string, covers ...string) DeclarationDimension {
		return DeclarationDimension{Name: "accountId", From: "path", Param: "account_id", Collection: collection, Covers: covers}
	}

	tests := []struct {
		name     string
		dim      DeclarationDimension
		wantErrs []string
	}{
		{name: "valid", dim: dim("accounts", "balances", "operations")},
		{name: "valid_none", dim: dim("accounts")},
		{
			name:     "empty_entry",
			dim:      dim("accounts", "balances", ""),
			wantErrs: []string{"scope.dimensions[0].covers[1]: must not be empty"},
		},
		{
			name:     "blank_entry",
			dim:      dim("accounts", "  "),
			wantErrs: []string{"scope.dimensions[0].covers[0]: must not be empty"},
		},
		{
			name:     "duplicate",
			dim:      dim("accounts", "balances", "operations", "balances"),
			wantErrs: []string{`scope.dimensions[0].covers[2]: duplicate collection "balances"`},
		},
		{
			name:     "duplicate_case_insensitive",
			dim:      dim("accounts", "balances", "BALANCES"),
			wantErrs: []string{`scope.dimensions[0].covers[1]: duplicate collection "BALANCES"`},
		},
		{
			name:     "duplicate_after_trim",
			dim:      dim("accounts", "balances", " Balances "),
			wantErrs: []string{`scope.dimensions[0].covers[1]: duplicate collection "Balances"`},
		},
		{
			name:     "own_collection",
			dim:      dim("accounts", "balances", "accounts"),
			wantErrs: []string{`scope.dimensions[0].covers[1]: must not repeat the dimension's own collection "accounts"`},
		},
		{
			name:     "own_collection_case_insensitive",
			dim:      dim("accounts", "Accounts"),
			wantErrs: []string{`scope.dimensions[0].covers[0]: must not repeat the dimension's own collection "accounts"`},
		},
		{
			name:     "own_collection_after_trim",
			dim:      dim(" Accounts", "accounts  "),
			wantErrs: []string{`scope.dimensions[0].covers[0]: must not repeat the dimension's own collection "Accounts"`},
		},
		{
			name: "aggregates",
			dim:  dim("accounts", "", "accounts", "holds", "HOLDS"),
			wantErrs: []string{
				"scope.dimensions[0].covers[0]: must not be empty",
				`scope.dimensions[0].covers[1]: must not repeat the dimension's own collection "accounts"`,
				`scope.dimensions[0].covers[3]: duplicate collection "HOLDS"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := parseManifest([]byte(feesJSON))
			require.NoError(t, err)

			m.Scope = &DeclarationScope{Dimensions: []DeclarationDimension{tt.dim}}

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
		})
	}
}

// Two dimensions may each cover the same collection, and a dimension may cover
// another dimension's own collection: the checks are per dimension.
func TestValidate_ScopeCovers_PerDimension(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(feesJSON))
	require.NoError(t, err)

	m.Scope = &DeclarationScope{Dimensions: []DeclarationDimension{
		{Name: "ledgerId", From: "path", Param: "ledger_id", Collection: "ledgers", Covers: []string{"operations", "accounts"}},
		{Name: "accountId", From: "path", Param: "account_id", Collection: "accounts", Covers: []string{"operations"}},
	}}

	require.NoError(t, m.Validate())
}
