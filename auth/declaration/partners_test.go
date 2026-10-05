package declaration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// partnersCanonical is the exact canonical serialization of scopedJSON with
// partners: true, written out by hand: "partners" is the LAST member, after
// the scope. The identity service recomputes the hash over the same bytes.
const partnersCanonical = `{"service":"plugin-fees","permissions":[{"resource":"billing-packages","action":"read","effect":"allow","roles":["fees/viewer"]}],"roles":[{"name":"fees/viewer"}],"scope":{"dimensions":[{"name":"organizationId","from":"path","param":"organization_id","required":true,"collection":"organizations","label":"Organization"},{"name":"ledgerId","from":"path","param":"ledger_id","multi":true,"collection":"ledgers","label":"ledger"}]},"partners":true}`

func optedIn(t *testing.T, raw string) *DeclarationManifest {
	t.Helper()

	m, err := parseManifest([]byte(raw))
	require.NoError(t, err)

	m.Partners = true

	return m
}

func TestParseManifest_Partners(t *testing.T) {
	t.Parallel()

	fromYAML, err := parseManifest([]byte(scopedYAML + "partners: true\n"))
	require.NoError(t, err)
	assert.True(t, fromYAML.Partners)

	fromJSON, err := parseManifest([]byte(`{"service":"plugin-fees","version":1,"partners":true}`))
	require.NoError(t, err)
	assert.True(t, fromJSON.Partners)

	absent, err := parseManifest([]byte(scopedYAML))
	require.NoError(t, err)
	assert.False(t, absent.Partners, "partners defaults to false")
}

func TestCanonicalHash_IncludesPartners(t *testing.T) {
	t.Parallel()

	m := optedIn(t, scopedJSON)
	require.NoError(t, m.Validate())

	sum := sha256.Sum256([]byte(partnersCanonical))

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(sum[:]), hash)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Contains(t, string(wire), `"label":"ledger"}]},"partners":true}`)
}

// A manifest that does not opt in publishes the same bytes and hash as before
// the field existed.
func TestManifestWithoutPartners_WireAndHashUnchanged(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(scopedJSON))
	require.NoError(t, err)

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, scopedJSONPreviousHash, hash)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, scopedJSONPreviousWire, string(wire))
}

// A product may opt in without declaring any scope dimension: its partners
// are then granted tenant-wide.
func TestValidate_PartnersWithoutScope(t *testing.T) {
	t.Parallel()

	require.NoError(t, optedIn(t, feesJSON).Validate())
}

// The scope-only publication carries the opt-in next to the scope.
func TestPublish_ScopeOnly_CarriesPartners(t *testing.T) {
	t.Parallel()

	body := publishScopeOnly(t, optedIn(t, scopedJSON))

	assert.JSONEq(t, `{
	  "service": "plugin-fees",
	  "version": 3,
	  "scope": {"dimensions": [
	    {"name": "organizationId", "from": "path", "param": "organization_id", "required": true, "collection": "organizations", "label": "Organization"},
	    {"name": "ledgerId", "from": "path", "param": "ledger_id", "multi": true, "collection": "ledgers", "label": "ledger"}
	  ]},
	  "partners": true
	}`, body)
}

// A product that opts in with no scope section still has something to
// publish: the opt-in itself.
func TestPublish_ScopeOnly_PartnersWithoutScopeIsPublished(t *testing.T) {
	t.Parallel()

	body := publishScopeOnly(t, optedIn(t, feesJSON))

	assert.JSONEq(t, `{"service": "plugin-fees", "version": 3, "partners": true}`, body)
}

// Positive control for the test above: without the opt-in and without a scope
// a scope-only publisher still sends nothing.
func TestPublish_ScopeOnly_NeitherScopeNorPartnersSendsNothing(t *testing.T) {
	t.Parallel()

	assert.Empty(t, publishScopeOnly(t, mustParse(t, feesJSON)))
}

func mustParse(t *testing.T, raw string) *DeclarationManifest {
	t.Helper()

	m, err := parseManifest([]byte(raw))
	require.NoError(t, err)

	return m
}

// publishScopeOnly publishes m through a scope-only publisher and returns the
// body the identity service received ("" when it received none).
func publishScopeOnly(t *testing.T, m *DeclarationManifest) string {
	t.Helper()

	raw, err := m.wireJSON()
	require.NoError(t, err)

	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	cfg := testConfig(t, auth.URL, identity.URL)
	cfg.Manifest = raw
	cfg.ScopeOnly = true

	p := newFastPublisher(t, cfg)
	require.NoError(t, p.Publish(context.Background()))

	identity.mu.Lock()
	defer identity.mu.Unlock()

	return identity.gotBody
}

// With the permission declaration off and auth on, a manifest that opts in
// without a scope section publishes the opt-in alone.
func TestWireFromEnv_DeclarationOff_AuthOn_PartnersWithoutScope(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{}`)
	t.Cleanup(identity.Close)

	setScopeOnlyEnv(t, identity.URL, auth.URL)

	stop, err := WireFromEnv(context.Background(), WireInput{
		Slug:     "plugin-fees",
		Manifest: []byte(`{"service":"plugin-fees","version":3,"partners":true}`),
		Logger:   obs.Nop(),
	})
	require.NoError(t, err)
	t.Cleanup(stop)

	select {
	case <-identity.puts:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a background scope-only PUT")
	}

	identity.mu.Lock()
	body := identity.gotBody
	identity.mu.Unlock()

	assert.JSONEq(t, `{"service":"plugin-fees","version":3,"partners":true}`, body)
}
