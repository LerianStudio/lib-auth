package declaration

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// levelsYAML declares three permissions: two with a level, one between them
// without. The scope-only body must carry exactly the two, in declaration order.
const levelsYAML = `
service: plugin-fees
version: 3
partners: true
permissions:
  - resource: billing-packages
    action: read
    effect: allow
    roles: [fees/viewer]
    level: ledgerId
  - resource: billing-packages
    action: create
    effect: allow
    roles: [fees/viewer]
  - resource: fee-rules
    action: update
    effect: allow
    roles: [fees/viewer]
    level: tenant
roles:
  - name: fees/viewer
scope:
  dimensions:
    - { name: organizationId, from: path, param: organization_id, required: true, collection: organizations, label: "Organization" }
    - { name: ledgerId, from: path, param: ledger_id, multi: true, collection: ledgers, label: "ledger" }
`

const levelsScopeJSON = `"scope":{"dimensions":[{"name":"organizationId","from":"path","param":"organization_id","required":true,"collection":"organizations","label":"Organization"},{"name":"ledgerId","from":"path","param":"ledger_id","multi":true,"collection":"ledgers","label":"ledger"}]}`

// levelsScopeOnlyWire is the exact scope-only body of levelsYAML: "levels" is
// the LAST member, after "partners", and each entry carries resource, action
// and level only.
const levelsScopeOnlyWire = `{"service":"plugin-fees","version":3,` + levelsScopeJSON +
	`,"partners":true,"levels":[{"resource":"billing-packages","action":"read","level":"ledgerId"},{"resource":"fee-rules","action":"update","level":"tenant"}]}`

// levelsScopeOnlyCanonical is the scope-only canonical serialization of
// levelsYAML, written out by hand: the version is left out and "levels" is the
// LAST member. The authorization service recomputes the hash over these bytes.
const levelsScopeOnlyCanonical = `{"service":"plugin-fees",` + levelsScopeJSON +
	`,"partners":true,"levels":[{"resource":"billing-packages","action":"read","level":"ledgerId"},{"resource":"fee-rules","action":"update","level":"tenant"}]}`

// The scope-only body and hash of scopedJSON with partners: true as computed by
// the release before levels were published scope-only. A manifest that declares
// no level must keep them byte for byte.
const (
	scopeOnlyPartnersPreviousWire = `{"service":"plugin-fees","version":3,` + levelsScopeJSON + `,"partners":true}`
	scopeOnlyPartnersPreviousHash = "11b38190106f98365fea1e7fa1e1c2c89912d9259fe4c4e894e2837fc3181a59"
)

func TestScopeOnly_CarriesLevels(t *testing.T) {
	t.Parallel()

	m := mustParse(t, levelsYAML)
	require.NoError(t, m.Validate())

	wire, err := m.scopeOnly().wireJSON()
	require.NoError(t, err)
	assert.Equal(t, levelsScopeOnlyWire, string(wire))
}

func TestScopeOnly_CanonicalHash_IncludesLevels(t *testing.T) {
	t.Parallel()

	m := mustParse(t, levelsYAML)

	sum := sha256.Sum256([]byte(levelsScopeOnlyCanonical))

	hash, err := m.scopeOnly().CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(sum[:]), hash)

	// A level change alone must change the hash, or the publisher would skip it.
	changed := mustParse(t, levelsYAML)
	changed.Permissions[2].Level = "organizationId"

	changedHash, err := changed.scopeOnly().CanonicalHash()
	require.NoError(t, err)
	assert.NotEqual(t, hash, changedHash)
}

// A manifest that declares no level publishes the same scope-only bytes and
// hash as before levels were published there.
func TestScopeOnly_WithoutLevels_WireAndHashUnchanged(t *testing.T) {
	t.Parallel()

	m := optedIn(t, scopedJSON)

	wire, err := m.scopeOnly().wireJSON()
	require.NoError(t, err)
	assert.Equal(t, scopeOnlyPartnersPreviousWire, string(wire))

	hash, err := m.scopeOnly().CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, scopeOnlyPartnersPreviousHash, hash)
}

// The full declaration already carries each level inside its permission; it
// does not repeat them in a "levels" member.
func TestFullDeclaration_DoesNotCarryLevels(t *testing.T) {
	t.Parallel()

	m := mustParse(t, levelsYAML)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.NotContains(t, string(wire), `"levels"`)
	assert.Contains(t, string(wire), `"roles":["fees/viewer"],"level":"tenant"}`)
}

// The scope-only publisher sends the levels on the wire.
func TestPublish_ScopeOnly_CarriesLevels(t *testing.T) {
	t.Parallel()

	body := publishScopeOnly(t, mustParse(t, levelsYAML))

	assert.JSONEq(t, levelsScopeOnlyWire, body)
}
