package declaration

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// leveledYAML is scopedYAML with a permission that declares the level of the
// resource it grants.
const leveledYAML = `
service: plugin-fees
version: 3
permissions:
  - resource: billing-packages
    action: read
    effect: allow
    roles: [fees/viewer]
    level: ledger
roles:
  - name: fees/viewer
scope:
  dimensions:
    - { name: organizationId, from: path, param: organization_id, required: true, collection: organizations, label: "Organization" }
    - { name: ledgerId, from: path, param: ledger_id, multi: true, collection: ledgers, label: "ledger" }
`

// leveledCanonical is the exact canonical serialization of leveledYAML, written
// out by hand: "level" is the LAST member of a permission. The identity service
// recomputes the hash over the same bytes, so the member order is contract.
const leveledCanonical = `{"service":"plugin-fees","permissions":[{"resource":"billing-packages","action":"read","effect":"allow","roles":["fees/viewer"],"level":"ledger"}],"roles":[{"name":"fees/viewer"}],"scope":{"dimensions":[{"name":"organizationId","from":"path","param":"organization_id","required":true,"collection":"organizations","label":"Organization"},{"name":"ledgerId","from":"path","param":"ledger_id","multi":true,"collection":"ledgers","label":"ledger"}]}}`

func TestCanonicalHash_IncludesLevel(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(leveledYAML))
	require.NoError(t, err)
	require.NoError(t, m.Validate())

	sum := sha256.Sum256([]byte(leveledCanonical))

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(sum[:]), hash)
	assert.NotEqual(t, scopedJSONPreviousHash, hash, "declaring a level must change the hash")

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Contains(t, string(wire), `"roles":["fees/viewer"],"level":"ledger"}`)
}

// A manifest without levels publishes the same bytes and hash as before the
// field existed, so upgrading the library republishes nothing.
func TestManifestWithoutLevel_WireAndHashUnchanged(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(scopedJSON))
	require.NoError(t, err)

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, scopedJSONPreviousHash, hash)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Equal(t, scopedJSONPreviousWire, string(wire))
	assert.NotContains(t, string(wire), "level")
}

func TestValidate_PermissionLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		level   string
		noScope bool
		wantErr string
	}{
		{name: "absent", level: ""},
		{name: "tenant", level: "tenant"},
		{name: "organization", level: "organization"},
		{name: "ledger", level: "ledger"},
		{name: "catalog_dimension", level: "ledgerId"},
		{name: "keyword_without_scope", level: "tenant", noScope: true},
		{
			name:    "unknown",
			level:   "portfolio",
			wantErr: `permissions[0]: level "portfolio" must be "tenant", "organization", "ledger" or a scope dimension name`,
		},
		{
			name:    "keyword_in_other_case",
			level:   "Tenant",
			wantErr: `permissions[0]: level "Tenant" must be`,
		},
		{
			name:    "padded",
			level:   " ledger",
			wantErr: `permissions[0]: level " ledger" must be`,
		},
		{
			name:    "dimension_without_scope",
			level:   "ledgerId",
			noScope: true,
			wantErr: `permissions[0]: level "ledgerId" must be`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := parseManifest([]byte(leveledYAML))
			require.NoError(t, err)

			m.Permissions[0].Level = tt.level
			if tt.noScope {
				m.Scope = nil
			}

			err = m.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			var me *ManifestError

			require.ErrorAs(t, err, &me)
			assert.Contains(t, me.Reason, tt.wantErr)
			assert.Equal(t, 1, strings.Count(me.Reason, "level"), "one violation, naming the level once")
		})
	}
}
