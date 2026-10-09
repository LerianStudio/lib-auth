package declaration

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationsCanonical is the exact canonical serialization of scopedJSON
// opted in to partners and declaring two integrations, written out by hand:
// "integrations" is the LAST member, after "partners". The identity service
// recomputes the hash over the same bytes.
const integrationsCanonical = `{"service":"plugin-fees","permissions":[{"resource":"billing-packages","action":"read","effect":"allow","roles":["fees/viewer"]}],"roles":[{"name":"fees/viewer"}],"scope":{"dimensions":[{"name":"organizationId","from":"path","param":"organization_id","required":true,"collection":"organizations","label":"Organization"},{"name":"ledgerId","from":"path","param":"ledger_id","multi":true,"collection":"ledgers","label":"ledger"}]},"partners":true,"integrations":["midaz","plugin-crm"]}`

func integrated(t *testing.T, raw string, integrations ...string) *DeclarationManifest {
	t.Helper()

	m := optedIn(t, raw)
	m.Integrations = integrations

	return m
}

func TestParseManifest_Integrations(t *testing.T) {
	t.Parallel()

	fromYAML, err := parseManifest([]byte(scopedYAML + "integrations: [midaz, plugin-crm]\n"))
	require.NoError(t, err)
	assert.Equal(t, []string{"midaz", "plugin-crm"}, fromYAML.Integrations)

	fromJSON, err := parseManifest([]byte(`{"service":"plugin-fees","version":1,"integrations":["midaz","plugin-crm"]}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"midaz", "plugin-crm"}, fromJSON.Integrations)

	absent, err := parseManifest([]byte(scopedYAML))
	require.NoError(t, err)
	assert.Empty(t, absent.Integrations, "integrations default to none")
}

func TestValidate_Integrations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		integrations []string
		want         string
	}{
		{name: "valid", integrations: []string{"midaz", "plugin-crm"}},
		{name: "empty_entry", integrations: []string{"midaz", ""}, want: "integrations[1]: must not be empty"},
		{name: "blank_entry", integrations: []string{"  "}, want: "integrations[0]: must not be empty"},
		{
			name:         "duplicate_ignoring_case_and_space",
			integrations: []string{"midaz", " MIDAZ "},
			want:         `integrations[1]: duplicate service "MIDAZ"`,
		},
		{
			name:         "own_service",
			integrations: []string{"Plugin-Fees"},
			want:         `integrations[0]: must not repeat the manifest's own service "plugin-fees"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := integrated(t, scopedJSON, tt.integrations...).Validate()
			if tt.want == "" {
				require.NoError(t, err)

				return
			}

			var manifestErr *ManifestError

			require.ErrorAs(t, err, &manifestErr)
			assert.Equal(t, tt.want, manifestErr.Reason)
		})
	}
}

func TestCanonicalHash_IncludesIntegrations(t *testing.T) {
	t.Parallel()

	m := integrated(t, scopedJSON, "midaz", "plugin-crm")
	require.NoError(t, m.Validate())

	sum := sha256.Sum256([]byte(integrationsCanonical))

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(sum[:]), hash)

	wire, err := m.wireJSON()
	require.NoError(t, err)
	assert.Contains(t, string(wire), `"partners":true,"integrations":["midaz","plugin-crm"]}`)
}

// A manifest that declares no integration publishes the same bytes and hash as
// before the field existed.
func TestManifestWithoutIntegrations_WireAndHashUnchanged(t *testing.T) {
	t.Parallel()

	m := integrated(t, scopedJSON)

	sum := sha256.Sum256([]byte(partnersCanonical))

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(sum[:]), hash)
}

// The scope-only publication carries the integrations as its last member.
func TestPublish_ScopeOnly_CarriesIntegrations(t *testing.T) {
	t.Parallel()

	body := publishScopeOnly(t, integrated(t, feesJSON, "midaz", "plugin-crm"))

	assert.JSONEq(t, `{"service": "plugin-fees", "version": 3, "partners": true, "integrations": ["midaz", "plugin-crm"]}`, body)

	s := integrated(t, feesJSON, "midaz", "plugin-crm").scopeOnly()

	hash, err := s.CanonicalHash()
	require.NoError(t, err)

	sum := sha256.Sum256([]byte(`{"service":"plugin-fees","partners":true,"integrations":["midaz","plugin-crm"]}`))
	assert.Equal(t, hex.EncodeToString(sum[:]), hash)
}

// Integrations are something to publish on their own: a product that relays
// for partners states it even before it declares a scope or opts in.
func TestPublish_ScopeOnly_IntegrationsAloneArePublished(t *testing.T) {
	t.Parallel()

	m := mustParse(t, feesJSON)
	m.Integrations = []string{"midaz"}

	body := publishScopeOnly(t, m)

	assert.JSONEq(t, `{"service": "plugin-fees", "version": 3, "integrations": ["midaz"]}`, body)
}
