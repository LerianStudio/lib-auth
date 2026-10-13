package declaration

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// feesHashBeforeM2MRoles is the CanonicalHash of feesJSON as it was before
// m2m.roles existed. A manifest that does not declare m2m.roles must publish the
// same bytes and hash, or every service would re-publish on the upgrade and an
// access manager that does not know the field would see a body it never saw.
// The literal is the contract: it is not recomputed here.
const feesHashBeforeM2MRoles = "3791eee47e35334ba96a82d15f1e833216a3709601907a1229228993beaa3bfc"

// machineOnlyYAML is the br-sisbajud shape the field exists for: a permission
// the template grants to the service's M2M identity and to no business role
// (systemplane), held by a role bound to no group and named in m2m.roles.
const machineOnlyYAML = `
service: br-sisbajud
version: 2
permissions:
  - { resource: order, action: order:read, effect: allow, roles: [operator, machine] }
  - { resource: systemplane, action: systemplane:read, effect: allow, roles: [machine] }
  - { resource: systemplane, action: systemplane:write, effect: allow, roles: [machine] }
roles:
  - name: operator
    granted_to:
      - group: br-sisbajud-operator
  - name: machine
m2m:
  exposed: true
  roles: [machine]
`

func TestM2MRoles_AbsentKeepsWireAndHash(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(feesJSON))
	require.NoError(t, err)
	require.NoError(t, m.Validate())

	hash, err := m.CanonicalHash()
	require.NoError(t, err)
	assert.Equal(t, feesHashBeforeM2MRoles, hash)

	wire, err := m.wireJSON()
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(wire, &body))
	assert.Equal(t, map[string]any{"exposed": true, "needs": []any{"midaz"}}, body["m2m"],
		"a manifest without m2m.roles must not grow a roles member on the wire")
}

func TestM2MRoles_MachineOnlyPermissionIsDeclarable(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(machineOnlyYAML))
	require.NoError(t, err)
	require.NoError(t, m.Validate())
	assert.Equal(t, []string{"machine"}, m.M2M.Roles)
}

func TestM2MRoles_PublishedAndHashed(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(machineOnlyYAML))
	require.NoError(t, err)

	wire, err := m.wireJSON()
	require.NoError(t, err)

	var body struct {
		M2M struct {
			Roles []string `json:"roles"`
		} `json:"m2m"`
	}
	require.NoError(t, json.Unmarshal(wire, &body))
	assert.Equal(t, []string{"machine"}, body.M2M.Roles, "m2m.roles must reach the access manager")

	without := *m
	without.M2M = &DeclarationM2M{Exposed: true}

	withHash, err := m.CanonicalHash()
	require.NoError(t, err)

	withoutHash, err := without.CanonicalHash()
	require.NoError(t, err)

	assert.NotEqual(t, withHash, withoutHash,
		"m2m.roles must be hashed, or a change to it would never be published")
}

func TestM2MRoles_RoundTripsJSONAndYAML(t *testing.T) {
	t.Parallel()

	fromYAML, err := parseManifest([]byte(machineOnlyYAML))
	require.NoError(t, err)

	wire, err := fromYAML.wireJSON()
	require.NoError(t, err)

	fromJSON, err := parseManifest(wire)
	require.NoError(t, err)

	assert.Equal(t, fromYAML.M2M, fromJSON.M2M)
}

func TestM2MRoles_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(m *DeclarationManifest)
		want   string
	}{
		{
			name:   "undeclared_role",
			mutate: func(m *DeclarationManifest) { m.M2M.Roles = []string{"editor"} },
			want:   `m2m.roles[0]: references undeclared role "editor"`,
		},
		{
			name:   "empty_entry",
			mutate: func(m *DeclarationManifest) { m.M2M.Roles = []string{"machine", " "} },
			want:   "m2m.roles[1]: role name must not be empty",
		},
		{
			name:   "duplicate_entry",
			mutate: func(m *DeclarationManifest) { m.M2M.Roles = []string{"machine", "machine"} },
			want:   `m2m.roles[1]: duplicate role "machine"`,
		},
		{
			name:   "not_exposed",
			mutate: func(m *DeclarationManifest) { m.M2M.Exposed = false },
			want:   "m2m.roles requires m2m.exposed: true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := parseManifest([]byte(machineOnlyYAML))
			require.NoError(t, err)
			require.NoError(t, m.Validate(), "positive control: valid before the mutation")

			tt.mutate(m)

			err = m.Validate()
			require.Error(t, err)

			var me *ManifestError
			require.ErrorAs(t, err, &me)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

// A role named in m2m.roles may also be bound to groups: midaz's editor is held
// by people and by the M2M identity alike. The field names the machine's tier;
// it does not make the role machine-only.
func TestM2MRoles_RoleWithGroupsIsAccepted(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(machineOnlyYAML))
	require.NoError(t, err)

	m.M2M.Roles = []string{"operator", "machine"}
	require.NoError(t, m.Validate())
}

// The rest of the M2M contract is untouched: a manifest that is not exposed and
// declares no m2m.roles stays valid.
func TestM2MRoles_NotExposedWithoutRolesIsValid(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(machineOnlyYAML))
	require.NoError(t, err)

	m.M2M = &DeclarationM2M{Needs: []string{"midaz"}}
	require.NoError(t, m.Validate())
}
