package declaration

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// feesJSON mirrors ~/Downloads/RI-AM/local-test/plugin-fees.manifest.json — the
// real wire fixture proven green by declare.sh.
const feesJSON = `{
  "service": "plugin-fees",
  "version": 3,
  "permissions": [
    { "resource": "billing-packages", "action": "create", "effect": "allow", "roles": ["fees/editor"] },
    { "resource": "billing-packages", "action": "read",   "effect": "allow", "roles": ["fees/editor", "fees/viewer"] },
    { "resource": "billing-packages", "action": "delete", "effect": "deny",  "roles": ["fees/viewer"] }
  ],
  "roles": [
    { "name": "fees/editor", "granted_to": [{ "group": "fees-admins" }] },
    { "name": "fees/viewer", "granted_to": [{ "group": "fees-viewers" }] }
  ],
  "m2m": { "exposed": true, "needs": ["midaz"] }
}`

// feesYAML is the authored (human) form of the SAME manifest. The lib must parse
// YAML or JSON into the same struct / same wire JSON.
const feesYAML = `
service: plugin-fees
version: 3
permissions:
  - resource: billing-packages
    action: create
    effect: allow
    roles: [fees/editor]
  - resource: billing-packages
    action: read
    effect: allow
    roles: [fees/editor, fees/viewer]
  - resource: billing-packages
    action: delete
    effect: deny
    roles: [fees/viewer]
roles:
  - name: fees/editor
    granted_to:
      - group: fees-admins
  - name: fees/viewer
    granted_to:
      - group: fees-viewers
m2m:
  exposed: true
  needs: [midaz]
`

func TestParseManifest_YAMLAndJSON_ProduceSameStructAndWire(t *testing.T) {
	fromJSON, err := parseManifest([]byte(feesJSON))
	require.NoError(t, err)

	fromYAML, err := parseManifest([]byte(feesYAML))
	require.NoError(t, err)

	assert.Equal(t, fromJSON, fromYAML, "YAML and JSON must parse into an identical struct")

	wireJSONBytes, err := fromJSON.wireJSON()
	require.NoError(t, err)

	wireYAMLBytes, err := fromYAML.wireJSON()
	require.NoError(t, err)

	assert.JSONEq(t, string(wireJSONBytes), string(wireYAMLBytes), "wire JSON must be identical")

	// The wire JSON must deserialize back into the manifest model (server round-trip).
	roundTrip, err := parseManifest(wireJSONBytes)
	require.NoError(t, err)
	assert.Equal(t, fromJSON, roundTrip)
}

func TestParseManifest_Invalid(t *testing.T) {
	_, err := parseManifest([]byte("not: [valid: yaml"))
	require.Error(t, err)

	_, err = parseManifest([]byte("   "))
	require.Error(t, err)
}

func TestCanonicalHash_ExcludesVersion(t *testing.T) {
	v3, err := parseManifest([]byte(feesJSON))
	require.NoError(t, err)

	v99 := *v3
	v99.Version = 99

	h1, err := v3.CanonicalHash()
	require.NoError(t, err)

	h2, err := v99.CanonicalHash()
	require.NoError(t, err)

	assert.Equal(t, h1, h2, "manifests differing only in version must hash identically (R1)")
	assert.Len(t, h1, 64, "hash must be hex-encoded sha256 (64 chars)")
}

func TestCanonicalHash_KeyOrderIndependent(t *testing.T) {
	reordered := `{
      "m2m": { "needs": ["midaz"], "exposed": true },
      "roles": [
        { "granted_to": [{ "group": "fees-admins" }], "name": "fees/editor" },
        { "name": "fees/viewer", "granted_to": [{ "group": "fees-viewers" }] }
      ],
      "version": 3,
      "service": "plugin-fees",
      "permissions": [
        { "roles": ["fees/editor"], "effect": "allow", "action": "create", "resource": "billing-packages" },
        { "resource": "billing-packages", "action": "read", "effect": "allow", "roles": ["fees/editor", "fees/viewer"] },
        { "resource": "billing-packages", "action": "delete", "effect": "deny", "roles": ["fees/viewer"] }
      ]
    }`

	base, err := parseManifest([]byte(feesJSON))
	require.NoError(t, err)

	shuffled, err := parseManifest([]byte(reordered))
	require.NoError(t, err)

	hBase, err := base.CanonicalHash()
	require.NoError(t, err)

	hShuffled, err := shuffled.CanonicalHash()
	require.NoError(t, err)

	assert.Equal(t, hBase, hShuffled, "wire key ordering must not change the hash")
}

func TestCanonicalHash_ContentChangeChangesHash(t *testing.T) {
	base, err := parseManifest([]byte(feesJSON))
	require.NoError(t, err)

	mutated := *base
	perms := make([]DeclarationPermission, len(base.Permissions))
	copy(perms, base.Permissions)
	perms[0].Effect = "deny"
	mutated.Permissions = perms

	hBase, err := base.CanonicalHash()
	require.NoError(t, err)

	hMut, err := mutated.CanonicalHash()
	require.NoError(t, err)

	assert.NotEqual(t, hBase, hMut, "any content change must change the hash")
}

// TestValidate_RejectsDotSegmentService asserts a manifest whose service is a
// dot-segment ("." or "..") is rejected. url.PathEscape leaves these intact, so an
// unguarded ".." would form /v1/declarations/.. and a path-normalizing intermediary
// could redirect the PUT to the wrong endpoint. New enforces slug==service, so
// guarding service in Validate covers both.
func TestValidate_RejectsDotSegmentService(t *testing.T) {
	tests := map[string]string{
		"single dot": `{"service":".","version":1}`,
		"double dot": `{"service":"..","version":1}`,
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := parseManifest([]byte(raw))
			require.NoError(t, err)

			verr := m.Validate()
			require.Error(t, verr, "a dot-segment service must be rejected")

			var me *ManifestError
			assert.ErrorAs(t, verr, &me, "validation error must be a *ManifestError")
		})
	}
}

func TestValidate_Valid(t *testing.T) {
	m, err := parseManifest([]byte(feesJSON))
	require.NoError(t, err)
	require.NoError(t, m.Validate())
}

// TestValidate_AllowsHTTPVerbAndSemanticActions locks in the REMOVAL of the
// HTTP-verb action reject: an action is validated only for non-emptiness, so
// HTTP-verb actions (post/get/put/patch, case-insensitive, incl. whitespace-padded)
// now PASS Validate() with no error — exactly as they did before the reject existed.
// It also keeps semantic actions ("delete" and CRUD verbs) and arbitrary domain
// verbs passing. If the reject is ever accidentally re-added, this test fails.
func TestValidate_AllowsHTTPVerbAndSemanticActions(t *testing.T) {
	actions := []string{
		// Previously-rejected HTTP verbs (all cases + whitespace padding) — now valid.
		"post", "get", "put", "patch", "POST", "GET", "Put", "PaTcH",
		" post ", "  PATCH  ",
		// Semantic CRUD actions and domain verbs — always valid.
		"create", "read", "update", "delete", "DELETE", "rotate",
		// Other HTTP methods that were never rejected — still valid.
		"head", "options", "trace", "connect",
	}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			raw := fmt.Sprintf(`{"service":"s","version":1,"roles":[{"name":"x"}],"permissions":[{"resource":"r","action":%q,"effect":"allow","roles":["x"]}]}`, action)

			m, err := parseManifest([]byte(raw))
			require.NoError(t, err)

			require.NoError(t, m.Validate(), "action %q must be accepted (no HTTP-verb reject)", action)
		})
	}
}

func TestValidate_RejectsBadManifests(t *testing.T) {
	tests := map[string]string{
		"empty service":   `{"version":1,"permissions":[{"resource":"r","action":"read","effect":"allow","roles":["x"]}],"roles":[{"name":"x"}]}`,
		"zero version":    `{"service":"s","version":0,"roles":[{"name":"x"}],"permissions":[{"resource":"r","action":"read","effect":"allow","roles":["x"]}]}`,
		"bad effect":      `{"service":"s","version":1,"roles":[{"name":"x"}],"permissions":[{"resource":"r","action":"read","effect":"maybe","roles":["x"]}]}`,
		"undeclared role": `{"service":"s","version":1,"roles":[{"name":"x"}],"permissions":[{"resource":"r","action":"read","effect":"allow","roles":["ghost"]}]}`,
		"perm no roles":   `{"service":"s","version":1,"roles":[{"name":"x"}],"permissions":[{"resource":"r","action":"read","effect":"allow"}]}`,
		"empty resource":  `{"service":"s","version":1,"roles":[{"name":"x"}],"permissions":[{"resource":"","action":"read","effect":"allow","roles":["x"]}]}`,
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := parseManifest([]byte(raw))
			require.NoError(t, err)

			verr := m.Validate()
			require.Error(t, verr, "expected validation to reject manifest")

			var me *ManifestError
			assert.ErrorAs(t, verr, &me, "validation error must be a *ManifestError")
		})
	}
}
