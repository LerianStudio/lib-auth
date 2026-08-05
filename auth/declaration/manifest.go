package declaration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Permission effects. A permission either grants (allow) or refuses (deny) the
// declared (resource, action) pair. These are the only accepted values. They
// mirror the server model (plugin-access-manager identity pkg/model).
const (
	effectAllow = "allow"
	effectDeny  = "deny"
)

// httpVerbActions is the set of HTTP methods that map 1:1 onto CRUD semantic actions
// (post->create, get->read, put/patch->update) and are therefore NEVER valid as a
// declared action: the SEMANTIC action naming standard requires the domain intent, not
// the transport verb. "delete" is deliberately EXCLUDED — it is the one HTTP method
// that is also a valid semantic action (delete == delete). The set is kept conservative
// (head/options/trace/connect are NOT listed) to match the documented HTTP->semantic
// mapping and avoid false positives on legitimate domain verbs.
var httpVerbActions = map[string]struct{}{
	"post":  {},
	"get":   {},
	"put":   {},
	"patch": {},
}

// DeclarationManifest is the wire model for a plugin's access-manager declaration
// (the body of PUT /v1/declarations/{slug}). It is a faithful client-side mirror of
// the server model
// (plugin-access-manager/components/identity/pkg/model/declaration.go): the JSON
// tags are byte-identical so a marshalled manifest deserializes into the server's
// DeclarationManifest, and CanonicalHash reproduces the server hash exactly.
//
// The struct additionally carries yaml tags so the authored permissions.yaml
// (human form) parses into the same struct as the JSON wire form.
type DeclarationManifest struct {
	// Service the manifest belongs to. Matches the caller's token; the
	// `plugin-` prefix is kept (not stripped). Required, non-empty.
	Service string `json:"service,omitempty" yaml:"service,omitempty"`
	// Version is advisory metadata. It is EXCLUDED from CanonicalHash, so a
	// version bump with identical content hashes identically. Required, positive.
	Version int `json:"version,omitempty" yaml:"version,omitempty"`
	// Permissions declared by the plugin: one entry per (resource, action).
	Permissions []DeclarationPermission `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	// Roles declared by the plugin. Role names are free-form and may contain '/'.
	Roles []DeclarationRole `json:"roles,omitempty" yaml:"roles,omitempty"`
	// M2M is the plugin's bilateral machine-to-machine contract.
	M2M *DeclarationM2M `json:"m2m,omitempty" yaml:"m2m,omitempty"`
}

// DeclarationPermission is a single declared permission. The action is SEMANTIC
// (create/read/update/delete), never an HTTP verb — Validate ENFORCES this, rejecting
// post/get/put/patch (case-insensitive); "delete" is allowed as it is the one HTTP
// method that is also a valid semantic action. The resource is written bare; the
// central reconciler composes the `{service}/` prefix.
type DeclarationPermission struct {
	Resource string   `json:"resource,omitempty" yaml:"resource,omitempty"`
	Action   string   `json:"action,omitempty" yaml:"action,omitempty"`
	Effect   string   `json:"effect,omitempty" yaml:"effect,omitempty"`
	Roles    []string `json:"roles,omitempty" yaml:"roles,omitempty"`
}

// DeclarationRole is a role declared by the plugin. A role names itself and
// optionally binds to already-existing groups via GrantedTo.
type DeclarationRole struct {
	Name      string             `json:"name,omitempty" yaml:"name,omitempty"`
	GrantedTo []DeclarationGrant `json:"granted_to,omitempty" yaml:"granted_to,omitempty"`
}

// DeclarationGrant binds a role to an existing group. Members of the group
// receive the role.
type DeclarationGrant struct {
	Group string `json:"group,omitempty" yaml:"group,omitempty"`
}

// DeclarationM2M is the plugin's bilateral machine-to-machine contract.
type DeclarationM2M struct {
	Exposed bool     `json:"exposed,omitempty" yaml:"exposed,omitempty"`
	Needs   []string `json:"needs,omitempty" yaml:"needs,omitempty"`
}

// canonicalManifest is the deterministic, hashable projection of a manifest. It
// deliberately OMITS Version so a version bump with identical content produces the
// same hash. Field order is fixed by struct declaration and there are no maps, so
// encoding/json emits a byte-stable form regardless of the ordering of keys in the
// original wire payload.
//
// This mirrors the server's canonicalManifest exactly
// (plugin-access-manager/components/identity/pkg/model/declaration.go:98) — the
// json tags and field order MUST stay in lock-step with the server or the
// idempotency-by-hash contract breaks. Note "service" carries NO omitempty, matching
// the server.
type canonicalManifest struct {
	Service     string                  `json:"service"`
	Permissions []DeclarationPermission `json:"permissions,omitempty"`
	Roles       []DeclarationRole       `json:"roles,omitempty"`
	M2M         *DeclarationM2M         `json:"m2m,omitempty"`
}

// ManifestError reports an invalid or unparseable manifest. It is the client-side
// counterpart of the server's 422 (UnprocessableOperation): the same validation is
// run eagerly at New so a bad embedded manifest fails fast instead of PUTting a
// guaranteed-422 body.
type ManifestError struct {
	Reason string
}

func (e *ManifestError) Error() string {
	return "declaration manifest invalid: " + e.Reason
}

// parseManifest parses the embedded manifest bytes (authored YAML or wire JSON)
// into the manifest model. JSON is detected by a leading '{'; anything else is
// treated as YAML. Both forms target the same struct (json/yaml tags are aligned),
// so they produce an identical manifest and identical wire JSON.
func parseManifest(raw []byte) (*DeclarationManifest, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, &ManifestError{Reason: "manifest is empty"}
	}

	var m DeclarationManifest

	if trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &m); err != nil {
			return nil, &ManifestError{Reason: fmt.Sprintf("parse json manifest: %v", err)}
		}

		return &m, nil
	}

	if err := yaml.Unmarshal(trimmed, &m); err != nil {
		return nil, &ManifestError{Reason: fmt.Sprintf("parse yaml manifest: %v", err)}
	}

	return &m, nil
}

// wireJSON marshals the manifest into the JSON body PUT to the identity service.
// The server deserializes it into its own DeclarationManifest (tags are aligned).
func (m *DeclarationManifest) wireJSON() ([]byte, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal wire manifest: %w", err)
	}

	return payload, nil
}

// CanonicalHash returns a stable hex-encoded SHA-256 over a deterministic
// serialization of the manifest, EXCLUDING Version. Two manifests that differ only
// in wire key ordering or in Version hash identically; any content difference
// changes the hash.
//
// It is a byte-for-byte mirror of the server's
// DeclarationManifest.CanonicalHash
// (plugin-access-manager/components/identity/pkg/model/declaration.go:277): the
// server stores this hex in the app's `declaration-hash` Tag and no-ops the PUT
// when it matches, so the two implementations MUST agree.
func (m *DeclarationManifest) CanonicalHash() (string, error) {
	payload, err := json.Marshal(canonicalManifest{
		Service:     m.Service,
		Permissions: m.Permissions,
		Roles:       m.Roles,
		M2M:         m.M2M,
	})
	if err != nil {
		return "", fmt.Errorf("marshal canonical manifest: %w", err)
	}

	sum := sha256.Sum256(payload)

	return hex.EncodeToString(sum[:]), nil
}

// Validate performs structural validation and the permission->role cross-reference
// checks, mirroring the server's Validate
// (plugin-access-manager/.../pkg/model/declaration.go:136). Running it eagerly at
// New surfaces a broken embedded manifest at boot instead of as a runtime 422.
// All violations are aggregated into a single *ManifestError.
func (m *DeclarationManifest) Validate() error {
	var violations []string

	if strings.TrimSpace(m.Service) == "" {
		violations = append(violations, "service must not be empty")
	}

	// A dot-segment service ("." or "..") survives url.PathEscape intact, so it would
	// form /v1/declarations/.. and a path-normalizing intermediary could redirect the
	// PUT to the wrong endpoint. New enforces slug==service, so guarding here covers both.
	if m.Service == "." || m.Service == ".." {
		violations = append(violations, fmt.Sprintf("service must not be a dot-segment %q", m.Service))
	}

	if m.Version < 1 {
		violations = append(violations, "version must be a positive integer")
	}

	declaredRoles, roleViolations := m.validateRoles()
	violations = append(violations, roleViolations...)
	violations = append(violations, m.validatePermissions(declaredRoles)...)

	if len(violations) == 0 {
		return nil
	}

	return &ManifestError{Reason: strings.Join(violations, "; ")}
}

// validateRoles validates each declared role and returns the set of declared role
// names plus any violations. It enforces a non-empty name, no duplicate composed
// name ("{service}/{name}"), and no two roles sharing the lossy Casdoor-safe
// derivation of that composed name (nor a derivation collapsing to empty) — mirroring
// the server so a manifest that passes here also passes the server's reconcile.
func (m *DeclarationManifest) validateRoles() (map[string]struct{}, []string) {
	var violations []string

	declaredRoles := make(map[string]struct{}, len(m.Roles))
	seenComposed := make(map[string]struct{}, len(m.Roles))
	seenKebab := make(map[string]string, len(m.Roles))

	for i, r := range m.Roles {
		if strings.TrimSpace(r.Name) == "" {
			violations = append(violations, fmt.Sprintf("roles[%d]: role name must not be empty", i))
			continue
		}

		declaredRoles[r.Name] = struct{}{}

		composed := m.Service + "/" + r.Name
		if _, dup := seenComposed[composed]; dup {
			violations = append(violations, fmt.Sprintf("roles[%d]: duplicate composed role name %q", i, composed))
			continue
		}

		seenComposed[composed] = struct{}{}

		switch kebab := casdoorSafeName(composed); kebab {
		case "":
			violations = append(violations, fmt.Sprintf("roles[%d]: role name %q derives an empty Casdoor-safe name", i, composed))
		default:
			if first, dup := seenKebab[kebab]; dup {
				violations = append(violations, fmt.Sprintf("roles[%d]: role names %q and %q derive the same Casdoor-safe name %q", i, first, composed, kebab))
			} else {
				seenKebab[kebab] = composed
			}
		}
	}

	return declaredRoles, violations
}

// validatePermissions validates each declared permission against declaredRoles and
// returns any violations. It enforces a non-empty resource and action, an
// allow/deny effect, at least one granted (declared) role, no duplicate composed
// name, and no lossy Casdoor-safe collision — mirroring the server.
func (m *DeclarationManifest) validatePermissions(declaredRoles map[string]struct{}) []string {
	var violations []string

	seenComposed := make(map[string]struct{}, len(m.Permissions))
	seenKebab := make(map[string]string, len(m.Permissions))

	for i, p := range m.Permissions {
		if strings.TrimSpace(p.Resource) == "" {
			violations = append(violations, fmt.Sprintf("permissions[%d]: resource must not be empty", i))
		}

		if strings.TrimSpace(p.Action) == "" {
			violations = append(violations, fmt.Sprintf("permissions[%d]: action must not be empty", i))
		} else if _, isHTTPVerb := httpVerbActions[strings.ToLower(strings.TrimSpace(p.Action))]; isHTTPVerb {
			violations = append(violations, fmt.Sprintf("permissions[%d]: action %q is an HTTP verb; declare a SEMANTIC action (create/read/update/delete or a domain verb) — only \"delete\" is an HTTP method that is also a valid semantic action", i, p.Action))
		}

		if p.Effect != effectAllow && p.Effect != effectDeny {
			violations = append(violations, fmt.Sprintf("permissions[%d]: effect must be %q or %q", i, effectAllow, effectDeny))
		}

		if len(p.Roles) == 0 {
			violations = append(violations, fmt.Sprintf("permissions[%d]: must grant to at least one role", i))
		}

		for _, roleRef := range p.Roles {
			if _, ok := declaredRoles[roleRef]; !ok {
				violations = append(violations, fmt.Sprintf("permissions[%d]: references undeclared role %q", i, roleRef))
			}
		}

		composed := m.Service + "/" + p.Resource + ":" + p.Action
		if _, dup := seenComposed[composed]; dup {
			violations = append(violations, fmt.Sprintf("permissions[%d]: duplicate composed permission name %q", i, composed))
			continue
		}

		seenComposed[composed] = struct{}{}

		switch kebab := casdoorSafeName(composed); kebab {
		case "":
			violations = append(violations, fmt.Sprintf("permissions[%d]: permission name %q derives an empty Casdoor-safe name", i, composed))
		default:
			if first, dup := seenKebab[kebab]; dup {
				violations = append(violations, fmt.Sprintf("permissions[%d]: permission names %q and %q derive the same Casdoor-safe name %q", i, first, composed, kebab))
			} else {
				seenKebab[kebab] = composed
			}
		}
	}

	return violations
}

// casdoorSafeName derives a deterministic, Casdoor-safe identity from the standard
// slash/colon notation. Every forbidden char (and any run of separators, including
// literal hyphens) collapses to a single "-"; leading/trailing separators are
// trimmed. It mirrors the server's CasdoorSafeName so client-side validation agrees
// with the server's create/lookup keying.
func casdoorSafeName(standard string) string {
	var b strings.Builder

	b.Grow(len(standard))

	prevHyphen := false

	for _, r := range standard {
		if r == '-' || isForbiddenNameChar(r) {
			if prevHyphen {
				continue
			}

			b.WriteByte('-')

			prevHyphen = true

			continue
		}

		b.WriteRune(r)

		prevHyphen = false
	}

	return strings.Trim(b.String(), "-")
}

// isForbiddenNameChar reports whether r is rejected by Casdoor in a role or
// permission name: the fixed forbidden set plus any Unicode whitespace.
func isForbiddenNameChar(r rune) bool {
	switch r {
	case '/', '?', ':', '#', '&', '%', '=', '+', ';':
		return true
	}

	return unicode.IsSpace(r)
}
