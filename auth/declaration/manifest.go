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

// effectAllow is the only accepted permission effect. It mirrors the server
// model (plugin-access-manager identity pkg/model).
//
// "deny" is deliberately NOT accepted. The manifest used to take it and the
// reconciler wrote it to Casdoor as a real permission, but no decision point
// applies it: every evaluator treats an effect other than allow as "did not
// match" and carries on, authorizing on the first allow that does match. There
// is no deny-wins pass, and Casdoor's own enforcer — which would honour it — is
// replaced by that implementation. Accepting a deny would therefore be a lie:
// the author reads a refusal, the runtime grants.
//
// Refusing it at the door is the mitigation, not the whole answer. Real
// deny-wins semantics across the evaluation points is separate work; until it
// exists, the safe state is that no deny can be authored at all.
const effectAllow = "allow"

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
	// Scope is the product's catalog of instance dimensions — the "where" a
	// partner credential can be narrowed to (an organization, a ledger). It is a
	// global, per-product catalog, published on its own switch (see
	// Config.ScopeOnly), and it is what the middleware derives a route's scope
	// from (see WireScope). Optional: a manifest without it behaves exactly as
	// before the section existed, on the wire and in the hash.
	Scope *DeclarationScope `json:"scope,omitempty" yaml:"scope,omitempty"`
	// Partners opts the product in to partner credentials: the access manager
	// grants a partner access only to products that declare it. It is published
	// with the full manifest and with the scope alone (see Config.ScopeOnly), and
	// hashed as the LAST member; false is omitted, so a manifest that does not
	// opt in publishes the same bytes and hash as before the field existed.
	Partners bool `json:"partners,omitempty" yaml:"partners,omitempty"`
}

// The places a request carries a dimension's value. A catalog dimension is read
// from the path, the query or a header; a scope.routes dimension from the JSON
// body, a urlencoded form body, the query or a header.
const (
	scopeFromPath   = "path"
	scopeFromQuery  = "query"
	scopeFromHeader = "header"
	scopeFromBody   = "body"
	scopeFromForm   = "form"
)

// DeclarationScope is the product's catalog of scope dimensions.
type DeclarationScope struct {
	// Dimensions are listed in tree order: the first is the top of the funnel
	// (an organization), each next one narrows the previous (a ledger inside
	// it). The order is content — it is hashed and it is the order a route's
	// identifiers are resolved in.
	Dimensions []DeclarationDimension `json:"dimensions,omitempty" yaml:"dimensions,omitempty"`
	// Routes declares, per route, the catalog dimensions that route reads from
	// its JSON request body instead of its path. They are this library's to
	// read: the identity service never receives them, and they are left out of
	// the wire body and of CanonicalHash (see serverProjection), so declaring
	// them changes nothing that is published.
	Routes []DeclarationScopeRoute `json:"routes,omitempty" yaml:"routes,omitempty"`
}

// DeclarationScopeRoute names one route and the dimensions it reads from its
// request body.
type DeclarationScopeRoute struct {
	// Method is the route's HTTP method, in any letter case.
	Method string `json:"method,omitempty" yaml:"method,omitempty"`
	// Path is the route's full path exactly as it is registered, group prefixes
	// included, with its ':' parameters (e.g. "/v2/transactions/direct").
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
	// Dimensions are the catalog dimensions the route reads from somewhere other
	// than its path. The dimensions its path carries are still derived from the
	// path; one read from both must name the same values in each.
	Dimensions []DeclarationRouteDimension `json:"dimensions,omitempty" yaml:"dimensions,omitempty"`
	// Filter names catalog dimensions the route filters its list on: when a
	// partner request leaves one out, the authorization service is asked for
	// the values of it the partner may see instead of refusing, and the handler
	// confines its list to them (see middleware.RequestScope.Allowed).
	Filter []string `json:"filter,omitempty" yaml:"filter,omitempty"`
}

// DeclarationRouteDimension declares where in a route's request ONE catalog
// dimension is read.
type DeclarationRouteDimension struct {
	// Name is a dimension of the catalog (scope.dimensions[].name).
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// From is where the request carries the value: "body", "form", "query" or
	// "header". A route reads its body either as JSON (body) or as an
	// application/x-www-form-urlencoded form (form), never both.
	From string `json:"from,omitempty" yaml:"from,omitempty"`
	// Field is where under From the value is. For "body", its path in the JSON
	// body: object keys separated by '.', a key followed by "[]" being an array
	// whose every element is read ("id", "items[].id"), and a path ending in "[]"
	// an array of strings, every string one value ("target.ids[]"); see
	// middleware.FromBody.
	// For "form", the form field name; for "query", the parameter name; for
	// "header", the header name, in any letter case. A form field, query
	// parameter or header may list several values; see middleware.FromQuery and
	// middleware.FromForm.
	Field string `json:"field,omitempty" yaml:"field,omitempty"`
	// Optional means a request may leave the value out: when the request does
	// not carry it (a body key on its path absent or null, a form field, query
	// parameter or header absent) the question is asked without the dimension.
	// A value that is there must still be a non-empty string. See
	// middleware.Dimension.Optional.
	Optional bool `json:"optional,omitempty" yaml:"optional,omitempty"`
	// Resolve optionally names the resolver (middleware.AuthClient.
	// RegisterScopeResolver) that translates the value read at Field into the
	// dimension's values: an account alias into the account id, a transaction
	// id into the account ids of its legs. With it, From may also be "path",
	// Field then naming a parameter of the route path.
	Resolve string `json:"resolve,omitempty" yaml:"resolve,omitempty"`
	// Match optionally says, for a dimension that declares Resolve, how the
	// values one request value resolves to are judged: "all" (the default)
	// allows the request only when every one is allowed, "any" when at least
	// one is. See middleware.Dimension.MatchAny. Read by this library only, like
	// the rest of scope.routes.
	Match string `json:"match,omitempty" yaml:"match,omitempty"`
}

// DeclarationDimension declares ONE instance dimension of the product.
type DeclarationDimension struct {
	// Name is the attribute key the authorization service knows the dimension
	// by (e.g. "organizationId"). Unique within the scope.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// From is where a request carries the value: "path", "query" or "header".
	// A path dimension applies to the routes whose path carries its parameter;
	// a query or header dimension to every route of the product, on the
	// requests that carry it.
	From string `json:"from,omitempty" yaml:"from,omitempty"`
	// Param names the value under From: the route path parameter without the
	// ':' marker (e.g. "organization_id" for a route segment
	// ":organization_id"), the query parameter, or the header name. Unique
	// within the scope for its From, header names compared without regard to
	// letter case.
	Param string `json:"param,omitempty" yaml:"param,omitempty"`
	// Required means every partner scope line for this product must name a
	// value for the dimension.
	Required bool `json:"required,omitempty" yaml:"required,omitempty"`
	// Multi means a partner scope line may name several values for it.
	Multi bool `json:"multi,omitempty" yaml:"multi,omitempty"`
	// Collection names the product collection the values are identifiers of
	// (e.g. "organizations"). Required.
	Collection string `json:"collection,omitempty" yaml:"collection,omitempty"`
	// Covers optionally names OTHER product collections whose items belong to
	// the dimension's instances (e.g. an accountId dimension, whose collection is
	// "accounts", covering "balances" and "operations"). A partner scoped on the
	// dimension is confined on a request that does not name it when the request's
	// resource is the dimension's own collection; Covers extends that confinement
	// to the listed collections. The authorization service enforces it; this
	// library declares, validates and publishes it. Entries are non-empty, unique
	// and distinct from Collection, all compared case-insensitively. The order is
	// content: it is hashed like the dimensions' order.
	Covers []string `json:"covers,omitempty" yaml:"covers,omitempty"`
	// Label is an optional human-readable name for consoles.
	Label string `json:"label,omitempty" yaml:"label,omitempty"`
	// Resolve optionally names the resolver (middleware.AuthClient.
	// RegisterScopeResolver) that translates the value read at Param into the
	// dimension's values. It is read by this library only: it is never
	// published and is not part of CanonicalHash.
	Resolve string `json:"resolve,omitempty" yaml:"resolve,omitempty"`
	// Match optionally says, for a dimension that declares Resolve, how the
	// values one request value resolves to are judged: "all" (the default)
	// allows the request only when every one is allowed, "any" when at least
	// one is. See middleware.Dimension.MatchAny. Like Resolve, it is read by
	// this library only: never published and not part of CanonicalHash.
	Match string `json:"match,omitempty" yaml:"match,omitempty"`
	// Parent optionally names the dimension whose instances hold this one's
	// (e.g. a ledgerId dimension's parent is "organizationId"), declaring the
	// hierarchy of the catalog. It names another declared dimension, and
	// following parents never comes back to a dimension. A dimension without
	// one is a root. It is the LAST member and omitted when absent, so a manifest
	// that declares none publishes and hashes byte-for-byte as before.
	Parent string `json:"parent,omitempty" yaml:"parent,omitempty"`
}

// DeclarationPermission is a single declared permission. The action is a free-form
// string that must be non-empty; the SEMANTIC action naming standard (prefer domain
// intent over transport verbs) is documented guidance, not enforced here. The resource
// is written bare; the central reconciler composes the `{service}/` prefix.
type DeclarationPermission struct {
	Resource string   `json:"resource,omitempty" yaml:"resource,omitempty"`
	Action   string   `json:"action,omitempty" yaml:"action,omitempty"`
	Effect   string   `json:"effect,omitempty" yaml:"effect,omitempty"`
	Roles    []string `json:"roles,omitempty" yaml:"roles,omitempty"`
	// Level optionally names how wide one instance of the resource is: "tenant"
	// (the resource spans the whole tenant), "organization", "ledger", or the
	// name of a scope dimension (scope.dimensions[].name) whose instances hold it.
	// The access manager uses it to refuse granting a partner a write on a
	// resource wider than the partner's narrowest scope. It is published and
	// hashed; it is the LAST member of a permission, and omitted when empty, so a
	// manifest that declares no level publishes the same bytes as before.
	Level string `json:"level,omitempty" yaml:"level,omitempty"`
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
	// Scope is appended LAST and omitted when absent, so a manifest without a
	// scope serializes — and hashes — byte-for-byte as it did before the section
	// existed.
	Scope *DeclarationScope `json:"scope,omitempty"`
	// Partners is appended after Scope and omitted when false, for the same
	// reason.
	Partners bool `json:"partners,omitempty"`
	// Levels is appended after Partners. Only the scope-only publication sets
	// it (see scopeOnlyManifest); the full manifest carries each level inside
	// its permission, so this member is omitted there and its hash is unchanged.
	Levels []DeclarationLevel `json:"levels,omitempty"`
}

// DeclarationLevel is the level a permission declares, without its roles and
// effect. The scope-only publication carries one per permission that declares a
// level, so the authorization service knows how wide each resource is when the
// permission declaration itself is not published.
type DeclarationLevel struct {
	Resource string `json:"resource,omitempty"`
	Action   string `json:"action,omitempty"`
	Level    string `json:"level,omitempty"`
}

// scopeOnlyManifest is the body a scope-only publication sends: the service and
// version that identify it, the scope, the partner opt-in, and the permissions'
// levels. Every other section is left out, so the receiver replaces nothing but
// those. Levels is the LAST member and omitted when no permission declares a
// level, so such a manifest publishes the same bytes and hash as before it
// existed.
type scopeOnlyManifest struct {
	Service  string             `json:"service,omitempty"`
	Version  int                `json:"version,omitempty"`
	Scope    *DeclarationScope  `json:"scope,omitempty"`
	Partners bool               `json:"partners,omitempty"`
	Levels   []DeclarationLevel `json:"levels,omitempty"`
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
	payload, err := json.Marshal(m.serverProjection())
	if err != nil {
		return nil, fmt.Errorf("marshal wire manifest: %w", err)
	}

	return payload, nil
}

// scopeOnly is the projection a scope-only publication sends (see
// scopeOnlyManifest). The scope is the server projection's: scope.routes and the
// dimensions' resolve stay with this library.
func (m *DeclarationManifest) scopeOnly() *scopeOnlyManifest {
	published := (&DeclarationManifest{Service: m.Service, Scope: m.Scope}).serverProjection()

	var levels []DeclarationLevel

	for _, p := range m.Permissions {
		if p.Level != "" {
			levels = append(levels, DeclarationLevel{Resource: p.Resource, Action: p.Action, Level: p.Level})
		}
	}

	return &scopeOnlyManifest{
		Service:  m.Service,
		Version:  m.Version,
		Scope:    published.Scope,
		Partners: m.Partners,
		Levels:   levels,
	}
}

// wireJSON marshals the scope-only body PUT to the identity service.
func (s *scopeOnlyManifest) wireJSON() ([]byte, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal scope-only manifest: %w", err)
	}

	return payload, nil
}

// CanonicalHash hashes the scope-only body the way DeclarationManifest.
// CanonicalHash hashes the full one: the same canonical member order, the
// version left out, and the levels as the LAST member.
func (s *scopeOnlyManifest) CanonicalHash() (string, error) {
	return hashCanonical(canonicalManifest{
		Service:  s.Service,
		Scope:    s.Scope,
		Partners: s.Partners,
		Levels:   s.Levels,
	})
}

// hasScopeCatalog reports whether a scope-only publication has anything to
// send: a scope section, or the partner opt-in.
func (m *DeclarationManifest) hasScopeCatalog() bool {
	return m.Scope != nil || m.Partners
}

// serverProjection is the manifest the identity service knows: everything but
// scope.routes and the dimensions' resolve and match, which only this library
// reads. Both
// the wire body and CanonicalHash are taken from it, so neither ever changes
// what is published nor the hash the service compares. The receiver is not
// modified.
func (m *DeclarationManifest) serverProjection() *DeclarationManifest {
	if m.Scope == nil || (len(m.Scope.Routes) == 0 && !m.Scope.resolves()) {
		return m
	}

	dims := m.Scope.Dimensions
	if m.Scope.resolves() {
		dims = make([]DeclarationDimension, len(m.Scope.Dimensions))
		for i, d := range m.Scope.Dimensions {
			d.Resolve = ""
			d.Match = ""
			dims[i] = d
		}
	}

	projected := *m
	projected.Scope = &DeclarationScope{Dimensions: dims}

	return &projected
}

// resolves reports whether a catalog dimension names a resolver or how its
// resolved values match.
func (s *DeclarationScope) resolves() bool {
	for _, d := range s.Dimensions {
		if d.Resolve != "" || d.Match != "" {
			return true
		}
	}

	return false
}

// resolveProblem describes what is wrong with resolve as a resolver name, or
// returns "" when it is absent or valid.
func resolveProblem(prefix, resolve string) string {
	if resolve == "" || (strings.TrimSpace(resolve) == resolve) {
		return ""
	}

	return fmt.Sprintf("%s: resolve %q must be a resolver name with no surrounding whitespace", prefix, resolve)
}

// matchAny is the match that allows a resolved request value when any of its
// values is allowed; matchAll, the default, when every one is.
const (
	matchAll = "all"
	matchAny = "any"
)

// matchProblem describes what is wrong with match on a dimension resolved by
// resolve, or returns "" when it is absent or valid.
func matchProblem(prefix, match, resolve string) string {
	switch {
	case match == "":
		return ""
	case match != matchAll && match != matchAny:
		return fmt.Sprintf(`%s: match must be "all" or "any", got %q`, prefix, match)
	case resolve == "":
		return prefix + ": match requires resolve"
	default:
		return ""
	}
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
//
// A dimension's Covers is hashed with the rest of the scope. The publisher skips
// a PUT whose hash it already published, so a field left out of the hash would
// make a covers-only change never reach the service; and because Covers is
// omitempty, a manifest that declares none serializes to the same bytes, and
// hashes to the same value, as before the field existed. A dimension's Parent
// is hashed the same way, as the dimension's last member.
func (m *DeclarationManifest) CanonicalHash() (string, error) {
	published := m.serverProjection()

	return hashCanonical(canonicalManifest{
		Service:     published.Service,
		Permissions: published.Permissions,
		Roles:       published.Roles,
		M2M:         published.M2M,
		Scope:       published.Scope,
		Partners:    published.Partners,
	})
}

// hashCanonical returns the hex-encoded SHA-256 of the canonical serialization.
func hashCanonical(c canonicalManifest) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal canonical manifest: %w", err)
	}

	sum := sha256.Sum256(payload)

	return hex.EncodeToString(sum[:]), nil
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
