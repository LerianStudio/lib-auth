package declaration

import (
	"fmt"
	"strings"
	"unicode"
)

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
	violations = append(violations, m.validateScope()...)
	violations = append(violations, m.validateLevels()...)

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
// allow effect, at least one granted (declared) role, no duplicate composed
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
		}

		if p.Effect != effectAllow {
			violations = append(violations, fmt.Sprintf(
				"permissions[%d]: effect must be %q (a deny effect is recorded but never enforced, so it is not accepted)", i, effectAllow))
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

// Resource levels a permission may name besides a scope dimension.
const (
	levelTenant       = "tenant"
	levelOrganization = "organization"
	levelLedger       = "ledger"
)

// validateLevels checks every permission's level is a level keyword or the
// name of a scope dimension, spelled exactly: the access manager compares it
// as written, so a near miss would be a level nobody recognizes.
func (m *DeclarationManifest) validateLevels() []string {
	var violations []string

	for i, p := range m.Permissions {
		switch p.Level {
		case "", levelTenant, levelOrganization, levelLedger:
			continue
		}

		if m.hasDimension(p.Level) {
			continue
		}

		violations = append(violations, fmt.Sprintf(
			`permissions[%d]: level %q must be %q, %q, %q or a scope dimension name`,
			i, p.Level, levelTenant, levelOrganization, levelLedger))
	}

	return violations
}

// hasDimension reports whether the scope catalog declares a dimension named name.
func (m *DeclarationManifest) hasDimension(name string) bool {
	if m.Scope == nil {
		return false
	}

	for _, d := range m.Scope.Dimensions {
		if d.Name == name {
			return true
		}
	}

	return false
}

// validateScope validates the scope catalog: every dimension names itself, reads
// from the path, the query or a header, names a valid parameter there and the
// collection, and no two dimensions share a name or the same parameter of the
// same carrier; a dimension's covers are checked by validateCovers. A shared
// name would make two dimensions one attribute; a shared parameter would make
// one value answer for two dimensions. An absent scope, or one with no
// dimensions, is valid.
func (m *DeclarationManifest) validateScope() []string {
	if m.Scope == nil {
		return nil
	}

	var violations []string

	seenNames := make(map[string]struct{}, len(m.Scope.Dimensions))
	seenParams := make(map[string]struct{}, len(m.Scope.Dimensions))

	for i, d := range m.Scope.Dimensions {
		prefix := fmt.Sprintf("scope.dimensions[%d]", i)

		if strings.TrimSpace(d.Name) == "" {
			violations = append(violations, prefix+": name must not be empty")
		} else if _, dup := seenNames[d.Name]; dup {
			violations = append(violations, fmt.Sprintf("%s: duplicate name %q", prefix, d.Name))
		} else {
			seenNames[d.Name] = struct{}{}
		}

		if _, ok := catalogDimensionSources[d.From]; !ok {
			violations = append(violations, fmt.Sprintf(`%s: from must be one of "path", "query", "header", got %q`, prefix, d.From))
		}

		switch problem := requestKeyProblem(d.From, d.Param); {
		case strings.TrimSpace(d.Param) == "":
			violations = append(violations, prefix+": param must not be empty")
		case problem != "":
			violations = append(violations, fmt.Sprintf("%s: param %q %s", prefix, d.Param, problem))
		default:
			key := carrierKey(d.From, d.Param)
			if _, dup := seenParams[key]; dup {
				violations = append(violations, fmt.Sprintf("%s: duplicate param %q", prefix, d.Param))
			} else {
				seenParams[key] = struct{}{}
			}
		}

		if strings.TrimSpace(d.Collection) == "" {
			violations = append(violations, prefix+": collection must not be empty")
		}

		violations = append(violations, validateCovers(prefix, d)...)
	}

	violations = append(violations, m.validateParents(seenNames)...)

	return append(violations, m.validateScopeRoutes(seenNames)...)
}

// validateParents validates the dimensions' parents: each names a declared
// dimension other than itself, and following parents from any dimension ends at
// a root. A cycle is reported once, at its first dimension in catalog order.
func (m *DeclarationManifest) validateParents(declared map[string]struct{}) []string {
	var violations []string

	parents := make(map[string]string, len(m.Scope.Dimensions))
	for _, d := range m.Scope.Dimensions {
		if _, seen := parents[d.Name]; !seen {
			parents[d.Name] = d.Parent
		}
	}

	inCycle := make(map[string]struct{})

	for i, d := range m.Scope.Dimensions {
		if d.Parent == "" {
			continue
		}

		prefix := fmt.Sprintf("scope.dimensions[%d]", i)

		if d.Parent == d.Name {
			violations = append(violations, fmt.Sprintf("%s: parent %q must not be the dimension itself", prefix, d.Parent))

			continue
		}

		if _, ok := declared[d.Parent]; !ok {
			violations = append(violations, fmt.Sprintf("%s: parent %q is not a declared dimension", prefix, d.Parent))

			continue
		}

		if _, reported := inCycle[d.Name]; reported {
			continue
		}

		if path := parentCycle(d.Name, parents); path != nil {
			for _, name := range path {
				inCycle[name] = struct{}{}
			}

			violations = append(violations, fmt.Sprintf("%s: parent %q makes a cycle: %s", prefix, d.Parent, strings.Join(path, " -> ")))
		}
	}

	return violations
}

// parentCycle follows parents from name and returns the path back to name when
// it comes back to it, or nil when it ends at a root, an undeclared parent, or
// a cycle name is not part of.
func parentCycle(name string, parents map[string]string) []string {
	path := []string{name}
	visited := map[string]struct{}{name: {}}

	for current := parents[name]; current != ""; current = parents[current] {
		path = append(path, current)

		if current == name {
			return path
		}

		if _, again := visited[current]; again {
			return nil
		}

		visited[current] = struct{}{}
	}

	return nil
}

// validateCovers validates one dimension's covers: every entry names a
// collection, none repeats another, and none repeats the dimension's own
// collection. Collections are compared trimmed and case-insensitively, as the
// authorization service compares them, so two spellings of one collection are
// one collection.
func validateCovers(prefix string, d DeclarationDimension) []string {
	var violations []string

	own := strings.TrimSpace(d.Collection)
	seen := make(map[string]struct{}, len(d.Covers))

	for j, c := range d.Covers {
		entry := fmt.Sprintf("%s.covers[%d]", prefix, j)
		trimmed := strings.TrimSpace(c)
		key := strings.ToLower(trimmed)

		switch {
		case trimmed == "":
			violations = append(violations, entry+": must not be empty")
		case strings.EqualFold(trimmed, own):
			violations = append(violations, fmt.Sprintf("%s: must not repeat the dimension's own collection %q", entry, own))
		default:
			if _, dup := seen[key]; dup {
				violations = append(violations, fmt.Sprintf("%s: duplicate collection %q", entry, trimmed))
			} else {
				seen[key] = struct{}{}
			}
		}
	}

	return violations
}

// validateScopeRoutes validates scope.routes against the catalog: every route
// names its method and an absolute path, appears once, and declares at least one
// dimension, reading its body at most one way; every dimension names a catalog
// dimension, reads from the body, a form, the query, a header or the path, and
// names its field there. Whether the fields fit together on the route — a
// well-formed body path, a path parameter the route carries, every dimension
// read for each array element, no field read twice — is checked by the
// middleware when the route is wired.
func (m *DeclarationManifest) validateScopeRoutes(catalog map[string]struct{}) []string {
	var violations []string

	seenRoutes := make(map[string]struct{}, len(m.Scope.Routes))

	for i, r := range m.Scope.Routes {
		prefix := fmt.Sprintf("scope.routes[%d]", i)
		method := strings.ToUpper(strings.TrimSpace(r.Method))

		if method == "" {
			violations = append(violations, prefix+": method must not be empty")
		}

		if !strings.HasPrefix(r.Path, "/") {
			violations = append(violations, fmt.Sprintf("%s: path %q must start with '/'", prefix, r.Path))
		}

		key := method + " " + r.Path
		if _, dup := seenRoutes[key]; dup {
			violations = append(violations, fmt.Sprintf("%s: duplicate route %q", prefix, key))
		}

		seenRoutes[key] = struct{}{}

		if len(r.Dimensions) == 0 {
			violations = append(violations, prefix+": must declare at least one dimension")
		}

		bodyAs := make(map[string]struct{}, len(r.Dimensions))

		for j, d := range r.Dimensions {
			violations = append(violations, validateRouteDimension(fmt.Sprintf("%s.dimensions[%d]", prefix, j), d, catalog)...)
			bodyAs[d.From] = struct{}{}
		}

		_, readsJSON := bodyAs[scopeFromBody]
		_, readsForm := bodyAs[scopeFromForm]

		if readsJSON && readsForm {
			violations = append(violations, prefix+": reads the request body both as JSON (from: body) and as a form (from: form)")
		}
	}

	return violations
}

// validateRouteDimension validates one dimension of a scope.routes entry: it
// names a catalog dimension, reads from a known carrier, and names its field
// there.
func validateRouteDimension(prefix string, d DeclarationRouteDimension, catalog map[string]struct{}) []string {
	var violations []string

	if strings.TrimSpace(d.Name) == "" {
		violations = append(violations, prefix+": name must not be empty")
	} else if _, ok := catalog[d.Name]; !ok {
		violations = append(violations, fmt.Sprintf("%s: %q is not a scope dimension of the catalog", prefix, d.Name))
	}

	if _, known := routeDimensionSources[d.From]; !known {
		violations = append(violations, fmt.Sprintf(
			`%s: from must be one of "body", "form", "query", "header", "path", got %q`, prefix, d.From))
	}

	switch problem := requestKeyProblem(d.From, d.Field); {
	case strings.TrimSpace(d.Field) == "":
		violations = append(violations, prefix+": field must not be empty")
	case problem != "":
		violations = append(violations, fmt.Sprintf("%s: field %q %s", prefix, d.Field, problem))
	}

	return violations
}

// requestKeyProblem describes what is wrong with key as the name of a value
// carried in from, or returns "" when it is a valid name there — or when from is
// not a carrier this check knows, which the caller reports on its own. A body
// field's path is checked by the middleware when the route is wired.
func requestKeyProblem(from, key string) string {
	switch from {
	case scopeFromPath:
		if !isPathParamName(key) {
			return "must be a bare path parameter name (no ':' marker, '/', or whitespace)"
		}
	case scopeFromQuery, scopeFromForm:
		if strings.ContainsAny(key, "&=#?+%;") || strings.IndexFunc(key, unicode.IsSpace) >= 0 {
			kind := "query parameter"
			if from == scopeFromForm {
				kind = "form field"
			}

			return "must be a " + kind + " name (no whitespace, '&', '=', '#', '?', '+', '%' or ';')"
		}
	case scopeFromHeader:
		if !isHeaderName(key) {
			return "must be a header name (letters, digits and !#$%&'*+-.^_`|~ only)"
		}
	}

	return ""
}

// carrierKey identifies the place a value is carried: header names are one
// place in any letter case.
func carrierKey(from, key string) string {
	if from == scopeFromHeader {
		key = strings.ToLower(key)
	}

	return from + ":" + key
}

// isHeaderName reports whether h is an HTTP field name: a non-empty token.
func isHeaderName(h string) bool {
	if h == "" {
		return false
	}

	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}

	return true
}

// isPathParamName reports whether p can be a route parameter name as written
// after the ':' marker of a path segment: no marker of its own, no segment
// separator, no whitespace.
func isPathParamName(p string) bool {
	for _, r := range p {
		if r == ':' || r == '/' || unicode.IsSpace(r) {
			return false
		}
	}

	return true
}
