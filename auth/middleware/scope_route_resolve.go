package middleware

import (
	"strings"
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
)

// A handler mounted with Use — on the app, on a group, or inside a mounted
// sub-app — does not see the route a request is for: Fiber reports the mount
// prefix as its route, with the request's method, and reads no path parameter
// past the prefix. The scope of such a request is resolved here instead, by
// matching the request's method and path against the routes the app registers
// and the routes the product's manifest declares, so a product authorizing in
// prefix middleware needs no code of its own.

// segmentKind orders the kinds of template segment from the least specific to
// the most: a request segment a literal matches is more precisely described by
// it than by a parameter, and so on.
type segmentKind int

const (
	segmentWildcard segmentKind = iota
	segmentOptional
	segmentParam
	segmentLiteral
)

// templateSegment is one '/'-separated segment of a route template.
type templateSegment struct {
	kind segmentKind
	// text is the literal, or the parameter's name.
	text string
	// nonEmpty is set on a '+' wildcard, which must match at least one segment.
	nonEmpty bool
}

// routingRules are the app settings that decide which route a path reaches,
// read from its fiber.Config so a request resolves where Fiber routes it. The
// zero value is Fiber's default.
type routingRules struct {
	// caseSensitive compares literals with letter case (fiber.Config.CaseSensitive).
	caseSensitive bool
	// strict makes a trailing slash significant (fiber.Config.StrictRouting).
	strict bool
}

// strictestRouting are the rules under which the fewest paths are one route:
// two routes that are one under them are one under any app's routing.
var strictestRouting = routingRules{caseSensitive: true, strict: true}

// routeTemplate is one route, method and path as registered, parsed for
// matching under an app's routing rules.
type routeTemplate struct {
	method   string
	path     string
	rules    routingRules
	segments []templateSegment
}

// parseRouteTemplate parses a registered route path. It returns false for a
// path whose syntax it does not read (several parameters in one segment, an
// optional parameter or a wildcard anywhere but last): such a route is never
// a candidate, and a request only it would serve resolves to no route.
func parseRouteTemplate(method, path string, rules routingRules) (routeTemplate, bool) {
	route := routeTemplate{method: method, path: path, rules: rules}
	parts := pathSegments(path, rules)

	for i, part := range parts {
		segment, ok := parseTemplateSegment(part)
		if !ok {
			return routeTemplate{}, false
		}

		if segment.kind < segmentParam && i != len(parts)-1 {
			return routeTemplate{}, false
		}

		route.segments = append(route.segments, segment)
	}

	return route, true
}

// parseTemplateSegment reads one segment in Fiber syntax: ":name", ":name?",
// ":name<constraint>", "*" or "+", or a literal free of route syntax.
func parseTemplateSegment(part string) (templateSegment, bool) {
	switch {
	case part == "*":
		return templateSegment{kind: segmentWildcard}, true
	case part == "+":
		return templateSegment{kind: segmentWildcard, nonEmpty: true}, true
	case strings.HasPrefix(part, ":"):
		name, kind := part[1:], segmentParam

		if trimmed, optional := strings.CutSuffix(name, "?"); optional {
			name, kind = trimmed, segmentOptional
		}

		if open := strings.IndexByte(name, '<'); open > 0 && strings.HasSuffix(name, ">") {
			name = name[:open]
		}

		if name == "" || strings.ContainsAny(name, ":*+?<>.-") {
			return templateSegment{}, false
		}

		return templateSegment{kind: kind, text: name}, true
	case strings.ContainsAny(part, ":*+?<>"):
		return templateSegment{}, false
	default:
		return templateSegment{kind: segmentLiteral, text: part}, true
	}
}

// pathSegments splits a path into its segments. Unless the routing is strict,
// trailing slashes are ignored, as Fiber ignores them.
func pathSegments(path string, rules routingRules) []string {
	if !rules.strict && len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}

	return strings.Split(path, "/")[1:]
}

// match reads the path parameters of a request, split by pathSegments, the
// template describes, or returns false. Literals and trailing slashes are
// compared as the app's routing compares them (routingRules). Nothing is allocated for a
// template that does not match, which is almost every candidate. On a match
// the map is never nil, even when the template has no parameter: a nil map
// reads parameters from Fiber, which has none past the mount prefix.
func (r *routeTemplate) match(parts []string) (map[string]string, bool) {
	if !r.fitsLength(len(parts)) || !r.fits(parts) {
		return nil, false
	}

	params := make(map[string]string, len(r.segments))

	for i, segment := range r.segments {
		if i < len(parts) && (segment.kind == segmentParam || segment.kind == segmentOptional) {
			params[segment.text] = parts[i]
		}
	}

	return params, true
}

// fits reports whether the request segments fit the template's, given a
// length fitsLength accepted.
func (r *routeTemplate) fits(parts []string) bool {
	for i, segment := range r.segments {
		switch {
		case segment.kind == segmentWildcard:
			return !segment.nonEmpty || hasNonEmpty(parts[min(i, len(parts)):])
		case segment.kind == segmentOptional && i == len(parts):
			return true
		case !segment.matches(parts[i], r.rules):
			return false
		}
	}

	return true
}

// hasNonEmpty reports whether any of the segments is not empty.
func hasNonEmpty(parts []string) bool {
	for _, part := range parts {
		if part != "" {
			return true
		}
	}

	return false
}

// fitsLength reports whether a request of n segments can match the template,
// checked before anything is allocated: most candidates fail here.
func (r *routeTemplate) fitsLength(n int) bool {
	// A path always has at least one segment ("/" is one empty segment).
	count := len(r.segments)

	switch r.segments[count-1].kind {
	case segmentWildcard:
		return n >= count-1
	case segmentOptional:
		return n == count || n == count-1
	case segmentParam, segmentLiteral:
		return n == count
	default:
		return n == count
	}
}

// matches reports whether one request segment fits the template segment: a
// literal when it is the same text — without regard to letter case unless the
// routing is case-sensitive — and a parameter when it is not empty.
func (s templateSegment) matches(part string, rules routingRules) bool {
	if s.kind == segmentLiteral && rules.caseSensitive {
		return s.text == part
	}

	if s.kind == segmentLiteral {
		return strings.EqualFold(s.text, part)
	}

	return part != ""
}

// compareSpecificity orders two templates matching the same request: positive
// when a describes it more precisely than b, negative when b does, and zero
// when neither does. Segments are compared from the left, the first that
// differs in kind deciding; a template that ends first, all before equal, is
// the more precise.
func compareSpecificity(a, b routeTemplate) int {
	for i := 0; i < len(a.segments) && i < len(b.segments); i++ {
		if diff := int(a.segments[i].kind) - int(b.segments[i].kind); diff != 0 {
			return diff
		}
	}

	return len(b.segments) - len(a.segments)
}

// sameShape reports whether two templates match exactly the same requests and
// read the same parameters at the same places under possibly other names —
// which makes them two names for one route.
func sameShape(a, b routeTemplate) bool {
	if len(a.segments) != len(b.segments) {
		return false
	}

	for i, sa := range a.segments {
		sb := b.segments[i]
		if sa.kind != sb.kind || sa.nonEmpty != sb.nonEmpty {
			return false
		}

		if sa.kind == segmentLiteral && !sa.matches(sb.text, a.rules) {
			return false
		}
	}

	return true
}

// resolvedRoute is the route a request was resolved to, with its parameters.
type resolvedRoute struct {
	method string
	path   string
	params map[string]string
}

// routeTable is the candidate routes of one app and product, compiled once per
// change of either.
type routeTable struct {
	app        *fiber.App
	handlers   uint32
	generation uint64
	rules      routingRules
	routes     []routeTemplate
}

// resolve returns the most specific candidate route describing the request,
// or a description of why none does: no candidate matches, or two equally
// specific ones under different paths do and the request cannot be read on
// either without guessing.
func (t *routeTable) resolve(method, path string) (resolvedRoute, string) {
	var (
		best      *routeTemplate
		bestParam map[string]string
		tied      *routeTemplate
	)

	parts := pathSegments(path, t.rules)

	for i := range t.routes {
		route := &t.routes[i]
		if route.method != method {
			continue
		}

		params, ok := route.match(parts)
		if !ok {
			continue
		}

		if best == nil {
			best, bestParam = route, params

			continue
		}

		switch order := compareSpecificity(*route, *best); {
		case order > 0:
			best, bestParam, tied = route, params, nil
		case order == 0 && route.path != best.path:
			tied = route
		}
	}

	switch {
	case best == nil:
		return resolvedRoute{}, "no registered or declared route serves " + method + " " + path
	case tied != nil:
		return resolvedRoute{}, method + " " + path + " is served equally by " + best.path + " and " + tied.path
	}

	return resolvedRoute{method: best.method, path: best.path, params: bestParam}, ""
}

// buildRouteTable compiles the app's routes — every route it registers, Use
// mounts aside — and the routes the product's manifest declares, each once.
func buildRouteTable(app *fiber.App, generation uint64, declared []string) *routeTable {
	config := app.Config()
	table := &routeTable{
		app:        app,
		handlers:   app.HandlersCount(),
		generation: generation,
		rules:      routingRules{caseSensitive: config.CaseSensitive, strict: config.StrictRouting},
	}
	seen := make(map[string]struct{})

	add := func(method, path string) {
		key := routeScopeKey(method, path)
		if _, dup := seen[key]; dup {
			return
		}

		seen[key] = struct{}{}

		if route, ok := parseRouteTemplate(method, path, table.rules); ok {
			table.routes = append(table.routes, route)
		}
	}

	for _, route := range app.GetRoutes(true) {
		add(route.Method, route.Path)
	}

	for _, key := range declared {
		method, path, _ := strings.Cut(key, " ")
		add(method, path)
	}

	return table
}

// routeTableCache holds the last table a routeScope compiled.
type routeTableCache struct {
	current atomic.Pointer[routeTable]
}

// servedByPrefix reports whether the route Fiber matched is a mount prefix of
// the request path rather than the request's own route: a Use mount reports
// its prefix, which has fewer segments than the request. A route with a
// wildcard or an optional parameter can match a longer path on its own and is
// never taken for a prefix.
func servedByPrefix(routePath, requestPath string) bool {
	if strings.ContainsAny(routePath, "*+?") {
		return false
	}

	return segmentCount(routePath) < segmentCount(requestPath)
}

// segmentCount counts the non-empty '/'-separated segments of a path, without
// allocating: it runs on every request a mounted handler sees.
func segmentCount(path string) int {
	count := 0

	for i := 0; i < len(path); i++ {
		if path[i] != '/' && (i == 0 || path[i-1] == '/') {
			count++
		}
	}

	return count
}

// scopeFor returns the scope of the route Fiber names for the request in
// flight, and a non-empty description of what is wrong when the route cannot
// be honoured. A request seen through a mount prefix is marked to be read on
// the route that serves it; that route is resolved only when a scope is read
// (readOnServingRoute), so a request no scope is read for — any caller that is
// not partner-bound — costs no more than on its own route.
func (r *routeScope) scopeFor(c fiber.Ctx) (ScopeDeclaration, string) {
	route := c.Route()

	scope, problem := r.forRoute(route.Method, route.Path)
	if problem == "" && servedByPrefix(route.Path, c.Path()) {
		scope.mounted = r
	}

	return scope, problem
}

// readOnServingRoute returns the scope of a request seen through a mount
// prefix, read on the route that serves it, or a non-empty description of why
// no single route does. A route with no scope to read — no catalog for its
// product and no declaration of its own — keeps the one it has, as before.
func (s ScopeDeclaration) readOnServingRoute(c fiber.Ctx) (ScopeDeclaration, string) {
	r := s.mounted
	if r == nil || !r.hasScope() {
		return s, ""
	}

	resolved, unresolved := r.table(c.App()).resolve(c.Method(), c.Path())
	if unresolved != "" {
		return ScopeDeclaration{}, unresolved
	}

	// A declaration's problem does not depend on the route and was refused in
	// scopeFor; it can reappear here only if the manifest was rewired between
	// the two reads, and is then refused all the same.
	scope, problem := r.forRoute(resolved.method, resolved.path)
	if problem != "" {
		return ScopeDeclaration{}, problem
	}

	scope.params = resolved.params

	return scope, ""
}

// hasScope reports whether the route has a scope to read: its own
// declaration, or its product's catalog.
func (r *routeScope) hasScope() bool {
	if r.explicit != nil {
		return true
	}

	return r.auth.hasManifestScope(r.product)
}

// table returns the candidate routes for app, compiling them again when the
// app registered routes or the manifest changed since.
func (r *routeScope) table(app *fiber.App) *routeTable {
	generation := r.auth.manifestGeneration()

	if t := r.tables.current.Load(); t != nil && t.app == app && t.handlers == app.HandlersCount() && t.generation == generation {
		return t
	}

	t := buildRouteTable(app, generation, r.auth.manifestRouteKeys(r.product))
	r.tables.current.Store(t)

	return t
}
