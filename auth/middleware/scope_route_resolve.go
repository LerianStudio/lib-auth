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

// routeTemplate is one route, method and path as registered, parsed for
// matching.
type routeTemplate struct {
	method   string
	path     string
	segments []templateSegment
}

// parseRouteTemplate parses a registered route path. It returns false for a
// path whose syntax it does not read (several parameters in one segment, an
// optional parameter or a wildcard anywhere but last): such a route is never
// a candidate, and a request only it would serve resolves to no route.
func parseRouteTemplate(method, path string) (routeTemplate, bool) {
	route := routeTemplate{method: method, path: path}
	parts := pathSegments(path)

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

// pathSegments splits a path into its segments, ignoring a trailing slash as
// Fiber's default routing does.
func pathSegments(path string) []string {
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}

	return strings.Split(path, "/")[1:]
}

// match reads the path parameters of a request path the template describes,
// or returns false. Literals match without regard to letter case, as Fiber's
// default routing does.
func (r *routeTemplate) match(path string) (map[string]string, bool) {
	parts := pathSegments(path)
	params := make(map[string]string, len(r.segments))

	for i, segment := range r.segments {
		switch {
		case segment.kind == segmentWildcard:
			return params, !segment.nonEmpty || strings.Join(parts[min(i, len(parts)):], "") != ""
		case segment.kind == segmentOptional && i == len(parts):
			return params, true
		case i >= len(parts) || !segment.matches(parts[i]):
			return nil, false
		case segment.kind != segmentLiteral:
			params[segment.text] = parts[i]
		}
	}

	return params, len(parts) == len(r.segments)
}

// matches reports whether one request segment fits the template segment: a
// literal without regard to letter case, a parameter when it is not empty.
func (s templateSegment) matches(part string) bool {
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

		if sa.kind == segmentLiteral && !strings.EqualFold(sa.text, sb.text) {
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

	for i := range t.routes {
		route := &t.routes[i]
		if route.method != method {
			continue
		}

		params, ok := route.match(path)
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
	table := &routeTable{app: app, handlers: app.HandlersCount(), generation: generation}
	seen := make(map[string]struct{})

	add := func(method, path string) {
		key := routeScopeKey(method, path)
		if _, dup := seen[key]; dup {
			return
		}

		seen[key] = struct{}{}

		if route, ok := parseRouteTemplate(method, path); ok {
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

// segmentCount counts the non-empty '/'-separated segments of a path.
func segmentCount(path string) int {
	count := 0

	for _, segment := range strings.Split(path, "/") {
		if segment != "" {
			count++
		}
	}

	return count
}

// scopeFor returns the scope of the request in flight, and a non-empty
// description of what is wrong when the route cannot be honoured. A request
// served on its own route takes that route's scope, exactly as before. A
// request seen through a mount prefix, for a route that has a scope to read,
// is resolved to the route that serves it.
func (r *routeScope) scopeFor(c fiber.Ctx) (ScopeDeclaration, string) {
	route := c.Route()
	if !servedByPrefix(route.Path, c.Path()) || !r.hasScope() {
		return r.forRoute(route.Method, route.Path)
	}

	resolved, unresolved := r.table(c.App()).resolve(c.Method(), c.Path())
	if unresolved != "" {
		return ScopeDeclaration{product: r.product, unresolved: unresolved}, ""
	}

	scope, problem := r.forRoute(resolved.method, resolved.path)
	scope.params = resolved.params

	return scope, problem
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
