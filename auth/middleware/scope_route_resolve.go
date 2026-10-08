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

// mountedResolutions counts the requests resolved to the route that serves
// them, process-wide. Only a request whose scope is read is resolved; the count
// is what lets that be checked.
var mountedResolutions atomic.Uint64

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
	// registered are the routes the app registers, in the order Fiber tries
	// them.
	registered []registeredRoute
	// declared are the routes only the manifest declares.
	declared []routeTemplate
}

// registeredRoute is a route the app registers. For a route whose path the
// matcher cannot read, its outline is kept: enough to tell that it cannot
// serve a request.
type registeredRoute struct {
	template routeTemplate
	readable bool
	method   string
	path     string
	outline  routeOutline
}

// resolve returns the route that serves the request, or a description of why
// none can be named. The app's routes are tried in the order Fiber tries them,
// and the first that matches is the one Fiber serves, whatever a more specific
// route registered later would say: the scope read must be that of the
// handler that runs. A route the matcher cannot read that could serve the
// request ends the search unresolved. Only when no route the app registers
// serves it is it resolved among the routes the manifest alone declares, the
// most specific winning, and two equally specific under different paths
// leaving it unresolved.
func (t *routeTable) resolve(method, path string) (resolvedRoute, string) {
	parts := pathSegments(path, t.rules)

	for i := range t.registered {
		route := &t.registered[i]
		if route.method != method {
			continue
		}

		if !route.readable {
			if route.outline.mayServe(parts, t.rules) {
				return resolvedRoute{}, "cannot tell whether " + method + " " + route.path + " serves " + path
			}

			continue
		}

		if params, ok := route.template.match(parts); ok {
			return resolvedRoute{method: method, path: route.path, params: params}, ""
		}
	}

	return t.resolveDeclared(method, path, parts)
}

// resolveDeclared resolves a request no registered route serves among the
// routes the manifest alone declares.
func (t *routeTable) resolveDeclared(method, path string, parts []string) (resolvedRoute, string) {
	var (
		best      *routeTemplate
		bestParam map[string]string
		tied      *routeTemplate
	)

	for i := range t.declared {
		route := &t.declared[i]
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
		return resolvedRoute{}, method + " " + path + " is served equally by the declared routes " + best.path + " and " + tied.path
	}

	return resolvedRoute{method: best.method, path: best.path, params: bestParam}, ""
}

// buildRouteTable compiles the app's routes — every route it registers, Use
// mounts aside, in its order — and the routes only the product's manifest
// declares.
func buildRouteTable(app *fiber.App, generation uint64, declared []string) *routeTable {
	config := app.Config()
	table := &routeTable{
		app:        app,
		handlers:   app.HandlersCount(),
		generation: generation,
		rules:      routingRules{caseSensitive: config.CaseSensitive, strict: config.StrictRouting},
	}
	seen := make(map[string]struct{})

	for _, route := range app.GetRoutes(true) {
		seen[routeScopeKey(route.Method, route.Path)] = struct{}{}

		template, readable := parseRouteTemplate(route.Method, route.Path, table.rules)
		table.registered = append(table.registered, registeredRoute{
			template: template,
			readable: readable,
			method:   route.Method,
			path:     route.Path,
			outline:  outlineRoute(route.Path, table.rules),
		})
	}

	for _, key := range declared {
		if _, registered := seen[key]; registered {
			continue
		}

		method, path, _ := strings.Cut(key, " ")
		if template, ok := parseRouteTemplate(method, path, table.rules); ok {
			table.declared = append(table.declared, template)
		}
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

	mountedResolutions.Add(1)

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
