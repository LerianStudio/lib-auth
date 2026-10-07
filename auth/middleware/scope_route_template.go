package middleware

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// ForRoute declares the route a request is for, for a handler that cannot see
// it: one mounted with Use on a prefix, where Fiber reports the prefix as the
// route and reads no path parameter. Pass it to Authorize in place of
// RequireScope:
//
//	app.Use("/v1/organizations", auth.Authorize("midaz", "ledgers", "get",
//		middleware.ForRoute("midaz", http.MethodGet, "/v1/organizations/{organization_id}/ledgers/{ledger_id}")))
//
// The route takes its scope from the product's manifest exactly as if Fiber had
// matched it: the catalog dimensions its path carries, and the dimensions the
// manifest's scope.routes declares for it. Path parameters are read by matching
// template against the request path. template is the route as registered, with
// each parameter a whole segment in Huma ("{organization_id}") or Fiber
// (":organization_id") syntax; optional parameters and wildcards are refused,
// and the declaration then refuses every request, as any misdeclared route.
//
// A partner-bound request that the stated route does not describe — another
// method, or a path the template does not match — is refused 403 before the
// round-trip: its scope cannot be read. Every other credential is decided
// exactly as on a route with no scope.
func ForRoute(product, method, template string) ScopeDeclaration {
	route, problem := parseRouteTemplate(method, template)
	route.problem = problem

	return ScopeDeclaration{product: product, route: &route}
}

// routeTemplate is a route a declaration states, parsed once.
type routeTemplate struct {
	method string
	// path is the template in Fiber syntax, the form the manifest's routes are
	// keyed and derived by.
	path     string
	segments []templateSegment
	// problem is non-empty when the template cannot be honoured.
	problem string
}

// templateSegment is one '/'-separated segment of a template: a literal, or the
// name of the parameter it is.
type templateSegment struct {
	text  string
	param bool
}

// parseRouteTemplate parses a stated route, and describes what is wrong with
// it, or returns "".
func parseRouteTemplate(method, template string) (routeTemplate, string) {
	route := routeTemplate{method: strings.ToUpper(strings.TrimSpace(method))}

	switch {
	case route.method == "":
		return route, "stated route has no method"
	case !strings.HasPrefix(template, "/"):
		return route, "stated route " + strconv.Quote(template) + " must start with '/'"
	}

	parts := strings.Split(template, "/")[1:]
	seen := make(map[string]struct{}, len(parts))
	fiberParts := make([]string, 0, len(parts))

	for _, part := range parts {
		segment, problem := parseTemplateSegment(part)
		if problem != "" {
			return route, "stated route " + strconv.Quote(template) + ": segment " + strconv.Quote(part) + " " + problem
		}

		if segment.param {
			if _, dup := seen[segment.text]; dup {
				return route, "stated route " + strconv.Quote(template) + " names parameter " + strconv.Quote(segment.text) + " twice"
			}

			seen[segment.text] = struct{}{}
			fiberParts = append(fiberParts, ":"+segment.text)
		} else {
			fiberParts = append(fiberParts, segment.text)
		}

		route.segments = append(route.segments, segment)
	}

	route.path = "/" + strings.Join(fiberParts, "/")

	return route, ""
}

// parseTemplateSegment reads one segment: "{name}" or ":name" is a parameter,
// anything free of route syntax is a literal.
func parseTemplateSegment(part string) (templateSegment, string) {
	var name string

	switch {
	case strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}"):
		name = part[1 : len(part)-1]
	case strings.HasPrefix(part, ":"):
		name = part[1:]
	case strings.ContainsAny(part, "{}:*+?"):
		return templateSegment{}, "mixes route syntax into a literal; a parameter must be a whole segment"
	default:
		return templateSegment{text: part}, ""
	}

	if name == "" || strings.ContainsAny(name, "{}:*+?/ ") {
		return templateSegment{}, "is not a plain parameter name (optional parameters and wildcards are not supported)"
	}

	return templateSegment{text: name, param: true}, ""
}

// match reads the path parameters of a request the template describes, or
// returns false when it does not describe it. It matches as Fiber's default
// router does: literals without regard to letter case, a trailing slash
// ignored, every parameter one non-empty segment, and a HEAD request served by
// a GET route.
func (r *routeTemplate) match(method, path string) (map[string]string, bool) {
	if method != r.method && (method != fiber.MethodHead || r.method != fiber.MethodGet) {
		return nil, false
	}

	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}

	parts := strings.Split(path, "/")[1:]
	if len(parts) != len(r.segments) {
		return nil, false
	}

	params := make(map[string]string, len(parts))

	for i, segment := range r.segments {
		switch {
		case segment.param && parts[i] == "":
			return nil, false
		case segment.param:
			params[segment.text] = parts[i]
		case !strings.EqualFold(segment.text, parts[i]):
			return nil, false
		}
	}

	return params, true
}

// bindRequest returns the scope for the request in flight on a stated route:
// the route's scope carrying the path parameters read from the request, or
// marked unmatched when the route does not describe the request.
func (r *routeTemplate) bindRequest(c fiber.Ctx, scope ScopeDeclaration) ScopeDeclaration {
	params, matched := r.match(c.Method(), c.Path())
	if !matched {
		scope.unmatched = "request " + c.Method() + " " + c.Path() + " is not the stated route " + r.method + " " + r.path

		return scope
	}

	scope.params = params

	return scope
}

// servedByPrefix reports whether the route Fiber matched is a prefix of the
// request path rather than the request's own route: a handler mounted with Use
// sees its mount prefix, which has fewer segments than the request. Fiber
// reports the request's method for it, not "USE", so the path is the only
// sign. A route with a wildcard or an optional parameter can match a longer
// path on its own and is never taken for a prefix.
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
