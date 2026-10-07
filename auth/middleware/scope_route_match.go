package middleware

import "strings"

// The route template matcher: a registered or declared route path, parsed in
// Fiber syntax, compared against a request path under the app's routing
// rules. scope_route_resolve.go uses it to find the route a request seen
// through a mount prefix is for.

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
	if !strings.HasPrefix(path, "/") {
		return routeTemplate{}, false
	}

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
// "*" or "+", or a literal free of route syntax. A constrained parameter
// (":name<int>") is not read: whether Fiber serves a path with it depends on
// the constraint.
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
		// "//" trims to nothing, which is still the root: one empty segment,
		// never none, so a template always has a last segment to inspect.
		if path = strings.TrimRight(path, "/"); path == "" {
			path = "/"
		}
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

// routeOutline is what can be told of any route path: the literal segments it
// has, each at its place up to the first segment that can span a varying
// number of request segments, and whether there is no such segment, which
// fixes the number of segments a request it serves has.
type routeOutline struct {
	literals []string // "" marks a segment that is not a literal
	fixed    bool
}

// outlineRoute outlines a route path.
func outlineRoute(path string, rules routingRules) routeOutline {
	outline := routeOutline{fixed: true}

	for _, part := range pathSegments(path, rules) {
		if strings.ContainsAny(part, "*+?") {
			outline.fixed = false

			break
		}

		if segment, ok := parseTemplateSegment(part); ok && segment.kind == segmentLiteral {
			outline.literals = append(outline.literals, part)
		} else {
			outline.literals = append(outline.literals, "")
		}
	}

	return outline
}

// mayServe reports whether a route with this outline could serve a request:
// neither its length nor its literals rule it out.
func (o routeOutline) mayServe(parts []string, rules routingRules) bool {
	if len(parts) < len(o.literals) || (o.fixed && len(parts) != len(o.literals)) {
		return false
	}

	for i, literal := range o.literals {
		if literal != "" && !(templateSegment{kind: segmentLiteral, text: literal}).matches(parts[i], rules) {
			return false
		}
	}

	return true
}
