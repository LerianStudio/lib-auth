package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// FromBody reads a field of the JSON request body. Declare it like any other
// source, with the field's path as the key: Dim(name, FromBody).At(field).
//
// field is a path of object keys separated by '.', where a key followed by "[]"
// is an array whose every element is read:
//
//	"id"                      the top-level key
//	"target.id"               a key of a nested object
//	"items[].id"              the key in every element of the array
//	"groups[].items[].id"     the key in every element of nested arrays
//	"target.ids[]"            every string of an array of strings
//
// The last key names a string, or an array of strings when it ends in "[]";
// keys cannot contain '.', '[' or ']'.
//
// Every value the path reaches must be inside the credential's scope: each array
// element is its own question to the authorization service, and the request is
// refused when any one of them is denied. Fields under the same array element
// travel together in one question, and a field of an enclosing element — and
// every dimension read from another source (path, header, query) — joins every
// question of the elements nested in it. A dimension read from the body AND
// from another source must name the same values in both: each body value must
// be one the other source names, and each value it names must appear in the
// body; otherwise the request is refused with 400 naming both places. Each
// question must carry every dimension the route reads from the body.
//
// A dimension may be read from several distinct body fields — from different
// arrays, or two fields naming two different references (a top-level account
// and the aliases of a nested target). Each field is its own reference: every
// value of every field is asked and must be allowed, each with the fields of
// its own element, and Optional and Resolve apply per field. Reading the same
// field twice is a misdeclaration.
//
// The body is read only for a partner-bound credential; any other caller is
// decided on the dimensions from the other sources alone, as before. For a
// partner, a body that is not JSON, a field that is absent, empty or not a
// string, and an array that is empty or not an array are refused with 400 naming
// the field, before any authorization call and without calling the handler.
//
// A dimension declared Optional may be left out: when a key on its path is
// absent or null, the question is asked without it — and without every other
// optional field below an absent array. A value that is there is still refused
// unless it is a non-empty string, and an array that is there must still be a
// non-empty array. A question that ends up naming no dimension at all is refused
// for a partner, as a route that declares none is.
//
// A field ending in "[]" reads an array of strings: every element is one value,
// its own question, and an element that is not a non-empty string is refused
// with 400 naming the element. Optional applies to the array as a whole: absent
// or null, the dimension is absent. An empty array names no value, Optional or
// not: the questions are asked without the dimension, and the other dimensions
// are still asked. The elements of such an array are strings, so no other field
// of the route may read inside them.
//
// It is appended after the other sources so their values do not move.
const FromBody Source = FromQuery + 1

// maxBodyScopeQuestions caps the distinct sets of identifiers one request body
// can make Authorize ask about. Every set is one decision, so without a cap a
// batch could turn one request into an unbounded number of calls to the
// authorization service. A body over the cap is refused, never partly checked.
const maxBodyScopeQuestions = 100

// bodySegment is one key of a body field path.
type bodySegment struct {
	key   string
	array bool
}

// bodyField is one body dimension with its parsed path. prefixLen is the number
// of segments up to and including the last array segment, and depth the number
// of array segments among them: the value is read relative to the element of
// the depth-th array, along segments[prefixLen:].
type bodyField struct {
	dim       Dimension
	segments  []bodySegment
	prefixLen int
	depth     int
	// strings is set when the path ends in an array of strings: the element
	// itself is the value, so prefixLen spans the whole path.
	strings bool
	// element is the prefix of the element the value is read from: the
	// enclosing array element, or, for a string of an array of strings, the
	// element holding the array. A resolved value's siblings share it.
	element []bodySegment
}

// bodyGroup is one innermost array (or the body itself when no field crosses an
// array) whose every element makes one question, and the fields that question
// carries: its own, plus those of the enclosing elements.
type bodyGroup struct {
	prefix []bodySegment
	fields []bodyField
	// strings is set when the innermost array is an array of strings.
	strings bool
}

// bodyPlan is a route's body dimensions, compiled once at registration.
type bodyPlan struct {
	groups []bodyGroup
	fields []string
	// allOptional is set when every body dimension is optional, so a request
	// with no body at all names none of them instead of being malformed.
	allOptional bool
	// firstField locates, per dimension name, the first body field it is read
	// from, for the refusal of a body that disagrees with another carrier.
	firstField map[string]string
	// resolves is set when a body field names a resolver: the questions are then
	// collected whole, their keys translated in one batch, and only then asked.
	resolves bool
}

// parseBodyField parses a field path, or describes what is wrong with it.
func parseBodyField(field string) ([]bodySegment, string) {
	if field == "" {
		return nil, "declares an empty body field"
	}

	parts := strings.Split(field, ".")
	segments := make([]bodySegment, 0, len(parts))

	for _, part := range parts {
		key, array := strings.CutSuffix(part, "[]")
		if key == "" || strings.ContainsAny(key, "[]") {
			return nil, "declares body field " + strconv.Quote(field) + ", which is not a path of keys separated by '.'"
		}

		segments = append(segments, bodySegment{key: key, array: array})
	}

	return segments, ""
}

// isSegmentPrefix reports whether prefix is the leading part of path.
func isSegmentPrefix(prefix, path []bodySegment) bool {
	if len(prefix) > len(path) {
		return false
	}

	for i := range prefix {
		if prefix[i] != path[i] {
			return false
		}
	}

	return true
}

func renderPrefix(prefix []bodySegment) string {
	if len(prefix) == 0 {
		return "the request body"
	}

	var b strings.Builder

	for i, seg := range prefix {
		if i > 0 {
			b.WriteByte('.')
		}

		b.WriteString(seg.key)

		if seg.array {
			b.WriteString("[]")
		}
	}

	return "the elements of " + b.String()
}

// compileBodyPlan validates a route's body dimensions and compiles them, or
// describes what is wrong. A name the route also reads elsewhere (the path, a
// header) is held, per request, to naming the same values in both. It returns a
// nil plan when no dimension is read from the body.
func compileBodyPlan(dims []Dimension) (*bodyPlan, string) {
	fields := make([]bodyField, 0, len(dims))
	names := make(map[string]struct{})

	for _, dim := range dims {
		if dim.source != FromBody {
			continue
		}

		segments, problem := parseBodyField(dim.key)
		if problem != "" {
			return nil, "scope dimension " + dim.name + " " + problem
		}

		field := bodyField{dim: dim, segments: segments}

		for i, seg := range segments {
			if seg.array {
				field.prefixLen = i + 1
				field.depth++
			}
		}

		field.strings = segments[len(segments)-1].array

		field.element = segments[:field.prefixLen]
		if field.strings {
			field.element = segments[:enclosingArrayEnd(segments[:len(segments)-1])]
		}

		fields = append(fields, field)
		names[dim.name] = struct{}{}
	}

	if len(fields) == 0 {
		return nil, ""
	}

	if problem := sameFieldTwice(fields); problem != "" {
		return nil, problem
	}

	if problem := readInsideStrings(fields); problem != "" {
		return nil, problem
	}

	plan := &bodyPlan{fields: make([]string, 0, len(fields)), firstField: make(map[string]string), allOptional: true}
	for _, f := range fields {
		plan.fields = append(plan.fields, f.dim.key)
		plan.allOptional = plan.allOptional && f.dim.optional
		plan.resolves = plan.resolves || f.dim.resolver != ""

		if _, ok := plan.firstField[f.dim.name]; !ok {
			plan.firstField[f.dim.name] = f.dim.location()
		}
	}

	for _, leaf := range leafPrefixes(fields) {
		group, problem := buildBodyGroup(leaf, fields, names)
		if problem != "" {
			return nil, problem
		}

		plan.groups = append(plan.groups, group)
	}

	return plan, ""
}

// enclosingArrayEnd is the number of segments up to and including the last
// array among segments, or 0 when there is none.
func enclosingArrayEnd(segments []bodySegment) int {
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i].array {
			return i + 1
		}
	}

	return 0
}

// sameFieldTwice describes the first dimension read twice from one body field —
// the same path, compared the way lookupKey matches keys, without regard to
// letter case — or returns "". Two distinct fields naming one dimension are two
// references, each asked; one field declared twice is a misdeclaration.
func sameFieldTwice(fields []bodyField) string {
	for i, f := range fields {
		for _, g := range fields[:i] {
			if g.dim.name == f.dim.name && strings.EqualFold(g.dim.key, f.dim.key) {
				return "scope dimension " + f.dim.name + " reads body field " + strconv.Quote(f.dim.key) + " more than once"
			}
		}
	}

	return ""
}

// readInsideStrings describes the first field that reads inside the elements of
// an array another field reads as strings, or returns "".
func readInsideStrings(fields []bodyField) string {
	for _, s := range fields {
		if !s.strings {
			continue
		}

		for _, f := range fields {
			if f.dim.key == s.dim.key || !isSegmentPrefix(s.segments, f.segments[:f.prefixLen]) {
				continue
			}

			return "scope dimension " + f.dim.name + " reads body field " + strconv.Quote(f.dim.key) +
				" inside the elements of " + strconv.Quote(s.dim.key) + ", which scope dimension " + s.dim.name +
				" reads as strings"
		}
	}

	return ""
}

// leafPrefixes returns the array prefixes no other field's prefix extends, in
// declaration order. Each is one group of questions.
func leafPrefixes(fields []bodyField) [][]bodySegment {
	var leaves [][]bodySegment

	for i, f := range fields {
		prefix := f.segments[:f.prefixLen]
		leaf := true

		for j, other := range fields {
			otherPrefix := other.segments[:other.prefixLen]

			if len(otherPrefix) > len(prefix) && isSegmentPrefix(prefix, otherPrefix) {
				leaf = false

				break
			}

			// The first field with this exact prefix stands for all of them.
			if j < i && len(otherPrefix) == len(prefix) && isSegmentPrefix(prefix, otherPrefix) {
				leaf = false

				break
			}
		}

		if leaf {
			leaves = append(leaves, prefix)
		}
	}

	return leaves
}

// buildBodyGroup collects the fields one element of leaf carries — its own and
// those of the elements enclosing it — and checks each body dimension is read
// for it. A dimension several of them read is asked once per value (see emit).
func buildBodyGroup(leaf []bodySegment, fields []bodyField, names map[string]struct{}) (bodyGroup, string) {
	group := bodyGroup{prefix: leaf}
	seen := make(map[string]struct{}, len(names))

	for _, f := range fields {
		if !isSegmentPrefix(f.segments[:f.prefixLen], leaf) {
			continue
		}

		seen[f.dim.name] = struct{}{}
		group.fields = append(group.fields, f)
		group.strings = group.strings || f.strings
	}

	for _, f := range fields {
		if _, ok := seen[f.dim.name]; !ok {
			return bodyGroup{}, "scope dimension " + f.dim.name + " is not read for " + renderPrefix(leaf) +
				", so a question about them would leave it out"
		}
	}

	return group, ""
}

// questions reads the body dimensions of the request and returns every distinct
// set of identifiers to ask about, each carrying the values the other carriers
// (the path, the query, headers) name too, and, per set, where the resolved
// value it carries was read ("" for none).
//
// A request with no body names nothing; when every body dimension is optional
// that is a body without them, not a malformed one.
func (p *bodyPlan) questions(body []byte, readings requestValues, r scopeResolution) (scopeQuestions, *errBodyScope) {
	var root any

	switch {
	case p.allOptional && len(bytes.TrimSpace(body)) == 0:
		root = map[string]any{}
	default:
		if err := json.Unmarshal(body, &root); err != nil {
			return scopeQuestions{}, bodyFieldError(p.fields[0], "cannot be read: the request body is not valid JSON")
		}
	}

	set := newQuestionSet(p, readings)

	var raw *[]rawQuestion
	if p.resolves {
		raw = &[]rawQuestion{}
	}

	for _, group := range p.groups {
		w := groupWalk{group: group, set: set, raw: raw}
		if err := w.walk(root, 0, "", []any{root}, []string{""}); err != nil {
			return scopeQuestions{}, err
		}
	}

	if raw != nil {
		if err := r.resolveBody(*raw, set, readings); err != nil {
			return scopeQuestions{}, err
		}
	}

	if err := set.complete(); err != nil {
		return scopeQuestions{}, err
	}

	return set.asked(), nil
}

// routeBodyScope is one route's dimensions — those its path carries and those
// the manifest declares for it — compiled once.
type routeBodyScope struct {
	dims []Dimension
	plan *bodyPlan
	// filter names the dimensions the route filters its list on (see
	// SetManifestRouteFilter).
	filter []string
}

func routeScopeKey(method, path string) string {
	return method + " " + path
}

// SetManifestRouteScope declares the dimensions ONE route of the product reads
// from somewhere other than its path — its JSON body (FromBody), the query
// (FromQuery) or a header (FromHeader) — for a product
// whose catalog SetManifestScope already wired: some routes carry the instance
// they address in the body, and only the route knows where.
//
// method and path identify the route exactly as it is registered (the full path,
// group prefixes included, with its ':' parameters). dims are catalog
// dimensions declared with Dim(name, source).At(key), validated exactly as a
// RequireScope declaration is. The route still derives the dimensions its path
// carries; a dimension it also reads elsewhere must name the same values in
// both, or the request is refused with 400 naming the two. The declaration package
// builds these from the manifest's scope.routes: call declaration.WireScope
// rather than this directly, at boot, BEFORE registering routes.
//
// A route that passes RequireScope keeps its own declaration and ignores this.
// SetManifestScope drops every route declared for the product.
func (auth *AuthClient) SetManifestRouteScope(product, method, path string, dims ...Dimension) error {
	if auth == nil {
		return errors.New("manifest route scope: nil auth client")
	}

	method = strings.ToUpper(strings.TrimSpace(method))

	switch {
	case strings.TrimSpace(product) == "":
		return errors.New("manifest route scope: product must not be empty")
	case method == "":
		return errors.New("manifest route scope: method must not be empty")
	case !strings.HasPrefix(path, "/"):
		return errors.New("manifest route scope: path " + strconv.Quote(path) + " must start with '/'")
	case len(dims) == 0:
		return errors.New("manifest route scope: " + method + " " + path + " declares no dimension")
	}

	auth.manifestScopeMu.Lock()
	defer auth.manifestScopeMu.Unlock()

	catalog := auth.manifestScopes[product]
	if len(catalog) == 0 {
		return errors.New("manifest route scope: product " + product + " has no manifest scope; call SetManifestScope first")
	}

	known := make(map[string]struct{}, len(catalog))
	for _, dim := range catalog {
		known[dim.name] = struct{}{}
	}

	for _, dim := range dims {
		if problem := auth.checkRouteDimension(product, path, dim, known); problem != "" {
			return errors.New("manifest route scope: dimension " + dim.name + " on " + method + " " + path + " " + problem)
		}
	}

	routeDims := append(deriveRouteDimensions(catalog, path), dims...)

	plan, problem := compileDims(routeDims)
	if problem != "" {
		return errors.New("manifest route scope: " + method + " " + path + ": " + problem)
	}

	if auth.manifestRouteScopes == nil {
		auth.manifestRouteScopes = make(map[string]map[string]routeBodyScope)
	}

	if auth.manifestRouteScopes[product] == nil {
		auth.manifestRouteScopes[product] = make(map[string]routeBodyScope)
	}

	key := routeScopeKey(method, path)

	auth.manifestRouteScopes[product][key] = routeBodyScope{
		dims:   routeDims,
		plan:   plan,
		filter: auth.manifestRouteScopes[product][key].filter,
	}
	auth.manifestGen++

	return nil
}

// checkRouteDimension describes what is wrong with dim as a dimension declared
// on one manifest route, or returns "". The route's path dimensions are derived
// from its path, as on every other route; the manifest route declares the ones
// read elsewhere, and a path parameter whose value is resolved into the
// dimension.
func (auth *AuthClient) checkRouteDimension(product, path string, dim Dimension, catalog map[string]struct{}) string {
	switch {
	case dim.source == FromPath && dim.resolver == "":
		return "is derived from the path and must not be declared on the route unless it is resolved"
	case dim.source == FromPath && !hasPathParam(path, dim.key):
		return "reads path parameter " + strconv.Quote(dim.key) + ", which the route path does not carry"
	}

	if problem := auth.unregisteredResolver([]Dimension{dim}); problem != "" {
		return "names resolver " + strconv.Quote(dim.resolver) + ", which is not registered; call RegisterScopeResolver first"
	}

	if _, ok := catalog[dim.name]; !ok {
		return "is not declared in the manifest scope of product " + product
	}

	return ""
}

// hasPathParam reports whether one whole segment of path is the parameter
// :param.
func hasPathParam(path, param string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == ":"+param {
			return true
		}
	}

	return false
}

// manifestGeneration is the count of manifest scope changes, read by routes to
// tell whether what they derived is still current.
func (auth *AuthClient) manifestGeneration() uint64 {
	auth.manifestScopeMu.RLock()
	defer auth.manifestScopeMu.RUnlock()

	return auth.manifestGen
}

// manifestRouteScope returns, in one consistent read, the manifest generation,
// the product's catalog and the scope declared for the route key, if any.
func (auth *AuthClient) manifestRouteScope(product, key string) (uint64, []Dimension, routeBodyScope, bool) {
	auth.manifestScopeMu.RLock()
	defer auth.manifestScopeMu.RUnlock()

	body, declared := auth.manifestRouteScopes[product][key]

	return auth.manifestGen, auth.manifestScopes[product], body, declared
}

// questions returns each set of identifiers the request must be authorized
// for: none when the request names no dimension; the values read from the path,
// headers or query alone when the route reads nothing from the body or the
// caller is not partner-bound (the body is then never read) — one question per
// combination of values when a carrier names several; and otherwise one set per
// question the body makes, each carrying those other values.
//
// Resolved dimensions are translated only when readBody is set — for a
// partner-bound caller. Any other caller is asked without them, exactly as a
// caller whose body is not read is asked without the body's dimensions.
func (s ScopeDeclaration) questions(c fiber.Ctx, readings requestValues, readBody bool, r scopeResolution) (scopeQuestions, *errBodyScope) {
	if readBody {
		readings = readForm(c, s.dims, readings)
	}

	if readings.problem != nil {
		return scopeQuestions{}, readings.problem
	}

	if readBody && len(readings.pending) > 0 {
		resolved, err := r.resolvePending(readings)
		if err != nil {
			return scopeQuestions{}, err
		}

		readings = resolved
	}

	if s.body == nil || !readBody {
		if len(readings.names) == 0 {
			return scopeQuestions{}, nil
		}

		set := newQuestionSet(nil, readings)
		if err := set.add(map[string]string{}, nil); err != nil {
			return scopeQuestions{}, err
		}

		return set.asked(), nil
	}

	return s.body.questions(c.Body(), readings, r)
}
