package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
//
// The last key names a string; keys cannot contain '.', '[' or ']'.
//
// Every value the path reaches must be inside the credential's scope: each array
// element is its own question to the authorization service, and the request is
// refused when any one of them is denied. Fields under the same array element
// travel together in one question, and a field of an enclosing element — and
// every dimension read from another source (path, header, query) — joins every
// question of the elements nested in it. A dimension can be declared more than
// once on a route, from different arrays, but each question must carry every
// dimension the route reads from the body.
//
// The body is read only for a partner-bound credential; any other caller is
// decided on the dimensions from the other sources alone, as before. For a
// partner, a body that is not JSON, a field that is absent, empty or not a
// string, and an array that is empty or not an array are refused with 400 naming
// the field, before any authorization call and without calling the handler.
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
}

// bodyGroup is one innermost array (or the body itself when no field crosses an
// array) whose every element makes one question, and the fields that question
// carries: its own, plus those of the enclosing elements.
type bodyGroup struct {
	prefix []bodySegment
	fields []bodyField
}

// bodyPlan is a route's body dimensions, compiled once at registration.
type bodyPlan struct {
	groups []bodyGroup
	fields []string
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

	if segments[len(segments)-1].array {
		return nil, "declares body field " + strconv.Quote(field) + ", which must end at a key holding a string, not at an array"
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
// describes what is wrong. constants are the names the route reads from
// elsewhere (the path, a header): a name read from both would have two values
// for one question. It returns a nil plan when no dimension is read from the
// body.
func compileBodyPlan(dims []Dimension, constants map[string]struct{}) (*bodyPlan, string) {
	fields := make([]bodyField, 0, len(dims))
	names := make(map[string]struct{})

	for _, dim := range dims {
		if dim.source != FromBody {
			continue
		}

		if _, clash := constants[dim.name]; clash {
			return nil, "scope dimension " + dim.name + " is read from the body and also from the path, a header or the query"
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

		fields = append(fields, field)
		names[dim.name] = struct{}{}
	}

	if len(fields) == 0 {
		return nil, ""
	}

	plan := &bodyPlan{fields: make([]string, 0, len(fields))}
	for _, f := range fields {
		plan.fields = append(plan.fields, f.dim.key)
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
// exactly once for it.
func buildBodyGroup(leaf []bodySegment, fields []bodyField, names map[string]struct{}) (bodyGroup, string) {
	group := bodyGroup{prefix: leaf}
	seen := make(map[string]struct{}, len(names))

	for _, f := range fields {
		if !isSegmentPrefix(f.segments[:f.prefixLen], leaf) {
			continue
		}

		if _, dup := seen[f.dim.name]; dup {
			return bodyGroup{}, "scope dimension " + f.dim.name + " is read more than once for " + renderPrefix(leaf)
		}

		seen[f.dim.name] = struct{}{}
		group.fields = append(group.fields, f)
	}

	for _, f := range fields {
		if _, ok := seen[f.dim.name]; !ok {
			return bodyGroup{}, "scope dimension " + f.dim.name + " is not read for " + renderPrefix(leaf) +
				", so a question about them would leave it out"
		}
	}

	return group, ""
}

// errBodyScope is the refusal of a request whose body cannot be read for its
// declared dimensions. It carries the message the 400 answers with.
type errBodyScope struct{ message string }

func (e *errBodyScope) Error() string { return e.message }

func bodyFieldError(location, problem string) *errBodyScope {
	return &errBodyScope{message: "scope field " + strconv.Quote(location) + " " + problem}
}

func joinLocation(base, key string) string {
	if base == "" {
		return key
	}

	return base + "." + key
}

// lookupKey reads key from obj the way a struct decoder does: an exact key, or
// else one differing only in letter case. Two keys that both match are refused,
// because which of them a handler reads depends on its decoder, and the scope
// must check the value the handler acts on.
func lookupKey(obj map[string]any, key, location string) (any, *errBodyScope) {
	var (
		value any
		found int
	)

	for k, v := range obj {
		if strings.EqualFold(k, key) {
			value = v
			found++
		}
	}

	switch found {
	case 0:
		return nil, bodyFieldError(location, "is missing from the request body")
	case 1:
		return value, nil
	default:
		return nil, bodyFieldError(location, "is given more than once, in different letter case")
	}
}

// questionSet accumulates the distinct questions of a request in order.
type questionSet struct {
	plan      *bodyPlan
	constants map[string]string
	seen      map[string]struct{}
	questions []map[string]string
}

func (q *questionSet) add(values map[string]string) *errBodyScope {
	question := make(map[string]string, len(q.constants)+len(values))
	for name, v := range q.constants {
		question[name] = v
	}

	for name, v := range values {
		question[name] = v
	}

	key := attributesCacheKey(question)
	if _, dup := q.seen[key]; dup {
		return nil
	}

	if len(q.questions) == maxBodyScopeQuestions {
		quoted := make([]string, 0, len(q.plan.fields))
		for _, f := range q.plan.fields {
			quoted = append(quoted, strconv.Quote(f))
		}

		return &errBodyScope{message: fmt.Sprintf(
			"the request body names more than %d distinct sets of scope values in fields %s",
			maxBodyScopeQuestions, strings.Join(quoted, ", "))}
	}

	q.seen[key] = struct{}{}
	q.questions = append(q.questions, question)

	return nil
}

// questions reads the body dimensions of the request and returns every distinct
// set of identifiers to ask about, each carrying the constants (the dimensions
// read from the path or headers) too.
func (p *bodyPlan) questions(body []byte, constants map[string]string) ([]map[string]string, *errBodyScope) {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, bodyFieldError(p.fields[0], "cannot be read: the request body is not valid JSON")
	}

	set := &questionSet{plan: p, constants: constants, seen: make(map[string]struct{})}

	for _, group := range p.groups {
		w := groupWalk{group: group, set: set}
		if err := w.walk(root, 0, "", []any{root}, []string{""}); err != nil {
			return nil, err
		}
	}

	return set.questions, nil
}

type groupWalk struct {
	group bodyGroup
	set   *questionSet
}

// walk descends the group's array prefix from node. chain holds the element of
// every array crossed so far (the body itself first), and locations their
// rendered positions, so each field is read relative to its own element and
// named at its concrete position when it is wrong.
func (w groupWalk) walk(node any, i int, location string, chain []any, locations []string) *errBodyScope {
	if i == len(w.group.prefix) {
		return w.emit(chain, locations)
	}

	seg := w.group.prefix[i]
	at := joinLocation(location, seg.key)

	obj, ok := node.(map[string]any)
	if !ok {
		return bodyFieldError(at, "cannot be read: its parent is not a JSON object")
	}

	child, err := lookupKey(obj, seg.key, at)
	if err != nil {
		return err
	}

	if !seg.array {
		return w.walk(child, i+1, at, chain, locations)
	}

	elements, ok := child.([]any)
	if !ok || len(elements) == 0 {
		return bodyFieldError(at, "must be a non-empty JSON array")
	}

	for idx, element := range elements {
		elementAt := at + "[" + strconv.Itoa(idx) + "]"

		if err := w.walk(element, i+1, elementAt, append(chain, element), append(locations, elementAt)); err != nil {
			return err
		}
	}

	return nil
}

// emit reads every field of one element and adds the question they make.
func (w groupWalk) emit(chain []any, locations []string) *errBodyScope {
	values := make(map[string]string, len(w.group.fields))

	for _, f := range w.group.fields {
		node := chain[f.depth]
		location := locations[f.depth]

		for _, seg := range f.segments[f.prefixLen:] {
			location = joinLocation(location, seg.key)

			obj, ok := node.(map[string]any)
			if !ok {
				return bodyFieldError(location, "cannot be read: its parent is not a JSON object")
			}

			child, err := lookupKey(obj, seg.key, location)
			if err != nil {
				return err
			}

			node = child
		}

		value, ok := node.(string)
		if !ok {
			return bodyFieldError(location, "must be a JSON string")
		}

		if value == "" {
			return bodyFieldError(location, "must not be empty")
		}

		values[f.dim.name] = value
	}

	return w.set.add(values)
}

// routeBodyScope is one route's dimensions — those its path carries and those
// the manifest declares for it — compiled once.
type routeBodyScope struct {
	dims []Dimension
	plan *bodyPlan
}

func routeScopeKey(method, path string) string {
	return method + " " + path
}

// SetManifestRouteScope declares the dimensions ONE route of the product reads
// from somewhere other than its path — its JSON body (FromBody) — for a product
// whose catalog SetManifestScope already wired: some routes carry the instance
// they address in the body, and only the route knows where.
//
// method and path identify the route exactly as it is registered (the full path,
// group prefixes included, with its ':' parameters). dims are catalog
// dimensions declared with Dim(name, source).At(key), validated exactly as a
// RequireScope declaration is. The route still derives the dimensions its path
// carries; a dimension cannot be read from both. The declaration package
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
		// The route's path dimensions are derived from its path, as on every
		// other route; the manifest route declares the ones read elsewhere.
		if dim.source == FromPath {
			return errors.New("manifest route scope: dimension " + dim.name + " on " + method + " " + path +
				" is derived from the path and must not be declared on the route")
		}

		if _, ok := known[dim.name]; !ok {
			return errors.New("manifest route scope: dimension " + dim.name + " on " + method + " " + path +
				" is not declared in the manifest scope of product " + product)
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

	auth.manifestRouteScopes[product][routeScopeKey(method, path)] = routeBodyScope{
		dims: routeDims,
		plan: plan,
	}
	auth.manifestGen++

	return nil
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
// for: none when the route declares nothing; the dimensions read from the path,
// headers or query alone when the route reads nothing from the body or the
// caller is not partner-bound (the body is then never read); and otherwise one
// set per question the body makes, each carrying those other dimensions. A body
// that cannot be read, or cannot be read for the declared dimensions, is the
// refusal: 400 naming the field, or the status the adapter could not read the
// body with.
func (s ScopeDeclaration) questions(req requestView, attributes map[string]string, readBody bool) ([]map[string]string, *RefusalError) {
	if s.body == nil || !readBody {
		if attributes == nil {
			return nil, nil
		}

		return []map[string]string{attributes}, nil
	}

	body, refusal := req.body()
	if refusal != nil {
		return nil, refusal
	}

	questions, badBody := s.body.questions(body, attributes)
	if badBody != nil {
		return nil, newRefusal(http.StatusBadRequest, badBody.Error())
	}

	return questions, nil
}

// sharedAttributes returns the identifiers every question carries with the same
// value: the whole question when there is one.
func sharedAttributes(questions []map[string]string) map[string]string {
	if len(questions) == 0 {
		return nil
	}

	shared := make(map[string]string, len(questions[0]))
	for name, value := range questions[0] {
		shared[name] = value
	}

	for _, question := range questions[1:] {
		for name, value := range shared {
			if question[name] != value {
				delete(shared, name)
			}
		}
	}

	return shared
}
