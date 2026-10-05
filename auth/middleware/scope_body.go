package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

func joinLocation(base, key string) string {
	if base == "" {
		return key
	}

	return base + "." + key
}

// lookupKey reads key from obj the way a struct decoder does: an exact key, or
// else one differing only in letter case. Two keys that both match are refused,
// because which of them a handler reads depends on its decoder, and the scope
// must check the value the handler acts on. A key that is absent, or whose value
// is JSON null, is reported as not named — a struct decoder leaves the field at
// its zero value for both — and the caller decides whether that is an error.
func lookupKey(obj map[string]any, key, location string) (any, bool, *errBodyScope) {
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
		return nil, false, nil
	case 1:
		return value, value != nil, nil
	default:
		return nil, false, bodyFieldError(location, "is given more than once, in different letter case")
	}
}

// notNamed is the error for a field the body does not name. A null value is
// reported as what it is, so the caller fixes the value and not the key.
func notNamed(obj map[string]any, key, location string) *errBodyScope {
	for k, v := range obj {
		if strings.EqualFold(k, key) && v == nil {
			return bodyFieldError(location, "must not be null")
		}
	}

	return bodyFieldError(location, "is missing from the request body")
}

// questionSet accumulates the distinct questions of a request in order. Each
// question carries the dimensions the body names for it and the values the
// other carriers name: a dimension those carriers name several values of asks
// one question per value.
//
// The questions are decided in groups: a group is allowed when one of its
// questions is. A question stands alone in its group, except those carrying a
// value resolved with MatchAny, which share a group with the questions
// carrying the other values the same request value resolved to.
type questionSet struct {
	plan      *bodyPlan
	readings  requestValues
	seen      map[string]int
	questions []map[string]string
	// groups are the indexes into questions of each group, in the order made.
	groups [][]int
	// carried records, per dimension the other carriers name, the values the
	// questions carry, so a value they name and the body never does is caught.
	carried map[string]map[string]struct{}
	// resolvedAt locates the resolved value the questions being added carry,
	// "" when they carry none; located holds it per question.
	resolvedAt string
	located    []string
	// unioned holds the dimensions the body and another carrier both name
	// where one of the two is resolved: the values of each are asked, rather
	// than checked for agreement.
	unioned map[string]bool
}

func newQuestionSet(plan *bodyPlan, readings requestValues) *questionSet {
	return &questionSet{
		plan: plan, readings: readings, seen: make(map[string]int), carried: make(map[string]map[string]struct{}),
		resolvedAt: readings.resolvedAt,
	}
}

// add adds the questions one set of body values makes. locations name where in
// the body each of those values was read.
func (q *questionSet) add(values, locations map[string]string) *errBodyScope {
	return q.addGroup([]map[string]string{values}, locations, nil)
}

// addGroup adds the questions one group of alternative sets of body values
// makes: the alternatives name the same dimensions, and the request is allowed
// on one of them. An alternative naming a value another carrier does not name
// for the same dimension is dropped; when every one is, the two disagree.
// resolved names the dimensions whose body values were resolved: those, and
// the dimensions another carrier resolved, are not checked for agreement.
func (q *questionSet) addGroup(alternatives []map[string]string, locations, resolved map[string]string) *errBodyScope {
	alternatives, problem := q.agreeing(alternatives, locations, resolved)
	if problem != nil {
		return problem
	}

	// Each requirement is a group: one of its questions must be allowed.
	requirements := [][]map[string]string{alternatives}
	count := len(alternatives)

	for _, name := range q.readings.names {
		if _, inBody := alternatives[0][name]; inBody {
			continue
		}

		// The values of one carrier are distinct, so every combination is: the
		// count is exact, and refusing past the cap here never builds them.
		perRequirement := q.valueCount(name)
		if count*perRequirement > maxBodyScopeQuestions {
			return q.tooMany()
		}

		count *= perRequirement

		items := q.items(name)
		next := make([][]map[string]string, 0, len(requirements)*len(items))

		for _, requirement := range requirements {
			for _, item := range items {
				next = append(next, withEach(requirement, name, item))
			}
		}

		requirements = next
	}

	for _, requirement := range requirements {
		if err := q.addRequirement(requirement); err != nil {
			return err
		}
	}

	return nil
}

// valueCount is the number of values the other carriers name for name, every
// value of every request value resolved with MatchAny counted.
func (q *questionSet) valueCount(name string) int {
	items, matchAny := q.readings.anyOf[name]
	if !matchAny {
		return len(q.readings.values[name])
	}

	count := 0
	for _, item := range items {
		count += len(item)
	}

	return count
}

// items are the values the other carriers name for name, as the requirements
// they make: one per value of a dimension matching all; one per request value
// of a dimension resolved with MatchAny, its resolved values the alternatives.
func (q *questionSet) items(name string) [][]string {
	if items, matchAny := q.readings.anyOf[name]; matchAny {
		return items
	}

	items := make([][]string, 0, len(q.readings.values[name]))
	for _, value := range q.readings.values[name] {
		items = append(items, []string{value})
	}

	return items
}

// agreeing returns the alternatives whose every value another carrier naming
// the same dimension names too, or the disagreement when there is none. A
// dimension resolved on either side is recorded as unioned instead.
func (q *questionSet) agreeing(alternatives []map[string]string, locations, resolved map[string]string) ([]map[string]string, *errBodyScope) {
	var (
		kept    []map[string]string
		problem *errBodyScope
	)

	for _, values := range alternatives {
		diverges := false

		for _, name := range sortedKeys(values) {
			named, ok := q.readings.values[name]
			if !ok {
				continue
			}

			if _, bodyResolved := resolved[name]; bodyResolved || q.readings.derived[name] {
				q.markUnioned(name)

				continue
			}

			if !containsValue(named, values[name]) {
				if problem == nil {
					problem = divergence(name, q.readings.where[name], locations[name])
				}

				diverges = true

				break
			}
		}

		if !diverges {
			kept = append(kept, values)
		}
	}

	if len(kept) == 0 {
		return nil, problem
	}

	return kept, nil
}

// markUnioned records that the values of name on both sides are asked.
func (q *questionSet) markUnioned(name string) {
	if q.unioned == nil {
		q.unioned = make(map[string]bool)
	}

	q.unioned[name] = true
}

// addRequirement adds the questions of one group and records the group. A
// question several groups share is added once, and decided once.
func (q *questionSet) addRequirement(alternatives []map[string]string) *errBodyScope {
	group := make([]int, 0, len(alternatives))

	for _, question := range alternatives {
		index, err := q.addOne(question)
		if err != nil {
			return err
		}

		group = append(group, index)
	}

	q.groups = append(q.groups, group)

	return nil
}

// addOne adds a question, once, and returns its index.
func (q *questionSet) addOne(question map[string]string) (int, *errBodyScope) {
	key := attributesCacheKey(question)
	if index, dup := q.seen[key]; dup {
		return index, nil
	}

	if len(q.questions) == maxBodyScopeQuestions {
		return 0, q.tooMany()
	}

	q.seen[key] = len(q.questions)
	q.questions = append(q.questions, question)
	q.located = append(q.located, q.resolvedAt)

	for name, value := range question {
		if _, ok := q.readings.values[name]; !ok {
			continue
		}

		if q.carried[name] == nil {
			q.carried[name] = make(map[string]struct{})
		}

		q.carried[name][value] = struct{}{}
	}

	return len(q.questions) - 1, nil
}

// complete checks that every value another carrier names for a dimension the
// body also names is carried by some question: one the body never names is a
// disagreement between the two. When one side of the two is resolved, the
// values of the other carriers are asked instead, on their own questions.
func (q *questionSet) complete() *errBodyScope {
	if q.plan == nil {
		return nil
	}

	union := false

	for _, name := range q.readings.names {
		field, inBody := q.plan.firstField[name]
		if !inBody {
			continue
		}

		if q.unioned[name] {
			union = true

			continue
		}

		// A request value resolved with MatchAny agrees with the body when the
		// body names one of the values it resolved to.
		if items, matchAny := q.readings.anyOf[name]; matchAny {
			for _, item := range items {
				if !q.carriesOne(name, item) {
					return divergence(name, q.readings.where[name], field)
				}
			}

			continue
		}

		for _, value := range q.readings.values[name] {
			if _, ok := q.carried[name][value]; !ok {
				return divergence(name, q.readings.where[name], field)
			}
		}
	}

	if !union {
		return nil
	}

	q.resolvedAt = q.readings.resolvedAt

	return q.add(map[string]string{}, nil)
}

// scopeQuestions are the questions a request makes: the sets of identifiers
// to ask about, where the resolved value each carries was read ("" for none),
// and the groups they are decided in — each the indexes of sets of which one
// must be allowed.
type scopeQuestions struct {
	sets    []map[string]string
	located []string
	groups  [][]int
}

func (q *questionSet) asked() scopeQuestions {
	return scopeQuestions{sets: q.questions, located: q.located, groups: q.groups}
}

// carriesOne reports whether some question carries one of values for name.
func (q *questionSet) carriesOne(name string, values []string) bool {
	for _, value := range values {
		if _, ok := q.carried[name][value]; ok {
			return true
		}
	}

	return false
}

func (q *questionSet) tooMany() *errBodyScope {
	locations := make([]string, 0, len(q.readings.names)+1)
	for _, name := range q.readings.names {
		locations = append(locations, q.readings.where[name])
	}

	if q.plan != nil {
		for _, f := range q.plan.fields {
			locations = append(locations, "body field "+strconv.Quote(f))
		}
	}

	return &errBodyScope{message: fmt.Sprintf(
		"the request names more than %d distinct sets of scope values in %s",
		maxBodyScopeQuestions, strings.Join(locations, ", "))}
}

func containsValue(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
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

type groupWalk struct {
	group bodyGroup
	set   *questionSet
	// raw, when non-nil, collects each question instead of adding it to set:
	// the plan resolves body keys, which are translated in one batch first.
	raw *[]rawQuestion
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

	child, named, err := lookupKey(obj, seg.key, at)
	if err != nil {
		return err
	}

	if !named {
		// The body names nothing below this key. That is a question without
		// the fields below it when every one of them is optional; the fields
		// of the elements already crossed are still read.
		if w.optionalFrom(len(chain)) {
			return w.emit(chain, locations)
		}

		return notNamed(obj, seg.key, at)
	}

	if !seg.array {
		return w.walk(child, i+1, at, chain, locations)
	}

	elements, ok := child.([]any)

	// The innermost array of a group of strings holds the values themselves:
	// an empty one names none, and the question goes without them.
	if w.group.strings && i == len(w.group.prefix)-1 {
		if !ok {
			return bodyFieldError(at, "must be a JSON array of strings")
		}

		if len(elements) == 0 {
			return w.emit(chain, locations)
		}
	}

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

// optionalFrom reports whether every field of the group read inside an element
// at depth or deeper is optional — the fields an absent array at that depth
// leaves without a value.
func (w groupWalk) optionalFrom(depth int) bool {
	for _, f := range w.group.fields {
		if f.depth >= depth && !f.dim.optional {
			return false
		}
	}

	return true
}

// bodyReading is the value one field of the group names for one element, and
// where it was read.
type bodyReading struct {
	field bodyField
	value string
	at    string
}

// emit reads every field of one element and adds the questions they make.
// chain stops short of the group's innermost element when an optional array
// was absent; the fields inside the missing elements are then left out.
//
// A dimension read by one field makes one question with the other fields. A
// dimension read by several fields — two distinct references, a top-level
// account and the aliases of a nested target, say — is asked once per value:
// each reading anchors a question, and every other dimension takes the value
// read nearest to it (see nearest), so each value travels with the fields of
// its own element.
func (w groupWalk) emit(chain []any, locations []string) *errBodyScope {
	readings := make([]bodyReading, 0, len(w.group.fields))

	for _, f := range w.group.fields {
		if f.depth >= len(chain) {
			continue
		}

		value, location, err := readBodyField(f, chain[f.depth], locations[f.depth])
		if err != nil {
			return err
		}

		if location != "" {
			readings = append(readings, bodyReading{field: f, value: value, at: "body field " + strconv.Quote(location)})
		}
	}

	combinations, err := w.combine(readings)
	if err != nil {
		return err
	}

	for _, chosen := range combinations {
		values := make(map[string]string, len(chosen))
		at := make(map[string]string, len(chosen))
		resolvers := make(map[string]string)
		matchAny := make(map[string]bool)
		optional := make(map[string]bool)

		for _, r := range chosen {
			values[r.field.dim.name] = r.value
			at[r.field.dim.name] = r.at

			if r.field.dim.resolver != "" {
				resolvers[r.field.dim.name] = r.field.dim.resolver
				matchAny[r.field.dim.name] = r.field.dim.matchAny
				optional[r.field.dim.name] = r.field.dim.optional
			}
		}

		if w.raw != nil {
			*w.raw = append(*w.raw, rawQuestion{
				values: values, at: at, resolvers: resolvers, siblings: siblings(chosen), matchAny: matchAny,
				optional: optional,
			})

			continue
		}

		if err := w.set.add(values, at); err != nil {
			return err
		}
	}

	return nil
}

// combine returns the distinct sets of readings one element asks about, in the
// order first made: one per reading it anchors, carrying for every other
// dimension the readings nearest to the anchor. When the element names nothing
// it is one empty set, the question without the body's dimensions.
func (w groupWalk) combine(readings []bodyReading) ([][]bodyReading, *errBodyScope) {
	if len(readings) == 0 {
		return [][]bodyReading{nil}, nil
	}

	var (
		out  [][]bodyReading
		seen = make(map[string]struct{})
	)

	for _, anchor := range readings {
		combinations := [][]bodyReading{{anchor}}

		for _, name := range readingNames(readings) {
			if name == anchor.field.dim.name {
				continue
			}

			candidates := nearest(anchor, readings, name)

			if len(combinations)*len(candidates) > maxBodyScopeQuestions {
				return nil, w.set.tooMany()
			}

			next := make([][]bodyReading, 0, len(combinations)*len(candidates))

			for _, combination := range combinations {
				for _, c := range candidates {
					next = append(next, append(append([]bodyReading(nil), combination...), c))
				}
			}

			combinations = next
		}

		for _, combination := range combinations {
			key := readingsKey(combination)
			if _, dup := seen[key]; dup {
				continue
			}

			seen[key] = struct{}{}

			out = append(out, combination)
		}
	}

	return out, nil
}

// readingNames lists the dimensions the readings name, each once, in order.
func readingNames(readings []bodyReading) []string {
	var names []string

	seen := make(map[string]struct{}, len(readings))

	for _, r := range readings {
		if _, dup := seen[r.field.dim.name]; !dup {
			seen[r.field.dim.name] = struct{}{}
			names = append(names, r.field.dim.name)
		}
	}

	return names
}

// nearest returns the readings of name that join a question anchored on
// anchor: those of the deepest element enclosing the anchor's own (its own
// element included), so a field of the anchor's element wins over one of an
// enclosing element; when no reading of name encloses it, those sharing the
// longest leading part of its element. Readings tied on that are each one
// question.
func nearest(anchor bodyReading, readings []bodyReading, name string) []bodyReading {
	var (
		best      []bodyReading
		bestScore = -1
	)

	for _, r := range readings {
		if r.field.dim.name != name {
			continue
		}

		// Enclosing readings rank above every other, deepest first.
		score := commonPrefixLen(r.field.element, anchor.field.element)
		if score == len(r.field.element) {
			score += len(anchor.field.element) + 1
		}

		switch {
		case score > bestScore:
			best, bestScore = append(best[:0], r), score
		case score == bestScore:
			best = append(best, r)
		}
	}

	return best
}

func commonPrefixLen(a, b []bodySegment) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}

	return n
}

// readingsKey identifies a set of readings by each field and value, so the same
// values read through a resolved and a plain field stay apart.
func readingsKey(readings []bodyReading) string {
	var b strings.Builder

	for _, r := range readings {
		writeLengthPrefixed(&b, r.field.dim.name)
		writeLengthPrefixed(&b, r.field.dim.key)
		writeLengthPrefixed(&b, r.value)
	}

	return b.String()
}

// siblings returns, per resolved reading of a question, the values of the
// question's plain readings of the same element: what the resolver is given to
// confine its lookup to. A reading with none has no entry.
func siblings(chosen []bodyReading) map[string]map[string]string {
	var out map[string]map[string]string

	for _, f := range chosen {
		if f.field.dim.resolver == "" {
			continue
		}

		for _, g := range chosen {
			if g.field.dim.resolver != "" || g.field.strings || !sameSegments(g.field.element, f.field.element) {
				continue
			}

			if out == nil {
				out = make(map[string]map[string]string)
			}

			if out[f.field.dim.name] == nil {
				out[f.field.dim.name] = make(map[string]string)
			}

			out[f.field.dim.name][g.field.dim.name] = g.value
		}
	}

	return out
}

func sameSegments(a, b []bodySegment) bool {
	return len(a) == len(b) && isSegmentPrefix(a, b)
}

// readBodyField reads one field relative to its element, and returns where it
// was read. The location is empty when the body does not name an optional
// field: a key on its path is absent or null. Anything else that is not a
// non-empty string is refused.
func readBodyField(f bodyField, node any, location string) (string, string, *errBodyScope) {
	for _, seg := range f.segments[f.prefixLen:] {
		location = joinLocation(location, seg.key)

		obj, ok := node.(map[string]any)
		if !ok {
			return "", "", bodyFieldError(location, "cannot be read: its parent is not a JSON object")
		}

		child, named, err := lookupKey(obj, seg.key, location)
		if err != nil {
			return "", "", err
		}

		if !named {
			if f.dim.optional {
				return "", "", nil
			}

			return "", "", notNamed(obj, seg.key, location)
		}

		node = child
	}

	value, ok := node.(string)
	if !ok {
		return "", "", bodyFieldError(location, "must be a JSON string")
	}

	if value == "" {
		return "", "", bodyFieldError(location, "must not be empty")
	}

	return value, location, nil
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
