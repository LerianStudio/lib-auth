package middleware

import (
	"strconv"
	"strings"
)

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
