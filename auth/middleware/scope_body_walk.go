package middleware

import (
	"strconv"
	"strings"
)

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

		for _, r := range chosen {
			values[r.field.dim.name] = r.value
			at[r.field.dim.name] = r.at
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
// values read through two fields stay apart.
func readingsKey(readings []bodyReading) string {
	var b strings.Builder

	for _, r := range readings {
		writeLengthPrefixed(&b, r.field.dim.name)
		writeLengthPrefixed(&b, r.field.dim.key)
		writeLengthPrefixed(&b, r.value)
	}

	return b.String()
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
