package middleware

import (
	"bytes"
	"encoding/json"

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
// its own element, and Optional applies per field. Reading the same field
// twice is a misdeclaration.
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

// questions reads the body dimensions of the request and returns every distinct
// set of identifiers to ask about, each carrying the values the other carriers
// (the path, the query, headers) name too.
//
// A request with no body names nothing; when every body dimension is optional
// that is a body without them, not a malformed one.
func (p *bodyPlan) questions(body []byte, readings requestValues) ([]map[string]string, *errBodyScope) {
	var root any

	switch {
	case p.allOptional && len(bytes.TrimSpace(body)) == 0:
		root = map[string]any{}
	default:
		if err := json.Unmarshal(body, &root); err != nil {
			return nil, bodyFieldError(p.fields[0], "cannot be read: the request body is not valid JSON")
		}
	}

	set := newQuestionSet(p, readings)

	for _, group := range p.groups {
		w := groupWalk{group: group, set: set}
		if err := w.walk(root, 0, "", []any{root}, []string{""}); err != nil {
			return nil, err
		}
	}

	if err := set.complete(); err != nil {
		return nil, err
	}

	return set.questions, nil
}

// questions returns each set of identifiers a partner-bound request must be
// authorized for: none when the request names no dimension; the values read
// from the path, headers, query or a form alone when the route reads nothing
// from the JSON body — one question per combination of values when a carrier
// names several; and otherwise one set per question the body makes, each
// carrying those other values.
func (s ScopeDeclaration) questions(c fiber.Ctx, readings requestValues) ([]map[string]string, *errBodyScope) {
	readings = readForm(c, s.dims, readings)
	if readings.problem != nil {
		return nil, readings.problem
	}

	if s.body == nil {
		if len(readings.names) == 0 {
			return nil, nil
		}

		set := newQuestionSet(nil, readings)
		if err := set.add(map[string]string{}, nil); err != nil {
			return nil, err
		}

		return set.questions, nil
	}

	return s.body.questions(c.Body(), readings)
}
