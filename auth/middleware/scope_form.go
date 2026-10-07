package middleware

import (
	"bytes"
	"mime"
	"net/url"
)

// FromForm reads a field of an application/x-www-form-urlencoded request body.
// Declare it with the field's name as the key: Dim(name, FromForm).At(field).
// Like a query parameter, a field repeated, or a value listing several
// separated by ',', names every one of them, each its own question.
//
// Only a urlencoded body is read. For a partner-bound credential, a body of any
// other type — a multipart form above all, which this library does not parse —
// is refused with 400 naming the field, whether or not the dimension is
// optional: it may carry the field where the scope cannot see it. An empty body
// names no field. A field that is absent is refused with 400 unless the
// dimension is Optional; a value that is there but empty is always refused.
// As with FromBody, the form is read only for a partner-bound credential, and a
// route cannot read its body both as JSON and as a form.
const FromForm Source = FromBody + 1

// formMediaType is the only body type FromForm reads.
const formMediaType = "application/x-www-form-urlencoded"

// readForm reads the route's form dimensions into readings, which the values
// read from the path, the query and headers are already in: a form field naming
// a dimension one of those names too must name the same values.
func readForm(req requestView, dims []Dimension, readings requestValues) requestValues {
	var (
		form   url.Values
		parsed bool
	)

	for _, dim := range dims {
		if dim.source != FromForm || readings.problem != nil {
			continue
		}

		if !parsed {
			var problem string

			body, unreadable := req.body()
			if unreadable != nil {
				readings.problem = unreadable

				continue
			}

			form, problem = parseForm(body, req.contentType())
			parsed = true

			if problem != "" {
				readings.problem = &errBodyScope{message: "scope " + dim.location() + " cannot be read: " + problem}

				continue
			}
		}

		values, present, problem := splitValues(form[dim.key])

		switch {
		case problem != "":
			readings.problem = &errBodyScope{message: "scope " + dim.location() + " " + problem}
		case !present && dim.optional:
		case !present:
			readings.problem = &errBodyScope{message: "scope " + dim.location() + " is missing from the request body"}
		default:
			readings.add(dim, values)
		}
	}

	return readings
}

// parseForm parses the request body as a urlencoded form, or describes why it
// cannot. A body the standard parser refuses is refused here rather than read
// leniently, so the value checked is never one a stricter or looser reader
// would see differently.
func parseForm(body []byte, contentType string) (url.Values, string) {
	if len(bytes.TrimSpace(body)) == 0 {
		return url.Values{}, ""
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != formMediaType {
		return nil, "the request body is not " + formMediaType
	}

	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, "the request body is not valid " + formMediaType
	}

	return form, ""
}
