package middleware

import (
	"net/http"
	"strconv"
)

// errBodyScope is the refusal of a request whose scope cannot be read for its
// declared dimensions. It carries the message it answers with, and its status:
// 400 unless set.
type errBodyScope struct {
	message string
	status  int
}

func (e *errBodyScope) Error() string { return e.message }

// statusCode is the status the request is refused with.
func (e *errBodyScope) statusCode() int {
	if e.status == 0 {
		return http.StatusBadRequest
	}

	return e.status
}

func bodyFieldError(location, problem string) *errBodyScope {
	return &errBodyScope{message: "scope field " + strconv.Quote(location) + " " + problem}
}
