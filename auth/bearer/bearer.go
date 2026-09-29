// Package bearer extracts a bearer token from an Authorization header with one
// strict set of rules, so every service that cannot use the Fiber middleware
// parses the credential the same way instead of carrying its own copy.
//
// It imports the standard library only, and it answers only whether the header
// carries a token that is SHAPED like a signed JWT. It never verifies a
// signature and never decides authorization: that stays with the Access Manager
// (see middleware.AuthClient.AuthorizeHTTP).
package bearer

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// MaxTokenBytes is the largest token accepted, in bytes. A real access token is
// a few hundred bytes to a few KiB; anything past 8 KiB is refused before it is
// decoded, hashed for the decision cache or sent to the Access Manager.
const MaxTokenBytes = 8 << 10

// maxHeaderBytes bounds the whole header before any other work: the token cap
// plus room for the scheme, its separator and the spaces a client may pad with.
const maxHeaderBytes = MaxTokenBytes + 64

const scheme = "Bearer"

var (
	// ErrMissing reports a request that carries no credential at all: the header
	// is absent or blank.
	ErrMissing = errors.New("bearer: missing token")
	// ErrMalformed reports every other refusal: a header that carries something,
	// but not exactly one well-formed bearer token.
	ErrMalformed = errors.New("bearer: malformed authorization header")
)

// FromRequest extracts the bearer token from r's Authorization header.
//
// A nil request, or one with no or a blank Authorization header, is ErrMissing.
// More than one Authorization header line is ErrMalformed: two credentials are
// never one, and picking either would let an intermediary choose which is used.
// Otherwise the single value goes through Parse.
func FromRequest(r *http.Request) (string, error) {
	if r == nil {
		return "", ErrMissing
	}

	values := r.Header.Values("Authorization")

	switch len(values) {
	case 0:
		return "", ErrMissing
	case 1:
		return Parse(values[0])
	default:
		return "", ErrMalformed
	}
}

// Parse extracts the token from one Authorization header value. It accepts
// exactly "Bearer <token>" — the scheme matched case-insensitively, one or more
// spaces before the token — where the token is at most MaxTokenBytes and is
// three non-empty, unpadded base64url segments separated by dots.
//
// It refuses, with ErrMalformed: a bare token with no scheme, any other scheme,
// more than one token, any control byte (TAB, CR and LF included), any byte
// outside printable ASCII, and an unsigned token whose signature segment is
// empty. A blank value is ErrMissing.
func Parse(authorization string) (string, error) {
	value := strings.Trim(authorization, " ")
	if value == "" {
		return "", ErrMissing
	}

	if len(value) > maxHeaderBytes || !printableASCII(value) {
		return "", ErrMalformed
	}

	gotScheme, rest, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(gotScheme, scheme) {
		return "", ErrMalformed
	}

	token := strings.TrimLeft(rest, " ")
	if token == "" || strings.Contains(token, " ") || len(token) > MaxTokenBytes {
		return "", ErrMalformed
	}

	if !threeBase64URLSegments(token) {
		return "", ErrMalformed
	}

	return token, nil
}

// printableASCII reports whether s holds only printable ASCII (0x20-0x7E). The
// check is explicit because base64 decoding silently skips CR and LF, so a
// header smuggling a line break would otherwise survive the segment check.
func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}

	return true
}

// threeBase64URLSegments reports whether token is exactly three non-empty,
// dot-separated segments, each decoding as unpadded base64url. That refuses "="
// padding and the standard "+" and "/" alphabet as well as the empty signature
// of an unsigned token.
func threeBase64URLSegments(token string) bool {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return false
	}

	for _, segment := range segments {
		if segment == "" {
			return false
		}

		if _, err := base64.RawURLEncoding.DecodeString(segment); err != nil {
			return false
		}
	}

	return true
}
