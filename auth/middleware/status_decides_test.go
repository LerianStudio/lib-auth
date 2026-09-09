package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// The invariant: only a 2xx answer from the Access Manager is an answer
// ---------------------------------------------------------------------------

// accessManagerServing stands in for an Access Manager that answers every
// authorization and every token request with one fixed status and body, so a test
// can pin what this library makes of a given wire answer. /health is carved out
// exactly as the other Access Manager stubs in this package carve it out.
func accessManagerServing(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, "healthy")

			return
		}

		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(statusCode)
		_, _ = io.WriteString(w, body)
	}))

	t.Cleanup(server.Close)

	return server
}

// TestAuthorize_OnlyA2xxIsAnAuthorizationDecision pins the invariant this library
// must never lose: the HTTP STATUS decides whether the Access Manager answered,
// never an optional field inside the body. A body field is optional by
// construction — the shared RFC 9457 problem document the Access Manager now
// serves on /v1/authorize omits `code` on every framework-generated refusal — so a
// library that reads one to tell "refused" from "decided" reads a coin flip.
//
// Every case below is a refusal, and every case is refused AT ITS OWN STATUS with
// the reason the Access Manager actually wrote. Before this pin, a refusal whose
// body carried no `code` fell through to the decision branch and rendered a flat
// 403 with the word "Forbidden", discarding both the status and the reason; a
// fully coded problem document rendered the bare status word, because the reason
// was read from `message` and the problem document writes it in `detail`.
func TestAuthorize_OnlyA2xxIsAnAuthorizationDecision(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// status and body are what the Access Manager puts on the wire.
		status int
		body   string
		// wantStatus and wantMessage are what the caller must read.
		wantStatus  int
		wantMessage string
	}{
		{
			// The shape /v1/authorize serves today: a problem document whose human
			// text lives in `detail`, never in `message`.
			name:        "problem_document_with_a_code",
			status:      http.StatusUnprocessableEntity,
			body:        `{"type":"https://errors.lerian.studio/v1/AUT-0007","title":"Unprocessable Entity","status":422,"detail":"resource must not be empty","code":"AUT-0007"}`,
			wantStatus:  http.StatusUnprocessableEntity,
			wantMessage: "resource must not be empty",
		},
		{
			// A framework-generated refusal: the request never reached the policy
			// engine, so no domain code was ever assigned. This is the case that used
			// to render 403 "Forbidden".
			name:        "problem_document_without_a_code",
			status:      http.StatusUnprocessableEntity,
			body:        `{"title":"Unprocessable Entity","status":422,"detail":"expected object, but received string"}`,
			wantStatus:  http.StatusUnprocessableEntity,
			wantMessage: "expected object, but received string",
		},
		{
			name:        "rate_limited",
			status:      http.StatusTooManyRequests,
			body:        `{"title":"Too Many Requests","status":429,"detail":"rate limit exceeded"}`,
			wantStatus:  http.StatusTooManyRequests,
			wantMessage: "rate limit exceeded",
		},
		{
			// A misconfigured PLUGIN_AUTH_ADDRESS reaches something that is not the
			// Access Manager. Nothing in the body is usable; the status still is.
			name:        "not_found_with_a_body_that_is_not_json",
			status:      http.StatusNotFound,
			body:        `<html><body>404 not found</body></html>`,
			wantStatus:  http.StatusNotFound,
			wantMessage: "Not Found",
		},
		{
			// The legacy envelope, still served by the Fiber-native routes: the reason
			// lives in `message`. Both shapes must be read.
			name:        "legacy_envelope_with_a_message",
			status:      http.StatusUnauthorized,
			body:        `{"entityType":"Auth","title":"Unauthorized","message":"token has expired","code":"AUT-0001"}`,
			wantStatus:  http.StatusUnauthorized,
			wantMessage: "token has expired",
		},
		{
			// A refusal carrying nothing at all still refuses, and still says
			// something rather than rendering an empty line.
			name:        "refusal_with_an_empty_body",
			status:      http.StatusBadRequest,
			body:        `{}`,
			wantStatus:  http.StatusBadRequest,
			wantMessage: "Bad Request",
		},
		{
			// The adversarial case. A grant smuggled into a refusal body is not a
			// grant: the status already said the service refused.
			name:        "refusal_whose_body_claims_authorized",
			status:      http.StatusForbidden,
			body:        `{"authorized":true}`,
			wantStatus:  http.StatusForbidden,
			wantMessage: "Forbidden",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := accessManagerServing(t, tc.status, tc.body)

			app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

			resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))

			// StatusTeapot is what newCapturingApp's handler writes: the refusal
			// reached the application's own ErrorHandler instead of a body written
			// past it.
			assert.Equal(t, http.StatusTeapot, resp.StatusCode)
			requireFiberError(t, capture.get(), tc.wantStatus, tc.wantMessage)
		})
	}
}

// TestAuthorize_A2xxDecisionStillDecides is the positive control for the pin
// above: reading the status first must not cost the library its ability to allow a
// request. A 200 carrying an allow still calls the next handler, and a 200 carrying
// a deny is still the plain 403 a policy denial has always been — the Access
// Manager answers a denied permission with 200 and authorized=false, not with 403.
func TestAuthorize_A2xxDecisionStillDecides(t *testing.T) {
	t.Parallel()

	t.Run("allow", func(t *testing.T) {
		t.Parallel()

		server := accessManagerServing(t, http.StatusOK, `{"authorized":true}`)

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NoError(t, capture.get())
	})

	t.Run("deny", func(t *testing.T) {
		t.Parallel()

		server := accessManagerServing(t, http.StatusOK, `{"authorized":false}`)

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusForbidden, "Forbidden")
	})

	t.Run("a_2xx_body_that_is_not_a_decision_is_an_outage", func(t *testing.T) {
		t.Parallel()

		// A 200 whose body cannot be read as a decision is the Access Manager
		// failing to answer, not an answer. It refuses, and it refuses as 503 so the
		// rail's operator reads an outage rather than a policy denial.
		server := accessManagerServing(t, http.StatusOK, `<html>not json</html>`)

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
	})
}
