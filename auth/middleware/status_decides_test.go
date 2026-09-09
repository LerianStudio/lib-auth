package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
// Every case below is a refusal OF THE CALLER, and every one is refused AT ITS OWN
// STATUS with the reason the Access Manager actually wrote. Before this pin, a
// refusal whose body carried no `code` fell through to the decision branch and
// rendered a flat 403 with the word "Forbidden", discarding both the status and
// the reason; a fully coded problem document rendered the bare status word,
// because the reason was read from `message` and the problem document writes it
// in `detail`.
//
// The statuses here are the ones the Access Manager emits ABOUT THE CALLER, and
// each is pinned with the domain code that produces it, so a later reader can
// check the claim against plugin-access-manager rather than trust this comment:
// 401 AUT-0006/AUT-0007 (token missing or invalid), 403 AUT-0021 (tenant IP
// allowlist), 404 AUT-1015 (no subject exists for the token's sub, raised on the
// normal-user hot path by both the single-tenant and multi-tenant enforcers in
// components/auth/internal/adapters/authserver/casdoor/casdoor_permission.go).
// The statuses that mean the service could not answer are pinned separately, in
// TestAuthorize_A4xxThatIsNotAboutTheCallerIs503.
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
			// text lives in `detail`, never in `message`. AUT-1015 is the Access
			// Manager's own "no subject for this sub" — a real 404 about the caller,
			// which is why 404 is NOT swept into the unavailable set.
			name:        "problem_document_with_a_code",
			status:      http.StatusNotFound,
			body:        `{"type":"https://errors.lerian.studio/v1/AUT-1015","title":"Enforcement Sub Not Found","status":404,"detail":"No subject was found for the provided 'sub'.","code":"AUT-1015"}`,
			wantStatus:  http.StatusNotFound,
			wantMessage: "No subject was found for the provided 'sub'.",
		},
		{
			// A refusal that never reached the policy engine, so no domain code was
			// ever assigned. This is the case that used to render 403 "Forbidden".
			name:        "problem_document_without_a_code",
			status:      http.StatusNotFound,
			body:        `{"title":"Not Found","status":404,"detail":"no subject for the supplied token"}`,
			wantStatus:  http.StatusNotFound,
			wantMessage: "no subject for the supplied token",
		},
		{
			// The tenant IP allowlist. A 403 on this route means AUT-0021, never a
			// plain permission denial — the Access Manager answers a denied permission
			// with 200 and authorized=false.
			name:        "ip_allowlist_denied_the_caller",
			status:      http.StatusForbidden,
			body:        `{"status":403,"detail":"caller address is not on the tenant allowlist","code":"AUT-0021"}`,
			wantStatus:  http.StatusForbidden,
			wantMessage: "caller address is not on the tenant allowlist",
		},
		{
			// A misconfigured PLUGIN_AUTH_ADDRESS reaches something that is not the
			// Access Manager. Nothing in the body is usable; the status still is. This
			// one renders 404 rather than 503 deliberately — see the test below for
			// why the alternative is worse.
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
			status:      http.StatusConflict,
			body:        `{}`,
			wantStatus:  http.StatusConflict,
			wantMessage: "Conflict",
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

// TestAuthorize_A4xxThatIsNotAboutTheCallerIs503 pins the other half of the line.
// Three 4xx statuses do NOT mean the caller was refused, so surfacing them at
// their own status tells the caller — and the operator — the wrong thing:
//
//   - 400 and 422: the Access Manager rejected the request BODY, and that body is
//     built entirely by this library. /v1/authorize declares no field constraint a
//     caller could violate, so these mean this library and the Access Manager
//     disagree about the contract. That is a deployment fault an operator must be
//     paged for, not a verdict to render to a customer.
//   - 429: the Access Manager's own rate limiter, whose permission tier is sized
//     for service callers — and the direct caller of /v1/authorize IS this service.
//     The end caller holds no such quota, so "slow down" is addressed to nobody.
//
// All three refuse, exactly as before; only the word changes, and 503 is the word
// that reaches a rail's 5xx alarms and lets the retry and breaker layers absorb a
// throttle.
func TestAuthorize_A4xxThatIsNotAboutTheCallerIs503(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"bad_request", http.StatusBadRequest, `{"status":400,"detail":"sub must be a string","code":"AUT-0009"}`},
		{"unprocessable_entity_with_a_code", http.StatusUnprocessableEntity, `{"status":422,"detail":"resource must not be empty","code":"AUT-0007"}`},
		{"unprocessable_entity_from_the_framework", http.StatusUnprocessableEntity, `{"title":"Unprocessable Entity","status":422,"detail":"expected object, but received string"}`},
		{"rate_limited", http.StatusTooManyRequests, `{"title":"Too Many Requests","status":429,"detail":"rate limit exceeded"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := accessManagerServing(t, tc.status, tc.body)

			app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

			resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
			assert.Equal(t, http.StatusTeapot, resp.StatusCode)
			requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
		})
	}
}

// TestAuthorize_EveryNon2xxStillRefuses is the safety pin for the split above. The
// line between "refused at its own status" and "503" decides only which WORD the
// caller reads. It must never decide whether the request proceeds: sweeping a
// status from one side to the other cannot introduce a grant, on any body,
// including a body that claims the caller was authorized.
func TestAuthorize_EveryNon2xxStillRefuses(t *testing.T) {
	t.Parallel()

	statuses := []int{
		http.StatusMovedPermanently, http.StatusBadRequest, http.StatusUnauthorized,
		http.StatusForbidden, http.StatusNotFound, http.StatusConflict,
		http.StatusUnprocessableEntity, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout,
	}

	// The most adversarial body available: a grant, in every error shape at once.
	body := `{"authorized":true,"code":"AUT-0021","message":"allowed","detail":"allowed","status":200}`

	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			server := accessManagerServing(t, status, body)

			app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

			resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))

			// Not StatusOK: the protected handler was never reached.
			require.Equal(t, http.StatusTeapot, resp.StatusCode,
				"a %d must never reach the protected handler", status)
			require.Error(t, capture.get(), "a %d must always produce a refusal", status)
		})
	}
}
