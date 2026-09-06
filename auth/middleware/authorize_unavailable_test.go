package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Authorize - an Access Manager that could not decide is 503, never 403/500
// ---------------------------------------------------------------------------

// unavailableAccessManager stands in for an Access Manager that is reachable on
// /health but answers every authorization with a 5xx. body is written verbatim, so
// a test can choose between the two 5xx shapes that used to render differently:
// an empty body (unparseable -> the old 500) and a JSON body (parseable -> the old
// 403). It counts /v1/authorize hits so a test can prove a breaker short-circuited.
func unavailableAccessManager(t *testing.T, body string) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, "healthy")

			return
		}

		hits.Add(1)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, body)
	}))

	t.Cleanup(server.Close)

	return server, &hits
}

// TestAuthorize_UnavailableAccessManagerReturns503 pins FC-10: fail-closed is
// right, but the word matters. When the Access Manager never produced an answer —
// transport failure, 5xx, retries exhausted, breaker open — Authorize must refuse
// with 503, so the rail's operator reads "the authorization service is down"
// instead of "you are Forbidden", and the outage shows up in 5xx alarms.
func TestAuthorize_UnavailableAccessManagerReturns503(t *testing.T) {
	t.Parallel()

	t.Run("service_answers_5xx_with_an_unparseable_body", func(t *testing.T) {
		t.Parallel()

		server, _ := unavailableAccessManager(t, "")

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
	})

	t.Run("service_answers_5xx_with_a_decision_body", func(t *testing.T) {
		t.Parallel()

		// An ALLOW in a 5xx body is the fail-OPEN this change closes: the legacy
		// result carried (true, 5xx, nil) and Authorize called the next handler. An
		// answer the service could not stand behind is not an answer.
		server, _ := unavailableAccessManager(t, `{"authorized":true}`)

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
	})

	t.Run("service_is_unreachable", func(t *testing.T) {
		t.Parallel()

		// A closed server leaves an address nothing listens on: the dial is refused,
		// which is the transport failure a real outage produces.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeAuthorized(w, true)
		}))
		server.Close()

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
	})

	t.Run("coded_5xx_body_is_503_not_the_coded_status", func(t *testing.T) {
		t.Parallel()

		// The one branch where the resolution carries BOTH a coded error and the
		// outage: a 5xx is never an authoritative refusal, so the outage wins and the
		// body's envelope is discarded rather than rendered as a policy answer.
		server := mockAccessManagerErrorBody(t, http.StatusBadGateway, map[string]string{
			"code":    "X",
			"title":   "T",
			"message": "M",
		})
		defer server.Close()

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)

		err := capture.get()
		requireFiberError(t, err, http.StatusServiceUnavailable, "Service Unavailable")

		var commonsErr commons.Response

		assert.False(t, errors.As(err, &commonsErr),
			"a 5xx body must not reach the caller as a coded refusal it can render as a decision")
	})

	t.Run("breaker_open", func(t *testing.T) {
		t.Parallel()

		server, hits := unavailableAccessManager(t, "")

		app, capture := newCapturingApp(&AuthClient{
			Address: server.URL,
			Enabled: true,
			Logger:  &testLogger{},
			breaker: newAuthBreaker(1, time.Minute),
		})

		token := createTestJWT(normalUserClaims())

		// The first 5xx trips the breaker; the second request never leaves the process.
		gatedRequest(t, app, token)

		resp := gatedRequest(t, app, token)
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
		assert.Equal(t, int64(1), hits.Load(), "an open breaker must short-circuit, not reach the Access Manager")
	})
}

// TestAuthorize_RetriesExhaustedReturns503 drives the same outage through a client
// built the way a deployment builds one — from the environment — so the 503 is
// pinned on the configured retry path, not only on a hand-assembled client.
func TestAuthorize_RetriesExhaustedReturns503(t *testing.T) {
	// Cannot use t.Parallel(): t.Setenv.
	t.Setenv("AUTH_JWT_VERIFY_CERT", "")
	t.Setenv("AUTH_JWT_VERIFY_CERT_PATH", "")
	t.Setenv("AUTH_BREAKER_ENABLED", "")
	t.Setenv("AUTH_RETRY_MAX", "1")
	t.Setenv("AUTH_TIMEOUT", "2s")

	server, hits := unavailableAccessManager(t, "")

	auth := NewAuthClient(server.URL, true, &testLogger{})
	require.EqualValues(t, 1, auth.retryMax, "the retry layer must be configured for this test to mean anything")

	app, capture := newCapturingApp(auth)

	resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
	assert.Equal(t, int64(2), hits.Load(), "the retry budget must be spent before the outage is reported")
}

// TestAuthorize_AnsweredRefusalsKeepTheirStatus is the other half of FC-10: only an
// Access Manager that could NOT decide becomes 503. A refusal it actually answered
// keeps the status it answered with, and a coded body stays recoverable.
func TestAuthorize_AnsweredRefusalsKeepTheirStatus(t *testing.T) {
	t.Parallel()

	t.Run("coded_403_body_stays_403", func(t *testing.T) {
		t.Parallel()

		server := mockAccessManagerErrorBody(t, http.StatusForbidden, map[string]string{
			"code":    "FORBIDDEN",
			"title":   "Forbidden",
			"message": "You do not have permission",
		})
		defer server.Close()

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)

		err := capture.get()
		requireFiberError(t, err, http.StatusForbidden, "You do not have permission")

		var commonsErr commons.Response

		require.True(t, errors.As(err, &commonsErr), "a coded refusal must stay recoverable as commons.Response")
		assert.Equal(t, "FORBIDDEN", commonsErr.Code)
	})

	t.Run("plain_denial_stays_403", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, false, http.StatusOK)
		defer server.Close()

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusForbidden, "Forbidden")
	})
}

// TestAuthorize_DefaultErrorHandlerRendersTheOutage is what a rail that never
// customized its ErrorHandler puts on the wire during an Access Manager outage.
func TestAuthorize_DefaultErrorHandlerRendersTheOutage(t *testing.T) {
	t.Parallel()

	server, _ := unavailableAccessManager(t, "")

	app := fiber.New()
	app.Get("/x", (&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}).
		Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Service Unavailable", string(body))
}
