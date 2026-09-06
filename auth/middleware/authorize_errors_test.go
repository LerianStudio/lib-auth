package middleware

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Authorize - refusals are RETURNED, never written
// ---------------------------------------------------------------------------

// errCapture holds the error a Fiber ErrorHandler received. app.Test serves the
// request on another goroutine, so the handoff is mutex-guarded rather than a
// bare field.
type errCapture struct {
	mu  sync.Mutex
	err error
}

func (e *errCapture) set(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.err = err
}

func (e *errCapture) get() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.err
}

// newCapturingApp mounts Authorize behind an ErrorHandler that keeps the error
// instead of rendering it — what a consuming rail's own handler does before
// writing its problem+json envelope. The status it writes (418) is deliberately
// one Authorize never produces, so a test that reads it knows the error reached
// the application handler rather than a body written past it.
func newCapturingApp(auth *AuthClient) (*fiber.App, *errCapture) {
	capture := &errCapture{}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			capture.set(err)

			return c.SendStatus(http.StatusTeapot)
		},
	})

	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	return app, capture
}

// gatedRequest drives GET /x through app, sending a bearer token only when one is
// given so the missing-token refusals stay reachable.
func gatedRequest(t *testing.T, app *fiber.App, token string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := app.Test(req)
	require.NoError(t, err)

	return resp
}

// mockAccessManagerErrorBody stands in for an Access Manager that answers a coded
// error body instead of a plain decision.
func mockAccessManagerErrorBody(t *testing.T, status int, body map[string]string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)

		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("mock access manager: failed to encode response: %v", err)
		}
	}))
}

func requireFiberError(t *testing.T, err error, code int, message string) {
	t.Helper()

	require.Error(t, err)

	var fe *fiber.Error

	require.True(t, errors.As(err, &fe), "a refusal must resolve to *fiber.Error, got %T", err)
	assert.Equal(t, code, fe.Code)
	assert.Equal(t, message, fe.Message)
}

// TestAuthorize_RefusalsAreReturnedAsFiberErrors pins the contract every consuming
// rail depends on: Authorize never writes a refusal body itself, so the service's
// own ErrorHandler renders it and keeps its RFC 9457 envelope. Each site keeps the
// status and the message text it wrote before.
func TestAuthorize_RefusalsAreReturnedAsFiberErrors(t *testing.T) {
	t.Parallel()

	t.Run("required_and_disabled_returns_503", func(t *testing.T) {
		t.Parallel()

		app, capture := newCapturingApp(&AuthClient{Enabled: false, Required: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, "")
		assert.Equal(t, http.StatusTeapot, resp.StatusCode, "the application handler rendered the refusal")
		requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
	})

	t.Run("enabled_without_address_returns_503", func(t *testing.T) {
		t.Parallel()

		app, capture := newCapturingApp(&AuthClient{
			Address:                       "",
			Enabled:                       true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
	})

	t.Run("missing_token_returns_401", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, "")
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusUnauthorized, "Missing Token")
	})

	t.Run("denial_returns_403", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, false, http.StatusOK)
		defer server.Close()

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusForbidden, "Forbidden")
	})

	t.Run("decoded_access_manager_error_stays_recoverable", func(t *testing.T) {
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

		require.True(t, errors.As(err, &commonsErr),
			"the decoded Access Manager body must stay recoverable by a consumer that knows lib-commons")
		assert.Equal(t, "FORBIDDEN", commonsErr.Code)
		assert.Equal(t, "Forbidden", commonsErr.Title)
		assert.Equal(t, "You do not have permission", commonsErr.Message)
	})

	t.Run("local_token_failure_returns_the_status_text", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		app, capture := newCapturingApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})

		resp := gatedRequest(t, app, "not-a-valid-jwt")
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	})

	t.Run("no_round_trip_missing_token_returns_401", func(t *testing.T) {
		t.Parallel()

		app, capture := newCapturingApp(&AuthClient{
			Enabled:                       false,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		})

		resp := gatedRequest(t, app, "")
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusUnauthorized, "Missing Token")
	})

	t.Run("no_round_trip_derivation_failure_returns_the_status_text", func(t *testing.T) {
		t.Parallel()

		app, capture := newCapturingApp(&AuthClient{
			Enabled:                       false,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		})

		resp := gatedRequest(t, app, "not-a-valid-jwt")
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
		requireFiberError(t, capture.get(), http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	})
}

// TestAuthorize_DefaultErrorHandlerRendersTheRefusals is the other half of the
// contract: a service that never customized its ErrorHandler must see the same
// wire response it saw when Authorize wrote the body itself. Fiber's
// DefaultErrorHandler resolves the *fiber.Error through errors.As, so status and
// message survive the switch from written to returned.
//
// The one deliberate change is the decoded Access Manager error: its body was the
// JSON encoding of commons.Response and is now that response's message as text,
// because Fiber's default handler renders text. A consumer that wants the JSON
// envelope back recovers the commons.Response with errors.As in its own handler.
func TestAuthorize_DefaultErrorHandlerRendersTheRefusals(t *testing.T) {
	t.Parallel()

	newDefaultApp := func(auth *AuthClient) *fiber.App {
		app := fiber.New()

		app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
			return c.SendString("reached handler")
		})

		return app
	}

	assertResponse := func(t *testing.T, resp *http.Response, status int, body string) {
		t.Helper()

		assert.Equal(t, status, resp.StatusCode)

		read, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(read))
	}

	t.Run("required_and_disabled", func(t *testing.T) {
		t.Parallel()

		app := newDefaultApp(&AuthClient{Enabled: false, Required: true, Logger: &testLogger{}})
		assertResponse(t, gatedRequest(t, app, ""), http.StatusServiceUnavailable, "Service Unavailable")
	})

	t.Run("missing_token", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		app := newDefaultApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})
		assertResponse(t, gatedRequest(t, app, ""), http.StatusUnauthorized, "Missing Token")
	})

	t.Run("denial", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, false, http.StatusOK)
		defer server.Close()

		app := newDefaultApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})
		assertResponse(t, gatedRequest(t, app, createTestJWT(normalUserClaims())), http.StatusForbidden, "Forbidden")
	})

	t.Run("local_token_failure", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		app := newDefaultApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})
		assertResponse(t, gatedRequest(t, app, "not-a-valid-jwt"),
			http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	})

	t.Run("decoded_access_manager_error_renders_status_and_message", func(t *testing.T) {
		t.Parallel()

		server := mockAccessManagerErrorBody(t, http.StatusForbidden, map[string]string{
			"code":    "FORBIDDEN",
			"title":   "Forbidden",
			"message": "You do not have permission",
		})
		defer server.Close()

		app := newDefaultApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})
		assertResponse(t, gatedRequest(t, app, createTestJWT(normalUserClaims())),
			http.StatusForbidden, "You do not have permission")
	})

	t.Run("decoded_access_manager_error_without_a_message_falls_back_to_the_title", func(t *testing.T) {
		t.Parallel()

		server := mockAccessManagerErrorBody(t, http.StatusConflict, map[string]string{
			"code":  "CONFLICT",
			"title": "Conflicting Request",
		})
		defer server.Close()

		app := newDefaultApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}})
		assertResponse(t, gatedRequest(t, app, createTestJWT(normalUserClaims())),
			http.StatusConflict, "Conflicting Request")
	})
}
