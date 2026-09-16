package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorize_V4WritesRefusalsWithoutCallingApplicationErrorHandler(t *testing.T) {
	t.Parallel()

	var errorHandlerCalls atomic.Int64
	newApp := func(auth *AuthClient) *fiber.App {
		app := fiber.New(fiber.Config{
			ErrorHandler: func(c fiber.Ctx, _ error) error {
				errorHandlerCalls.Add(1)

				return c.Status(http.StatusTeapot).SendString("application error handler")
			},
		})
		app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
			return c.SendString("reached handler")
		})

		return app
	}

	t.Run("missing token", func(t *testing.T) {
		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		resp, err := newApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}).
			Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("authorization denied", func(t *testing.T) {
		server := mockAuthServer(t, false, http.StatusOK)
		defer server.Close()

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+createTestJWT(normalUserClaims()))

		resp, err := newApp(&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}).Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	assert.Zero(t, errorHandlerCalls.Load(), "v4 refusals must not enter the consuming application's ErrorHandler")
}
