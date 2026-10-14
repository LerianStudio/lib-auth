package middleware

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkRequestApp serves /x with a handler that asks CheckRequest about its own
// request and writes back what it got: the status, and the decision in a header.
// The app carries the misconfigured proxy setup, so a forwarded header would
// leak through c.IP() if CheckRequest ever read it.
func checkRequestApp(auth *AuthClient) *fiber.App {
	app := fiber.New(misconfiguredProxyConfig())
	app.Get("/x", func(c fiber.Ctx) error {
		authorized, status, err := auth.CheckRequest(c, "midaz", "resource", "get")
		if err != nil {
			return c.Status(status).SendString(err.Error())
		}

		c.Set("X-Authorized", strconv.FormatBool(authorized))

		return c.SendStatus(status)
	})

	return app
}

func TestCheckRequest(t *testing.T) {
	t.Parallel()

	t.Run("trusted_chain_forwards_the_caller_ip_and_allows", func(t *testing.T) {
		t.Parallel()

		var capturedBody map[string]string

		auth := &AuthClient{
			Address:        bodyCapturingAuthServer(t, &capturedBody).URL,
			Enabled:        true,
			Logger:         &testLogger{},
			trustedProxies: mustPrefixes(t, testPeerCIDR, "10.0.0.0/8"),
		}

		resp := getThroughApp(t, checkRequestApp(auth), "203.0.113.7, 10.1.2.3")

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "true", resp.Header.Get("X-Authorized"))
		assert.Equal(t, "203.0.113.7", capturedBody["clientIp"])
	})

	t.Run("forwarded_header_from_an_untrusted_peer_is_ignored", func(t *testing.T) {
		t.Parallel()

		var capturedBody map[string]string

		auth := &AuthClient{
			Address:        bodyCapturingAuthServer(t, &capturedBody).URL,
			Enabled:        true,
			Logger:         &testLogger{},
			trustedProxies: mustPrefixes(t, "10.0.0.0/8"),
		}

		resp := getThroughApp(t, checkRequestApp(auth), "203.0.113.7")

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "0.0.0.0", capturedBody["clientIp"], "only the socket peer is attributable")
	})

	t.Run("denial_is_403_without_an_error", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, false, http.StatusOK)
		t.Cleanup(server.Close)

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		resp := getThroughApp(t, checkRequestApp(auth))

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Equal(t, "false", resp.Header.Get("X-Authorized"))
	})

	t.Run("nil_receiver_reports_authorized", func(t *testing.T) {
		t.Parallel()

		var auth *AuthClient

		resp := getThroughApp(t, checkRequestApp(auth))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "true", resp.Header.Get("X-Authorized"))
	})
}
