package middleware

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetApplicationToken_OnlyA2xxCarriesAToken pins the same invariant on the
// token path, where losing it is sharper: the caller receives a bearer, not a
// decision, so a failure reported as success hands out an EMPTY bearer with a nil
// error. The declaration publisher reads exactly that pair as "auth is disabled or
// misconfigured" and stops retrying permanently, so a transient refusal at boot
// used to become a permanent give-up.
func TestGetApplicationToken_OnlyA2xxCarriesAToken(t *testing.T) {
	t.Parallel()

	// Every body below unmarshals cleanly into the token model and yields an empty
	// access token — which is exactly why the emptiness of a body field could never
	// be the test for failure.
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"problem_document_without_a_code", http.StatusUnauthorized, `{"title":"Unauthorized","status":401,"detail":"invalid client credentials"}`},
		{"problem_document_with_a_code", http.StatusUnauthorized, `{"status":401,"detail":"invalid client credentials","code":"AUT-0001"}`},
		{"legacy_envelope", http.StatusBadRequest, `{"code":"AUT-0004","message":"grantType is required"}`},
		{"empty_json_object", http.StatusUnprocessableEntity, `{}`},
		{"internal_server_error_with_a_code", http.StatusInternalServerError, `{"code":"AUT-0500","message":"internal error"}`},
		{"bad_gateway_from_an_ingress", http.StatusBadGateway, `{"error":"upstream unavailable"}`},
		{"not_found", http.StatusNotFound, `{}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := accessManagerServing(t, tc.status, tc.body)

			auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

			token, err := auth.GetApplicationToken(context.Background(), "client-id", "client-secret")
			require.Error(t, err, "a %d must never be reported as a successful login", tc.status)
			assert.Empty(t, token)
			assert.NotEmpty(t, err.Error(), "a refusal must say something a caller can log")
		})
	}

	t.Run("reason_is_read_from_the_problem_document", func(t *testing.T) {
		t.Parallel()

		server := accessManagerServing(t, http.StatusUnauthorized, `{"status":401,"detail":"invalid client credentials","code":"AUT-0001"}`)

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		_, err := auth.GetApplicationToken(context.Background(), "client-id", "client-secret")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid client credentials")
	})

	t.Run("a_2xx_with_no_token_is_a_failure", func(t *testing.T) {
		t.Parallel()

		server := accessManagerServing(t, http.StatusOK, `{}`)

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		token, err := auth.GetApplicationToken(context.Background(), "client-id", "client-secret")
		require.Error(t, err, "an empty bearer is not a successful login")
		assert.Empty(t, token)
	})

	t.Run("a_2xx_with_a_token_still_succeeds", func(t *testing.T) {
		t.Parallel()

		server := accessManagerServing(t, http.StatusOK, `{"accessToken":"the-token","tokenType":"Bearer","expiresIn":3600}`)

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		token, err := auth.GetApplicationToken(context.Background(), "client-id", "client-secret")
		require.NoError(t, err)
		assert.Equal(t, "the-token", token)
	})

	t.Run("auth_disabled_still_yields_an_empty_token_and_no_error", func(t *testing.T) {
		t.Parallel()

		// The one place ("", nil) is correct, and it is decided before any request
		// leaves: the declaration publisher relies on it to tell "auth is off" from
		// "the login failed".
		auth := &AuthClient{Enabled: false, Logger: &testLogger{}}

		token, err := auth.GetApplicationToken(context.Background(), "client-id", "client-secret")
		require.NoError(t, err)
		assert.Empty(t, token)
	})
}
