package middleware

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	observability "github.com/LerianStudio/lib-observability/v4"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// createTestJWT builds a signed JWT string for testing.
// checkAuthorization uses ParseUnverified so the signing key does not matter.
func createTestJWT(claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		// This should never happen in tests with a valid key.
		panic("failed to sign test JWT: " + err.Error())
	}

	return signed
}

// mockAuthServer returns an httptest.Server that responds to POST /v1/authorize.
func mockAuthServer(t *testing.T, authorized bool, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		resp := AuthResponse{Authorized: authorized}

		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Errorf("mock server: failed to encode response: %v", err)
		}
	}))
}

// testLogger is a minimal obs.Logger implementation for tests that discards all
// output. It is declared with universal types only and imports nothing from
// lib-observability, which is the property auth/obs exists to make possible.
type testLogger struct{}

func (l *testLogger) Log(_ context.Context, _ int, _ string, _ ...any) {}
func (l *testLogger) Enabled(_ int) bool                               { return false }
func (l *testLogger) Sync(_ context.Context) error                     { return nil }

// ---------------------------------------------------------------------------
// checkAuthorization - subject construction
// ---------------------------------------------------------------------------

func TestCheckAuthorization_NormalUser_SubjectConstruction(t *testing.T) {
	t.Parallel()

	// Mock server captures the request body to verify the constructed subject.
	var capturedBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&capturedBody)
		if err != nil {
			t.Errorf("mock server: failed to decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := AuthResponse{Authorized: true}

		encErr := json.NewEncoder(w).Encode(resp)
		if encErr != nil {
			t.Errorf("mock server: failed to encode response: %v", encErr)
		}
	}))
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)

	// For normal-user, sub is the JWT identity "owner/userId", not the product.
	assert.Equal(t, "acme-org/user123", capturedBody["sub"])
	// The product is forwarded so the auth service can isolate by product.
	assert.Equal(t, "midaz", capturedBody["product"])
}

func TestCheckAuthorization_ApplicationUser_SubjectConstruction(t *testing.T) {
	t.Parallel()

	// Application (M2M) tokens are identified by their real sub claim (already in
	// "owner/name" form); no product-editor-role is fabricated and product is not forwarded.
	var capturedBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&capturedBody)
		if err != nil {
			t.Errorf("mock server: failed to decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := AuthResponse{Authorized: true}

		encErr := json.NewEncoder(w).Encode(resp)
		if encErr != nil {
			t.Errorf("mock server: failed to encode response: %v", encErr)
		}
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
	}

	token := createTestJWT(jwt.MapClaims{
		"type": "application",
		"name": "my-app",
		"sub":  "app-sub",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "my-app", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)

	// For M2M, the subject is the real sub claim of the application token.
	assert.Equal(t, "app-sub", capturedBody["sub"])
	// Product is NOT forwarded for application tokens when ForwardM2MProduct is off (default).
	_, hasProduct := capturedBody["product"]
	assert.False(t, hasProduct)
}

func TestCheckAuthorization_Application_ForwardM2MProductEnabled_ForwardsProduct(t *testing.T) {
	t.Parallel()

	// With ForwardM2MProduct enabled, an application (M2M) token forwards the route
	// product so the auth service can strip the "{product}/" prefix from stored
	// resources and dual-match a bare request. The subject stays the real sub claim.
	var capturedBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&capturedBody)
		if err != nil {
			t.Errorf("mock server: failed to decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := AuthResponse{Authorized: true}

		encErr := json.NewEncoder(w).Encode(resp)
		if encErr != nil {
			t.Errorf("mock server: failed to encode response: %v", encErr)
		}
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		ForwardM2MProduct:   true,
		M2MInversionEnabled: true,
	}

	token := createTestJWT(jwt.MapClaims{
		"type": "application",
		"name": "my-app",
		"sub":  "acme-org/my-app",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)

	// Subject is still the real sub of the application token.
	assert.Equal(t, "acme-org/my-app", capturedBody["sub"])
	// Product IS forwarded for M2M when ForwardM2MProduct is enabled.
	assert.Equal(t, "midaz", capturedBody["product"])
}

func TestCheckAuthorization_Application_ForwardM2MProductEnabled_EmptyProduct_NotForwarded(t *testing.T) {
	t.Parallel()

	// Even with ForwardM2MProduct enabled, an empty product is never forwarded
	// (gate-by-presence preserved).
	var capturedBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&capturedBody)
		if err != nil {
			t.Errorf("mock server: failed to decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := AuthResponse{Authorized: true}

		encErr := json.NewEncoder(w).Encode(resp)
		if encErr != nil {
			t.Errorf("mock server: failed to encode response: %v", encErr)
		}
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		ForwardM2MProduct:   true,
		M2MInversionEnabled: true,
	}

	token := createTestJWT(jwt.MapClaims{
		"type": "application",
		"name": "my-app",
		"sub":  "acme-org/my-app",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)

	_, hasProduct := capturedBody["product"]
	assert.False(t, hasProduct)
}

func TestCheckAuthorization_MissingOwnerClaim(t *testing.T) {
	t.Parallel()

	server := mockAuthServer(t, true, http.StatusOK)
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	// normal-user without "owner" claim should cause an error.
	token := createTestJWT(jwt.MapClaims{
		"type": "normal-user",
		"sub":  "user123",
		// "owner" is intentionally missing
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "sub", "resource", "action", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Contains(t, err.Error(), "missing owner claim")
}

func TestCheckAuthorization_MissingSubClaim(t *testing.T) {
	t.Parallel()

	// The auth backend must never be reached: a missing-sub token has to fail
	// closed in checkAuthorization before any request is made.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("auth backend must not be called when the sub claim is missing")
	}))
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	// normal-user without "sub" claim must fail closed instead of emitting "<owner>/".
	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		// "sub" is intentionally missing
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Contains(t, err.Error(), "missing sub claim")
}

func TestCheckAuthorization_NormalUser_EmptyProduct_NotForwarded(t *testing.T) {
	t.Parallel()

	// With an empty product the previous behavior must be preserved: the subject
	// is still the JWT identity and no "product" field is forwarded (gate-by-presence).
	var capturedBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&capturedBody)
		if err != nil {
			t.Errorf("mock server: failed to decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := AuthResponse{Authorized: true}

		encErr := json.NewEncoder(w).Encode(resp)
		if encErr != nil {
			t.Errorf("mock server: failed to encode response: %v", encErr)
		}
	}))
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)

	// Subject is still the JWT identity, unchanged by the empty product.
	assert.Equal(t, "acme-org/user123", capturedBody["sub"])
	// No product forwarded when product is empty.
	_, hasProduct := capturedBody["product"]
	assert.False(t, hasProduct)
}

func TestCheckAuthorization_MockServerReturnsAuthorizedTrue(t *testing.T) {
	t.Parallel()

	server := mockAuthServer(t, true, http.StatusOK)
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "org1",
		"sub":   "user1",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "sub", "resource", "read", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
}

func TestCheckAuthorization_MockServerReturnsAuthorizedFalse(t *testing.T) {
	t.Parallel()

	server := mockAuthServer(t, false, http.StatusOK)
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "org1",
		"sub":   "user1",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "sub", "resource", "read", token, "",
	)

	require.NoError(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
}

func TestCheckAuthorization_MockServerReturnsForbiddenWithErrorBody(t *testing.T) {
	t.Parallel()

	// When the auth server returns a non-200 response with a Response body that
	// has a non-empty Code field, checkAuthorization returns an error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)

		resp := map[string]string{
			"code":    "FORBIDDEN",
			"title":   "Forbidden",
			"message": "You do not have permission",
		}

		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Errorf("mock server: failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "org1",
		"sub":   "user1",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "sub", "resource", "write", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusForbidden, statusCode)
}

func TestCheckAuthorization_InvalidToken(t *testing.T) {
	t.Parallel()

	server := mockAuthServer(t, true, http.StatusOK)
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	// Completely invalid JWT string that cannot be parsed.
	invalidToken := "not-a-valid-jwt"

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "sub", "resource", "action", invalidToken, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestCheckAuthorization_EmptyTypeClaim_Rejected(t *testing.T) {
	t.Parallel()

	// When the "type" claim is empty or absent it is not in the whitelist
	// {normal-user, application}, so the request must fail closed with 401 and
	// the auth backend must never be reached.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("auth backend must not be called when the type claim is absent")
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
	}

	// No "type" claim at all -> defaults to empty string -> not whitelisted.
	token := createTestJWT(jwt.MapClaims{
		"sub": "some-app",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "some-app", "resource", "action", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Contains(t, err.Error(), "unsupported token type")
}

func TestCheckAuthorization_ApplicationUser_MissingSubClaim_FailsClosed(t *testing.T) {
	t.Parallel()

	// An application token without a "sub" claim must fail closed with 401 before
	// the auth backend is reached.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("auth backend must not be called when the application sub claim is missing")
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
	}

	token := createTestJWT(jwt.MapClaims{
		"type": "application",
		"name": "my-app",
		// "sub" is intentionally missing
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "my-app", "resource", "action", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Contains(t, err.Error(), "missing sub claim")
}

func TestCheckAuthorization_NonCanonicalType_Rejected(t *testing.T) {
	t.Parallel()

	// Any type outside the whitelist {normal-user, application} must fail closed
	// with 401 and never reach the auth backend.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("auth backend must not be called for a non-canonical token type")
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "service-account",
		"owner": "acme-org",
		"sub":   "svc-1",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Contains(t, err.Error(), "unsupported token type")
}

func TestCheckAuthorization_MockServerDown(t *testing.T) {
	t.Parallel()

	// Use a server and immediately close it to simulate a connection failure.
	server := mockAuthServer(t, true, http.StatusOK)
	server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "org1",
		"sub":   "user1",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "sub", "resource", "read", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusInternalServerError, statusCode)
	assert.Contains(t, err.Error(), "failed to make request")
}

func TestCheckAuthorization_ServerReturnsInvalidJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write invalid JSON
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "org1",
		"sub":   "user1",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "sub", "resource", "read", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	// 503, not 500: a 2xx body that cannot be read as a decision is the Access
	// Manager failing to decide, not this library failing internally.
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

// ---------------------------------------------------------------------------
// NewAuthClient - ForwardM2MProduct flag
// ---------------------------------------------------------------------------

// unsetEnvForTest makes key absent for the duration of the test and restores the
// pre-test state — including "it was unset" — through t.Setenv's own cleanup.
// Go 1.26 has no t.Unsetenv and t.Setenv cannot express absence, so the pairing is
// deliberate: t.Setenv registers the restore, then os.Unsetenv removes the key so
// os.LookupEnv reports ok=false. This is the only way to exercise the "unset"
// branch of a LookupEnv-based default; an empty string does NOT reach it.
func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()

	t.Setenv(key, "")

	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("failed to unset %s: %v", key, err)
	}
}

func TestNewAuthClient_ReadsForwardM2MProductFlag(t *testing.T) {
	// Cannot use t.Parallel(): subtests mutate process env (t.Setenv/os.Unsetenv).
	// enabled=false / empty address returns early without any network call, so the
	// flag wiring is exercised in isolation.
	const (
		envForward   = "AUTH_M2M_PRODUCT_FORWARD_ENABLED"
		envInversion = "AUTH_M2M_INVERSION_ENABLED"
	)

	logger := &testLogger{}

	tests := []struct {
		name        string
		forward     string // meaningful only when forwardSet is true
		forwardSet  bool   // false = the variable is absent from the environment
		wantForward bool
	}{
		{name: "flag_absent_defaults_false", forwardSet: false, wantForward: false},
		{name: "flag_true_enables_forward", forward: "true", forwardSet: true, wantForward: true},
		{name: "flag_explicit_false_disables_forward", forward: "false", forwardSet: true, wantForward: false},
		{name: "flag_empty_value_is_false", forward: "", forwardSet: true, wantForward: false},
		{name: "flag_non_true_value_is_false", forward: "1", forwardSet: true, wantForward: false},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			// The forward flag is read independently of the inversion flag, so pin
			// the inversion flag to absent: an ambient value in the developer's or
			// CI's environment must never be able to move this result.
			unsetEnvForTest(t, envInversion)

			if tt.forwardSet {
				t.Setenv(envForward, tt.forward)
			} else {
				unsetEnvForTest(t, envForward)
			}

			client := NewAuthClient("", false, logger)

			assert.Equal(t, tt.wantForward, client.ForwardM2MProduct, "ForwardM2MProduct")
		})
	}
}

// ---------------------------------------------------------------------------
// NewAuthClient - Required (AUTH_REQUIRED) flag
// ---------------------------------------------------------------------------

func TestNewAuthClient_ReadsRequiredFlag(t *testing.T) {
	// Cannot use t.Parallel(): subtests use t.Setenv which modifies process env.
	// enabled=false / empty address returns early without any network call, so the
	// flag wiring is exercised in isolation.
	logger := &testLogger{}

	t.Run("flag_true_enables_required", func(t *testing.T) {
		t.Setenv("AUTH_REQUIRED", "true")

		client := NewAuthClient("", false, logger)
		assert.True(t, client.Required)
	})

	t.Run("flag_absent_defaults_false", func(t *testing.T) {
		t.Setenv("AUTH_REQUIRED", "")

		client := NewAuthClient("", false, logger)
		assert.False(t, client.Required)
	})

	t.Run("flag_non_true_value_is_false", func(t *testing.T) {
		t.Setenv("AUTH_REQUIRED", "1")

		client := NewAuthClient("", false, logger)
		assert.False(t, client.Required)
	})
}

// ---------------------------------------------------------------------------
// Authorize - fail-closed (AUTH_REQUIRED) posture
// ---------------------------------------------------------------------------

func TestAuthorize_FailClosed(t *testing.T) {
	t.Parallel()

	const reached = "reached handler"

	newApp := func(auth *AuthClient) *fiber.App {
		app := fiber.New()
		app.Get("/x", auth.Authorize("product", "resource", "get"), func(c fiber.Ctx) error {
			return c.SendString(reached)
		})

		return app
	}

	t.Run("required_and_disabled_refuses_with_503", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Enabled: false, Required: true, Logger: &testLogger{}}

		resp, err := newApp(auth).Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("required_and_empty_address_refuses_with_503", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Address: "", Enabled: true, Required: true, Logger: &testLogger{}}

		resp, err := newApp(auth).Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("not_required_and_disabled_passes_through", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Enabled: false, Required: false, Logger: &testLogger{}}

		resp, err := newApp(auth).Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, reached, string(body))
	})

	t.Run("required_and_enabled_authorizes_normally", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Required: true, Logger: &testLogger{}}

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+createTestJWT(jwt.MapClaims{
			"type":  "normal-user",
			"owner": "org1",
			"sub":   "user1",
		}))

		resp, err := newApp(auth).Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, reached, string(body))
	})
}

// ---------------------------------------------------------------------------
// Authorize - client IP forwarding (clientIp)
// ---------------------------------------------------------------------------

// TestAuthorize_ForwardsClientIP drives a request through the Fiber Authorize
// middleware and asserts the caller IP derived by the middleware is forwarded to
// the authorize endpoint as an OPTIONAL "clientIp" body field: present (== the
// derived IP) when one is available, and ABSENT when it is empty so the wire
// body stays byte-identical to today for every deployed access-manager. The
// derivation itself (and its trusted-proxy inputs) is covered in clientip_test.go.
func TestAuthorize_ForwardsClientIP(t *testing.T) {
	t.Parallel()

	// newApp builds a Fiber app carrying the trusted-proxy config a correctly
	// configured service sets. The middleware no longer reads it — it derives the
	// caller IP from its own TRUSTED_PROXIES list (testPeerCIDR below, matching the
	// in-memory test connection's 0.0.0.0 peer) — but keeping it here shows the two
	// agree when the service IS configured.
	newApp := func(auth *AuthClient) *fiber.App {
		app := fiber.New(fiber.Config{
			TrustProxy:       true,
			TrustProxyConfig: fiber.TrustProxyConfig{Proxies: []string{"0.0.0.0"}},
			ProxyHeader:      fiber.HeaderXForwardedFor,
		})
		app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
			return c.SendString("reached handler")
		})

		return app
	}

	newCapturingServer := func(t *testing.T, captured *map[string]string) *httptest.Server {
		t.Helper()

		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(captured); err != nil {
				t.Errorf("mock server: failed to decode request body: %v", err)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			if err := json.NewEncoder(w).Encode(AuthResponse{Authorized: true}); err != nil {
				t.Errorf("mock server: failed to encode response: %v", err)
			}
		}))
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	})

	t.Run("forwards_resolved_client_ip", func(t *testing.T) {
		t.Parallel()

		var capturedBody map[string]string

		server := newCapturingServer(t, &capturedBody)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}, trustedProxies: mustPrefixes(t, testPeerCIDR)}

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(fiber.HeaderXForwardedFor, "203.0.113.7")

		resp, err := newApp(auth).Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// The resolved caller IP is forwarded as the optional clientIp field.
		assert.Equal(t, "203.0.113.7", capturedBody["clientIp"])
	})

	t.Run("omits_client_ip_when_empty", func(t *testing.T) {
		t.Parallel()

		var capturedBody map[string]string

		server := newCapturingServer(t, &capturedBody)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}, trustedProxies: mustPrefixes(t, testPeerCIDR)}

		// No X-Forwarded-For header: the only hop is the test connection's
		// 0.0.0.0, which the client lists as a trusted proxy, so the walk skips it
		// and no untrusted address remains -> the derived IP is "" -> key
		// omitted. This is not a harness quirk: it mirrors fully-internal
		// traffic, where every hop is a trusted proxy and no caller IP can be
		// attributed, which is exactly what the empty-value guard exists for.
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := newApp(auth).Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		_, hasClientIP := capturedBody["clientIp"]
		assert.False(t, hasClientIP, "clientIp must be absent when the resolved IP is empty")
	})
}

// TestAuthorize_DecisionCache_ScopedByClientIP proves the in-memory decision
// cache keys entries by client IP, so an "authorized" decision cached for an
// ALLOWED source IP is never served to a request from a DIFFERENT (blocked) IP
// with the same {sub,resource,action,product}. The /v1/authorize decision is
// IP-dependent (tenant IP-allowlist), so a cross-IP cache hit would bypass the
// allowlist entirely. Same-IP requests must still be served from cache.
func TestAuthorize_DecisionCache_ScopedByClientIP(t *testing.T) {
	t.Parallel()

	const (
		allowedIP = "203.0.113.7"
		blockedIP = "198.51.100.9"
	)

	// newApp builds a Fiber app fronted by a trusted proxy (the in-memory test
	// connection's 0.0.0.0 peer, listed in the client's TRUSTED_PROXIES fixture),
	// so a test can drive a known client IP through X-Forwarded-For.
	newApp := func(auth *AuthClient) *fiber.App {
		app := fiber.New(fiber.Config{
			TrustProxy:       true,
			TrustProxyConfig: fiber.TrustProxyConfig{Proxies: []string{"0.0.0.0"}},
			ProxyHeader:      fiber.HeaderXForwardedFor,
		})
		app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
			return c.SendString("reached handler")
		})

		return app
	}

	// ipAllowlistServer mimics the access-manager tenant IP-allowlist: it authorizes
	// only requests whose forwarded clientIp equals allowedIP. It counts hits so a
	// cache HIT (no request) is distinguishable from a cache MISS (a request).
	ipAllowlistServer := func(t *testing.T) (*httptest.Server, *atomic.Int64) {
		return countingAuthServer(t, func(w http.ResponseWriter, r *http.Request, _ int64) {
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("mock server: failed to decode request body: %v", err)
			}

			writeAuthorized(w, body["clientIp"] == allowedIP)
		})
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	})

	doGet := func(app *fiber.App, ip string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(fiber.HeaderXForwardedFor, ip)

		resp, err := app.Test(req)
		require.NoError(t, err)

		return resp
	}

	t.Run("cross_ip_is_a_cache_miss_and_denied", func(t *testing.T) {
		t.Parallel()

		server, hits := ipAllowlistServer(t)
		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}, cache: newDecisionCache(time.Minute), trustedProxies: mustPrefixes(t, testPeerCIDR)}
		app := newApp(auth)

		// Request 1 from the ALLOWED IP: authorized and cached.
		resp1 := doGet(app, allowedIP)
		assert.Equal(t, http.StatusOK, resp1.StatusCode)

		// Request 2 from a BLOCKED IP, identical sub/resource/action. With the IP in
		// the cache key this is a MISS -> the server is re-queried and denies. Without
		// the IP in the key it would be served the cached allow -> the bypass.
		resp2 := doGet(app, blockedIP)
		assert.Equal(t, http.StatusForbidden, resp2.StatusCode, "a blocked IP must not be served the allow cached for a different IP")
		assert.Equal(t, int64(2), hits.Load(), "the blocked-IP request must re-query the authz service (cache miss on a different IP)")
	})

	t.Run("same_ip_is_served_from_cache", func(t *testing.T) {
		t.Parallel()

		server, hits := ipAllowlistServer(t)
		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}, cache: newDecisionCache(time.Minute), trustedProxies: mustPrefixes(t, testPeerCIDR)}
		app := newApp(auth)

		// Two identical requests from the SAME allowed IP: the second is served from
		// cache, so the authz service is queried exactly once.
		for i := 0; i < 2; i++ {
			resp := doGet(app, allowedIP)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}

		assert.Equal(t, int64(1), hits.Load(), "a repeat request from the same IP must be served from cache (no second query)")
	})
}

// ---------------------------------------------------------------------------
// GetApplicationToken
// ---------------------------------------------------------------------------

// TestAuthorize_DoesNotTraceClientIP proves the caller IP reaches the wire body
// but never a span attribute. A client IP is personal data, and traces are
// retained longer and read more widely than authz logs, so the span payload is
// emitted from a copy with clientIp stripped.
func TestAuthorize_DoesNotTraceClientIP(t *testing.T) {
	t.Parallel()

	const clientIP = "203.0.113.7"

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })

	var capturedBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		require.NoError(t, json.NewEncoder(w).Encode(AuthResponse{Authorized: true}))
	}))
	defer server.Close()

	auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}, trustedProxies: mustPrefixes(t, testPeerCIDR)}

	app := fiber.New(fiber.Config{
		TrustProxy:       true,
		TrustProxyConfig: fiber.TrustProxyConfig{Proxies: []string{"0.0.0.0"}},
		ProxyHeader:      fiber.HeaderXForwardedFor,
	})

	// Seed the tracer the middleware recovers from the request context.
	app.Use(func(c fiber.Ctx) error {
		c.SetContext(observability.ContextWithTracer(c.Context(), tp.Tracer("test")))

		return c.Next()
	})
	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(fiber.HeaderXForwardedFor, clientIP)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The wire body still carries the IP — enforcement depends on it.
	assert.Equal(t, clientIP, capturedBody["clientIp"])

	// No span attribute may expose it, by key or by value.
	spans := exporter.GetSpans()
	require.NotEmpty(t, spans, "expected the authorization spans to be exported")

	for _, s := range spans {
		for _, attr := range s.Attributes {
			assert.NotContains(t, string(attr.Key), "clientIp",
				"span %q exposes a clientIp attribute", s.Name)
			assert.NotContains(t, attr.Value.AsString(), clientIP,
				"span %q leaks the caller IP in attribute %q", s.Name, attr.Key)
		}
	}
}

func TestGetApplicationToken_DoesNotTraceClientSecret(t *testing.T) {
	t.Parallel()

	const (
		clientID     = "test-client-id"
		clientSecret = "super-secret-client-secret"
		accessToken  = "application-access-token"
	)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })

	var capturedBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/login/oauth/access_token", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		require.NoError(t, json.NewEncoder(w).Encode(oauth2Token{AccessToken: accessToken}))
	}))
	defer server.Close()

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
	}

	ctx := observability.ContextWithTracer(context.Background(), tp.Tracer("test"))

	token, err := auth.GetApplicationToken(ctx, clientID, clientSecret)
	require.NoError(t, err)
	assert.Equal(t, accessToken, token)

	assert.Equal(t, map[string]string{
		"grantType":    "client_credentials",
		"clientId":     clientID,
		"clientSecret": clientSecret,
	}, capturedBody)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "lib_auth.get_application_token", spans[0].Name)

	payloadAttributes := map[string]string{}
	for _, attr := range spans[0].Attributes {
		key := string(attr.Key)
		if !strings.HasPrefix(key, "app.request.payload") {
			continue
		}

		payloadAttributes[key] = attr.Value.AsString()
		assert.NotContains(t, key, "clientSecret")
		assert.NotContains(t, attr.Value.AsString(), clientSecret)
	}

	assert.Equal(t, "client_credentials", payloadAttributes["app.request.payload.grantType"])
	assert.Equal(t, clientID, payloadAttributes["app.request.payload.clientId"])
	assert.NotContains(t, payloadAttributes, "app.request.payload.clientSecret")
}

// ---------------------------------------------------------------------------
// AuthResponse JSON serialization
// ---------------------------------------------------------------------------

func TestAuthResponse_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := AuthResponse{Authorized: true}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AuthResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Authorized, decoded.Authorized)
}

// ---------------------------------------------------------------------------
// AUTH_M2M_INVERSION_ENABLED - M2M/authz inversion toggle
// ---------------------------------------------------------------------------

// captureAuthServer returns a mock /v1/authorize server that decodes the request
// body into capturedBody and always authorizes. Reaching it proves the type was
// NOT rejected before the backend call (fail-open).
func captureAuthServer(t *testing.T, capturedBody *map[string]string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(capturedBody); err != nil {
			t.Errorf("mock server: failed to decode request body: %v", err)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(AuthResponse{Authorized: true}); err != nil {
			t.Errorf("mock server: failed to encode response: %v", err)
		}
	}))
}

func TestCheckAuthorization_M2MInversionOff_ApplicationGetsEditorRole(t *testing.T) {
	t.Parallel()

	// Legacy (pre-#122) behavior with the inversion flag OFF (default): an
	// application (M2M) token yields the fabricated product-scoped role
	// "admin/<product>-editor-role" and the real sub is NOT used.
	var capturedBody map[string]string

	server := captureAuthServer(t, &capturedBody)
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: false,
	}

	token := createTestJWT(jwt.MapClaims{
		"type": "application",
		"name": "my-app",
		"sub":  "acme-org/my-app",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "admin/midaz-editor-role", capturedBody["sub"])
	// Legacy forwards product only for normal-user, never for M2M.
	_, hasProduct := capturedBody["product"]
	assert.False(t, hasProduct)
}

func TestCheckAuthorization_M2MInversionOff_UnknownType_FailsOpen(t *testing.T) {
	t.Parallel()

	// Legacy (pre-#122) fail-open behavior: any non-normal-user type (including an
	// unknown one) is treated as M2M and yields the editor role. It is NEVER
	// rejected on type and DOES reach the backend.
	var capturedBody map[string]string

	server := captureAuthServer(t, &capturedBody)
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: false,
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "service-account",
		"owner": "acme-org",
		"sub":   "svc-1",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "admin/midaz-editor-role", capturedBody["sub"])
}

func TestCheckAuthorization_M2MInversionOff_EmptyType_FailsOpen(t *testing.T) {
	t.Parallel()

	// An absent "type" claim is also non-normal-user under the legacy path, so it
	// fails open with the editor role rather than returning 401.
	var capturedBody map[string]string

	server := captureAuthServer(t, &capturedBody)
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: false,
	}

	// No "type" claim -> empty string -> non-normal-user under legacy.
	token := createTestJWT(jwt.MapClaims{
		"sub": "some-app",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "admin/midaz-editor-role", capturedBody["sub"])
}

func TestCheckAuthorization_M2MInversionOn_ApplicationGetsRealSub(t *testing.T) {
	t.Parallel()

	// Inversion ON: an application (M2M) token is identified by its real sub claim;
	// no product-scoped role is fabricated.
	var capturedBody map[string]string

	server := captureAuthServer(t, &capturedBody)
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
	}

	token := createTestJWT(jwt.MapClaims{
		"type": "application",
		"name": "my-app",
		"sub":  "acme-org/my-app",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "acme-org/my-app", capturedBody["sub"])
}

func TestCheckAuthorization_M2MInversionOn_UnknownType_FailsClosed(t *testing.T) {
	t.Parallel()

	// Inversion ON: any type outside {normal-user, application} fails closed with
	// 401 and never reaches the backend.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("auth backend must not be called for a non-canonical token type under inversion")
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
	}

	token := createTestJWT(jwt.MapClaims{
		"type":  "service-account",
		"owner": "acme-org",
		"sub":   "svc-1",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "action", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Contains(t, err.Error(), "unsupported token type")
}

func TestCheckAuthorization_M2MInversion_NormalUserUnchanged(t *testing.T) {
	t.Parallel()

	// normal-user behavior is identical in both modes: subject is the JWT identity
	// "<owner>/<userID>" and the product is forwarded.
	tests := []struct {
		name      string
		inversion bool
	}{
		{name: "inversion_off", inversion: false},
		{name: "inversion_on", inversion: true},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var capturedBody map[string]string

			server := captureAuthServer(t, &capturedBody)
			defer server.Close()

			auth := &AuthClient{
				Address:             server.URL,
				Enabled:             true,
				Logger:              &testLogger{},
				M2MInversionEnabled: tt.inversion,
			}

			token := createTestJWT(jwt.MapClaims{
				"type":  "normal-user",
				"owner": "acme-org",
				"sub":   "user123",
			})

			authorized, statusCode, err := auth.checkAuthorization(
				context.Background(), "midaz", "resource", "action", token, "",
			)

			require.NoError(t, err)
			assert.True(t, authorized)
			assert.Equal(t, http.StatusOK, statusCode)
			assert.Equal(t, "acme-org/user123", capturedBody["sub"])
			assert.Equal(t, "midaz", capturedBody["product"])
		})
	}
}

// ---------------------------------------------------------------------------
// NewAuthClient - M2MInversionEnabled (AUTH_M2M_INVERSION_ENABLED) flag
// ---------------------------------------------------------------------------

func TestNewAuthClient_ReadsM2MInversionFlag(t *testing.T) {
	// Cannot use t.Parallel(): subtests use t.Setenv which modifies process env.
	// enabled=false / empty address returns early without any network call, so the
	// flag wiring is exercised in isolation.
	logger := &testLogger{}

	t.Run("flag_true_enables_inversion", func(t *testing.T) {
		t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

		client := NewAuthClient("", false, logger)
		assert.True(t, client.M2MInversionEnabled)
	})

	t.Run("flag_absent_defaults_false", func(t *testing.T) {
		t.Setenv("AUTH_M2M_INVERSION_ENABLED", "")

		client := NewAuthClient("", false, logger)
		assert.False(t, client.M2MInversionEnabled)
	})

	t.Run("flag_non_true_value_is_false", func(t *testing.T) {
		t.Setenv("AUTH_M2M_INVERSION_ENABLED", "1")

		client := NewAuthClient("", false, logger)
		assert.False(t, client.M2MInversionEnabled)
	})
}

// ---------------------------------------------------------------------------
// Authorize - Principal publication
// ---------------------------------------------------------------------------

// newPrincipalEchoApp builds a Fiber app whose single route is gated by Authorize
// and echoes the published Principal back through response headers. The handler
// reads it from the framework-agnostic Go context (c.Context()), the same path
// humafiber-derived handlers rely on, and reports whether it ran at all.
func newPrincipalEchoApp(auth *AuthClient, product string, reached *atomic.Bool) *fiber.App {
	app := fiber.New()

	app.Get("/x", auth.Authorize(product, "resource", "get"), func(c fiber.Ctx) error {
		if reached != nil {
			reached.Store(true)
		}

		p, ok := PrincipalFromContext(c.Context())

		c.Set("X-P-Found", strconv.FormatBool(ok))
		c.Set("X-P-Type", p.Type)
		c.Set("X-P-Owner", p.Owner)
		c.Set("X-P-Sub", p.Sub)
		c.Set("X-P-Subject", p.Subject)
		c.Set("X-P-Client-Id", p.ClientID)

		return c.SendStatus(http.StatusOK)
	})

	return app
}

func authorizedRequest(t *testing.T, app *fiber.App, token string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	require.NoError(t, err)

	return resp
}

func TestAuthorize_PublishesPrincipal(t *testing.T) {
	t.Parallel()

	t.Run("normal_user_carries_owner_sub_and_derived_subject", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", nil), createTestJWT(jwt.MapClaims{
			"type":  "normal-user",
			"owner": "acme-org",
			"sub":   "user123",
		}))

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "true", resp.Header.Get("X-P-Found"))
		assert.Equal(t, "normal-user", resp.Header.Get("X-P-Type"))
		assert.Equal(t, "acme-org", resp.Header.Get("X-P-Owner"))
		assert.Equal(t, "user123", resp.Header.Get("X-P-Sub"))
		assert.Equal(t, "acme-org/user123", resp.Header.Get("X-P-Subject"))
	})

	t.Run("application_under_inversion_carries_real_sub_and_azp", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, M2MInversionEnabled: true, Logger: &testLogger{}}

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", nil), createTestJWT(jwt.MapClaims{
			"type": "application",
			"sub":  "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
			"azp":  "66bac70fbea746daa760",
		}))

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "true", resp.Header.Get("X-P-Found"))
		assert.Equal(t, "application", resp.Header.Get("X-P-Type"))
		assert.Empty(t, resp.Header.Get("X-P-Owner"))
		assert.Equal(t, "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc", resp.Header.Get("X-P-Sub"))
		// For an application token the Access Manager subject IS the real sub.
		assert.Equal(t, resp.Header.Get("X-P-Sub"), resp.Header.Get("X-P-Subject"))
		assert.Equal(t, "66bac70fbea746daa760", resp.Header.Get("X-P-Client-Id"))
	})

	t.Run("decision_cache_hit_still_publishes", func(t *testing.T) {
		t.Parallel()

		server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
			writeAuthorized(w, true)
		})

		auth := &AuthClient{
			Address: server.URL,
			Enabled: true,
			Logger:  &testLogger{},
			cache:   newDecisionCache(time.Minute),
		}
		app := newPrincipalEchoApp(auth, "midaz", nil)

		token := createTestJWT(jwt.MapClaims{
			"type":  "normal-user",
			"owner": "acme-org",
			"sub":   "user123",
		})

		for i := range 2 {
			resp := authorizedRequest(t, app, token)

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "true", resp.Header.Get("X-P-Found"), "request %d must carry a principal", i+1)
			assert.Equal(t, "acme-org/user123", resp.Header.Get("X-P-Subject"), "request %d", i+1)
		}

		assert.Equal(t, int64(1), hits.Load(), "the second request must be served from the decision cache")
	})

	t.Run("legacy_fabricated_role_reports_absent", func(t *testing.T) {
		t.Parallel()

		// Inversion OFF: a "service" token authorizes under the fabricated
		// "admin/<product>-editor-role" and carries no real sub, so the request
		// proceeds but no principal is identified.
		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", nil), createTestJWT(jwt.MapClaims{
			"type": "service",
		}))

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "false", resp.Header.Get("X-P-Found"))
		assert.Empty(t, resp.Header.Get("X-P-Subject"))
	})

	t.Run("legacy_application_with_sub_still_reports_absent", func(t *testing.T) {
		t.Parallel()

		// Inversion OFF authorizes every non-human token under the fabricated
		// product role. A sub claim present on the token does not change the subject
		// of that decision, so it must not turn the fabricated role into a published
		// application identity.
		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", nil), createTestJWT(jwt.MapClaims{
			"type": application,
			"sub":  "admin/robot",
		}))

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "false", resp.Header.Get("X-P-Found"))
		assert.Empty(t, resp.Header.Get("X-P-Subject"))
	})

	t.Run("denied_request_publishes_nothing", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, false, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		var reached atomic.Bool

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), createTestJWT(jwt.MapClaims{
			"type":  "normal-user",
			"owner": "acme-org",
			"sub":   "user123",
		}))

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.False(t, reached.Load(), "a denied request must never reach the handler, so nothing is published")
	})
}

// TestAuthorize_WhitespaceOnlyIdentityClaimsAreRefused pins the fail-closed half of
// the identity contract on the authorizing path: a claim made only of whitespace
// names nobody, so it is refused with 401 BEFORE the round-trip. The hit count is
// the load-bearing assertion — the Access Manager is never asked to decide for a
// caller that has no name, and no principal reaches the handler.
func TestAuthorize_WhitespaceOnlyIdentityClaimsAreRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{
			name:   "normal_user_blank_owner",
			claims: jwt.MapClaims{"type": "normal-user", "owner": "  ", "sub": "user123"},
		},
		{
			name:   "normal_user_blank_sub",
			claims: jwt.MapClaims{"type": "normal-user", "owner": "acme-org", "sub": "  "},
		},
		{
			name:   "application_blank_sub",
			claims: jwt.MapClaims{"type": "application", "sub": " \t "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
				writeAuthorized(w, true)
			})

			auth := &AuthClient{
				Address:             server.URL,
				Enabled:             true,
				M2MInversionEnabled: true,
				Logger:              &testLogger{},
			}

			var reached atomic.Bool

			resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), createTestJWT(tt.claims))

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			assert.False(t, reached.Load(), "a nameless caller must never reach the handler")
			assert.Empty(t, resp.Header.Get("X-P-Found"), "no principal may be published")
			assert.Equal(t, int64(0), hits.Load(), "the authorization service must never be asked to decide")
		})
	}
}

// TestAuthorize_TracesPrincipalNotToken proves the telemetry rule for the whole
// authorization path: across EVERY span this package exports, the only identity
// attribute is app.auth.principal.type, and neither the bearer token nor any caller
// identifier — owner, subject, client id — reaches an attribute key or value. The
// span copy of the authorization payload is redacted for that reason; the body sent
// to the authorization service still carries the subject, and the round-trip subtest
// captures it to prove only the telemetry copy changed.
func TestAuthorize_TracesPrincipalNotToken(t *testing.T) {
	t.Parallel()

	// Distinct sentinels, so an assertion that finds one names exactly which claim
	// leaked. None appears verbatim in the token, whose claims are base64-encoded.
	const (
		sentinelOwner    = "sentinel-owner-77f1"
		sentinelSubject  = "sentinel-subject-91ab"
		sentinelClientID = "sentinel-client-3c2d"
	)

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": sentinelOwner,
		"sub":   sentinelSubject,
		"azp":   sentinelClientID,
	})

	assertOnlyPrincipalTypeIsRecorded := func(t *testing.T, spans tracetest.SpanStubs) {
		t.Helper()

		require.NotEmpty(t, spans, "expected the authorization spans to be exported")

		var (
			sawPrincipalType bool
			identityKeys     []string
		)

		for _, s := range spans {
			for _, attr := range s.Attributes {
				key := string(attr.Key)
				value := attr.Value.AsString()

				assert.NotContains(t, value, token,
					"span %q leaks the access token in attribute %q", s.Name, key)

				for _, sentinel := range []string{sentinelOwner, sentinelSubject, sentinelClientID} {
					assert.NotContains(t, key, sentinel,
						"span %q leaks a caller identifier in the key %q", s.Name, key)
					assert.NotContains(t, value, sentinel,
						"span %q leaks a caller identifier in attribute %q", s.Name, key)
				}

				if key == "app.auth.principal.type" {
					sawPrincipalType = true

					assert.Equal(t, "normal-user", value)

					continue
				}

				if strings.HasPrefix(key, "app.auth.principal.") || strings.HasSuffix(key, ".sub") {
					identityKeys = append(identityKeys, key)
				}
			}
		}

		assert.True(t, sawPrincipalType, "the principal type must be recorded")
		assert.Empty(t, identityKeys,
			"app.auth.principal.type must be the only identity attribute on any span")
	}

	newTracedApp := func(t *testing.T, auth *AuthClient) (*fiber.App, *tracetest.InMemoryExporter) {
		t.Helper()

		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })

		app := fiber.New()
		app.Use(func(c fiber.Ctx) error {
			c.SetContext(observability.ContextWithTracer(c.Context(), tp.Tracer("test")))

			return c.Next()
		})
		app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
			return c.SendStatus(http.StatusOK)
		})

		return app, exporter
	}

	call := func(t *testing.T, app *fiber.App) {
		t.Helper()

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	t.Run("round_trip_redacts_the_span_copy_only", func(t *testing.T) {
		t.Parallel()

		var capturedBody map[string]string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
				t.Errorf("mock server: failed to decode request body: %v", err)

				return
			}

			writeAuthorized(w, true)
		}))
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		app, exporter := newTracedApp(t, auth)
		call(t, app)

		// The authorization service still decides on the subject: only the
		// telemetry copy of the payload is redacted.
		assert.Equal(t, sentinelOwner+"/"+sentinelSubject, capturedBody["sub"],
			"the body sent to the authorization service must still carry the subject")

		assertOnlyPrincipalTypeIsRecorded(t, exporter.GetSpans())
	})

	t.Run("cache_hit_carries_no_identity_either", func(t *testing.T) {
		t.Parallel()

		server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
			writeAuthorized(w, true)
		})

		auth := &AuthClient{
			Address: server.URL,
			Enabled: true,
			Logger:  &testLogger{},
			cache:   newDecisionCache(time.Minute),
		}

		app, exporter := newTracedApp(t, auth)

		call(t, app)
		call(t, app)

		require.Equal(t, int64(1), hits.Load(), "the second request must be served from the cache")

		assertOnlyPrincipalTypeIsRecorded(t, exporter.GetSpans())
	})

	t.Run("principal_required_when_disabled_carries_no_identity_either", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{
			Enabled:                       false,
			M2MInversionEnabled:           true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		app, exporter := newTracedApp(t, auth)
		call(t, app)

		assertOnlyPrincipalTypeIsRecorded(t, exporter.GetSpans())
	})
}

// ---------------------------------------------------------------------------
// Authorize - PrincipalRequiredWhenDisabled
// ---------------------------------------------------------------------------

// TestAuthorize_Disabled covers the branch taken when the client cannot authorize
// (disabled or addressless). The default is the historical pass-through every
// current consumer relies on; PrincipalRequiredWhenDisabled opts into demanding a
// bearer token that names a principal, skipping ONLY the round-trip.
func TestAuthorize_Disabled(t *testing.T) {
	t.Parallel()

	// unreachableServer stands in for the Access Manager and fails the test if the
	// disabled path ever calls it. Address is set on the client so a wrongly-taken
	// round-trip would reach a real endpoint instead of erroring on an empty URL.
	unreachableServer := func(t *testing.T) (*httptest.Server, *atomic.Int64) {
		t.Helper()

		return countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
			t.Error("the disabled path must not call the authorization service")
			writeAuthorized(w, true)
		})
	}

	t.Run("default_passes_through_without_a_token", func(t *testing.T) {
		t.Parallel()

		// This is the Midaz default: auth off, no opt-in, no Authorization header.
		// The request reaches the handler and no principal is published.
		auth := &AuthClient{Enabled: false, Logger: &testLogger{}}

		var reached atomic.Bool

		resp, err := newPrincipalEchoApp(auth, "midaz", &reached).
			Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, reached.Load())
		assert.Equal(t, "false", resp.Header.Get("X-P-Found"))
	})

	t.Run("nil_receiver_passes_through_without_a_token", func(t *testing.T) {
		t.Parallel()

		// A nil client is the historical "auth not wired" shape. Authorize keeps its
		// pass-through instead of dereferencing the receiver: no panic, the request
		// reaches the handler, and no principal is published.
		var auth *AuthClient

		var reached atomic.Bool

		resp, err := newPrincipalEchoApp(auth, "midaz", &reached).
			Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, reached.Load())
		assert.Equal(t, "false", resp.Header.Get("X-P-Found"))
	})

	t.Run("required_when_disabled_rejects_a_missing_token", func(t *testing.T) {
		t.Parallel()

		server, hits := unreachableServer(t)

		auth := &AuthClient{
			Address:                       server.URL,
			Enabled:                       false,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		resp, err := newPrincipalEchoApp(auth, "midaz", &reached).
			Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
		assert.Equal(t, int64(0), hits.Load())
	})

	t.Run("required_when_disabled_fails_closed_on_token_type", func(t *testing.T) {
		t.Parallel()

		// Inversion ON: "service-account" is outside {normal-user, application} and
		// is refused with 401 by the same rule the enabled path applies — with no
		// authorization call made.
		server, hits := unreachableServer(t)

		auth := &AuthClient{
			Address:                       server.URL,
			Enabled:                       false,
			M2MInversionEnabled:           true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), createTestJWT(jwt.MapClaims{
			"type": "service-account",
			"sub":  "admin/robot",
		}))

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
		assert.Equal(t, int64(0), hits.Load())
	})

	t.Run("required_when_disabled_publishes_an_application_principal", func(t *testing.T) {
		t.Parallel()

		server, hits := unreachableServer(t)

		auth := &AuthClient{
			Address:                       server.URL,
			Enabled:                       false,
			M2MInversionEnabled:           true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", nil), createTestJWT(jwt.MapClaims{
			"type": "application",
			"sub":  "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
			"azp":  "66bac70fbea746daa760",
		}))

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "true", resp.Header.Get("X-P-Found"))
		assert.Equal(t, "application", resp.Header.Get("X-P-Type"))
		assert.Equal(t, "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc", resp.Header.Get("X-P-Subject"))
		assert.Equal(t, "66bac70fbea746daa760", resp.Header.Get("X-P-Client-Id"))
		assert.Equal(t, int64(0), hits.Load(), "the round-trip is the ONLY thing this path skips")
	})

	t.Run("required_when_disabled_rejects_legacy_fabrication_without_a_principal", func(t *testing.T) {
		t.Parallel()

		// Inversion OFF (the Midaz default) can derive a fabricated
		// "admin/<product>-editor-role" without a real sub. With no Access Manager
		// round-trip, that cannot satisfy the opt-in requirement for a named caller.
		auth := &AuthClient{
			Enabled:                       false,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		token := createTestJWT(jwt.MapClaims{"type": "service"})
		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), token)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
		assert.Empty(t, resp.Header.Get("X-P-Found"))

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", token, "")
		require.Error(t, err)
		assert.False(t, authorized)
		assert.Equal(t, http.StatusUnauthorized, statusCode)
	})

	t.Run("required_when_disabled_rejects_legacy_fabrication_even_with_a_sub", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{
			Enabled:                       false,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		token := createTestJWT(jwt.MapClaims{
			"type": "application",
			"sub":  "admin/robot",
		})
		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), token)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
		assert.Empty(t, resp.Header.Get("X-P-Found"))
	})

	t.Run("required_wins_over_the_principal_requirement", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{
			Enabled:                       false,
			Required:                      true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", nil), createTestJWT(jwt.MapClaims{
			"type":  "normal-user",
			"owner": "acme-org",
			"sub":   "user123",
		}))

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("required_when_disabled_rejects_a_non_string_sub", func(t *testing.T) {
		t.Parallel()

		// A JSON number decodes to float64, never to a string, so the application
		// branch of deriveSubject sees an empty sub and refuses with 401 by the
		// SAME rule the enabled path applies. Nothing is published and the handler
		// never runs, so a malformed claim can never reach one as an identity.
		server, hits := unreachableServer(t)

		auth := &AuthClient{
			Address:                       server.URL,
			Enabled:                       false,
			M2MInversionEnabled:           true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), createTestJWT(jwt.MapClaims{
			"type": "application",
			"sub":  12345,
		}))

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
		assert.Equal(t, int64(0), hits.Load())
	})

	t.Run("required_when_disabled_rejects_a_missing_owner", func(t *testing.T) {
		t.Parallel()

		server, hits := unreachableServer(t)

		auth := &AuthClient{
			Address:                       server.URL,
			Enabled:                       false,
			M2MInversionEnabled:           true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), createTestJWT(jwt.MapClaims{
			"type": "normal-user",
			"sub":  "user123",
		}))

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
		assert.Equal(t, int64(0), hits.Load())
	})

	t.Run("required_when_disabled_rejects_a_missing_sub", func(t *testing.T) {
		t.Parallel()

		server, hits := unreachableServer(t)

		auth := &AuthClient{
			Address:                       server.URL,
			Enabled:                       false,
			M2MInversionEnabled:           true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), createTestJWT(jwt.MapClaims{
			"type":  "normal-user",
			"owner": "acme-org",
		}))

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
		assert.Equal(t, int64(0), hits.Load())
	})

	t.Run("required_when_disabled_rejects_a_whitespace_only_sub", func(t *testing.T) {
		t.Parallel()

		// A sub made only of whitespace names nobody, so this path refuses it with
		// 401 by the SAME rule the enabled path applies — and, as everywhere here,
		// with no authorization call made.
		server, hits := unreachableServer(t)

		auth := &AuthClient{
			Address:                       server.URL,
			Enabled:                       false,
			M2MInversionEnabled:           true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached), createTestJWT(jwt.MapClaims{
			"type": "application",
			"sub":  " \t ",
		}))

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
		assert.Empty(t, resp.Header.Get("X-P-Found"), "no principal may be published")
		assert.Equal(t, int64(0), hits.Load())
	})

	// The next two pin the trust boundary the field's godoc describes: the disabled
	// path runs the same extractClaims as the enabled one, so local verification is
	// live here. Configure keys and a forged signature is refused with 401 even
	// though no authorization call is made; without keys the token would be parsed
	// unverified and the same forgery would be published as an identity.
	t.Run("required_when_disabled_rejects_a_signature_from_another_key", func(t *testing.T) {
		t.Parallel()

		attackerKey, _ := newTestRSAKeyPEM(t)

		_, trustedPEM := newTestRSAKeyPEM(t)

		trustedKeys, err := parseRSAPublicKeys([]byte(trustedPEM))
		require.NoError(t, err)

		auth := &AuthClient{
			Enabled:                       false,
			PrincipalRequiredWhenDisabled: true,
			verifyKeys:                    trustedKeys,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached),
			signRS256(t, attackerKey, normalUserClaims()))

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, reached.Load())
	})

	t.Run("required_when_disabled_publishes_a_verified_principal", func(t *testing.T) {
		t.Parallel()

		key, pubPEM := newTestRSAKeyPEM(t)

		trustedKeys, err := parseRSAPublicKeys([]byte(pubPEM))
		require.NoError(t, err)

		auth := &AuthClient{
			Enabled:                       false,
			PrincipalRequiredWhenDisabled: true,
			verifyKeys:                    trustedKeys,
			Logger:                        &testLogger{},
		}

		var reached atomic.Bool

		resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", &reached),
			signRS256(t, key, normalUserClaims()))

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, reached.Load())
		assert.Equal(t, "true", resp.Header.Get("X-P-Found"))
		assert.Equal(t, "normal-user", resp.Header.Get("X-P-Type"))
		assert.Equal(t, "acme-org", resp.Header.Get("X-P-Owner"))
		assert.Equal(t, "user-123", resp.Header.Get("X-P-Sub"))
		assert.Equal(t, "acme-org/user-123", resp.Header.Get("X-P-Subject"))
	})
}

func TestNewAuthClient_ReadsPrincipalRequiredWhenDisabledFlag(t *testing.T) {
	t.Setenv("AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED", "true")
	assert.True(t, NewAuthClient("", false, &testLogger{}).PrincipalRequiredWhenDisabled)

	t.Setenv("AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED", "TRUE")
	assert.False(t, NewAuthClient("", false, &testLogger{}).PrincipalRequiredWhenDisabled,
		"only the exact string \"true\" opts in")

	os.Unsetenv("AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED")
	assert.False(t, NewAuthClient("", false, &testLogger{}).PrincipalRequiredWhenDisabled,
		"the default preserves the historical pass-through")
}

func TestAuthorize_EnabledWithoutAddressRefusesThePrincipalPath(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Address: "", Enabled: true, PrincipalRequiredWhenDisabled: true, Logger: &testLogger{}}
	token := createTestJWT(normalUserClaims())

	resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", nil), token)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"enabled but addressless is an incomplete configuration, never the no-round-trip branch")
	assert.Empty(t, resp.Header.Get("X-P-Found"))

	authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", token, "")
	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
}

func TestAuthorize_DisabledRefusesWhenConfiguredVerificationCannotLoad(t *testing.T) {
	t.Setenv("AUTH_JWT_VERIFY_CERT", "not a PEM")
	t.Setenv("AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED", "true")

	auth := NewAuthClient("", false, &testLogger{})
	resp := authorizedRequest(t, newPrincipalEchoApp(auth, "midaz", nil), createTestJWT(normalUserClaims()))

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("X-P-Found"))

	authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", createTestJWT(normalUserClaims()), "")
	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
}

// ---------------------------------------------------------------------------
// Check - authorization outside the middleware chain
// ---------------------------------------------------------------------------

func TestCheck(t *testing.T) {
	t.Parallel()

	normalUserToken := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	})

	t.Run("authorized", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", normalUserToken, "")
		require.NoError(t, err)
		assert.True(t, authorized)
		assert.Equal(t, http.StatusOK, statusCode)
	})

	t.Run("nil_receiver_reports_authorized", func(t *testing.T) {
		t.Parallel()

		// A nil client keeps the unavailable-client pass-through result Authorize has
		// always had, without dereferencing the receiver.
		var auth *AuthClient

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", normalUserToken, "")
		require.NoError(t, err)
		assert.True(t, authorized)
		assert.Equal(t, http.StatusOK, statusCode)
	})

	t.Run("denied_is_403_without_an_error", func(t *testing.T) {
		t.Parallel()

		server := mockAuthServer(t, false, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", normalUserToken, "")
		require.NoError(t, err, "a plain deny is an answer, not a failure")
		assert.False(t, authorized)
		assert.Equal(t, http.StatusForbidden, statusCode)
	})

	t.Run("unusable_token_is_401_with_an_error", func(t *testing.T) {
		t.Parallel()

		server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
			writeAuthorized(w, true)
		})

		auth := &AuthClient{Address: server.URL, Enabled: true, M2MInversionEnabled: true, Logger: &testLogger{}}

		token := createTestJWT(jwt.MapClaims{"type": "application"}) // no sub

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", token, "")
		require.Error(t, err)
		assert.False(t, authorized)
		assert.Equal(t, http.StatusUnauthorized, statusCode)
		assert.Equal(t, int64(0), hits.Load(), "an underivable token never reaches the authorization service")
	})

	t.Run("disabled_allows_without_calling_out", func(t *testing.T) {
		t.Parallel()

		server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
			t.Error("a disabled client must not call the authorization service")
			writeAuthorized(w, true)
		})

		auth := &AuthClient{Address: server.URL, Enabled: false, Logger: &testLogger{}}

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", "", "")
		require.NoError(t, err)
		assert.True(t, authorized)
		assert.Equal(t, http.StatusOK, statusCode)
		assert.Equal(t, int64(0), hits.Load())
	})

	t.Run("disabled_with_principal_required_still_validates_the_token", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{
			Enabled:                       false,
			M2MInversionEnabled:           true,
			PrincipalRequiredWhenDisabled: true,
			Logger:                        &testLogger{},
		}

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", normalUserToken, "")
		require.NoError(t, err)
		assert.True(t, authorized)
		assert.Equal(t, http.StatusOK, statusCode)

		// Same client, a token whose type it refuses: 401, not a silent allow.
		bad := createTestJWT(jwt.MapClaims{"type": "service-account", "sub": "admin/robot"})

		authorized, statusCode, err = auth.Check(context.Background(), "midaz", "resource", "get", bad, "")
		require.Error(t, err)
		assert.False(t, authorized)
		assert.Equal(t, http.StatusUnauthorized, statusCode)
	})

	t.Run("required_and_disabled_refuses_with_503", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Enabled: false, Required: true, Logger: &testLogger{}}

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", normalUserToken, "")
		require.Error(t, err)
		assert.False(t, authorized)
		assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	})
}

// TestCheck_SendsTheSameBodyAsAuthorize pins the two entry points to one wire
// contract: for the same token, product, resource and action the authorization
// service must not be able to tell which one asked.
func TestCheck_SendsTheSameBodyAsAuthorize(t *testing.T) {
	t.Parallel()

	capture := func(t *testing.T) (*httptest.Server, *[]map[string]string) {
		t.Helper()

		var bodies []map[string]string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string

			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("mock server: failed to decode request body: %v", err)

				return
			}

			bodies = append(bodies, body)
			writeAuthorized(w, true)
		}))
		t.Cleanup(server.Close)

		return server, &bodies
	}

	server, bodies := capture(t)

	auth := &AuthClient{Address: server.URL, Enabled: true, M2MInversionEnabled: true, Logger: &testLogger{}}

	token := createTestJWT(jwt.MapClaims{
		"type": "application",
		"sub":  "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
		"azp":  "66bac70fbea746daa760",
	})

	app := fiber.New()
	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	authorized, _, err := auth.Check(context.Background(), "midaz", "resource", "get", token, "")
	require.NoError(t, err)
	assert.True(t, authorized)

	require.Len(t, *bodies, 2)
	assert.Equal(t, (*bodies)[0], (*bodies)[1])
}

// ---------------------------------------------------------------------------
// Check - authorization-service outages are 503, never a denial (FC-4)
// ---------------------------------------------------------------------------

// authorizeWireAnswer drives Authorize on the given client through a real Fiber app
// and returns the status and body it wrote. Every outage subtest below holds the 503
// Check reports against this, to prove the middleware path answers the SAME word on
// the wire (FC-10): an Access Manager that could not decide is a 503 under every
// resilience configuration, never a 403 the caller reads as a policy denial and
// never a 500 that names the wrong subsystem.
func authorizeWireAnswer(t *testing.T, auth *AuthClient, token string) (int, string) {
	t.Helper()

	app := fiber.New()
	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// The retry subtest outlives Fiber's 1s default test deadline.
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second, FailOnTimeout: true})
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(body)
}

func TestCheck_AuthorizationServiceUnavailableIs503(t *testing.T) {
	t.Parallel()

	token := createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	})

	t.Run("connection_refused_without_retry_or_breaker", func(t *testing.T) {
		t.Parallel()

		// A server closed before use: nobody is listening on its address.
		server := mockAuthServer(t, true, http.StatusOK)
		server.Close()

		auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", token, "")
		require.Error(t, err)
		assert.False(t, authorized, "an unreachable authorization service must stay fail-closed")
		assert.Equal(t, http.StatusServiceUnavailable, statusCode)
		assert.Contains(t, err.Error(), "failed to make request")

		// Authorize agrees with Check: a transport error is the authorization service
		// being unreachable, not this service failing internally.
		status, body := authorizeWireAnswer(t, auth, token)
		assert.Equal(t, http.StatusServiceUnavailable, status)
		assert.Equal(t, http.StatusText(http.StatusServiceUnavailable), body)
	})

	t.Run("retries_exhausted", func(t *testing.T) {
		t.Parallel()

		server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		auth := &AuthClient{
			Address:  server.URL,
			Enabled:  true,
			Logger:   &testLogger{},
			timeout:  5 * time.Second,
			retryMax: 1,
		}

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", token, "")
		require.Error(t, err)
		assert.False(t, authorized)
		assert.Equal(t, http.StatusServiceUnavailable, statusCode)
		assert.Equal(t, int64(2), hits.Load(), "the initial attempt plus one retry must both have been made")

		// Authorize agrees with Check: the deny stays fail-closed, but an exhausted
		// retry budget is reported as the outage it is.
		status, body := authorizeWireAnswer(t, auth, token)
		assert.Equal(t, http.StatusServiceUnavailable, status)
		assert.Equal(t, "Service Unavailable", body)
	})

	t.Run("breaker_open", func(t *testing.T) {
		t.Parallel()

		server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		auth := &AuthClient{
			Address: server.URL,
			Enabled: true,
			Logger:  &testLogger{},
			breaker: newAuthBreaker(2, time.Minute),
		}

		// Two consecutive transient failures trip the breaker.
		for i := 0; i < 2; i++ {
			_, _, err := auth.checkAuthorization(context.Background(), "midaz", "resource", "get", token, "")
			require.NoError(t, err, "an absorbed outage denies without surfacing an error on the legacy path")
		}

		require.Equal(t, int64(2), hits.Load())

		authorized, statusCode, err := auth.Check(context.Background(), "midaz", "resource", "get", token, "")
		require.ErrorIs(t, err, gobreaker.ErrOpenState)
		assert.False(t, authorized)
		assert.Equal(t, http.StatusServiceUnavailable, statusCode)

		// Authorize agrees with Check: an open breaker denies fail-closed and says so
		// as an outage.
		status, body := authorizeWireAnswer(t, auth, token)
		assert.Equal(t, http.StatusServiceUnavailable, status)
		assert.Equal(t, "Service Unavailable", body)

		assert.Equal(t, int64(2), hits.Load(), "an open breaker must short-circuit, not reach the authz service")
	})
}
