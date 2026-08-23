package middleware

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	observability "github.com/LerianStudio/lib-observability/v2"
	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
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

// testLogger is a minimal log.Logger implementation for tests that discards all output.
type testLogger struct{}

func (l *testLogger) Log(_ context.Context, _ log.Level, _ string, _ ...log.Field) {}
func (l *testLogger) With(_ ...log.Field) log.Logger                               { return l }
func (l *testLogger) WithGroup(_ string) log.Logger                                { return l }
func (l *testLogger) Enabled(_ log.Level) bool                                     { return false }
func (l *testLogger) Sync(_ context.Context) error                                 { return nil }

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
	assert.Equal(t, http.StatusInternalServerError, statusCode)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

// ---------------------------------------------------------------------------
// NewAuthClient - ForwardM2MProduct flag
// ---------------------------------------------------------------------------

func TestNewAuthClient_ReadsForwardM2MProductFlag(t *testing.T) {
	// Cannot use t.Parallel(): subtests use t.Setenv which modifies process env.
	// enabled=false / empty address returns early without any network call, so the
	// flag wiring is exercised in isolation.
	logger := log.Logger(&testLogger{})

	t.Run("flag_true_enables_forward", func(t *testing.T) {
		t.Setenv("AUTH_M2M_PRODUCT_FORWARD_ENABLED", "true")

		client := NewAuthClient("", false, &logger)
		assert.True(t, client.ForwardM2MProduct)
	})

	t.Run("flag_absent_defaults_false", func(t *testing.T) {
		t.Setenv("AUTH_M2M_PRODUCT_FORWARD_ENABLED", "")

		client := NewAuthClient("", false, &logger)
		assert.False(t, client.ForwardM2MProduct)
	})

	t.Run("flag_non_true_value_is_false", func(t *testing.T) {
		t.Setenv("AUTH_M2M_PRODUCT_FORWARD_ENABLED", "1")

		client := NewAuthClient("", false, &logger)
		assert.False(t, client.ForwardM2MProduct)
	})
}

// ---------------------------------------------------------------------------
// NewAuthClient - Required (AUTH_REQUIRED) flag
// ---------------------------------------------------------------------------

func TestNewAuthClient_ReadsRequiredFlag(t *testing.T) {
	// Cannot use t.Parallel(): subtests use t.Setenv which modifies process env.
	// enabled=false / empty address returns early without any network call, so the
	// flag wiring is exercised in isolation.
	logger := log.Logger(&testLogger{})

	t.Run("flag_true_enables_required", func(t *testing.T) {
		t.Setenv("AUTH_REQUIRED", "true")

		client := NewAuthClient("", false, &logger)
		assert.True(t, client.Required)
	})

	t.Run("flag_absent_defaults_false", func(t *testing.T) {
		t.Setenv("AUTH_REQUIRED", "")

		client := NewAuthClient("", false, &logger)
		assert.False(t, client.Required)
	})

	t.Run("flag_non_true_value_is_false", func(t *testing.T) {
		t.Setenv("AUTH_REQUIRED", "1")

		client := NewAuthClient("", false, &logger)
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
	logger := log.Logger(&testLogger{})

	t.Run("flag_true_enables_inversion", func(t *testing.T) {
		t.Setenv("AUTH_M2M_INVERSION_ENABLED", "true")

		client := NewAuthClient("", false, &logger)
		assert.True(t, client.M2MInversionEnabled)
	})

	t.Run("flag_absent_defaults_false", func(t *testing.T) {
		t.Setenv("AUTH_M2M_INVERSION_ENABLED", "")

		client := NewAuthClient("", false, &logger)
		assert.False(t, client.M2MInversionEnabled)
	})

	t.Run("flag_non_true_value_is_false", func(t *testing.T) {
		t.Setenv("AUTH_M2M_INVERSION_ENABLED", "1")

		client := NewAuthClient("", false, &logger)
		assert.False(t, client.M2MInversionEnabled)
	})
}
