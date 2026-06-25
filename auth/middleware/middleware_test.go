package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	observability "github.com/LerianStudio/lib-observability"
	"github.com/LerianStudio/lib-observability/log"
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
		context.Background(), "midaz", "resource", "action", token,
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

	// Documents the current behavior: non-normal-user types get "admin/<product>-editor-role".
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
		"type": "application",
		"name": "my-app",
		"sub":  "app-sub",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "my-app", "resource", "action", token,
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)

	// For M2M, the subject is built from the product: "admin/<product>-editor-role".
	assert.Equal(t, "admin/my-app-editor-role", capturedBody["sub"])
	// Product is NOT forwarded for non-normal-user tokens.
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
		context.Background(), "sub", "resource", "action", token,
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
		context.Background(), "midaz", "resource", "action", token,
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
		context.Background(), "", "resource", "action", token,
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
		context.Background(), "sub", "resource", "read", token,
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
		context.Background(), "sub", "resource", "read", token,
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
		context.Background(), "sub", "resource", "write", token,
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
		context.Background(), "sub", "resource", "action", invalidToken,
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestCheckAuthorization_EmptyTypeClaim_TreatedAsNonNormalUser(t *testing.T) {
	t.Parallel()

	// When the "type" claim is empty or absent, userType != normalUser,
	// so the code takes the admin/ branch.
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

	// No "type" claim at all -> defaults to empty string -> non-normal-user path
	token := createTestJWT(jwt.MapClaims{
		"sub": "some-app",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "some-app", "resource", "action", token,
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "admin/some-app-editor-role", capturedBody["sub"])
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
		context.Background(), "sub", "resource", "read", token,
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
		context.Background(), "sub", "resource", "read", token,
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusInternalServerError, statusCode)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

// ---------------------------------------------------------------------------
// GetApplicationToken
// ---------------------------------------------------------------------------

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
