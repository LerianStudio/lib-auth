package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LerianStudio/lib-commons/v3/commons/log"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func (l *testLogger) Info(_ ...any)                                  {}
func (l *testLogger) Infof(_ string, _ ...any)                       {}
func (l *testLogger) Infoln(_ ...any)                                {}
func (l *testLogger) Error(_ ...any)                                 {}
func (l *testLogger) Errorf(_ string, _ ...any)                      {}
func (l *testLogger) Errorln(_ ...any)                               {}
func (l *testLogger) Warn(_ ...any)                                  {}
func (l *testLogger) Warnf(_ string, _ ...any)                       {}
func (l *testLogger) Warnln(_ ...any)                                {}
func (l *testLogger) Debug(_ ...any)                                 {}
func (l *testLogger) Debugf(_ string, _ ...any)                      {}
func (l *testLogger) Debugln(_ ...any)                               {}
func (l *testLogger) Fatal(_ ...any)                                 {}
func (l *testLogger) Fatalf(_ string, _ ...any)                      {}
func (l *testLogger) Fatalln(_ ...any)                               {}
func (l *testLogger) WithFields(_ ...any) log.Logger                 { return l }
func (l *testLogger) WithDefaultMessageTemplate(_ string) log.Logger { return l }
func (l *testLogger) Sync() error                                    { return nil }

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
		context.Background(), "initial-sub", "resource", "action", token,
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)

	// For normal-user, sub should be "owner/sub-from-jwt" (overrides the initial sub parameter).
	assert.Equal(t, "acme-org/user123", capturedBody["sub"])
}

func TestCheckAuthorization_ApplicationUser_SubjectConstruction(t *testing.T) {
	t.Parallel()

	// Documents the current behavior: non-normal-user types get "admin/<initial-sub>-editor-role".
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

	// BUG: hardcodes "admin/" prefix. The sub parameter is used as-is with the
	// "admin/<sub>-editor-role" pattern, regardless of the actual user type.
	assert.Equal(t, "admin/my-app-editor-role", capturedBody["sub"])
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
	assert.Equal(t, http.StatusInternalServerError, statusCode)
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
