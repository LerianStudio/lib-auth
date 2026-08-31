package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

// noopSpan returns a non-recording span for exercising verify() directly.
func noopSpan() trace.Span {
	return trace.SpanFromContext(context.Background())
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestRSAKeyPEM generates an RSA key pair and returns the private key plus
// the PKIX PEM encoding of its public half (the form NewM2MAuthenticator parses).
func newTestRSAKeyPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	return key, string(pemBytes)
}

// signRS256 signs claims with the given RSA private key using RS256.
func signRS256(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(key)
	require.NoError(t, err)

	return signed
}

// applicationClaims mirrors a real Casdoor client_credentials (M2M) token.
func applicationClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"type": "application",
		"sub":  "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
		"name": "3a09ac44-1faf-4e66-843c-5152b09b19dc",
		"azp":  "66bac70fbea746daa760",
		"exp":  float64(time.Now().Add(time.Hour).Unix()),
		"iat":  float64(time.Now().Add(-time.Minute).Unix()),
	}
}

func newTestM2MAuthenticator(t *testing.T, pubPEM string) *M2MAuthenticator {
	t.Helper()

	logger := &testLogger{}

	m, err := NewM2MAuthenticator(pubPEM, "", true, logger)
	require.NoError(t, err)

	return m
}

func newTestM2MAuthenticatorWithIssuer(t *testing.T, pubPEM, issuer string) *M2MAuthenticator {
	t.Helper()

	logger := &testLogger{}

	m, err := NewM2MAuthenticator(pubPEM, issuer, true, logger)
	require.NoError(t, err)

	return m
}

// newTestM2MApp builds a Fiber app whose single route is gated by RequireM2M and
// echoes the authenticated identity back through response headers. The downstream
// handler reads the identity from the framework-agnostic Go context
// (c.Context()), the same path humafiber-derived handlers rely on.
func newTestM2MApp(m *M2MAuthenticator) *fiber.App {
	app := fiber.New()

	app.Put("/declarations/:slug", m.RequireM2M(), func(c fiber.Ctx) error {
		id, _ := M2MIdentityFromContext(c.Context())

		c.Set("X-M2M-Subject", id.Subject)
		c.Set("X-M2M-Client-Id", id.ClientID)

		return c.SendStatus(http.StatusOK)
	})

	return app
}

// ---------------------------------------------------------------------------
// NewM2MAuthenticator
// ---------------------------------------------------------------------------

func TestNewM2MAuthenticator_DisabledAllowsEmptyCert(t *testing.T) {
	t.Parallel()

	logger := &testLogger{}

	m, err := NewM2MAuthenticator("", "", false, logger)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.False(t, m.enabled)
	assert.Nil(t, m.publicKey)
}

func TestNewM2MAuthenticator_EnabledRejectsInvalidCert(t *testing.T) {
	t.Parallel()

	logger := &testLogger{}

	m, err := NewM2MAuthenticator("not-a-pem", "", true, logger)
	require.Error(t, err)
	assert.Nil(t, m)
}

func TestNewM2MAuthenticator_EnabledParsesValidCert(t *testing.T) {
	t.Parallel()

	_, pubPEM := newTestRSAKeyPEM(t)

	logger := &testLogger{}

	m, err := NewM2MAuthenticator(pubPEM, "", true, logger)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.True(t, m.enabled)
	assert.NotNil(t, m.publicKey)
}

// ---------------------------------------------------------------------------
// verify - cryptographic core
// ---------------------------------------------------------------------------

func TestVerify_ValidApplicationToken(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	token := signRS256(t, key, applicationClaims())

	claims, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc", claims["sub"])
	assert.Equal(t, "66bac70fbea746daa760", claims["azp"])
}

func TestVerify_WrongKey_FailsClosed(t *testing.T) {
	t.Parallel()

	// Token signed by an attacker key that is NOT the authenticator's key.
	attackerKey, _ := newTestRSAKeyPEM(t)
	_, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	token := signRS256(t, attackerKey, applicationClaims())

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerify_AlgConfusionHS256_Rejected(t *testing.T) {
	t.Parallel()

	// Classic RS/HS confusion: attacker forges an HS256 token using the public
	// PEM bytes as the shared secret. WithValidMethods([]string{"RS256"}) must
	// reject it before the keyfunc runs.
	_, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, applicationClaims())

	signed, err := forged.SignedString([]byte(pubPEM))
	require.NoError(t, err)

	_, statusCode, verr := m.verify(context.Background(), noopSpan(), signed)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerify_AlgNone_Rejected(t *testing.T) {
	t.Parallel()

	_, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, applicationClaims())

	signed, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, statusCode, verr := m.verify(context.Background(), noopSpan(), signed)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerify_ExpiredToken_Rejected(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	claims := applicationClaims()
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())

	token := signRS256(t, key, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerify_MissingExp_Rejected(t *testing.T) {
	t.Parallel()

	// A validly-signed token that omits "exp" must be rejected (WithExpirationRequired).
	key, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	claims := applicationClaims()
	delete(claims, "exp")

	token := signRS256(t, key, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerify_ApplicationMissingSub_Rejected(t *testing.T) {
	t.Parallel()

	// A correctly-signed application token without a "sub" claim fails closed:
	// the stashed identity would otherwise be empty.
	key, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	claims := applicationClaims()
	delete(claims, "sub")

	token := signRS256(t, key, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerify_MatchingIssuer_Allows(t *testing.T) {
	t.Parallel()

	const issuer = "http://plugin-access-manager-auth-backend:8000"

	key, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticatorWithIssuer(t, pubPEM, issuer)

	claims := applicationClaims()
	claims["iss"] = issuer

	token := signRS256(t, key, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
}

func TestVerify_WrongIssuer_Rejected(t *testing.T) {
	t.Parallel()

	// A validly-signed application token from a different issuer (sharing the same
	// signing key) must be rejected when an expected issuer is pinned.
	key, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticatorWithIssuer(t, pubPEM, "http://expected-issuer:8000")

	claims := applicationClaims()
	claims["iss"] = "http://attacker-issuer:8000"

	token := signRS256(t, key, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerify_NonApplicationType_Forbidden(t *testing.T) {
	t.Parallel()

	// An authentic, correctly-signed token that is a normal-user (not M2M) must
	// be rejected with 403: authentication succeeds, but the route is M2M-only.
	key, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	claims := applicationClaims()
	claims["type"] = "normal-user"

	token := signRS256(t, key, claims)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusForbidden, statusCode)
}

func TestVerify_MalformedToken_Rejected(t *testing.T) {
	t.Parallel()

	_, pubPEM := newTestRSAKeyPEM(t)
	m := newTestM2MAuthenticator(t, pubPEM)

	_, statusCode, err := m.verify(context.Background(), noopSpan(), "not-a-jwt")

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerify_NilKey_FailsClosed(t *testing.T) {
	t.Parallel()

	// Defensive: an enabled authenticator with no key must deny, never allow.
	m := &M2MAuthenticator{publicKey: nil, enabled: true, logger: &testLogger{}}

	_, statusCode, err := m.verify(context.Background(), noopSpan(), "any-token")

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

// ---------------------------------------------------------------------------
// RequireM2M - Fiber middleware
// ---------------------------------------------------------------------------

func TestRequireM2M_Disabled_PassesThrough(t *testing.T) {
	t.Parallel()

	logger := &testLogger{}

	m, err := NewM2MAuthenticator("", "", false, logger)
	require.NoError(t, err)

	app := newTestM2MApp(m)

	// No Authorization header at all: a disabled authenticator must not block.
	req := httptest.NewRequest(http.MethodPut, "/declarations/plugin-fees", nil)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequireM2M_MissingToken_Unauthorized(t *testing.T) {
	t.Parallel()

	_, pubPEM := newTestRSAKeyPEM(t)
	app := newTestM2MApp(newTestM2MAuthenticator(t, pubPEM))

	req := httptest.NewRequest(http.MethodPut, "/declarations/plugin-fees", nil)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRequireM2M_ValidToken_AllowsAndExposesIdentity(t *testing.T) {
	t.Parallel()

	// End-to-end proof that RequireM2M propagates the identity onto the Go
	// context: the downstream handler reads it via M2MIdentityFromContext(c.Context())
	// (see newTestM2MApp), the same mechanism humafiber-derived handlers rely on.
	key, pubPEM := newTestRSAKeyPEM(t)
	app := newTestM2MApp(newTestM2MAuthenticator(t, pubPEM))

	token := signRS256(t, key, applicationClaims())

	req := httptest.NewRequest(http.MethodPut, "/declarations/plugin-fees", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc", resp.Header.Get("X-M2M-Subject"))
	assert.Equal(t, "66bac70fbea746daa760", resp.Header.Get("X-M2M-Client-Id"))
}

func TestRequireM2M_NormalUserToken_Forbidden(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	app := newTestM2MApp(newTestM2MAuthenticator(t, pubPEM))

	claims := applicationClaims()
	claims["type"] = "normal-user"

	token := signRS256(t, key, claims)

	req := httptest.NewRequest(http.MethodPut, "/declarations/plugin-fees", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// M2MIdentityFromContext - framework-agnostic accessor
// ---------------------------------------------------------------------------

func TestM2MIdentityFromContext_Present_RoundTrips(t *testing.T) {
	t.Parallel()

	want := M2MIdentity{
		Subject:  "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
		ClientID: "66bac70fbea746daa760",
	}
	ctx := context.WithValue(context.Background(), m2mIdentityContextKey{}, want)

	got, ok := M2MIdentityFromContext(ctx)

	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestM2MIdentityFromContext_Absent_ReturnsZeroFalse(t *testing.T) {
	t.Parallel()

	got, ok := M2MIdentityFromContext(context.Background())

	assert.False(t, ok)
	assert.Equal(t, M2MIdentity{}, got)
}

func TestM2MIdentityFromContext_EmptySubject_TreatedAsAbsent(t *testing.T) {
	t.Parallel()

	// A value with an empty Subject must be reported as absent (ok == false) so a
	// caller that only checks ok never treats a half-populated identity as
	// authenticated. RequireM2M never stores such a value (verify rejects an empty
	// sub), so this only guards against manual/defensive construction.
	ctx := context.WithValue(context.Background(), m2mIdentityContextKey{}, M2MIdentity{Subject: "", ClientID: "azp-only"})

	id, ok := M2MIdentityFromContext(ctx)

	assert.False(t, ok)
	assert.Equal(t, M2MIdentity{}, id, "an empty-subject identity must be reported as the zero value")
}
