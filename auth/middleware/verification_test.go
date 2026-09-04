package middleware

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// normalUserClaims mirrors a real Casdoor normal-user token (the general path).
func normalUserClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user-123",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
		"iat":   float64(time.Now().Add(-time.Minute).Unix()),
	}
}

// ---------------------------------------------------------------------------
// verifyToken - shared hardened verifier
// ---------------------------------------------------------------------------

func TestVerifyToken_ValidSignedToken_Passes(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	token := signRS256(t, key, normalUserClaims())

	claims, statusCode, verr := verifyToken(pubKeys, "", token)

	require.NoError(t, verr)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "acme-org", claims["owner"])
	assert.Equal(t, "user-123", claims["sub"])
}

func TestVerifyToken_WrongKey_FailsClosed(t *testing.T) {
	t.Parallel()

	attackerKey, _ := newTestRSAKeyPEM(t)
	_, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	token := signRS256(t, attackerKey, normalUserClaims())

	_, statusCode, verr := verifyToken(pubKeys, "", token)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerifyToken_ExpiredToken_FailsClosed(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	claims := normalUserClaims()
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())

	token := signRS256(t, key, claims)

	_, statusCode, verr := verifyToken(pubKeys, "", token)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerifyToken_MissingExp_FailsClosed(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	claims := normalUserClaims()
	delete(claims, "exp")

	token := signRS256(t, key, claims)

	_, statusCode, verr := verifyToken(pubKeys, "", token)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerifyToken_AlgConfusionHS256_Rejected(t *testing.T) {
	t.Parallel()

	// Attacker forges an HS256 token using the public PEM bytes as the shared
	// secret. WithValidMethods([]string{"RS256"}) must reject it.
	_, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, normalUserClaims())

	signed, err := forged.SignedString([]byte(pubPEM))
	require.NoError(t, err)

	_, statusCode, verr := verifyToken(pubKeys, "", signed)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerifyToken_AlgNone_Rejected(t *testing.T) {
	t.Parallel()

	_, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, normalUserClaims())

	signed, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, statusCode, verr := verifyToken(pubKeys, "", signed)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerifyToken_MatchingIssuer_Allows(t *testing.T) {
	t.Parallel()

	const issuer = "http://plugin-access-manager-auth-backend:8000"

	key, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	claims := normalUserClaims()
	claims["iss"] = issuer

	token := signRS256(t, key, claims)

	_, statusCode, verr := verifyToken(pubKeys, issuer, token)

	require.NoError(t, verr)
	assert.Equal(t, http.StatusOK, statusCode)
}

func TestVerifyToken_WrongIssuer_Rejected(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	claims := normalUserClaims()
	claims["iss"] = "http://attacker-issuer:8000"

	token := signRS256(t, key, claims)

	_, statusCode, verr := verifyToken(pubKeys, "http://expected-issuer:8000", token)

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerifyToken_NoKeys_FailsClosed(t *testing.T) {
	t.Parallel()

	key, _ := newTestRSAKeyPEM(t)
	token := signRS256(t, key, normalUserClaims())

	_, statusCode, err := verifyToken(nil, "", token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestVerifyToken_MalformedToken_Rejected(t *testing.T) {
	t.Parallel()

	_, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	_, statusCode, verr := verifyToken(pubKeys, "", "not-a-jwt")

	require.Error(t, verr)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

// TestVerifyToken_RotationBundle_AcceptsEitherKey proves the zero-downtime
// rotation contract: with the old and new certs both present, a token signed by
// EITHER key verifies, while a token signed by a key outside the set is rejected.
func TestVerifyToken_RotationBundle_AcceptsEitherKey(t *testing.T) {
	t.Parallel()

	oldKey, oldPEM := newTestRSAKeyPEM(t)
	newKey, newPEM := newTestRSAKeyPEM(t)
	strangerKey, _ := newTestRSAKeyPEM(t)

	bundle := oldPEM + "\n" + newPEM
	pubKeys, err := parseRSAPublicKeys([]byte(bundle))
	require.NoError(t, err)
	require.Len(t, pubKeys, 2)

	t.Run("old_key_accepted", func(t *testing.T) {
		t.Parallel()

		_, statusCode, verr := verifyToken(pubKeys, "", signRS256(t, oldKey, normalUserClaims()))
		require.NoError(t, verr)
		assert.Equal(t, http.StatusOK, statusCode)
	})

	t.Run("new_key_accepted", func(t *testing.T) {
		t.Parallel()

		_, statusCode, verr := verifyToken(pubKeys, "", signRS256(t, newKey, normalUserClaims()))
		require.NoError(t, verr)
		assert.Equal(t, http.StatusOK, statusCode)
	})

	t.Run("stranger_key_rejected", func(t *testing.T) {
		t.Parallel()

		_, statusCode, verr := verifyToken(pubKeys, "", signRS256(t, strangerKey, normalUserClaims()))
		require.Error(t, verr)
		assert.Equal(t, http.StatusUnauthorized, statusCode)
	})
}

// ---------------------------------------------------------------------------
// parseRSAPublicKeys
// ---------------------------------------------------------------------------

func TestParseRSAPublicKeys_Single(t *testing.T) {
	t.Parallel()

	_, pubPEM := newTestRSAKeyPEM(t)

	keys, err := parseRSAPublicKeys([]byte(pubPEM))

	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

func TestParseRSAPublicKeys_MultipleNewlineJoined(t *testing.T) {
	t.Parallel()

	_, pem1 := newTestRSAKeyPEM(t)
	_, pem2 := newTestRSAKeyPEM(t)
	_, pem3 := newTestRSAKeyPEM(t)

	keys, err := parseRSAPublicKeys([]byte(pem1 + "\n" + pem2 + "\n" + pem3))

	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestParseRSAPublicKeys_NoPEMBlock_Errors(t *testing.T) {
	t.Parallel()

	keys, err := parseRSAPublicKeys([]byte("not a pem"))

	require.Error(t, err)
	assert.Nil(t, keys)
}

func TestParseRSAPublicKeys_BadBlock_Errors(t *testing.T) {
	t.Parallel()

	badPEM := "-----BEGIN PUBLIC KEY-----\nZm9vYmFy\n-----END PUBLIC KEY-----\n"

	keys, err := parseRSAPublicKeys([]byte(badPEM))

	require.Error(t, err)
	assert.Nil(t, keys)
}

// ---------------------------------------------------------------------------
// checkAuthorization - verification hooked in via extractClaims
// ---------------------------------------------------------------------------

func TestCheckAuthorization_VerificationEnabled_ValidToken_ReachesAuthz(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	server := mockAuthServer(t, true, http.StatusOK)
	defer server.Close()

	auth := &AuthClient{
		Address:    server.URL,
		Enabled:    true,
		Logger:     &testLogger{},
		verifyKeys: pubKeys,
	}

	token := signRS256(t, key, normalUserClaims())

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "read", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
}

func TestCheckAuthorization_VerificationEnabled_ForgedToken_DeniedBeforeAuthz(t *testing.T) {
	t.Parallel()

	attackerKey, _ := newTestRSAKeyPEM(t)
	_, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	// The authz backend must never be reached: verification fails closed first.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("auth backend must not be called when local verification fails")
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:    server.URL,
		Enabled:    true,
		Logger:     &testLogger{},
		verifyKeys: pubKeys,
	}

	token := signRS256(t, attackerKey, normalUserClaims())

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "read", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

func TestCheckAuthorization_VerificationEnabled_ExpiredToken_Denied(t *testing.T) {
	t.Parallel()

	key, pubPEM := newTestRSAKeyPEM(t)
	pubKeys, err := parseRSAPublicKeys([]byte(pubPEM))
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("auth backend must not be called when the token is expired")
	}))
	defer server.Close()

	auth := &AuthClient{
		Address:    server.URL,
		Enabled:    true,
		Logger:     &testLogger{},
		verifyKeys: pubKeys,
	}

	claims := normalUserClaims()
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())

	token := signRS256(t, key, claims)

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "read", token, "",
	)

	require.Error(t, err)
	assert.False(t, authorized)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
}

// TestCheckAuthorization_VerificationDisabled_UnsignedTokenStillWorks proves the
// opt-in contract: with no verifyKeys, the historical ParseUnverified path is
// preserved exactly — an HS256 test token (not RS256-signed by any trusted key)
// still authorizes through the authz round-trip.
func TestCheckAuthorization_VerificationDisabled_UnsignedTokenStillWorks(t *testing.T) {
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
		"owner": "acme-org",
		"sub":   "user-123",
	})

	authorized, statusCode, err := auth.checkAuthorization(
		context.Background(), "midaz", "resource", "read", token, "",
	)

	require.NoError(t, err)
	assert.True(t, authorized)
	assert.Equal(t, http.StatusOK, statusCode)
}

// ---------------------------------------------------------------------------
// NewAuthClient - verification config wiring (AUTH_JWT_VERIFY_CERT*)
// ---------------------------------------------------------------------------

func TestNewAuthClient_VerificationConfig(t *testing.T) {
	// Cannot use t.Parallel(): subtests use t.Setenv. enabled=false returns early
	// without any network call, exercising the config wiring in isolation.
	logger := &testLogger{}

	t.Run("inline_cert_populates_keys", func(t *testing.T) {
		_, pubPEM := newTestRSAKeyPEM(t)
		t.Setenv("AUTH_JWT_VERIFY_CERT", pubPEM)
		t.Setenv("AUTH_JWT_ISSUER", "http://issuer:8000")

		client := NewAuthClient("", false, logger)
		assert.Len(t, client.verifyKeys, 1)
		assert.Equal(t, "http://issuer:8000", client.verifyIssuer)
	})

	t.Run("inline_bundle_populates_multiple_keys", func(t *testing.T) {
		_, pem1 := newTestRSAKeyPEM(t)
		_, pem2 := newTestRSAKeyPEM(t)
		t.Setenv("AUTH_JWT_VERIFY_CERT", pem1+"\n"+pem2)

		client := NewAuthClient("", false, logger)
		assert.Len(t, client.verifyKeys, 2)
	})

	t.Run("absent_cert_leaves_verification_off", func(t *testing.T) {
		t.Setenv("AUTH_JWT_VERIFY_CERT", "")
		t.Setenv("AUTH_JWT_VERIFY_CERT_PATH", "")

		client := NewAuthClient("", false, logger)
		assert.Nil(t, client.verifyKeys)
	})

	t.Run("bad_cert_disables_verification_without_panic", func(t *testing.T) {
		t.Setenv("AUTH_JWT_VERIFY_CERT", "-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----")

		client := NewAuthClient("", false, logger)
		assert.Nil(t, client.verifyKeys)
	})

	t.Run("cert_path_reads_file", func(t *testing.T) {
		_, pubPEM := newTestRSAKeyPEM(t)
		dir := t.TempDir()
		path := filepath.Join(dir, "cert.pem")
		require.NoError(t, os.WriteFile(path, []byte(pubPEM), 0o600))

		t.Setenv("AUTH_JWT_VERIFY_CERT", "")
		t.Setenv("AUTH_JWT_VERIFY_CERT_PATH", path)

		client := NewAuthClient("", false, logger)
		assert.Len(t, client.verifyKeys, 1)
	})

	t.Run("cert_path_missing_file_disables_without_panic", func(t *testing.T) {
		t.Setenv("AUTH_JWT_VERIFY_CERT", "")
		t.Setenv("AUTH_JWT_VERIFY_CERT_PATH", filepath.Join(t.TempDir(), "does-not-exist.pem"))

		client := NewAuthClient("", false, logger)
		assert.Nil(t, client.verifyKeys)
	})

	t.Run("inline_cert_takes_precedence_over_path", func(t *testing.T) {
		_, inlinePEM := newTestRSAKeyPEM(t)
		t.Setenv("AUTH_JWT_VERIFY_CERT", inlinePEM)
		t.Setenv("AUTH_JWT_VERIFY_CERT_PATH", filepath.Join(t.TempDir(), "unused.pem"))

		client := NewAuthClient("", false, logger)
		assert.Len(t, client.verifyKeys, 1)
	})
}

// ---------------------------------------------------------------------------
// extractClaims via a dynamic KeySource (card 1.1.7 convergence, lib-auth side)
//
// These prove AuthClient's verified path shares the SAME verifyToken + KeySource
// refresh-and-retry machinery as the M2M gate, and that WithKeySource is additive:
// the default (nil source) path is untouched.
// ---------------------------------------------------------------------------

func TestExtractClaims_KeySource_ValidToken_Verifies(t *testing.T) {
	t.Parallel()

	key, _ := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{&key.PublicKey}}

	auth := (&AuthClient{Enabled: true, Logger: &testLogger{}}).WithKeySource(source)

	token := signRS256(t, key, normalUserClaims())

	claims, statusCode, err := auth.extractClaims(context.Background(), noopSpan(), token)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, 0, source.refreshes(), "a token that verifies on the first try must not refresh")
}

// The stable-kid rotation recovery is shared: a token signed by a rotated key that is
// not yet cached triggers exactly ONE forced refresh, then verifies — identical to
// the M2M gate, via the same verifyTokenWithSource helper.
func TestExtractClaims_KeySource_StaleKey_RefreshesOnceAndRetries(t *testing.T) {
	t.Parallel()

	_, oldPub := pubKeyOf(t)
	newPriv, newPub := pubKeyOf(t)

	source := &fakeKeySource{
		keys:      []*rsa.PublicKey{oldPub},
		onRefresh: func() []*rsa.PublicKey { return []*rsa.PublicKey{newPub} },
	}

	auth := (&AuthClient{Enabled: true, Logger: &testLogger{}}).WithKeySource(source)

	token := signRS256(t, newPriv, normalUserClaims())

	claims, statusCode, err := auth.extractClaims(context.Background(), noopSpan(), token)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "user-123", claims["sub"])
	assert.Equal(t, 1, source.refreshes(), "exactly ONE forced refresh on the signature failure")
}

func TestExtractClaims_KeySource_ForgedToken_FailsClosed(t *testing.T) {
	t.Parallel()

	attackerKey, _ := pubKeyOf(t)
	_, serverPub := pubKeyOf(t)

	source := &fakeKeySource{keys: []*rsa.PublicKey{serverPub}}

	auth := (&AuthClient{Enabled: true, Logger: &testLogger{}}).WithKeySource(source)

	token := signRS256(t, attackerKey, normalUserClaims())

	_, statusCode, err := auth.extractClaims(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.LessOrEqual(t, source.refreshes(), 1,
		"a forged (bad-signature) token forces at most ONE refresh, never a loop")
}

// An expired but validly-signed token is a CLAIM failure, not key staleness: the
// source-path retry logic must NOT force any refresh.
func TestExtractClaims_KeySource_ExpiredToken_NoRefresh(t *testing.T) {
	t.Parallel()

	key, pub := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{pub}}

	auth := (&AuthClient{Enabled: true, Logger: &testLogger{}}).WithKeySource(source)

	claims := normalUserClaims()
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())

	token := signRS256(t, key, claims)

	_, statusCode, err := auth.extractClaims(context.Background(), noopSpan(), token)

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, statusCode)
	assert.Equal(t, 0, source.refreshes(),
		"an expired validly-signed token is a claim failure, not key staleness: ZERO refreshes")
}

// WithKeySource is strictly additive: a client with no KeySource keeps the exact
// prior behavior (env-PEM verifyKeys, else ParseUnverified).
func TestWithKeySource_NilSource_NoOp(t *testing.T) {
	t.Parallel()

	auth := (&AuthClient{Enabled: true, Logger: &testLogger{}}).WithKeySource(nil)
	assert.Nil(t, auth.source)
}
