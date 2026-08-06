//go:build integration

// Live integration proof for PAM card #3755: verify that an M2M token minted by a
// REAL Casdoor is accepted through the dynamic-JWKS path, and that a WRONG bootstrap
// seed is recovered by fetching the live JWKS (the from-scratch cert-mismatch gotcha).
//
// Run against the local plugin-access-manager stack:
//
//	M2M_TOKEN="$(cat .../m2m.token)" \
//	  go test -tags=integration -run TestLiveJWKS -v ./auth/middleware/
//
// JWKS_URL defaults to Casdoor's local endpoint; ISSUER must match the token's iss.
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/golang-jwt/jwt/v5"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}

	return def
}

// wrongBootstrapPEM returns a PKIX PEM for a freshly generated, UNRELATED RSA public
// key — guaranteed NOT to match Casdoor's signing key, so verification can only pass
// if the live JWKS fetch actually happened.
func wrongBootstrapPEM(t *testing.T) []byte {
	t.Helper()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestLiveJWKS_WrongBootstrapRecoveredByLiveFetch(t *testing.T) {
	token := os.Getenv("M2M_TOKEN")
	if token == "" {
		t.Skip("M2M_TOKEN not set; skipping live integration test")
	}

	jwksURL := envOr("JWKS_URL", "http://localhost:8000/.well-known/jwks")
	issuer := envOr("ISSUER", "http://plugin-auth-casdoor-backend:8000")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.Logger(&testLogger{})

	source, err := NewJWKSKeySource(JWKSConfig{
		URL:             jwksURL,
		BootstrapPEM:    wrongBootstrapPEM(t), // deliberately WRONG seed
		RefreshInterval: time.Minute,
		Ctx:             ctx,
		Logger:          logger,
	})
	if err != nil {
		t.Fatalf("NewJWKSKeySource: %v", err)
	}
	defer func() { _ = source.Close() }()

	m, err := NewM2MAuthenticatorWithKeySource(source, issuer, true, &logger)
	if err != nil {
		t.Fatalf("NewM2MAuthenticatorWithKeySource: %v", err)
	}

	// verify() forces a single JWKS refresh on the initial (wrong-seed) signature
	// failure, pulls the LIVE Casdoor key, and retries — proving the whole path
	// against a real IdP. A short retry loop tolerates the background lazy fetch
	// racing ahead of the forced one; either way success REQUIRES the live fetch.
	var (
		claims     jwt.MapClaims
		statusCode int
		verr       error
	)

	for attempt := 0; attempt < 3; attempt++ {
		claims, statusCode, verr = m.verify(ctx, noopSpan(), token)
		if verr == nil {
			break
		}

		time.Sleep(300 * time.Millisecond)
	}

	if verr != nil {
		t.Fatalf("live verify failed after retries: status=%d err=%v", statusCode, verr)
	}

	if statusCode != 200 {
		t.Fatalf("expected 200, got %d", statusCode)
	}

	if claims["type"] != "application" {
		t.Fatalf("expected type=application, got %v", claims["type"])
	}

	t.Logf("LIVE VERIFY OK: status=%d iss=%v sub=%v type=%v",
		statusCode, claims["iss"], claims["sub"], claims["type"])
}

// Control: WRONG bootstrap + UNREACHABLE JWKS URL must FAIL closed — proving the
// success above is genuinely due to the live fetch, not an accidental match.
func TestLiveJWKS_WrongBootstrapUnreachableFailsClosed(t *testing.T) {
	token := os.Getenv("M2M_TOKEN")
	if token == "" {
		t.Skip("M2M_TOKEN not set; skipping live integration test")
	}

	issuer := envOr("ISSUER", "http://plugin-auth-casdoor-backend:8000")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.Logger(&testLogger{})

	source, err := NewJWKSKeySource(JWKSConfig{
		URL:             "http://127.0.0.1:1/.well-known/jwks", // unreachable
		BootstrapPEM:    wrongBootstrapPEM(t),
		RefreshInterval: time.Minute,
		Ctx:             ctx,
		Logger:          logger,
	})
	if err != nil {
		t.Fatalf("NewJWKSKeySource: %v", err)
	}
	defer func() { _ = source.Close() }()

	m, err := NewM2MAuthenticatorWithKeySource(source, issuer, true, &logger)
	if err != nil {
		t.Fatalf("NewM2MAuthenticatorWithKeySource: %v", err)
	}

	_, statusCode, verr := m.verify(ctx, noopSpan(), token)
	if verr == nil {
		t.Fatalf("expected fail-closed with wrong seed + unreachable JWKS, got success (status=%d)", statusCode)
	}

	t.Logf("FAIL-CLOSED as expected: status=%d err=%v", statusCode, verr)
}
