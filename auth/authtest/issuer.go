package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	jwt "github.com/golang-jwt/jwt/v5"
)

// tokenLifetime is how long an issued token stays valid: long enough for any
// test, short enough that a leaked one is useless.
const tokenLifetime = 5 * time.Minute

// Issuer signs RS256 tokens with an RSA-2048 key generated in the test
// process, for tests that drive the real Authorize with signature verification
// on. The key is never written anywhere and is read-only after NewIssuer, so an
// Issuer is safe to share between parallel tests.
type Issuer struct {
	key *rsa.PrivateKey
	iss string
}

// NewIssuer generates the signing key. iss is the "iss" claim every token
// carries; set it to the AUTH_JWT_ISSUER of the client under test, or pass ""
// for no iss claim. A key-generation failure fails the test and returns nil. A
// nil tb panics.
//
//nolint:thelper // a nil tb must panic with a message naming authtest before tb.Helper() dereferences it.
func NewIssuer(tb testing.TB, iss string) *Issuer {
	requireTB(tb, "NewIssuer")
	tb.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("authtest: NewIssuer: generate RSA key: %v", err)

		return nil
	}

	return &Issuer{key: key, iss: iss}
}

// KeySource returns a middleware.StaticKeySource over the issuer's public key,
// for AuthClient.WithKeySource.
func (i *Issuer) KeySource() middleware.KeySource {
	return middleware.StaticKeySource(&i.key.PublicKey)
}

// PublicKeyPEM returns the issuer's public key as a PKIX "PUBLIC KEY" PEM block,
// for t.Setenv("AUTH_JWT_VERIFY_CERT", ...) before NewAuthClient.
func (i *Issuer) PublicKeyPEM() string {
	der, err := x509.MarshalPKIXPublicKey(&i.key.PublicKey)
	if err != nil {
		// An RSA public key always marshals; this is unreachable.
		panic("authtest: marshal RSA public key: " + err.Error())
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// Token returns a signed token Authorize derives p from: claims type and sub,
// owner for a normal-user, azp when ClientID is set, tenantId when TenantID is
// set, iss when the issuer has one, iat now and exp five minutes later. p is
// validated with the rules of WithPrincipal; an invalid p fails the test and
// returns "". A nil tb panics.
//
//nolint:thelper // a nil tb must panic with a message naming authtest before tb.Helper() dereferences it.
func (i *Issuer) Token(tb testing.TB, p middleware.Principal) string {
	requireTB(tb, "Token")
	tb.Helper()

	if !validPrincipal(tb, "Token", p) {
		return ""
	}

	now := time.Now()

	claims := jwt.MapClaims{
		"type": p.Type,
		"sub":  p.Sub,
		"iat":  now.Unix(),
		"exp":  now.Add(tokenLifetime).Unix(),
	}

	if p.Type == normalUser {
		claims["owner"] = p.Owner
	}

	if p.ClientID != "" {
		claims["azp"] = p.ClientID
	}

	if p.TenantID != "" {
		claims["tenantId"] = p.TenantID
	}

	if i.iss != "" {
		claims["iss"] = i.iss
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(i.key)
	if err != nil {
		tb.Fatalf("authtest: Token: sign: %v", err)

		return ""
	}

	return signed
}
