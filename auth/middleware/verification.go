package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/LerianStudio/lib-auth/v3/auth/obs"
	"github.com/LerianStudio/lib-observability/v4/tracing"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/trace"
)

// verifyToken cryptographically verifies a JWT and returns its claims. It pins
// RS256 (closing the alg-substitution hole: a token forged with "none" or with
// HS256 using the public key as the shared secret is rejected before the keyfunc
// runs), requires "exp", and — when expectedIssuer is non-empty — pins the "iss"
// claim.
//
// pubKeys is a rotation-overlap set: the token is accepted if it verifies against
// ANY key, so an operator can carry the old and new certs simultaneously across a
// key rotation without downtime (the static-keyset-with-overlap pattern). It
// performs NO application-level claim checks (token type, sub); the caller applies
// those. Every failure returns http.StatusUnauthorized so callers fail closed. It
// never logs the token.
//
// This is the shared hardened verifier extracted from the M2M gate: both
// RequireM2M (via M2MAuthenticator.verify) and the general checkAuthorization path
// route their signature verification through here so there is one audited RS256
// verifier, not two.
func verifyToken(pubKeys []*rsa.PublicKey, expectedIssuer, accessToken string) (jwt.MapClaims, int, error) {
	if len(pubKeys) == 0 {
		return nil, http.StatusUnauthorized, errors.New("no verification key configured")
	}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	}
	if expectedIssuer != "" {
		opts = append(opts, jwt.WithIssuer(expectedIssuer))
	}

	keySet := jwt.VerificationKeySet{Keys: make([]jwt.VerificationKey, len(pubKeys))}
	for i, key := range pubKeys {
		keySet.Keys[i] = key
	}

	claims := jwt.MapClaims{}

	token, err := jwt.NewParser(opts...).ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (any, error) {
		return keySet, nil
	})
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("token verification failed: %w", err)
	}

	if !token.Valid {
		return nil, http.StatusUnauthorized, errors.New("invalid token")
	}

	return claims, http.StatusOK, nil
}

// extractClaims returns the token claims used to build the authorization subject.
//
// It routes ALL cryptographic decisions through the single authoritative verifyToken
// (RS256 + exp + iss), exactly as the M2M gate does — there is one verifier, not two.
//
// Three sources of verification keys, in precedence order, all opt-in and additive:
//  1. a dynamic JWKS KeySource wired via WithKeySource (the same path the M2M gate
//     uses): resolves keys from the serve-stale cache and forces ONE refresh-and-retry
//     on a signature failure (the stable-kid rotation case), via the shared
//     verifyTokenWithSource helper;
//  2. static env-PEM keys (verifyKeys, from AUTH_JWT_VERIFY_CERT /
//     AUTH_JWT_VERIFY_CERT_PATH): cryptographically verifies and fails closed;
//  3. neither configured: preserves the historical ParseUnverified behavior EXACTLY
//     — the network authorization call remains the trust anchor.
//
// Default construction sets neither a KeySource nor verifyKeys, so the unverified
// path (3) is unchanged and the feature is fully backward compatible.
func (auth *AuthClient) extractClaims(ctx context.Context, span trace.Span, accessToken string) (jwt.MapClaims, int, error) {
	if auth.source != nil {
		return verifyTokenWithSource(ctx, span, auth.source, auth.verifyIssuer, accessToken, auth.Logger)
	}

	if len(auth.verifyKeys) > 0 {
		claims, statusCode, err := verifyToken(auth.verifyKeys, auth.verifyIssuer, accessToken)
		if err != nil {
			logErrorf(ctx, auth.Logger, "Failed to verify token: %v", err)

			tracing.HandleSpanError(span, "Failed to verify token", err)

			return nil, statusCode, err
		}

		return claims, http.StatusOK, nil
	}

	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to parse token: %v", err)

		tracing.HandleSpanError(span, "Failed to parse token", err)

		return nil, http.StatusUnauthorized, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logErrorf(ctx, auth.Logger, "Failed to parse claims: token.Claims is not of type jwt.MapClaims")

		err := errors.New("token claims are not in the expected format")

		tracing.HandleSpanError(span, "Failed to parse claims", err)

		return nil, http.StatusUnauthorized, err
	}

	return claims, http.StatusOK, nil
}

// loadVerification reads the opt-in local JWT verification config from the
// environment: AUTH_JWT_VERIFY_CERT (inline, newline-joined PEMs for rotation
// overlap) or, when it is empty, AUTH_JWT_VERIFY_CERT_PATH (a mounted file), plus
// AUTH_JWT_ISSUER (optional "iss" pin). Absence of both cert sources leaves
// verification off (nil keys), preserving the historical ParseUnverified behavior.
//
// A configured-but-unparseable cert is logged loud at ERROR and verification is
// left disabled (the authz round-trip stays the trust anchor); it never silently
// accepts a bad cert and never panics, keeping NewAuthClient's no-error signature.
func loadVerification(logger obs.Logger) (keys []*rsa.PublicKey, issuer string) {
	issuer = strings.TrimSpace(os.Getenv("AUTH_JWT_ISSUER"))

	pemData, err := loadVerifyCertPEM()
	if err != nil {
		logErrorf(context.Background(), logger,
			"AUTH_JWT_VERIFY_CERT_PATH unreadable, local JWT verification disabled: %v", err)

		return nil, issuer
	}

	if len(pemData) == 0 {
		return nil, issuer
	}

	keys, err = parseRSAPublicKeys(pemData)
	if err != nil {
		logErrorf(context.Background(), logger,
			"failed to parse verification certificate, local JWT verification disabled: %v", err)

		return nil, issuer
	}

	return keys, issuer
}

// loadVerifyCertPEM returns the PEM bytes for local JWT verification, preferring
// the inline AUTH_JWT_VERIFY_CERT over the file referenced by
// AUTH_JWT_VERIFY_CERT_PATH. It returns (nil, nil) when neither is set, which
// leaves verification off (opt-in by presence, like the M2M cert gate).
func loadVerifyCertPEM() ([]byte, error) {
	if inline := strings.TrimSpace(os.Getenv("AUTH_JWT_VERIFY_CERT")); inline != "" {
		return []byte(inline), nil
	}

	path := strings.TrimSpace(os.Getenv("AUTH_JWT_VERIFY_CERT_PATH"))
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path) // #nosec G304 G703 -- path is operator-supplied deployment config (a mounted secret), not request/user input
	if err != nil {
		return nil, fmt.Errorf("failed to read AUTH_JWT_VERIFY_CERT_PATH %q: %w", path, err)
	}

	return data, nil
}

// parseRSAPublicKeys parses one or more PEM blocks (concatenated / newline-joined)
// into RSA public keys. Each block may be a PKIX public key or an X.509
// certificate (e.g. Casdoor's token_jwt_key.pem). Supporting multiple blocks is
// what makes zero-downtime key rotation possible: the operator carries the old and
// new certs together for the overlap window. It errors if any block fails to parse
// or if no PEM block is found, so a misconfiguration is caught rather than silently
// yielding an empty (deny-everything) key set.
func parseRSAPublicKeys(pemData []byte) ([]*rsa.PublicKey, error) {
	var keys []*rsa.PublicKey

	rest := pemData

	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}

		rest = remainder

		key, err := jwt.ParseRSAPublicKeyFromPEM(pem.EncodeToMemory(block))
		if err != nil {
			return nil, fmt.Errorf("failed to parse verification key: %w", err)
		}

		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, errors.New("no PEM blocks found in verification certificate")
	}

	return keys, nil
}
