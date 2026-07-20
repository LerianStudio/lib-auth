package middleware

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"

	observability "github.com/LerianStudio/lib-observability/v2"
	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/LerianStudio/lib-observability/v2/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/LerianStudio/lib-commons/v6/commons"
	libHTTP "github.com/LerianStudio/lib-commons/v6/commons/net/http"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
)

// M2MIdentity is the authenticated application identity extracted from a verified
// M2M token. RequireM2M stores it on the request Go context; read it back with
// M2MIdentityFromContext.
type M2MIdentity struct {
	Subject  string // "sub" claim, "<owner>/<id>" form
	ClientID string // "azp" claim (the Casdoor application clientId)
}

// m2mIdentityContextKey is the unexported, typed key under which RequireM2M stores
// the M2MIdentity on the request context. A dedicated type (rather than a string)
// avoids collisions with any other context value.
type m2mIdentityContextKey struct{}

// M2MAuthenticator authenticates machine-to-machine (application) callers by
// verifying a Casdoor-issued RS256 access token offline against an injected
// public key (the issuer's certificate).
//
// It authenticates only; it does NOT authorize. There is no RBAC round-trip and
// no binding of the caller to a target resource or slug: possession of a valid
// M2M token — whose issuing application is provisioned only by a trusted
// operator — is the trust boundary. Callers that need per-resource ownership
// must enforce it themselves downstream.
//
// Verification is fully local (no network call, no Casdoor SDK dependency), so
// any service can reuse this by supplying its own issuer certificate.
type M2MAuthenticator struct {
	publicKey *rsa.PublicKey
	// expectedIssuer, when non-empty, pins the accepted token "iss" claim so a
	// token minted by a different issuer sharing the same signing key is
	// rejected. Empty means the issuer is not checked (acceptable only in a
	// single-issuer deployment).
	expectedIssuer string
	enabled        bool
	logger         log.Logger
}

// NewM2MAuthenticator builds an M2MAuthenticator from the issuer's certificate
// (a PEM-encoded X.509 certificate or RSA public key, e.g. Casdoor's
// token_jwt_key.pem).
//
// When enabled is false the authenticator is a pass-through (RequireM2M calls
// c.Next() without inspecting the request) and the certificate may be empty —
// this mirrors AuthClient behavior for local/dev where auth is disabled. When
// enabled is true a parseable certificate is required; an empty or invalid PEM
// returns an error so a misconfigured service fails to start rather than
// silently accepting unverified tokens.
//
// expectedIssuer, when non-empty, pins the token "iss" claim (defense in depth
// against reuse of a token minted by a different issuer that shares the same
// signing key). Pass "" to skip the issuer check; this is only safe in a
// single-issuer deployment and setting it is recommended otherwise.
func NewM2MAuthenticator(certificatePEM, expectedIssuer string, enabled bool, logger *log.Logger) (*M2MAuthenticator, error) {
	var l log.Logger

	if logger != nil {
		l = *logger
	} else {
		var err error

		l, err = initializeDefaultLogger()
		if err != nil {
			stdlog.Printf("failed to initialize logger, using NopLogger: %v", err)

			l = log.NewNop()
		}
	}

	if !enabled {
		return &M2MAuthenticator{publicKey: nil, expectedIssuer: expectedIssuer, enabled: false, logger: l}, nil
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(certificatePEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	}

	return &M2MAuthenticator{publicKey: publicKey, expectedIssuer: expectedIssuer, enabled: true, logger: l}, nil
}

// RequireM2M is a Fiber middleware that rejects any request not carrying a
// valid, unexpired, RS256-signed Casdoor application (M2M) token. On success the
// application identity is stored on the request Go context (readable via
// M2MIdentityFromContext, framework-agnostically, by any downstream handler —
// fiber-native via c.Context(), humafiber-derived, or gRPC) and the request
// proceeds.
//
// All failure modes fail closed:
//   - missing token                          -> 401 Unauthorized
//   - unparseable / bad signature / expired  -> 401 Unauthorized
//   - authentic token whose type is not
//     "application" (e.g. a normal-user)     -> 403 Forbidden
func (m *M2MAuthenticator) RequireM2M() fiber.Handler {
	return func(c fiber.Ctx) error {
		if !m.enabled {
			return c.Next()
		}

		ctx := tracing.ExtractHTTPContext(c.Context(), c)

		_, tracer, reqID, _ := observability.NewTrackingFromContext(ctx)

		ctx, span := tracer.Start(ctx, "lib_auth.require_m2m")
		defer span.End()

		span.SetAttributes(
			attribute.String("app.request.request_id", reqID),
		)

		accessToken := libHTTP.ExtractTokenFromHeader(c)

		if commons.IsNilOrEmpty(&accessToken) {
			return c.Status(http.StatusUnauthorized).SendString("Missing Token")
		}

		claims, statusCode, err := m.verify(ctx, span, accessToken)
		if err != nil {
			return c.Status(statusCode).SendString(http.StatusText(statusCode))
		}

		subject, _ := claims["sub"].(string)
		clientID, _ := claims["azp"].(string)

		// Store the identity on the request Go context (derived from c.Context(),
		// NOT the tracing ctx) so this adds only the identity value without altering
		// span/tracing topology. Downstream handlers read it via M2MIdentityFromContext.
		c.SetContext(context.WithValue(c.Context(), m2mIdentityContextKey{}, M2MIdentity{Subject: subject, ClientID: clientID}))

		span.SetAttributes(
			attribute.String("app.auth.m2m.subject", subject),
			attribute.String("app.auth.m2m.client_id", clientID),
		)

		return c.Next()
	}
}

// verify parses and cryptographically validates the access token, enforcing
// RS256 against the injected public key and the default expiry/not-before
// checks, then requires the whitelisted "application" token type. It never logs
// the token itself.
func (m *M2MAuthenticator) verify(ctx context.Context, span trace.Span, accessToken string) (jwt.MapClaims, int, error) {
	if m.publicKey == nil {
		err := errors.New("m2m authenticator has no verification key")

		logErrorf(ctx, m.logger, "M2M authentication misconfigured: missing verification key")
		tracing.HandleSpanError(span, "M2M authentication misconfigured", err)

		return nil, http.StatusUnauthorized, err
	}

	claims := jwt.MapClaims{}

	// WithValidMethods pins the accepted signing algorithm to RS256, closing the
	// alg-substitution hole (a token forged with "none" or with HS256 using the
	// public key as the shared secret is rejected before the keyfunc runs).
	// WithExpirationRequired rejects a validly-signed token that omits "exp", so a
	// non-expiring credential cannot slip through (Casdoor always emits exp).
	// WithIssuer, when an expected issuer is configured, rejects a token minted by
	// a different issuer that shares the same signing key.
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	}
	if m.expectedIssuer != "" {
		opts = append(opts, jwt.WithIssuer(m.expectedIssuer))
	}

	parser := jwt.NewParser(opts...)

	token, err := parser.ParseWithClaims(accessToken, claims, func(_ *jwt.Token) (any, error) {
		return m.publicKey, nil
	})
	if err != nil {
		logErrorf(ctx, m.logger, "Failed to verify M2M token: %v", err)
		tracing.HandleSpanError(span, "Failed to verify M2M token", err)

		return nil, http.StatusUnauthorized, errors.New("invalid token")
	}

	if !token.Valid {
		err := errors.New("invalid token")

		logErrorf(ctx, m.logger, "M2M token failed validation")
		tracing.HandleSpanError(span, "M2M token failed validation", err)

		return nil, http.StatusUnauthorized, err
	}

	userType, _ := claims["type"].(string)
	if userType != application {
		err := errors.New("token is not an application token")

		logErrorf(ctx, m.logger, "Rejected non-application token on M2M-only route: type=%q", userType)
		tracing.HandleSpanError(span, "Non-application token on M2M route", err)

		return nil, http.StatusForbidden, err
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		err := errors.New("missing sub claim in application token")

		logErrorf(ctx, m.logger, "Missing sub claim in application token")
		tracing.HandleSpanError(span, "Missing sub claim in application token", err)

		return nil, http.StatusUnauthorized, err
	}

	return claims, http.StatusOK, nil
}

// M2MIdentityFromContext returns the authenticated M2M identity that RequireM2M
// stored on the request context, or (zero, false) when absent. A stored identity
// with an empty Subject is reported as absent so callers never treat a
// half-populated identity as authenticated.
func M2MIdentityFromContext(ctx context.Context) (M2MIdentity, bool) {
	id, ok := ctx.Value(m2mIdentityContextKey{}).(M2MIdentity)

	return id, ok && id.Subject != ""
}
