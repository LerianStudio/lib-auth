package middleware

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"

	"github.com/LerianStudio/lib-auth/v4/auth/obs"
	observability "github.com/LerianStudio/lib-observability/v4"
	"github.com/LerianStudio/lib-observability/v4/tracing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/LerianStudio/lib-commons/v7/commons"
	libHTTP "github.com/LerianStudio/lib-commons/v7/commons/net/http"
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
	// source, when non-nil, supplies the verification keys dynamically (JWKS-backed
	// cache with serve-stale + forced refresh on signature failure). When nil the
	// authenticator uses the legacy static single-PEM publicKey path unchanged, so
	// the original constructor and behavior are fully preserved.
	source KeySource
	// expectedIssuer, when non-empty, pins the accepted token "iss" claim so a
	// token minted by a different issuer sharing the same signing key is
	// rejected. Empty means the issuer is not checked (acceptable only in a
	// single-issuer deployment).
	expectedIssuer string
	enabled        bool
	logger         obs.Logger
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
func NewM2MAuthenticator(certificatePEM, expectedIssuer string, enabled bool, logger obs.Logger) (*M2MAuthenticator, error) {
	l := resolveLogger(logger)

	if !enabled {
		return &M2MAuthenticator{publicKey: nil, expectedIssuer: expectedIssuer, enabled: false, logger: l}, nil
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(certificatePEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	}

	return &M2MAuthenticator{publicKey: publicKey, expectedIssuer: expectedIssuer, enabled: true, logger: l}, nil
}

// NewM2MAuthenticatorWithKeySource builds an M2MAuthenticator that resolves its
// verification keys from a KeySource instead of a build-time PEM. This is the
// dynamic-JWKS path: keys are served from an in-memory cache (never blocking a
// verify on the network), and on a signature verification failure the gate forces
// ONE single-flight refresh and retries — covering the stable-kid Casdoor rotation
// case where refresh-on-unknown-kid never fires.
//
// It is strictly additive: the existing NewM2MAuthenticator and its static
// single-PEM behavior are unchanged. When enabled is false the authenticator is a
// pass-through and source may be nil. When enabled is true a non-nil source is
// required, so a misconfigured service fails to start rather than silently
// accepting unverified tokens.
//
// expectedIssuer pins the token "iss" claim when non-empty (defense in depth), the
// same as the static constructor.
func NewM2MAuthenticatorWithKeySource(source KeySource, expectedIssuer string, enabled bool, logger obs.Logger) (*M2MAuthenticator, error) {
	l := resolveLogger(logger)

	if !enabled {
		return &M2MAuthenticator{source: source, expectedIssuer: expectedIssuer, enabled: false, logger: l}, nil
	}

	if source == nil {
		return nil, errors.New("m2m authenticator requires a non-nil key source when enabled")
	}

	return &M2MAuthenticator{source: source, expectedIssuer: expectedIssuer, enabled: true, logger: l}, nil
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

		// Inherit the ambient request context rather than extracting inbound trace
		// context here — same reasoning as AuthClient.Authorize: honoring a
		// caller-supplied traceparent is the application's decision to make, not
		// this middleware's.
		ctx := c.Context()

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
	claims, statusCode, err := m.verifySignature(ctx, span, accessToken)
	if err != nil {
		return nil, statusCode, err
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

// verifySignature cryptographically verifies the token through the shared hardened
// verifyToken (RS256 + exp + iss pins), resolving the verification keys from the
// static publicKey (legacy path) or the dynamic KeySource. On the source path a
// signature/keys failure triggers exactly ONE forced single-flight refresh and one
// retry — the stable-kid Casdoor rotation case — while exp/iss/alg/malformed
// failures never refresh (they are not key staleness). It never logs the token.
func (m *M2MAuthenticator) verifySignature(ctx context.Context, span trace.Span, accessToken string) (jwt.MapClaims, int, error) {
	// Legacy static single-PEM path — unchanged behavior when no KeySource is set.
	if m.source == nil {
		if m.publicKey == nil {
			err := errors.New("m2m authenticator has no verification key")

			logErrorf(ctx, m.logger, "M2M authentication misconfigured: missing verification key")
			tracing.HandleSpanError(span, "M2M authentication misconfigured", err)

			return nil, http.StatusUnauthorized, err
		}

		// verifyToken pins RS256 (closing the alg-substitution hole — a token forged
		// with "none" or HS256 using the public key as the shared secret is rejected
		// before the keyfunc runs), requires "exp", and pins "iss" when set.
		claims, statusCode, err := verifyToken([]*rsa.PublicKey{m.publicKey}, m.expectedIssuer, accessToken)
		if err != nil {
			logErrorf(ctx, m.logger, "Failed to verify M2M token: %v", err)
			tracing.HandleSpanError(span, "Failed to verify M2M token", err)

			return nil, statusCode, err
		}

		return claims, statusCode, nil
	}

	// Dynamic key-source path — shared verbatim with AuthClient.extractClaims so the
	// stable-kid rotation recovery (and its instrumentation) lives in exactly ONE
	// place. Resolves keys from the cache (never blocks on the network), verifies, and
	// retries once behind a forced refresh on key staleness.
	return verifyTokenWithSource(ctx, span, m.source, m.expectedIssuer, accessToken, m.logger)
}

// verifyTokenWithSource is the shared dynamic-JWKS verification path used by BOTH the
// M2M gate (M2MAuthenticator.verifySignature) and AuthClient.extractClaims. There is
// exactly ONE cryptographic verifier — the shared hardened verifyToken (RS256 + exp +
// iss pins); this helper only wraps it with the KeySource resolve + forced
// refresh-and-retry on genuine key staleness. On a retriable signature failure it
// forces ONE single-flight refresh and retries exactly once (THE stable-kid Casdoor
// gotcha, where refresh-on-unknown-kid never fires); exp/iss/alg/malformed failures
// never refresh (they are not key staleness). It emits jwks_unknown_kid_total (a
// metric-only kid-presence probe) and jwks_verify_fail_total (on a genuine verify
// failure), and never logs the token.
func verifyTokenWithSource(ctx context.Context, span trace.Span, source KeySource, expectedIssuer, accessToken string, logger obs.Logger) (jwt.MapClaims, int, error) {
	keys := source.Keys(ctx)

	// Metric-only: flag a token whose kid is absent from the cached JWKS. This does
	// NOT influence verification (which still tries all keys); it is the signal that
	// later distinguishes a new-kid rotation from the stable-kid case.
	recordUnknownKID(ctx, source, accessToken)

	claims, statusCode, err := verifyToken(keys, expectedIssuer, accessToken)
	if err != nil && isRetriableKeyFailure(keys, err, accessToken) {
		// THE gotcha: Casdoor republishes a regenerated keypair under the SAME kid
		// (cert-built-in), so refresh-on-unknown-kid never fires. Force ONE
		// single-flight refresh and retry exactly once.
		if rerr := source.Refresh(ctx); rerr != nil {
			logErrorf(ctx, logger, "Forced JWKS refresh failed after signature failure: %v", rerr)
			tracing.HandleSpanError(span, "Forced JWKS refresh failed", rerr)
			incrJWKSCounter(ctx, metricJWKSVerifyFailTotal, nil)

			// Fail closed on the original verification error.
			return nil, statusCode, err
		}

		keys = source.Keys(ctx)
		claims, statusCode, err = verifyToken(keys, expectedIssuer, accessToken)
	}

	if err != nil {
		logErrorf(ctx, logger, "Failed to verify token: %v", err)
		tracing.HandleSpanError(span, "Failed to verify token", err)
		incrJWKSCounter(ctx, metricJWKSVerifyFailTotal, nil)

		return nil, statusCode, err
	}

	return claims, statusCode, nil
}

// recordUnknownKID emits jwks_unknown_kid_total when the token presents a kid absent
// from the source's cached JWKS. It is METRIC-ONLY and never affects verification.
// Sources that do not track kids (static/PEM) are skipped, as are tokens carrying no
// kid (an absent kid is not the new-kid-rotation signal this metric surfaces). The
// kid is read from the UNVERIFIED header — safe because it drives a counter only,
// never a trust decision.
func recordUnknownKID(ctx context.Context, source KeySource, accessToken string) {
	checker, ok := source.(kidPresenceChecker)
	if !ok {
		return
	}

	kid := unverifiedKID(accessToken)
	if kid == "" {
		return
	}

	if !checker.hasKID(kid) {
		incrJWKSCounter(ctx, metricJWKSUnknownKIDTotal, nil)
	}
}

// unverifiedKID returns the "kid" JWT header parameter WITHOUT verifying the token.
// Used solely to feed jwks_unknown_kid_total; it never influences verification.
func unverifiedKID(accessToken string) string {
	token, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return ""
	}

	kid, _ := token.Header["kid"].(string)

	return kid
}

// isRetriableKeyFailure reports whether a verifyToken failure indicates possible
// key staleness — the only condition that warrants a forced JWKS refresh + retry.
//
// It is deliberately narrow to keep verification fail-closed and avoid a refresh
// loop on attack/claim failures:
//   - an empty key set (cache not yet warmed) is retriable — a fetch may populate it;
//   - otherwise ONLY a genuine RS256 signature mismatch is retriable. jwt/v5 reports
//     alg-confusion (HS256 or "none", rejected by WithValidMethods) as
//     ErrTokenSignatureInvalid TOO, so the token's header alg is checked and must be
//     exactly RS256; an alg-confusion attempt never triggers a refresh;
//   - exp/iss/malformed use other sentinels (ErrTokenExpired/ErrTokenInvalidIssuer/
//     ErrTokenMalformed) and are never retriable.
func isRetriableKeyFailure(keys []*rsa.PublicKey, err error, accessToken string) bool {
	if err == nil {
		return false
	}

	if len(keys) == 0 {
		return true
	}

	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return false
	}

	token, _, perr := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if perr != nil {
		return false
	}

	alg, _ := token.Header["alg"].(string)

	return alg == "RS256"
}

// M2MIdentityFromContext returns the authenticated M2M identity that RequireM2M
// stored on the request context, or (zero, false) when absent. A stored identity
// with an empty Subject is reported as absent so callers never treat a
// half-populated identity as authenticated.
func M2MIdentityFromContext(ctx context.Context) (M2MIdentity, bool) {
	id, ok := ctx.Value(m2mIdentityContextKey{}).(M2MIdentity)
	if !ok || id.Subject == "" {
		return M2MIdentity{}, false
	}

	return id, true
}
