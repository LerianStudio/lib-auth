package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/LerianStudio/lib-observability/v4/tracing"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Principal is the caller identity Authorize derived from the bearer token and
// published on the request context. Owner and Sub are the token claims VERBATIM
// (no normalization after rejecting empty or whitespace-only identity claims);
// Subject is the string sent to the Access Manager. Under the legacy derivation
// (M2MInversionEnabled=false) Subject is the fabricated role and Sub may be empty;
// PrincipalFromContext then reports absent.
type Principal struct {
	Type     string // token "type" claim: "normal-user" | "application"
	Owner    string // "owner" claim; empty for application tokens
	Sub      string // "sub" claim, verbatim
	Subject  string // "<owner>/<sub>" for normal-user, "<sub>" for application
	ClientID string // "azp" claim when present, else empty
}

// principalContextKey is the unexported, typed key under which Authorize stores
// the Principal on the request context. A dedicated type (rather than a string)
// keeps the entry unreachable and uncollidable from outside this package.
type principalContextKey struct{}

// PrincipalFromContext returns the Principal Authorize stored on the request Go
// context, or (zero, false) when absent or when the stored value does not describe
// one of the real identities this API promises. In particular, a legacy
// non-inversion M2M authorization uses a fabricated role as Subject; even when that
// token happens to carry a sub claim, the role is not the application identity and
// must not be exposed as one.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok || strings.TrimSpace(p.Sub) == "" {
		return Principal{}, false
	}

	switch p.Type {
	case normalUser:
		if strings.TrimSpace(p.Owner) == "" || p.Subject != p.Owner+"/"+p.Sub {
			return Principal{}, false
		}
	case application:
		if p.Owner != "" || p.Subject != p.Sub {
			return Principal{}, false
		}
	default:
		return Principal{}, false
	}

	return p, true
}

// principalFromClaims assembles the caller identity from the already-parsed token
// claims plus the subject deriveSubject produced for the authorization call. Each
// claim is copied verbatim except that application principals never expose an
// owner: their identity is the sub claim alone. A claim that is absent or not a
// string becomes the empty string, never an error, because the claim-level rules
// that DO fail closed (missing or whitespace-only owner, missing or whitespace-only
// sub) live in deriveSubject and have already run.
func principalFromClaims(claims jwt.MapClaims, subject string) Principal {
	userType, _ := claims["type"].(string)
	owner, _ := claims["owner"].(string)
	sub, _ := claims["sub"].(string)
	clientID, _ := claims["azp"].(string)

	if userType == application {
		owner = ""
	}

	return Principal{
		Type:     userType,
		Owner:    owner,
		Sub:      sub,
		Subject:  subject,
		ClientID: clientID,
	}
}

// derivePrincipal parses the bearer token and derives the caller identity with the
// SINGLE set of rules the authorizing path applies: extractClaims for the claims
// (locally verified or not, per configuration) and deriveSubject for the Access
// Manager subject and its fail-closed token-type rules. Every caller that needs an
// identity goes through here — the authorizing path and the
// PrincipalRequiredWhenDisabled path alike — so the two can never drift apart.
// It returns the status code to answer with when derivation fails.
func (auth *AuthClient) derivePrincipal(ctx context.Context, span trace.Span, accessToken, product string) (Principal, int, error) {
	claims, statusCode, err := auth.extractClaims(ctx, span, accessToken)
	if err != nil {
		return Principal{}, statusCode, err
	}

	userType, _ := claims["type"].(string)

	subject, statusCode, err := auth.deriveSubject(ctx, span, claims, userType, product)
	if err != nil {
		return Principal{}, statusCode, err
	}

	return principalFromClaims(claims, subject), http.StatusOK, nil
}

// derivePrincipalWithoutRoundTrip applies the extra fail-closed rule required when
// Access Manager is not available to anchor trust. An explicitly configured static
// key source that failed to load must not degrade this path to ParseUnverified.
func (auth *AuthClient) derivePrincipalWithoutRoundTrip(ctx context.Context, span trace.Span, accessToken, product string) (Principal, int, error) {
	if auth.staticVerificationConfigured && len(auth.verifyKeys) == 0 && auth.source == nil {
		err := errors.New("local JWT verification is configured but unavailable")
		tracing.HandleSpanError(span, "Local JWT verification unavailable", err)

		return Principal{}, http.StatusServiceUnavailable, err
	}

	principal, statusCode, err := auth.derivePrincipal(ctx, span, accessToken, product)
	if err != nil {
		return Principal{}, statusCode, err
	}

	// The legacy non-inversion derivation authorizes every non-human token under a
	// fabricated role rather than its own identity. Even when such a token happens
	// to carry a sub claim, the derived Subject is not that principal, so the
	// no-round-trip path cannot publish it as an identified caller.
	if !auth.M2MInversionEnabled && principal.Type != normalUser {
		err := errors.New("legacy token derivation does not identify a principal")
		tracing.HandleSpanError(span, "Legacy token derivation does not identify a principal", err)

		return Principal{}, http.StatusUnauthorized, err
	}

	if strings.TrimSpace(principal.Sub) == "" {
		err := errors.New("missing sub claim in token")
		tracing.HandleSpanError(span, "Missing sub claim in token", err)

		return Principal{}, http.StatusUnauthorized, err
	}

	return principal, http.StatusOK, nil
}

// publishPrincipal stores the derived caller identity on the request Go context —
// derived from c.Context(), NOT the tracing ctx, so it adds only the identity value
// without altering span topology — and records only the principal TYPE on the span.
// Neither the bearer token nor any identifier of the caller (Owner, Sub, Subject,
// ClientID) reaches a span attribute or a log line: the type says what kind of
// caller this was, the request id correlates it with the service's own audit trail.
func publishPrincipal(c fiber.Ctx, span trace.Span, p Principal) {
	c.SetContext(context.WithValue(c.Context(), principalContextKey{}, p))

	span.SetAttributes(attribute.String("app.auth.principal.type", p.Type))
}

// RequireHuman rejects any request whose published Principal.Type is not
// "normal-user" with 403; a missing Principal is 401. The handler returns the
// corresponding Fiber error so the service error handler can preserve its
// response envelope. Mount AFTER Authorize.
func RequireHuman() fiber.Handler {
	return requirePrincipalType(normalUser)
}

// RequireApplication rejects any request whose published Principal.Type is not
// "application" with 403; a missing Principal is 401. The handler returns the
// corresponding Fiber error so the service error handler can preserve its
// response envelope. Mount AFTER Authorize.
// Unlike RequireM2M it performs no signature verification: the Access Manager
// round-trip behind Authorize is the trust anchor, as it is for every other route.
func RequireApplication() fiber.Handler {
	return requirePrincipalType(application)
}

// requirePrincipalType is the shared body of the two type guards. The split
// between 401 and 403 is deliberate and load-bearing for the consuming rails:
// 401 says no principal was identified at all (Authorize is missing, or ran
// without deriving one), 403 says a known caller is of the wrong kind.
//
// Both are RETURNED as fiber errors rather than written here. Under Fiber's
// default error handler that renders the same 401 "Unauthorized" / 403
// "Forbidden" a written response would have produced, so nothing changes for a
// service that has not customized it; a service that installs its own
// ErrorHandler (problem+json, say) receives the error and keeps its envelope
// instead of having a bare plain-text body written past it.
func requirePrincipalType(want string) fiber.Handler {
	return func(c fiber.Ctx) error {
		p, ok := PrincipalFromContext(c.Context())
		if !ok {
			return fiber.ErrUnauthorized
		}

		if p.Type != want {
			return fiber.ErrForbidden
		}

		return c.Next()
	}
}
