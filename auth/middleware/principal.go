package middleware

import (
	"context"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Principal is the caller identity Authorize derived from the bearer token and
// published on the request context. Owner and Sub are the token claims VERBATIM
// (no trimming, no normalization); Subject is the string sent to the Access
// Manager. Under the legacy derivation (M2MInversionEnabled=false) Subject is the
// fabricated role and Sub may be empty; PrincipalFromContext then reports absent.
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
// context, or (zero, false) when absent or when Sub is empty.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok || p.Sub == "" {
		return Principal{}, false
	}

	return p, true
}

// principalFromClaims assembles the caller identity from the already-parsed token
// claims plus the subject deriveSubject produced for the authorization call. Each
// claim is copied verbatim: a claim that is absent or not a string becomes the
// empty string, never an error, because the claim-level rules that DO fail closed
// (missing owner, missing sub) live in deriveSubject and have already run.
func principalFromClaims(claims jwt.MapClaims, subject string) Principal {
	userType, _ := claims["type"].(string)
	owner, _ := claims["owner"].(string)
	sub, _ := claims["sub"].(string)
	clientID, _ := claims["azp"].(string)

	return Principal{
		Type:     userType,
		Owner:    owner,
		Sub:      sub,
		Subject:  subject,
		ClientID: clientID,
	}
}
