package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/LerianStudio/lib-auth/v5/auth/bearer"
	"github.com/LerianStudio/lib-commons/v7/commons"
	observability "github.com/LerianStudio/lib-observability/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// requestView is how the shared authorization flow reads one request, whatever
// the framework serving it. Each read happens lazily, at the step that needs it,
// so a pass-through never touches the token and a refused token never costs a
// client-IP walk.
type requestView interface {
	// token returns the access token, or bearer.ErrMissing when the request
	// carries none; any other error is a malformed credential.
	token() (string, error)
	// clientIP returns the caller address derived from TRUSTED_PROXIES, or "".
	clientIP(auth *AuthClient) string
	// dimension returns the value the request carries for d, or "".
	dimension(d Dimension) string
}

// authorizeRoute is what a mounted middleware knows about its route, fixed at
// registration time.
type authorizeRoute struct {
	product  string
	resource string
	action   string
	scope    ScopeDeclaration
	// declErr is non-empty when the scope declaration cannot be honoured; every
	// request on the route is then refused.
	declErr string
}

// newAuthorizeRoute validates the route's scope declaration ONCE, at registration
// time, not per request: a misdeclared route is a programming error and every one
// of its requests is refused, which is what makes it visible on the first call
// instead of on the first partner.
func newAuthorizeRoute(product, resource, action string, scopes []ScopeDeclaration) authorizeRoute {
	scope, declErr := resolveDeclaration(product, scopes)

	return authorizeRoute{product: product, resource: resource, action: action, scope: scope, declErr: declErr}
}

// authorizeOutcome is what the shared flow decided for one request. With neither
// a refusal nor a principal the request passes through untouched.
type authorizeOutcome struct {
	refusal   *RefusalError
	principal *Principal
	// scope is set only for a partner-bound credential, so a handler can never
	// mistake "this caller is not a partner" for "this partner has no restriction".
	scope *RequestScope
}

// publish returns ctx carrying the principal and, for a partner-bound credential,
// the request scope. Both are layered on the SAME context, principal first, so
// neither value can overwrite the other.
func (o authorizeOutcome) publish(ctx context.Context) context.Context {
	if o.principal != nil {
		ctx = context.WithValue(ctx, principalContextKey{}, *o.principal)
	}

	if o.scope != nil {
		ctx = context.WithValue(ctx, requestScopeContextKey{}, *o.scope)
	}

	return ctx
}

// decide is the one authorization flow every HTTP adapter runs, in this order:
// AUTH_REQUIRED with auth off refuses 503; a misdeclared scope refuses 403
// whatever the posture; a client that cannot authorize passes through, refuses
// 503 when enabled without an address, or derives the principal without a
// round-trip under PrincipalRequiredWhenDisabled; otherwise the Access Manager
// decides.
//
// ctx is the ambient request context, inherited rather than re-extracted from
// the inbound headers: whether a caller-supplied traceparent is honoured is the
// application's decision (lib-observability's TrustInboundTraceContext), and
// extracting here would override it and replace the application's baggage.
func (auth *AuthClient) decide(ctx context.Context, route authorizeRoute, req requestView) authorizeOutcome {
	if auth.mustRefuse() {
		// AUTH_REQUIRED opted in but auth is disabled/misconfigured: refuse to
		// serve (fail closed) instead of silently passing the request through.
		return authorizeOutcome{refusal: statusRefusal(http.StatusServiceUnavailable)}
	}

	// A misdeclared route refuses EVERY request, whatever the auth posture: the
	// disabled-auth pass-through below must not hide it, or the error would
	// surface only on the first deployment that turns auth on.
	if route.declErr != "" {
		if auth != nil {
			logErrorf(ctx, auth.Logger, "Refusing request on a misdeclared route: %s", route.declErr)
		}

		return authorizeOutcome{refusal: statusRefusal(http.StatusForbidden)}
	}

	if !auth.canAuthorize() {
		if !auth.principalRequiredWhenDisabled() {
			return authorizeOutcome{}
		}

		if auth.Enabled {
			// Enabled but addressless is an incomplete configuration, not a
			// deliberate "auth off": it never earns the no-round-trip branch.
			return authorizeOutcome{refusal: statusRefusal(http.StatusServiceUnavailable)}
		}

		return auth.decideWithoutRoundTrip(ctx, route.product, req)
	}

	return auth.decideWithRoundTrip(ctx, route, req)
}

// startAuthorizeSpan opens the "lib_auth.authorize" span every decision runs under.
func startAuthorizeSpan(ctx context.Context) (context.Context, trace.Span) {
	_, tracer, reqID, _ := observability.NewTrackingFromContext(ctx)

	ctx, span := tracer.Start(ctx, "lib_auth.authorize")

	span.SetAttributes(attribute.String("app.request.request_id", reqID))

	return ctx, span
}

// tokenRefusal maps a bearer extraction failure to its 401: "Missing Token" for
// no credential, the status text for a malformed one.
func tokenRefusal(err error) *RefusalError {
	if errors.Is(err, bearer.ErrMissing) {
		return newRefusal(http.StatusUnauthorized, "Missing Token")
	}

	return statusRefusal(http.StatusUnauthorized)
}

// decideWithRoundTrip asks the Access Manager.
func (auth *AuthClient) decideWithRoundTrip(ctx context.Context, route authorizeRoute, req requestView) authorizeOutcome {
	ctx, span := startAuthorizeSpan(ctx)
	defer span.End()

	accessToken, err := req.token()
	if err != nil {
		return authorizeOutcome{refusal: tokenRefusal(err)}
	}

	// The caller IP comes from this library's own TRUSTED_PROXIES list, never from
	// the framework's notion of it; with no trusted proxies it is empty and no IP
	// is forwarded (see resolveClientIP for why there is no socket-peer fallback).
	clientIP := req.clientIP(auth)

	// A declared dimension the request does not carry is refused here, before the
	// round-trip: an identifier with no value cannot be matched against a
	// partner's scope, and sending it absent would ask a narrower question.
	attributes, missing := resolveAttributes(req, route.scope.dims)
	if missing != "" {
		logErrorf(ctx, auth.Logger, "Declared scope dimension %q carries no value in this request; denying (fail closed)", missing)

		return authorizeOutcome{refusal: statusRefusal(http.StatusForbidden)}
	}

	resolution, principal := auth.checkAuthorizationWithPrincipal(ctx, authzParams{
		product:     route.product,
		resource:    route.resource,
		action:      route.action,
		accessToken: accessToken,
		clientIP:    clientIP,
		attributes:  attributes,
		declared:    route.scope.declared(),
	})

	// checkResult, not legacyResult: an Access Manager that never produced an
	// answer is refused as 503, so the outage lands in the service's 5xx alarms
	// instead of reading as "you are Forbidden".
	authorized, statusCode, err := resolution.checkResult()
	if err != nil {
		var commonsErr commons.Response
		if errors.As(err, &commonsErr) {
			return authorizeOutcome{refusal: accessManagerRefusalAt(statusCode, commonsErr)}
		}

		return authorizeOutcome{refusal: statusRefusal(statusCode)}
	}

	if !authorized {
		// The denial reason picks the word: a credential the Access Manager called
		// finished is answered 401 so its holder re-issues it; every other denial
		// stays 403.
		return authorizeOutcome{refusal: statusRefusal(denialStatus(resolution.reason))}
	}

	recordPrincipalType(span, principal)

	outcome := authorizeOutcome{principal: &principal}

	if resolution.partner != "" {
		outcome.scope = &RequestScope{Partner: resolution.partner, Attributes: attributes}
	}

	return outcome
}

// decideWithoutRoundTrip serves the PrincipalRequiredWhenDisabled path: the
// client cannot authorize, so the Access Manager is never called, but the bearer
// token is still demanded, parsed and derived with the SAME rules the enabled
// path applies, and the resulting Principal is published. A deployment running
// with auth off therefore still refuses an anonymous request and a token it
// cannot make sense of.
func (auth *AuthClient) decideWithoutRoundTrip(ctx context.Context, product string, req requestView) authorizeOutcome {
	ctx, span := startAuthorizeSpan(ctx)
	defer span.End()

	accessToken, err := req.token()
	if err != nil {
		return authorizeOutcome{refusal: tokenRefusal(err)}
	}

	principal, statusCode, err := auth.derivePrincipalWithoutRoundTrip(ctx, span, accessToken, product)
	if err != nil {
		return authorizeOutcome{refusal: statusRefusal(statusCode)}
	}

	recordPrincipalType(span, principal)

	return authorizeOutcome{principal: &principal}
}

// recordPrincipalType records only the principal TYPE on the span. Neither the
// bearer token nor any identifier of the caller (Owner, Sub, Subject, ClientID)
// reaches a span attribute or a log line: the type says what kind of caller this
// was, the request id correlates it with the service's own audit trail.
func recordPrincipalType(span trace.Span, p Principal) {
	span.SetAttributes(attribute.String("app.auth.principal.type", p.Type))
}
