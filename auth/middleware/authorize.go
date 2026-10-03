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
	// route returns the method and the registered path of the route serving the
	// request, its parameters written ":name", which is how a route that relies
	// on its product's manifest scope finds its dimensions. A path the adapter
	// cannot tell is "", and such a route derives no dimension.
	route() (method, path string)
	// body returns the request body, read for a route that declares dimensions
	// in it; a body the adapter cannot read is the refusal.
	body() ([]byte, *RefusalError)
}

// authorizeRoute is what a mounted middleware knows about its route, fixed at
// registration time.
type authorizeRoute struct {
	product  string
	resource string
	action   string
	scope    ScopeDeclaration
	// derived is set when the route passes no RequireScope and its product has
	// a manifest scope: the route's dimensions are then derived per request
	// from the route it is served on.
	derived *routeScope
	// declErr is non-empty when the scope declaration cannot be honoured; every
	// request on the route is then refused.
	declErr string
}

// newAuthorizeRoute validates the route's scope declaration ONCE, at registration
// time, not per request: a misdeclared route is a programming error and every one
// of its requests is refused, which is what makes it visible on the first call
// instead of on the first partner.
func (auth *AuthClient) newAuthorizeRoute(product, resource, action string, scopes []ScopeDeclaration) authorizeRoute {
	scope, derived, declErr := auth.registerRouteScope(product, scopes)

	return authorizeRoute{product: product, resource: resource, action: action, scope: scope, derived: derived, declErr: declErr}
}

// scopeFor is the declaration the request in flight is decided on: the route's
// own, or the one derived from its product's manifest scope for the route the
// request is served on.
func (route authorizeRoute) scopeFor(req requestView) ScopeDeclaration {
	if route.derived == nil {
		return route.scope
	}

	return route.derived.forRoute(req.route())
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
	scope := route.scopeFor(req)

	attributes, missing := resolveAttributes(req, scope.dims)
	if missing != "" {
		logErrorf(ctx, auth.Logger, "Declared scope dimension %q carries no value in this request; denying (fail closed)", missing)

		return authorizeOutcome{refusal: statusRefusal(http.StatusForbidden)}
	}

	resolution, principal, questions, refusal := auth.authorizeRequest(ctx, req, authzParams{
		product:     route.product,
		resource:    route.resource,
		action:      route.action,
		accessToken: accessToken,
		clientIP:    clientIP,
		declared:    scope.declared(),
	}, scope, attributes)
	if refusal != nil {
		return authorizeOutcome{refusal: refusal}
	}

	recordPrincipalType(span, principal)

	outcome := authorizeOutcome{principal: &principal}

	if resolution.partner != "" {
		outcome.scope = &RequestScope{
			Partner:    resolution.partner,
			Attributes: sharedAttributes(questions),
			Sets:       questions,
		}
	}

	return outcome
}

// authorizeRequest decides one request: it derives the caller once, works out
// the questions the request makes, and asks them in order under ONE deadline for
// the whole request, stopping at the first that is not allowed. It returns the
// last resolution and the questions asked, or the refusal.
//
// The body is read only for a partner-bound credential. The authorization
// service consumes attributes only to decide for a partner; for every other
// credential it ignores them. So any other caller is decided exactly as before
// body dimensions existed: one question, carrying only the dimensions read from
// the path, headers or query, and a body this layer never parses.
//
// The questions are asked one after another, not concurrently: they are few
// (distinct sets, capped), the decision cache answers repeats without a call,
// the first denial ends the request, and the single deadline bounds the total.
func (auth *AuthClient) authorizeRequest(ctx context.Context, req requestView, params authzParams, scope ScopeDeclaration, attributes map[string]string) (authzResolution, Principal, []map[string]string, *RefusalError) {
	_, tracer, reqID, _ := observability.NewTrackingFromContext(ctx)

	ctx, span := tracer.Start(ctx, "lib_auth.check_authorization")
	defer span.End()

	span.SetAttributes(attribute.String("app.request.request_id", reqID))

	if refused := auth.insecureEndpointResolution(ctx, span); refused != nil {
		return authzResolution{}, Principal{}, nil, refusalFor(*refused)
	}

	// One budget for the whole request, however many questions it makes.
	ctx, cancel := context.WithTimeout(ctx, auth.requestTimeout())
	defer cancel()

	caller, failure := auth.deriveCaller(ctx, span, params.accessToken, params.product)
	if failure != nil {
		return authzResolution{}, Principal{}, nil, refusalFor(*failure)
	}

	// A route that reads dimensions from its body asks one question per
	// distinct set of identifiers the body names, and every one must be
	// allowed. A body that cannot be read for them is the caller's to fix:
	// refused before any call, naming the field, and never let through.
	questions, badBody := scope.questions(req, attributes, caller.partner != "")
	if badBody != nil {
		return authzResolution{}, Principal{}, nil, badBody
	}

	asked := questions
	if len(asked) == 0 {
		asked = []map[string]string{nil}
	}

	var (
		resolution authzResolution
		principal  Principal
	)

	for _, question := range asked {
		params.attributes = question

		resolution, principal = auth.ask(ctx, span, params, caller)

		if refusal := refusalFor(resolution); refusal != nil {
			return authzResolution{}, Principal{}, nil, refusal
		}
	}

	return resolution, principal, questions, nil
}

// refusalFor is the refusal a resolution answers the request with, or nil when
// it allows it.
func refusalFor(resolution authzResolution) *RefusalError {
	// checkResult, not legacyResult: an Access Manager that never produced an
	// answer is refused as 503, so the outage lands in the service's 5xx alarms
	// instead of reading as "you are Forbidden".
	authorized, statusCode, err := resolution.checkResult()
	if err != nil {
		var commonsErr commons.Response
		if errors.As(err, &commonsErr) {
			return accessManagerRefusalAt(statusCode, commonsErr)
		}

		return statusRefusal(statusCode)
	}

	if !authorized {
		// The denial reason picks the word: a credential the Access Manager called
		// finished is answered 401 so its holder re-issues it; every other denial
		// stays 403.
		return statusRefusal(denialStatus(resolution.reason))
	}

	return nil
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
