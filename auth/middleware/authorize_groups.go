package middleware

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/trace"

	"github.com/gofiber/fiber/v3"
)

// groupDecider decides the groups of one request's questions, each question
// at most once, recording what the allowed ones were authorized as.
type groupDecider struct {
	auth   *AuthClient
	ctx    context.Context
	c      fiber.Ctx
	span   trace.Span
	params authzParams
	scope  ScopeDeclaration
	caller authzCaller
	asked  scopeQuestions

	// outcomes holds, per question decided, how it was decided.
	outcomes map[int]outcome
	// decision and principal are those of the last question allowed.
	decision   authzResolution
	principal  Principal
	allowed    allowedValues
	authorized []map[string]string
}

// outcome is how one question was decided: its refusal, nil when allowed, and
// the status a refused decision answers with (0 when there is none).
type outcome struct {
	refusal error
	status  int
}

// decideGroup asks the questions of one group in order, stopping at the first
// allowed. A group with every question refused for being outside the scope is
// refused as its first question is; any other refusal — the credential
// rejected, the authorization service unreachable — ends the request at once,
// whatever the questions after it would answer.
func (d *groupDecider) decideGroup(group []int) error {
	var first error

	for _, i := range group {
		decided := d.decideOne(i)
		if decided.refusal == nil {
			return nil
		}

		if decided.status != http.StatusForbidden {
			return decided.refusal
		}

		if first == nil {
			first = decided.refusal
		}
	}

	return first
}

// decideOne asks question i, once per request.
func (d *groupDecider) decideOne(i int) outcome {
	if decided, ok := d.outcomes[i]; ok {
		return decided
	}

	decided := d.ask(i)

	if d.outcomes == nil {
		d.outcomes = make(map[int]outcome)
	}

	d.outcomes[i] = decided

	return decided
}

// ask asks the authorization service about question i.
func (d *groupDecider) ask(i int) outcome {
	question := d.asked.sets[i]
	params := d.params
	params.attributes = question

	// On a route that filters, a partner's question that leaves a filtered
	// dimension out asks for the values it may see instead of a refusal.
	params.filter = nil
	if d.caller.partner != "" {
		params.filter = absentFilter(d.scope.filter, question)
	}

	// A question that names no dimension cannot be scoped, whatever the
	// route declares: an optional dimension the request left out is not a
	// value the partner's scope can be matched against. Unless it asks to
	// filter: the list is then confined by the values the answer carries.
	params.declared = len(question) > 0 || len(params.filter) > 0

	decision, principal := d.auth.decide(d.ctx, d.span, params, d.caller)

	resolvedAt := ""
	if d.asked.located != nil {
		resolvedAt = d.asked.located[i]
	}

	if refusal := d.auth.refusalOfResolved(d.c, decision, resolvedAt); refusal != nil {
		return outcome{refusal: refusal, status: deniedStatus(decision)}
	}

	// With no dimension named, the allowed values are the only thing that
	// confines the request: a grant without them for any filtered
	// dimension is refused, never served unconfined — unless it says, in so
	// many words, that the partner is unrestricted on the product. A
	// filtered dimension the answer leaves out is one the partner is not
	// scoped on.
	if len(question) == 0 && len(params.filter) > 0 && !confinesAny(params.filter, decision.allowed) && !decision.unrestricted {
		logErrorf(d.ctx, d.auth.Logger, "Partner-bound credential granted a filtered request naming no dimension without allowed values; denying (fail closed)")

		return outcome{refusal: d.auth.authorizeRefusal(d.c, http.StatusForbidden, http.StatusText(http.StatusForbidden))}
	}

	d.allowed.add(params.filter, decision.allowed)
	d.decision, d.principal = decision, principal
	d.authorized = append(d.authorized, question)

	return outcome{}
}

// resolverContext validates a partner-bound caller before any resolver runs
// (validateBeforeResolving) and returns the context the resolvers are called
// with: ctx carrying the principal that acceptance validated. A resolver
// confines its lookup to that identity, so a credential naming none is refused
// 401 before any runs. With nothing to resolve, ctx is returned as is.
func (auth *AuthClient) resolverContext(ctx context.Context, c fiber.Ctx, span trace.Span, params authzParams, scope ScopeDeclaration, readings requestValues, caller authzCaller) (context.Context, error) {
	validated, refusal := auth.validateBeforeResolving(ctx, c, span, params, scope, readings, caller)
	if refusal != nil {
		return nil, refusal
	}

	if !validated {
		return ctx, nil
	}

	identified, ok := resolverPrincipal(caller.principal)
	if !ok {
		logErrorf(ctx, auth.Logger, "Partner-bound credential names no principal for a scope resolver; denying (fail closed)")

		return nil, auth.authorizeRefusal(c, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}

	return context.WithValue(ctx, principalContextKey{}, identified), nil
}

// validateBeforeResolving asks, for a partner-bound caller on a route that
// resolves, the questions the request makes without its resolved values: the
// dimensions read from the path, the query, headers, a form and the body's
// plain fields. The authorization service accepting every one is what
// validates the credential — and confines the dimensions already known —
// before any resolver looks anything up. A question naming no dimension only
// validates the credential; the request is still decided on the resolved
// values that follow. Every one of these questions names, in "pending", the
// dimensions the request carries values of that are about to be resolved, so
// the service does not refuse a dimension the request will name as one it
// left out.
//
// It reports whether it asked: a request with no value to resolve is decided
// in one pass, as before. A refusal ends the request, and no resolver runs.
func (auth *AuthClient) validateBeforeResolving(ctx context.Context, c fiber.Ctx, span trace.Span, params authzParams, scope ScopeDeclaration, readings requestValues, caller authzCaller) (bool, error) {
	deferred := pendingDimensions{}

	asked, badBody := scope.questions(c, readings.clone(), true, scopeResolution{ctx: ctx, auth: auth, product: params.product, deferred: deferred})
	if badBody != nil {
		return false, auth.authorizeRefusal(c, badBody.statusCode(), badBody.Error())
	}

	if len(deferred) == 0 {
		return false, nil
	}

	params.pending = deferred.names()

	// Nothing is resolved yet, so every question stands alone: each must be
	// allowed.
	known := asked.sets
	if len(known) == 0 {
		known = []map[string]string{nil}
	}

	for _, question := range known {
		params.attributes = question
		params.filter = nil
		params.declared = true

		decision, _ := auth.decide(ctx, span, params, caller)
		if refusal := auth.refusalFor(c, decision); refusal != nil {
			return false, refusal
		}
	}

	return true, nil
}
