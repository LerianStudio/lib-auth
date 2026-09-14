package middleware

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// PartnerLocalsKey is the fiber.Locals key under which Authorize records the
// partner a request's credential is bound to, so the service's request log can
// name it without re-parsing the token. It is absent for every credential that
// is not partner-bound.
const PartnerLocalsKey = "partner"

// Source names WHERE in the request one instance identifier is read from.
//
// The identifier is the "where" of an authorization question — which
// organization, which ledger — next to the resource/action "what". Only the
// route knows where it sits in its own request, which is why it is declared at
// the route and not guessed here.
type Source int

const (
	// SourceUnset is the zero value and reads nothing. A dimension left at this
	// source resolves empty, which the fail-closed guard denies.
	SourceUnset Source = iota
	// FromPath reads a path parameter (fiber.Ctx.Params).
	FromPath
	// FromHeader reads a request header (fiber.Ctx.Get).
	FromHeader
	// FromQuery reads a query-string parameter (fiber.Ctx.Query).
	FromQuery
)

// Dimension declares ONE instance identifier a route addresses: the name the
// authorization service knows it by, and where to read its value in the request.
//
// The two are separate on purpose. The name is the product's declared scope
// field, fixed by the authorization service's catalog ("organizationId"), while
// the request key is whatever the route happens to call it ("organization_id",
// "X-Organization-Id"). Collapsing them would force every route to rename its
// own parameters to match an external catalog.
type Dimension struct {
	name   string
	source Source
	key    string
}

// Dim declares a dimension read from source under the SAME key as its name. Use
// At when the route's own parameter, header or query key differs.
func Dim(name string, source Source) Dimension {
	return Dimension{name: name, source: source, key: name}
}

// At returns a copy of the dimension reading from a different request key. It
// never mutates the receiver, so one declaration can be reused and re-keyed.
func (d Dimension) At(key string) Dimension {
	d.key = key

	return d
}

// Name is the attribute key sent to the authorization service.
func (d Dimension) Name() string { return d.name }

// Key is the request parameter, header or query key the value is read from.
func (d Dimension) Key() string { return d.key }

// Source is where in the request the value is read from.
func (d Dimension) Source() Source { return d.source }

// resolve reads the dimension's value out of the request, or "" when the source
// carries nothing.
func (d Dimension) resolve(c fiber.Ctx) string {
	switch d.source {
	case FromPath:
		return c.Params(d.key)
	case FromHeader:
		return c.Get(d.key)
	case FromQuery:
		return fiber.Query[string](c, d.key)
	case SourceUnset:
		return ""
	default:
		return ""
	}
}

// ScopeDeclaration is a route's statement of which product it belongs to and
// which instance identifiers its requests carry. Build it with RequireScope and
// pass it to Authorize.
type ScopeDeclaration struct {
	product string
	dims    []Dimension
}

// RequireScope declares the dimensions a route's requests carry, for the product
// that owns the route. The product must be the same one passed to Authorize: a
// declaration for another product names another product's dimensions, and an
// identifier sent under a name the authorization service does not know for this
// product matches nothing — and a dimension nobody matches never denies, so the
// mismatch would WIDEN access instead of failing. Authorize denies it instead.
func RequireScope(product string, dims ...Dimension) ScopeDeclaration {
	return ScopeDeclaration{product: product, dims: dims}
}

// declared reports whether the declaration carries at least one dimension.
func (s ScopeDeclaration) declared() bool {
	return len(s.dims) > 0
}

// RequestScope is what Authorize resolved for the request in flight: the partner
// the credential is bound to, and the instance identifiers that were sent as
// attributes. Read it with ScopeFromContext to apply the same scope inside the
// request body, where the route's declaration cannot reach.
//
// It is recorded ONLY for a partner-bound credential, so a handler can never
// mistake "this caller is not a partner" for "this partner has no restriction".
type RequestScope struct {
	// Partner identifies the partner the credential is bound to (the token's
	// "partner" claim). Never empty when the scope is present.
	Partner string
	// Attributes are the resolved instance identifiers, keyed by declared field
	// name — the same map that was sent to the authorization service.
	Attributes map[string]string
}

// requestScopeContextKey is the unexported, typed key the scope is stored under.
// A dedicated type (rather than a string) cannot collide with another package's
// context value.
type requestScopeContextKey struct{}

// ScopeFromContext returns the scope Authorize resolved for the request, and
// whether there was one. The second return is false for every credential that is
// not partner-bound, and for a context that never passed through Authorize.
func ScopeFromContext(ctx context.Context) (RequestScope, bool) {
	scope, ok := ctx.Value(requestScopeContextKey{}).(RequestScope)

	return scope, ok
}

// resolveAttributes reads every declared dimension out of the request. The second
// return names the first dimension whose source carried nothing, which the caller
// denies: a declared identifier with no value cannot be matched against anything,
// and sending it absent would silently ask a narrower question than the route
// promised.
func resolveAttributes(c fiber.Ctx, dims []Dimension) (map[string]string, string) {
	if len(dims) == 0 {
		return nil, ""
	}

	attributes := make(map[string]string, len(dims))

	for _, dim := range dims {
		value := dim.resolve(c)
		if value == "" {
			return nil, dim.name
		}

		attributes[dim.name] = value
	}

	return attributes, ""
}

// attributesCacheKey folds the attributes into a single deterministic string so
// the decision cache can key on them: the cache key is a comparable struct and a
// map cannot live in one.
//
// The encoding is injective BY CONSTRUCTION: every name and every value is
// written with its byte length in front of it, so the reader of the string could
// always recover the exact map it came from. Separator bytes alone would not be
// enough — a value is caller-supplied and can contain any byte, including the
// separator — and two maps that fold to one string are two different questions
// sharing one cached answer, which for a partner-scoped credential means one
// partner's decision serving another partner's request.
func attributesCacheKey(attributes map[string]string) string {
	if len(attributes) == 0 {
		return ""
	}

	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}

	sort.Strings(names)

	var b strings.Builder

	for _, name := range names {
		writeLengthPrefixed(&b, name)
		writeLengthPrefixed(&b, attributes[name])
	}

	return b.String()
}

// writeLengthPrefixed writes s as its decimal byte length, a colon, then s. The
// length is what makes the fold injective: the colon is a delimiter for the
// length only, and a length can never contain one.
func writeLengthPrefixed(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
}

// resolveDeclaration validates a route's scope declaration once, at registration
// time, and returns it together with a non-empty description of what is wrong
// when it cannot be honoured. A misdeclared route refuses every request: the
// alternative is sending identifiers under a name the authorization service does
// not know for this product, which matches nothing — and a dimension nobody
// matches never denies, so the mistake would widen access instead of failing.
func resolveDeclaration(product string, scopes []ScopeDeclaration) (ScopeDeclaration, string) {
	if len(scopes) == 0 {
		return ScopeDeclaration{product: product}, ""
	}

	if len(scopes) > 1 {
		return ScopeDeclaration{}, "a route carries at most one scope declaration"
	}

	scope := scopes[0]
	if scope.product != product {
		return ScopeDeclaration{}, "scope declaration names product " + scope.product +
			", which is not the route's product " + product
	}

	for _, dim := range scope.dims {
		if dim.name == "" {
			return ScopeDeclaration{}, "scope declaration carries a dimension with no name"
		}

		if dim.source == SourceUnset {
			return ScopeDeclaration{}, "scope dimension " + dim.name + " declares no source"
		}

		if dim.key == "" {
			return ScopeDeclaration{}, "scope dimension " + dim.name + " declares an empty request key"
		}
	}

	return scope, ""
}
