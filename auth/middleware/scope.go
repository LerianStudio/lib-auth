package middleware

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"

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
	// source is a misdeclaration, refused when the declaration is validated.
	SourceUnset Source = iota
	// FromPath reads a path parameter (fiber.Ctx.Params).
	FromPath
	// FromHeader reads a request header, its name compared without regard to
	// letter case. A header repeated, or a value listing several separated by
	// ',', names every one of them, each its own question.
	FromHeader
	// FromQuery reads a query-string parameter. A parameter repeated, or a value
	// listing several separated by ',', names every one of them, each its own
	// question.
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
	name     string
	source   Source
	key      string
	optional bool
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

// Optional returns a copy of the dimension that a request may leave out. A
// request that does not carry it — a body field absent or null — asks its
// question without it; a value that is there must still be a non-empty string.
// It never mutates the receiver.
func (d Dimension) Optional() Dimension {
	d.optional = true

	return d
}

// IsOptional reports whether a request may leave the dimension out.
func (d Dimension) IsOptional() bool { return d.optional }

// Name is the attribute key sent to the authorization service.
func (d Dimension) Name() string { return d.name }

// Key is the request parameter, header or query key the value is read from.
func (d Dimension) Key() string { return d.key }

// Source is where in the request the value is read from.
func (d Dimension) Source() Source { return d.source }

// read reads the dimension's values out of the request. present is false when
// the request does not carry the dimension at all; problem is non-empty when it
// carries it malformed. A path parameter is one value. A query parameter or a
// header may name several: every occurrence of it, each split on ',' with the
// spaces around an element trimmed, so "?id=a&id=b", "?id=a,b" and two header
// lines "a" and "b" all name a and b. An element that is empty after trimming
// names nothing and is malformed. Body dimensions are read by the body plan.
func (d Dimension) read(c fiber.Ctx) (values []string, present bool, problem string) {
	switch d.source {
	case FromPath:
		value := c.Params(d.key)

		return []string{value}, value != "", ""
	case FromHeader:
		var raw []string

		// Compared without regard to letter case, whatever the app's header
		// normalization: the header the handler reads is the header checked.
		for k, v := range c.Request().Header.All() {
			if strings.EqualFold(string(k), d.key) {
				raw = append(raw, string(v))
			}
		}

		return splitValues(raw)
	case FromQuery:
		var raw []string
		for _, v := range c.Request().URI().QueryArgs().PeekMulti(d.key) {
			raw = append(raw, string(v))
		}

		return splitValues(raw)
	case SourceUnset, FromBody, FromForm:
		return nil, false, ""
	default:
		return nil, false, ""
	}
}

// splitValues splits every occurrence of a query parameter, header or form
// field into its comma-separated elements, trimmed, keeping each distinct value
// once in the order first named.
func splitValues(raw []string) ([]string, bool, string) {
	if len(raw) == 0 {
		return nil, false, ""
	}

	var values []string

	seen := make(map[string]struct{})

	for _, occurrence := range raw {
		for _, element := range strings.Split(occurrence, ",") {
			value := strings.TrimSpace(element)
			if value == "" {
				return nil, true, "must not name an empty value"
			}

			if _, dup := seen[value]; dup {
				continue
			}

			seen[value] = struct{}{}
			values = append(values, value)
		}
	}

	return values, true, ""
}

// location names where in the request the dimension is read, for the refusals
// that point the caller at it.
func (d Dimension) location() string {
	switch d.source {
	case FromPath:
		return "path parameter " + strconv.Quote(d.key)
	case FromHeader:
		return "header " + strconv.Quote(d.key)
	case FromQuery:
		return "query parameter " + strconv.Quote(d.key)
	case FromBody:
		return "body field " + strconv.Quote(d.key)
	case FromForm:
		return "form field " + strconv.Quote(d.key)
	case SourceUnset:
		return "nowhere"
	default:
		return "nowhere"
	}
}

// carrier identifies the place in the request a dimension is read from. Header
// names are case-insensitive, so two spellings of one header are one carrier.
func (d Dimension) carrier() string {
	key := d.key
	if d.source == FromHeader {
		key = strings.ToLower(key)
	}

	return strconv.Itoa(int(d.source)) + ":" + key
}

// ScopeDeclaration is a route's statement of which product it belongs to and
// which instance identifiers its requests carry. Build it with RequireScope and
// pass it to Authorize.
type ScopeDeclaration struct {
	product string
	dims    []Dimension
	// body is the compiled plan of the dimensions read from the request body, or
	// nil when the route reads none.
	body *bodyPlan
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
	// Sets are the identifier sets the request was authorized for, one per
	// question asked. A route that reads its dimensions from the path asks one,
	// equal to Attributes; a route that reads them from a body batch asks one per
	// distinct set the body names, and Attributes then keeps only the
	// identifiers every set shares.
	Sets []map[string]string
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

// requestValues is what the request carries for the dimensions read outside
// its body: the distinct values of each dimension, in the order the dimensions
// are declared, and where each was first read.
type requestValues struct {
	names  []string
	values map[string][]string
	where  map[string]string
	// problem is the first carrier found malformed, or the first dimension two
	// carriers disagree on. It is reported once the caller is authenticated.
	problem *errBodyScope
}

// add records the values one carrier names for a dimension. A dimension already
// read from another carrier must name the same set of values there: when the two
// disagree the handler may act on either, and no single question checks both.
func (rv *requestValues) add(dim Dimension, values []string) {
	if previous, ok := rv.values[dim.name]; ok {
		if !sameValues(previous, values) && rv.problem == nil {
			rv.problem = divergence(dim.name, rv.where[dim.name], dim.location())
		}

		return
	}

	if rv.values == nil {
		rv.values = make(map[string][]string)
		rv.where = make(map[string]string)
	}

	rv.names = append(rv.names, dim.name)
	rv.values[dim.name] = values
	rv.where[dim.name] = dim.location()
}

// sameValues reports whether two lists of distinct values name the same set.
func sameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}

	for _, v := range b {
		if _, ok := set[v]; !ok {
			return false
		}
	}

	return true
}

func divergence(name, first, second string) *errBodyScope {
	return &errBodyScope{message: "scope dimension " + strconv.Quote(name) + " is given different values in " + first + " and " + second}
}

// resolveAttributes reads every declared dimension outside the body out of the
// request. The second return names the first required dimension the request
// does not carry, which the caller denies: a declared identifier with no value
// cannot be matched against anything, and sending it absent would silently ask
// a narrower question than the route promised. An optional dimension the request
// does not carry is left out.
func resolveAttributes(c fiber.Ctx, dims []Dimension) (requestValues, string) {
	var rv requestValues

	for _, dim := range dims {
		// A body dimension is not one value of the request but one per question
		// the body makes; the body plan reads those. A form field is read with
		// the body, only for the callers whose body is read.
		if dim.source == FromBody || dim.source == FromForm {
			continue
		}

		values, present, problem := dim.read(c)

		switch {
		case problem != "":
			if rv.problem == nil {
				rv.problem = &errBodyScope{message: "scope " + dim.location() + " " + problem}
			}
		case !present && dim.optional:
		case !present:
			return requestValues{}, dim.name
		default:
			rv.add(dim, values)
		}
	}

	return rv, ""
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

	plan, problem := compileDims(scope.dims)
	if problem != "" {
		return ScopeDeclaration{}, problem
	}

	scope.body = plan

	return scope, ""
}

// compileDims validates a route's dimensions, whatever their source, and
// compiles the ones read from the body. It is the one check every declaration
// passes — an explicit RequireScope and a manifest route alike.
//
// A dimension may be read from several carriers — the path and a header, the
// query and the body — and the request must then name the same values in each.
// Reading it twice from the SAME carrier is a mistake, not a wider question.
func compileDims(dims []Dimension) (*bodyPlan, string) {
	seen := make(map[string]struct{}, len(dims))
	sources := make(map[Source]struct{}, len(dims))

	for _, dim := range dims {
		sources[dim.source] = struct{}{}

		if dim.name == "" {
			return nil, "scope declaration carries a dimension with no name"
		}

		if dim.source == SourceUnset {
			return nil, "scope dimension " + dim.name + " declares no source"
		}

		if dim.key == "" {
			return nil, "scope dimension " + dim.name + " declares an empty request key"
		}

		// A body dimension may repeat, read from distinct fields, each asked; the
		// body plan refuses one field read twice.
		if dim.source == FromBody {
			continue
		}

		key := dim.name + "\x00" + dim.carrier()
		if _, duplicate := seen[key]; duplicate {
			return nil, "scope dimension " + dim.name + " is declared more than once from " + dim.location()
		}

		seen[key] = struct{}{}
	}

	_, readsJSON := sources[FromBody]
	_, readsForm := sources[FromForm]

	if readsJSON && readsForm {
		return nil, "scope declaration reads the request body both as JSON (FromBody) and as a form (FromForm)"
	}

	return compileBodyPlan(dims)
}

// checkAgainstCatalog reports the first dimension of an explicit declaration the
// catalog does not declare. Sending it would ask the authorization service about
// a field the product never published, which matches nothing — and a dimension
// nobody matches never denies.
func checkAgainstCatalog(scope ScopeDeclaration, catalog []Dimension) string {
	if len(catalog) == 0 {
		return ""
	}

	known := make(map[string]struct{}, len(catalog))
	for _, dim := range catalog {
		known[dim.name] = struct{}{}
	}

	for _, dim := range scope.dims {
		if _, ok := known[dim.name]; !ok {
			return "scope dimension " + dim.name + " is not declared in the manifest scope of product " + scope.product
		}
	}

	return ""
}

// deriveRouteDimensions returns the catalog dimensions a route addresses. A
// path dimension applies when one WHOLE segment of the path is its parameter
// with the ':' marker. A literal segment spelling the parameter is text, and a
// segment that merely contains it (":organization_id.json", ":organization_id?")
// is a different parameter. A dimension read from the query or a header applies
// to every route — the path cannot say whether a request carries it — and is
// derived optional: read when the request carries it, left out when it does not.
// The result keeps catalog order, whatever the order of the segments, and is
// empty when the route addresses none.
func deriveRouteDimensions(catalog []Dimension, path string) []Dimension {
	segments := make(map[string]struct{})

	for _, segment := range strings.Split(path, "/") {
		if strings.HasPrefix(segment, ":") {
			segments[segment[1:]] = struct{}{}
		}
	}

	dims := make([]Dimension, 0, len(catalog))

	for _, dim := range catalog {
		if dim.source != FromPath {
			dims = append(dims, dim.Optional())

			continue
		}

		if _, ok := segments[dim.key]; ok {
			dims = append(dims, dim)
		}
	}

	return dims
}

// routeScope works out, and remembers per route path, the scope of a route on
// its first request — not when the route is registered — so a catalog wired
// after the routes reaches them as one wired before does. One handler may be
// registered on several routes, so the path, not the handler, is the key.
type routeScope struct {
	auth    *AuthClient
	product string
	// explicit is the route's own declaration, already validated on its own;
	// nil when the route relies on its product's catalog.
	explicit *ScopeDeclaration
	byRoute  sync.Map // method and route path -> cachedRouteScope
}

// cachedRouteScope is a route's scope together with the manifest generation it
// was worked out from, so a later SetManifestScope or SetManifestRouteScope
// reaches routes that already served a request. problem is non-empty when the
// route cannot be honoured on that generation.
type cachedRouteScope struct {
	generation uint64
	scope      ScopeDeclaration
	problem    string
}

// forRoute returns the scope of the route, and a non-empty description of what
// is wrong when the route cannot be honoured: an explicit declaration naming a
// dimension its product's catalog does not declare.
func (r *routeScope) forRoute(method, path string) (ScopeDeclaration, string) {
	key := routeScopeKey(method, path)
	generation := r.auth.manifestGeneration()

	if cached, ok := r.byRoute.Load(key); ok {
		if entry := cached.(cachedRouteScope); entry.generation == generation {
			return entry.scope, entry.problem
		}
	}

	generation, catalog, route, declared := r.auth.manifestRouteScope(r.product, key)
	entry := cachedRouteScope{generation: generation}

	switch {
	case r.explicit != nil:
		entry.scope = *r.explicit
		entry.problem = checkAgainstCatalog(*r.explicit, catalog)
	case declared:
		entry.scope = ScopeDeclaration{product: r.product, dims: route.dims, body: route.plan}
	default:
		entry.scope = ScopeDeclaration{product: r.product, dims: deriveRouteDimensions(catalog, path)}
	}

	if entry.problem != "" {
		logErrorf(context.Background(), r.auth.Logger, "Route %s for product %q is misdeclared and will refuse every request: %s", key, r.product, entry.problem)
	}

	r.byRoute.Store(key, entry)

	return entry.scope, entry.problem
}

// registerRouteScope validates a route's explicit declaration on its own, at
// registration time, and returns what works out the route's scope on each
// request (see routeScope). A declaration that is wrong whatever the catalog is
// logged here, in the boot log, and not only on the first request it refuses.
// A nil client has no catalog, and its routes no scope.
func (auth *AuthClient) registerRouteScope(product string, scopes []ScopeDeclaration) (*routeScope, string) {
	scope, declErr := resolveDeclaration(product, scopes)
	if auth == nil {
		return nil, declErr
	}

	if declErr != "" {
		logErrorf(context.Background(), auth.Logger, "Route for product %q is misdeclared and will refuse every request: %s", product, declErr)

		return nil, declErr
	}

	route := &routeScope{auth: auth, product: product}
	if len(scopes) > 0 {
		route.explicit = &scope
	}

	return route, ""
}
