package middleware

import (
	"context"
	"errors"
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
	// source resolves empty, which the fail-closed guard denies.
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
	// resolver names the registered ScopeResolver that translates what the
	// request carries into the dimension's values; empty when the request
	// carries the values themselves.
	resolver string
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
	// pending are the values read for dimensions that are resolved: what the
	// request carries is not the dimension's value but a key to translate.
	// They join values only once resolved, for a partner-bound caller.
	pending []pendingValues
}

// pendingValues are the values one carrier names for a resolved dimension,
// still to be translated.
type pendingValues struct {
	dim    Dimension
	values []string
}

// record records the values a carrier names for dim: as the dimension's values,
// or as values still to resolve when the dimension is resolved.
func (rv *requestValues) record(dim Dimension, values []string) {
	if dim.resolver != "" {
		rv.pending = append(rv.pending, pendingValues{dim: dim, values: values})

		return
	}

	rv.add(dim, values)
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
			rv.record(dim, values)
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

		// A body dimension may repeat, read from different arrays; the body plan
		// checks each question still reads it once.
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

// SetManifestScope wires the product's scope catalog — the scope section of its
// declaration manifest — into the client, so Authorize can derive each route's
// dimensions from the route path instead of every route declaring them.
//
// dims are the catalog in tree order, each read from a path parameter
// (Dim(name, FromPath).At(param)), a query parameter (FromQuery) or a header
// (FromHeader); no two read the same place. The declaration package builds them from the
// embedded manifest: call declaration.WireScope(auth, manifest) rather than this
// directly. Call it at boot, BEFORE registering routes: a route registered
// while its product has no catalog never derives one. A later call reaches the
// routes already registered on a catalog: they derive from the new one.
//
// Once a product has a catalog, every route of that product that passes no
// RequireScope sends, as attributes, the catalog dimensions whose parameter is a
// WHOLE segment of the route path (":organization_id"), in catalog order — the
// same attributes an explicit declaration sends — plus every catalog dimension
// read from the query or a header that the request carries. A request that
// carries none of them behaves as on a route that declares nothing. A route that passes
// RequireScope keeps its declaration, which must then name only catalog
// dimensions.
//
// Calling it with no dims removes the product's catalog, leaving the client
// exactly as if it had never been called.
func (auth *AuthClient) SetManifestScope(product string, dims ...Dimension) error {
	if auth == nil {
		return errors.New("manifest scope: nil auth client")
	}

	if strings.TrimSpace(product) == "" {
		return errors.New("manifest scope: product must not be empty")
	}

	names := make(map[string]struct{}, len(dims))
	keys := make(map[string]struct{}, len(dims))

	for _, dim := range dims {
		switch {
		case dim.name == "":
			return errors.New("manifest scope: a dimension has no name")
		case dim.source != FromPath && dim.source != FromQuery && dim.source != FromHeader:
			return errors.New("manifest scope: dimension " + dim.name + " must be read from the path, the query or a header")
		case dim.key == "":
			return errors.New("manifest scope: dimension " + dim.name + " declares an empty request key")
		}

		if _, dup := names[dim.name]; dup {
			return errors.New("manifest scope: dimension " + dim.name + " is declared more than once")
		}

		if _, dup := keys[dim.carrier()]; dup {
			return errors.New("manifest scope: " + dim.location() + " is declared more than once")
		}

		if problem := auth.unregisteredResolver([]Dimension{dim}); problem != "" {
			return errors.New("manifest scope: " + problem)
		}

		names[dim.name] = struct{}{}
		keys[dim.carrier()] = struct{}{}
	}

	auth.manifestScopeMu.Lock()
	defer auth.manifestScopeMu.Unlock()

	// Route body scopes were checked against the catalog being replaced, and
	// routes already registered must stop using what they derived from it.
	delete(auth.manifestRouteScopes, product)
	auth.manifestGen++

	if len(dims) == 0 {
		delete(auth.manifestScopes, product)

		return nil
	}

	if auth.manifestScopes == nil {
		auth.manifestScopes = make(map[string][]Dimension)
	}

	auth.manifestScopes[product] = append([]Dimension(nil), dims...)

	return nil
}

// manifestScopeFor returns the product's catalog, or nil when it has none. A nil
// receiver has none.
func (auth *AuthClient) manifestScopeFor(product string) []Dimension {
	if auth == nil {
		return nil
	}

	auth.manifestScopeMu.RLock()
	defer auth.manifestScopeMu.RUnlock()

	return auth.manifestScopes[product]
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

// routeScope derives, and remembers per route path, the declaration of a route
// that relies on its product's catalog. One handler may be registered on several
// routes, so the path — not the handler — is the key.
type routeScope struct {
	auth    *AuthClient
	product string
	byRoute sync.Map // method and route path -> cachedRouteScope
}

// cachedRouteScope is a route's derived declaration together with the manifest
// generation it was derived from, so a later SetManifestScope or
// SetManifestRouteScope reaches routes registered before it.
type cachedRouteScope struct {
	generation uint64
	scope      ScopeDeclaration
}

func (r *routeScope) forRoute(method, path string) ScopeDeclaration {
	key := routeScopeKey(method, path)
	generation := r.auth.manifestGeneration()

	if cached, ok := r.byRoute.Load(key); ok {
		if entry := cached.(cachedRouteScope); entry.generation == generation {
			return entry.scope
		}
	}

	generation, catalog, body, declared := r.auth.manifestRouteScope(r.product, key)

	scope := ScopeDeclaration{product: r.product, dims: deriveRouteDimensions(catalog, path)}

	if declared {
		scope.dims = body.dims
		scope.body = body.plan
	}

	r.byRoute.Store(key, cachedRouteScope{generation: generation, scope: scope})

	return scope
}

// registerRouteScope resolves a route's scope at registration time: its explicit
// declaration, validated and — when the product has a manifest scope — checked
// against that catalog; or, when the route passes none and a catalog exists, the
// deriver that reads the route's dimensions from its path. A misdeclaration is
// logged here, in the boot log, and not only on the first request it refuses.
func (auth *AuthClient) registerRouteScope(product string, scopes []ScopeDeclaration) (ScopeDeclaration, *routeScope, string) {
	scope, declErr := resolveDeclaration(product, scopes)

	catalog := auth.manifestScopeFor(product)
	if declErr == "" && len(scopes) > 0 {
		declErr = checkAgainstCatalog(scope, catalog)
	}

	if declErr == "" {
		declErr = auth.unregisteredResolver(scope.dims)
	}

	var derived *routeScope
	if len(scopes) == 0 && len(catalog) > 0 {
		derived = &routeScope{auth: auth, product: product}
	}

	if declErr != "" && auth != nil {
		logErrorf(context.Background(), auth.Logger, "Route for product %q is misdeclared and will refuse every request: %s", product, declErr)
	}

	return scope, derived, declErr
}
