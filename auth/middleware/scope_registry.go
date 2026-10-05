package middleware

import (
	"errors"
	"strconv"
	"strings"
)

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
		case dim.matchProblem() != "":
			return errors.New("manifest scope: " + dim.matchProblem())
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

// routeBodyScope is one route's dimensions — those its path carries and those
// the manifest declares for it — compiled once.
type routeBodyScope struct {
	dims []Dimension
	plan *bodyPlan
	// filter names the dimensions the route filters its list on (see
	// SetManifestRouteFilter).
	filter []string
}

func routeScopeKey(method, path string) string {
	return method + " " + path
}

// SetManifestRouteScope declares the dimensions ONE route of the product reads
// from somewhere other than its path — its JSON body (FromBody), the query
// (FromQuery) or a header (FromHeader) — for a product
// whose catalog SetManifestScope already wired: some routes carry the instance
// they address in the body, and only the route knows where.
//
// method and path identify the route exactly as it is registered (the full path,
// group prefixes included, with its ':' parameters). dims are catalog
// dimensions declared with Dim(name, source).At(key), validated exactly as a
// RequireScope declaration is. The route still derives the dimensions its path
// carries; a dimension it also reads elsewhere must name the same values in
// both, or the request is refused with 400 naming the two. The declaration package
// builds these from the manifest's scope.routes: call declaration.WireScope
// rather than this directly, at boot, BEFORE registering routes.
//
// A route that passes RequireScope keeps its own declaration and ignores this.
// SetManifestScope drops every route declared for the product.
func (auth *AuthClient) SetManifestRouteScope(product, method, path string, dims ...Dimension) error {
	method, err := auth.routeTarget("manifest route scope", product, method, path, len(dims), "declares no dimension")
	if err != nil {
		return err
	}

	auth.manifestScopeMu.Lock()
	defer auth.manifestScopeMu.Unlock()

	catalog, known, err := auth.routeCatalog("manifest route scope", product)
	if err != nil {
		return err
	}

	for _, dim := range dims {
		if problem := auth.checkRouteDimension(product, path, dim, known); problem != "" {
			return errors.New("manifest route scope: dimension " + dim.name + " on " + method + " " + path + " " + problem)
		}
	}

	routeDims := append(deriveRouteDimensions(catalog, path), dims...)

	plan, problem := compileDims(routeDims)
	if problem != "" {
		return errors.New("manifest route scope: " + method + " " + path + ": " + problem)
	}

	key := routeScopeKey(method, path)

	auth.storeRouteScope(product, key, routeBodyScope{
		dims:   routeDims,
		plan:   plan,
		filter: auth.manifestRouteScopes[product][key].filter,
	})

	return nil
}

// routeTarget checks the route a manifest route setter addresses, and returns
// its method normalized. op prefixes every error, and nothing is how the route
// is described when it names no dimension (count is 0).
func (auth *AuthClient) routeTarget(op, product, method, path string, count int, nothing string) (string, error) {
	if auth == nil {
		return "", errors.New(op + ": nil auth client")
	}

	method = strings.ToUpper(strings.TrimSpace(method))

	switch {
	case strings.TrimSpace(product) == "":
		return "", errors.New(op + ": product must not be empty")
	case method == "":
		return "", errors.New(op + ": method must not be empty")
	case !strings.HasPrefix(path, "/"):
		return "", errors.New(op + ": path " + strconv.Quote(path) + " must start with '/'")
	case count == 0:
		return "", errors.New(op + ": " + method + " " + path + " " + nothing)
	}

	return method, nil
}

// routeCatalog returns the product's catalog and the names it declares, or the
// error for a product with none. The caller holds manifestScopeMu.
func (auth *AuthClient) routeCatalog(op, product string) ([]Dimension, map[string]struct{}, error) {
	catalog := auth.manifestScopes[product]
	if len(catalog) == 0 {
		return nil, nil, errors.New(op + ": product " + product + " has no manifest scope; call SetManifestScope first")
	}

	known := make(map[string]struct{}, len(catalog))
	for _, dim := range catalog {
		known[dim.name] = struct{}{}
	}

	return catalog, known, nil
}

// storeRouteScope records the scope of one route of the product and tells the
// routes already registered that the manifest scope changed. The caller holds
// manifestScopeMu.
func (auth *AuthClient) storeRouteScope(product, key string, route routeBodyScope) {
	if auth.manifestRouteScopes == nil {
		auth.manifestRouteScopes = make(map[string]map[string]routeBodyScope)
	}

	if auth.manifestRouteScopes[product] == nil {
		auth.manifestRouteScopes[product] = make(map[string]routeBodyScope)
	}

	auth.manifestRouteScopes[product][key] = route
	auth.manifestGen++
}

// checkRouteDimension describes what is wrong with dim as a dimension declared
// on one manifest route, or returns "". The route's path dimensions are derived
// from its path, as on every other route; the manifest route declares the ones
// read elsewhere, and a path parameter whose value is resolved into the
// dimension.
func (auth *AuthClient) checkRouteDimension(product, path string, dim Dimension, catalog map[string]struct{}) string {
	switch {
	case dim.source == FromPath && dim.resolver == "":
		return "is derived from the path and must not be declared on the route unless it is resolved"
	case dim.source == FromPath && !hasPathParam(path, dim.key):
		return "reads path parameter " + strconv.Quote(dim.key) + ", which the route path does not carry"
	}

	if problem := auth.unregisteredResolver([]Dimension{dim}); problem != "" {
		return "names resolver " + strconv.Quote(dim.resolver) + ", which is not registered; call RegisterScopeResolver first"
	}

	if _, ok := catalog[dim.name]; !ok {
		return "is not declared in the manifest scope of product " + product
	}

	return ""
}

// hasPathParam reports whether one whole segment of path is the parameter
// :param.
func hasPathParam(path, param string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == ":"+param {
			return true
		}
	}

	return false
}

// manifestGeneration is the count of manifest scope changes, read by routes to
// tell whether what they derived is still current.
func (auth *AuthClient) manifestGeneration() uint64 {
	auth.manifestScopeMu.RLock()
	defer auth.manifestScopeMu.RUnlock()

	return auth.manifestGen
}

// manifestRouteScope returns, in one consistent read, the manifest generation,
// the product's catalog and the scope declared for the route key, if any.
func (auth *AuthClient) manifestRouteScope(product, key string) (uint64, []Dimension, routeBodyScope, bool) {
	auth.manifestScopeMu.RLock()
	defer auth.manifestScopeMu.RUnlock()

	body, declared := auth.manifestRouteScopes[product][key]

	return auth.manifestGen, auth.manifestScopes[product], body, declared
}
