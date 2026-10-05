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
// embedded manifest: declaration.New wires it into the client it is given, and
// declaration.WireScope(auth, manifest) into any other. It may be called before
// or after the routes are registered: a route works out its scope on its first
// request, and again on the first request after every later call.
//
// Once a product has a catalog, every route of that product that passes no
// RequireScope sends, as the attributes of a partner-bound request, the catalog
// dimensions whose parameter is a
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

// routeBodyScope is one route's dimensions — those its path carries and those
// the manifest declares for it — compiled once.
type routeBodyScope struct {
	dims []Dimension
	plan *bodyPlan
}

func routeScopeKey(method, path string) string {
	return method + " " + path
}

// SetManifestRouteScope declares the dimensions ONE route of the product reads
// from somewhere other than its path — its JSON body (FromBody), a urlencoded
// form (FromForm), the query (FromQuery) or a header (FromHeader) — for a
// product whose catalog SetManifestScope already wired: some routes carry the
// instance they address in the body, and only the route knows where.
//
// method and path identify the route exactly as it is registered (the full path,
// group prefixes included, with its ':' parameters). dims are catalog
// dimensions declared with Dim(name, source).At(key), validated exactly as a
// RequireScope declaration is. The route still derives the dimensions its path
// carries; a dimension it also reads elsewhere must name the same values in
// both, or the request is refused with 400 naming the two.
//
// The declaration package builds these from the manifest's scope.routes: call
// declaration.WireScope rather than this directly. A route that passes
// RequireScope keeps its own declaration and ignores this. SetManifestScope
// drops every route declared for the product.
func (auth *AuthClient) SetManifestRouteScope(product, method, path string, dims ...Dimension) error {
	method, err := auth.routeTarget(product, method, path, len(dims))
	if err != nil {
		return err
	}

	auth.manifestScopeMu.Lock()
	defer auth.manifestScopeMu.Unlock()

	catalog := auth.manifestScopes[product]
	if len(catalog) == 0 {
		return errors.New("manifest route scope: product " + product + " has no manifest scope; call SetManifestScope first")
	}

	known := make(map[string]struct{}, len(catalog))
	for _, dim := range catalog {
		known[dim.name] = struct{}{}
	}

	for _, dim := range dims {
		if problem := checkRouteDimension(product, dim, known); problem != "" {
			return errors.New("manifest route scope: dimension " + dim.name + " on " + method + " " + path + " " + problem)
		}
	}

	routeDims := append(deriveRouteDimensions(catalog, path), dims...)

	plan, problem := compileDims(routeDims)
	if problem != "" {
		return errors.New("manifest route scope: " + method + " " + path + ": " + problem)
	}

	if auth.manifestRouteScopes == nil {
		auth.manifestRouteScopes = make(map[string]map[string]routeBodyScope)
	}

	if auth.manifestRouteScopes[product] == nil {
		auth.manifestRouteScopes[product] = make(map[string]routeBodyScope)
	}

	auth.manifestRouteScopes[product][routeScopeKey(method, path)] = routeBodyScope{dims: routeDims, plan: plan}
	auth.manifestGen++

	return nil
}

// routeTarget checks the route SetManifestRouteScope addresses, and returns its
// method normalized.
func (auth *AuthClient) routeTarget(product, method, path string, count int) (string, error) {
	if auth == nil {
		return "", errors.New("manifest route scope: nil auth client")
	}

	method = strings.ToUpper(strings.TrimSpace(method))

	switch {
	case strings.TrimSpace(product) == "":
		return "", errors.New("manifest route scope: product must not be empty")
	case method == "":
		return "", errors.New("manifest route scope: method must not be empty")
	case !strings.HasPrefix(path, "/"):
		return "", errors.New("manifest route scope: path " + strconv.Quote(path) + " must start with '/'")
	case count == 0:
		return "", errors.New("manifest route scope: " + method + " " + path + " declares no dimension")
	}

	return method, nil
}

// checkRouteDimension describes what is wrong with dim as a dimension declared
// on one manifest route, or returns "". The route's path dimensions are derived
// from its path, as on every other route.
func checkRouteDimension(product string, dim Dimension, catalog map[string]struct{}) string {
	if dim.source == FromPath {
		return "is derived from the path and must not be declared on the route"
	}

	if _, ok := catalog[dim.name]; !ok {
		return "is not declared in the manifest scope of product " + product
	}

	return ""
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
