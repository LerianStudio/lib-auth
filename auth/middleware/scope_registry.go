package middleware

import (
	"errors"
	"strconv"
	"strings"
	"sync"
)

// manifestScopeStore holds products' scope catalogs and route scopes. Every
// AuthClient has one, wired for the routes it authorizes; productScopes is the
// process-wide one, used by any client that has no catalog of its own for the
// product a route authorizes.
type manifestScopeStore struct {
	mu sync.RWMutex
	// scopes holds each product's scope catalog.
	scopes map[string][]Dimension
	// routes holds, per product, the dimensions single routes read from
	// somewhere other than their path, keyed by method and path.
	routes map[string]map[string]routeBodyScope
	// gen counts changes; routes compare it to what they derived from.
	gen uint64
}

// productScopes is the process-wide store declaration.New registers a manifest's
// scope in, keyed by the manifest's service.
var productScopes manifestScopeStore

// SetManifestScope wires the product's scope catalog — the scope section of its
// declaration manifest — into the client, so Authorize can derive each route's
// dimensions from the route path instead of every route declaring them.
//
// dims are the catalog in tree order, each read from a path parameter
// (Dim(name, FromPath).At(param)), a query parameter (FromQuery) or a header
// (FromHeader); no two read the same place. The declaration package builds them from the
// embedded manifest: declaration.New wires it into the client it is given and
// registers it process-wide (see SetProductManifestScope), and
// declaration.WireScope(auth, manifest) wires it into any other client. It may be called before
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

	return auth.manifestScope.setScope(product, dims)
}

// SetProductManifestScope registers the product's scope catalog process-wide:
// every AuthClient that has no catalog of its own for the product uses it, as if
// SetManifestScope had been called on it. A client with a catalog of its own for
// the product keeps it. Calling it with no dims removes the registered catalog.
//
// declaration.New registers the manifest it is given here, so the routes of a
// product derive their scope from its manifest even when they authorize with a
// client other than the one the publisher was built with.
func SetProductManifestScope(product string, dims ...Dimension) error {
	return productScopes.setScope(product, dims)
}

// SetProductManifestRouteScope declares, process-wide, the dimensions one route
// of the product reads from somewhere other than its path (see
// SetManifestRouteScope), for a product whose catalog SetProductManifestScope
// registered.
func SetProductManifestRouteScope(product, method, path string, dims ...Dimension) error {
	return productScopes.setRouteScope(product, method, path, dims)
}

func (store *manifestScopeStore) setScope(product string, dims []Dimension) error {
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

	store.mu.Lock()
	defer store.mu.Unlock()

	// Route body scopes were checked against the catalog being replaced, and
	// routes already registered must stop using what they derived from it.
	delete(store.routes, product)
	store.gen++

	if len(dims) == 0 {
		delete(store.scopes, product)

		return nil
	}

	if store.scopes == nil {
		store.scopes = make(map[string][]Dimension)
	}

	store.scopes[product] = append([]Dimension(nil), dims...)

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
	if auth == nil {
		return errors.New("manifest route scope: nil auth client")
	}

	return auth.manifestScope.setRouteScope(product, method, path, dims)
}

func (store *manifestScopeStore) setRouteScope(product, method, path string, dims []Dimension) error {
	method, err := routeTarget(product, method, path, len(dims))
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	catalog := store.scopes[product]
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

	if store.routes == nil {
		store.routes = make(map[string]map[string]routeBodyScope)
	}

	if store.routes[product] == nil {
		store.routes[product] = make(map[string]routeBodyScope)
	}

	if other := sameRouteUnderAnotherName(store.routes[product], method, path); other != "" {
		return errors.New("manifest route scope: " + method + " " + path + " and " + other + " name the same route; a request to it could not be told apart")
	}

	store.routes[product][routeScopeKey(method, path)] = routeBodyScope{dims: routeDims, plan: plan}
	store.gen++

	return nil
}

// sameRouteUnderAnotherName returns the path of a declared route of the same
// method that matches exactly the requests path does under other parameter
// names, or "". A request seen through a mount prefix is resolved among the
// declared routes, and two names for one route would leave it to a guess. The
// app's routing is not known here, so the routes are compared under the
// strictest one: only routes that are one route under any routing are refused,
// and the rest are told apart, or refused, when a request is resolved.
func sameRouteUnderAnotherName(routes map[string]routeBodyScope, method, path string) string {
	route, ok := parseRouteTemplate(method, path, strictestRouting)
	if !ok {
		return ""
	}

	for key := range routes {
		otherMethod, otherPath, _ := strings.Cut(key, " ")
		if otherMethod != method || otherPath == path {
			continue
		}

		if other, ok := parseRouteTemplate(otherMethod, otherPath, strictestRouting); ok && sameShape(route, other) {
			return otherPath
		}
	}

	return ""
}

// routeTarget checks the route SetManifestRouteScope addresses, and returns its
// method normalized.
func routeTarget(product, method, path string, count int) (string, error) {
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

// manifestGeneration is the count of manifest scope changes, the client's and
// the process-wide ones, read by routes to tell whether what they derived is
// still current. Both counts only grow, so their sum changes with either.
func (auth *AuthClient) manifestGeneration() uint64 {
	return auth.manifestScope.generation() + productScopes.generation()
}

// manifestRouteScope returns the manifest generation, the product's catalog and
// the scope declared for the route key, if any: the client's own when it has a
// catalog for the product, the process-wide ones otherwise. Each store is read
// in one consistent read; the generation covers both.
func (auth *AuthClient) manifestRouteScope(product, key string) (uint64, []Dimension, routeBodyScope, bool) {
	gen, catalog, body, declared := auth.manifestScope.route(product, key)
	sharedGen, sharedCatalog, sharedBody, sharedDeclared := productScopes.route(product, key)

	if len(catalog) > 0 {
		return gen + sharedGen, catalog, body, declared
	}

	return gen + sharedGen, sharedCatalog, sharedBody, sharedDeclared
}

// hasManifestScope reports whether the product has a catalog, the client's own
// or the process-wide one.
func (auth *AuthClient) hasManifestScope(product string) bool {
	return auth.manifestScope.hasScope(product) || productScopes.hasScope(product)
}

func (store *manifestScopeStore) hasScope(product string) bool {
	store.mu.RLock()
	defer store.mu.RUnlock()

	return len(store.scopes[product]) > 0
}

// manifestRouteKeys returns the method and path of every route the manifest
// declares for the product, from the same store manifestRouteScope reads.
func (auth *AuthClient) manifestRouteKeys(product string) []string {
	if keys, own := auth.manifestScope.routeKeys(product); own {
		return keys
	}

	keys, _ := productScopes.routeKeys(product)

	return keys
}

// routeKeys returns the product's declared route keys, and whether the store
// has a catalog for the product.
func (store *manifestScopeStore) routeKeys(product string) ([]string, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	keys := make([]string, 0, len(store.routes[product]))
	for key := range store.routes[product] {
		keys = append(keys, key)
	}

	return keys, len(store.scopes[product]) > 0
}

func (store *manifestScopeStore) generation() uint64 {
	store.mu.RLock()
	defer store.mu.RUnlock()

	return store.gen
}

func (store *manifestScopeStore) route(product, key string) (uint64, []Dimension, routeBodyScope, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	body, declared := store.routes[product][key]

	return store.gen, store.scopes[product], body, declared
}
