package middleware

import (
	"errors"
	"strconv"
	"strings"
)

// Filter returns a copy of the declaration for a route that LISTS what it
// addresses and filters the list itself: when a partner-bound request leaves
// one of dimensions out, the authorization service is asked to answer with the
// values of it the partner may see, instead of refusing the request, and the
// handler confines its list to them (see RequestScope.Allowed). It never
// mutates the receiver.
//
// Each dimension is named once, by its declared name; with a manifest scope it
// must be a catalog dimension.
func (s ScopeDeclaration) Filter(dimensions ...string) ScopeDeclaration {
	s.filter = append([]string(nil), dimensions...)

	return s
}

// filterProblem describes what is wrong with a route's filter, or returns "".
func filterProblem(filter []string) string {
	seen := make(map[string]struct{}, len(filter))

	for _, name := range filter {
		if name == "" {
			return "scope declaration filters on a dimension with no name"
		}

		if _, dup := seen[name]; dup {
			return "scope declaration filters on dimension " + name + " more than once"
		}

		seen[name] = struct{}{}
	}

	return ""
}

// SetManifestRouteFilter marks ONE route of the product as filtering its list
// on dimensions: when a partner-bound request leaves one of them out, the
// authorization service is asked for the values of it the partner may see
// instead of refusing, and the handler must confine its list to the values
// RequestScope.Allowed returns. The route still derives the dimensions its
// path carries, and keeps what SetManifestRouteScope declared for it, before or
// after this call.
//
// method and path identify the route exactly as SetManifestRouteScope does;
// dimensions are catalog dimension names, each once. The declaration package
// calls this for the filter of every scope.routes entry: call
// declaration.WireScope rather than this directly, at boot, BEFORE registering
// routes. SetManifestScope drops it, with every route declared for the product.
func (auth *AuthClient) SetManifestRouteFilter(product, method, path string, dimensions ...string) error {
	if auth == nil {
		return errors.New("manifest route filter: nil auth client")
	}

	method = strings.ToUpper(strings.TrimSpace(method))

	switch {
	case strings.TrimSpace(product) == "":
		return errors.New("manifest route filter: product must not be empty")
	case method == "":
		return errors.New("manifest route filter: method must not be empty")
	case !strings.HasPrefix(path, "/"):
		return errors.New("manifest route filter: path " + strconv.Quote(path) + " must start with '/'")
	case len(dimensions) == 0:
		return errors.New("manifest route filter: " + method + " " + path + " filters on no dimension")
	}

	if problem := filterProblem(dimensions); problem != "" {
		return errors.New("manifest route filter: " + method + " " + path + ": " + problem)
	}

	auth.manifestScopeMu.Lock()
	defer auth.manifestScopeMu.Unlock()

	catalog := auth.manifestScopes[product]
	if len(catalog) == 0 {
		return errors.New("manifest route filter: product " + product + " has no manifest scope; call SetManifestScope first")
	}

	known := make(map[string]struct{}, len(catalog))
	for _, dim := range catalog {
		known[dim.name] = struct{}{}
	}

	for _, name := range dimensions {
		if _, ok := known[name]; !ok {
			return errors.New("manifest route filter: dimension " + name + " on " + method + " " + path +
				" is not declared in the manifest scope of product " + product)
		}
	}

	key := routeScopeKey(method, path)

	route, declared := auth.manifestRouteScopes[product][key]
	if !declared {
		route = routeBodyScope{dims: deriveRouteDimensions(catalog, path)}
	}

	route.filter = append([]string(nil), dimensions...)

	if auth.manifestRouteScopes == nil {
		auth.manifestRouteScopes = make(map[string]map[string]routeBodyScope)
	}

	if auth.manifestRouteScopes[product] == nil {
		auth.manifestRouteScopes[product] = make(map[string]routeBodyScope)
	}

	auth.manifestRouteScopes[product][key] = route
	auth.manifestGen++

	return nil
}

// absentFilter returns the route's filter dimensions the question leaves out:
// the ones the authorization service is asked to answer with allowed values.
func absentFilter(filter []string, question map[string]string) []string {
	var absent []string

	for _, name := range filter {
		if _, named := question[name]; !named {
			absent = append(absent, name)
		}
	}

	return absent
}

// Allowed returns the values of dimension the authorization service said the
// partner may see, and whether it said any. It is set only on a route that
// filters on the dimension (Filter, or filter: in the manifest) and only when
// the request left the dimension out. The handler must then confine what it
// lists to these values, typically with "IN (...)":
//
//	if scope, ok := middleware.ScopeFromContext(ctx); ok {
//		if ids, ok := scope.Allowed("accountId"); ok {
//			query = query.Where(squirrel.Eq{"id": ids}) // an empty ids lists nothing
//		}
//	}
//
// An empty, non-nil result means the partner may see NONE: list nothing. The
// second return is false when the service confined nothing on the dimension.
// When the request asked several questions, the values are those any of them
// returned, in the order first returned.
func (s RequestScope) Allowed(dimension string) ([]string, bool) {
	values, ok := s.allowed[dimension]
	if !ok {
		return nil, false
	}

	return append([]string{}, values...), true
}

// allowedValues accumulates the allowed values of every question of a request.
type allowedValues struct {
	values map[string][]string
	seen   map[string]map[string]struct{}
}

// add records the values one question returned for the dimensions it asked to
// filter; values for any other dimension are ignored.
func (a *allowedValues) add(asked []string, returned map[string][]string) {
	for _, name := range asked {
		values, ok := returned[name]
		if !ok {
			continue
		}

		if a.values == nil {
			a.values = make(map[string][]string)
			a.seen = make(map[string]map[string]struct{})
		}

		if _, ok := a.values[name]; !ok {
			a.values[name] = []string{}
			a.seen[name] = make(map[string]struct{})
		}

		for _, v := range values {
			if _, dup := a.seen[name][v]; !dup {
				a.seen[name][v] = struct{}{}
				a.values[name] = append(a.values[name], v)
			}
		}
	}
}

// coversAll reports whether returned carries values for every asked dimension.
func coversAll(asked []string, returned map[string][]string) bool {
	for _, name := range asked {
		if _, ok := returned[name]; !ok {
			return false
		}
	}

	return true
}

// foldFilter folds a filter into one string for the decision cache key,
// injectively: every name is length-prefixed.
func foldFilter(filter []string) string {
	var b strings.Builder

	for _, name := range filter {
		writeLengthPrefixed(&b, name)
	}

	return b.String()
}
