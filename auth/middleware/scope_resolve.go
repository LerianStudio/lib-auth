package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// ResolveInput is what a ScopeResolver is asked to translate: the values ONE
// request carries for a resolved dimension, together with what the request
// already says about where it points.
type ResolveInput struct {
	// Product is the product the route belongs to.
	Product string
	// Resolver is the name the resolver was registered under.
	Resolver string
	// Dimension is the dimension the values translate into (e.g. "accountId").
	Dimension string
	// Values are the distinct values the request carries, in the order first
	// named: every element of a body array, every value of a query parameter.
	// They are batched — one call per dimension and resolver per request — and
	// never more than the per-request cap of distinct sets (100).
	Values []string
	// Known are the dimensions the request names directly, by name — those read
	// from the path, the query, headers or a form that are not themselves
	// resolved (e.g. organizationId and ledgerId from the path) — so the lookup
	// can be confined to them. Nil when the request names none.
	Known map[string][]string
}

// ScopeResolver translates request values into dimension values: a transaction
// id into the account ids of its legs, an account alias into the account id.
//
// It returns, for each input value it knows, the dimension values it stands
// for — one or several. A value left out of the result, or mapped to no value,
// is unknown: the request is refused with 422 naming where it was read. A
// returned error means the lookup itself failed: the request is refused with
// 503 naming the resolver, and the error is logged, never sent to the caller.
// An empty string among the returned values is treated as such a failure.
//
// ctx carries the request's authorization deadline.
type ScopeResolver func(ctx context.Context, in ResolveInput) (map[string][]string, error)

// RegisterScopeResolver registers a resolver under name, for the dimensions
// that declare Resolve(name) — or resolve: name in the manifest. Register every
// resolver at boot, BEFORE declaration.WireScope and before registering routes:
// a manifest or a route that names a resolver not registered yet is refused.
//
// A name is registered once; it must be non-empty and carry no surrounding
// whitespace.
func (auth *AuthClient) RegisterScopeResolver(name string, resolver ScopeResolver) error {
	switch {
	case auth == nil:
		return errors.New("scope resolver: nil auth client")
	case name == "" || strings.TrimSpace(name) != name:
		return errors.New("scope resolver: name " + strconv.Quote(name) + " must be non-empty, with no surrounding whitespace")
	case resolver == nil:
		return errors.New("scope resolver " + strconv.Quote(name) + ": resolver function must not be nil")
	}

	auth.resolversMu.Lock()
	defer auth.resolversMu.Unlock()

	if _, dup := auth.resolvers[name]; dup {
		return errors.New("scope resolver " + strconv.Quote(name) + " is already registered")
	}

	if auth.resolvers == nil {
		auth.resolvers = make(map[string]ScopeResolver)
	}

	auth.resolvers[name] = resolver

	return nil
}

// Resolve returns a copy of the dimension whose request values are keys to
// translate with the resolver registered under name, instead of the
// dimension's values themselves. It never mutates the receiver.
//
// Resolution runs only for a partner-bound credential, like the body's
// dimensions: any other caller is asked without the dimension, and the
// resolver is not called.
func (d Dimension) Resolve(name string) Dimension {
	d.resolver = name

	return d
}

// Resolver is the name of the resolver that translates the dimension's request
// values, or "" when the request carries the values themselves.
func (d Dimension) Resolver() string { return d.resolver }

// scopeResolver returns the resolver registered under name.
func (auth *AuthClient) scopeResolver(name string) (ScopeResolver, bool) {
	if auth == nil {
		return nil, false
	}

	auth.resolversMu.RLock()
	defer auth.resolversMu.RUnlock()

	resolver, ok := auth.resolvers[name]

	return resolver, ok
}

// unregisteredResolver describes the first dimension naming a resolver that is
// not registered, or returns "".
func (auth *AuthClient) unregisteredResolver(dims []Dimension) string {
	for _, dim := range dims {
		if dim.resolver == "" {
			continue
		}

		if _, ok := auth.scopeResolver(dim.resolver); !ok {
			return "scope dimension " + dim.name + " names resolver " + strconv.Quote(dim.resolver) +
				", which is not registered; call RegisterScopeResolver first"
		}
	}

	return ""
}

// scopeResolution is what translating a request's resolved values needs: the
// request's context and deadline, the client holding the resolvers, and the
// route's product.
type scopeResolution struct {
	ctx     context.Context
	auth    *AuthClient
	product string
}

// call asks the named resolver to translate values, validating its answer. The
// result maps each input value to its dimension values; an input it left out
// is the caller's to report as unknown.
func (r scopeResolution) call(resolverName, dimension string, values []string, known map[string][]string) (map[string][]string, *errBodyScope) {
	if len(values) > maxBodyScopeQuestions {
		return nil, &errBodyScope{message: fmt.Sprintf(
			"the request names more than %d distinct values of scope dimension %q to resolve", maxBodyScopeQuestions, dimension)}
	}

	unavailable := &errBodyScope{
		status: http.StatusServiceUnavailable,
		message: "scope resolver " + strconv.Quote(resolverName) + " for dimension " + strconv.Quote(dimension) +
			" is unavailable",
	}

	resolver, ok := r.auth.scopeResolver(resolverName)
	if !ok {
		logErrorf(r.ctx, r.auth.Logger, "Scope resolver %q is not registered; denying (fail closed)", resolverName)

		return nil, unavailable
	}

	out, err := resolver(r.ctx, ResolveInput{
		Product:   r.product,
		Resolver:  resolverName,
		Dimension: dimension,
		Values:    values,
		Known:     known,
	})
	if err != nil {
		logErrorf(r.ctx, r.auth.Logger, "Scope resolver %q failed for dimension %q; denying (fail closed): %v", resolverName, dimension, err)

		return nil, unavailable
	}

	for _, value := range values {
		for _, resolved := range out[value] {
			if resolved == "" {
				logErrorf(r.ctx, r.auth.Logger, "Scope resolver %q returned an empty value for dimension %q; denying (fail closed)", resolverName, dimension)

				return nil, unavailable
			}
		}
	}

	return out, nil
}

// unresolved is the refusal of a request value its resolver does not know.
func unresolved(location, dimension string) *errBodyScope {
	return &errBodyScope{
		status:  http.StatusUnprocessableEntity,
		message: "scope " + location + " names a value that does not resolve to any " + strconv.Quote(dimension),
	}
}

// knownValues copies the dimensions the request names directly, for a
// resolver's Known.
func knownValues(readings requestValues) map[string][]string {
	if len(readings.names) == 0 {
		return nil
	}

	known := make(map[string][]string, len(readings.names))
	for _, name := range readings.names {
		known[name] = append([]string(nil), readings.values[name]...)
	}

	return known
}

// resolvePending translates the values read for resolved dimensions outside the
// body and records them as the dimensions' values. A dimension a carrier also
// names directly must then name the same values in both.
func (r scopeResolution) resolvePending(readings requestValues) (requestValues, *errBodyScope) {
	known := knownValues(readings)
	pending := readings.pending
	readings.pending = nil

	for _, p := range pending {
		out, err := r.call(p.dim.resolver, p.dim.name, p.values, known)
		if err != nil {
			return requestValues{}, err
		}

		var values []string

		seen := make(map[string]struct{})

		for _, value := range p.values {
			resolved := out[value]
			if len(resolved) == 0 {
				return requestValues{}, unresolved(p.dim.location(), p.dim.name)
			}

			for _, v := range resolved {
				if _, dup := seen[v]; !dup {
					seen[v] = struct{}{}
					values = append(values, v)
				}
			}
		}

		readings.add(p.dim, values)
	}

	if readings.problem != nil {
		return requestValues{}, readings.problem
	}

	return readings, nil
}

// rawQuestion is one question of a body whose keys are still to be resolved:
// the values read for it, where each was read, and, per resolved dimension, the
// resolver that translates its value.
type rawQuestion struct {
	values    map[string]string
	at        map[string]string
	resolvers map[string]string
}

// resolveBatch is one resolver call of a body: the distinct keys of one
// dimension that one resolver translates.
type resolveBatch struct {
	resolver, dimension string
	values              []string
	seen                map[string]struct{}
}

func batchKey(resolver, dimension string) string { return resolver + "\x00" + dimension }

// resolveBody translates the resolved keys of every collected body question —
// one call per resolver and dimension, with every distinct key — and asks, for
// each question, every combination of the values its keys resolve to.
func (r scopeResolution) resolveBody(raw []rawQuestion, set *questionSet, readings requestValues) *errBodyScope {
	order, batches := collectBatches(raw)

	known := knownValues(readings)
	results := make(map[string]map[string][]string, len(batches))

	for _, key := range order {
		b := batches[key]

		out, err := r.call(b.resolver, b.dimension, b.values, known)
		if err != nil {
			return err
		}

		results[key] = out
	}

	for _, q := range raw {
		combinations, err := expandResolved(q, results, set)
		if err != nil {
			return err
		}

		for _, question := range combinations {
			if err := set.add(question, q.at); err != nil {
				return err
			}
		}
	}

	return nil
}

// collectBatches groups the resolved keys of the questions by resolver and
// dimension, each key once, in the order first named.
func collectBatches(raw []rawQuestion) ([]string, map[string]*resolveBatch) {
	var order []string

	batches := make(map[string]*resolveBatch)

	for _, q := range raw {
		for _, name := range sortedKeys(q.resolvers) {
			key := batchKey(q.resolvers[name], name)

			b, ok := batches[key]
			if !ok {
				b = &resolveBatch{resolver: q.resolvers[name], dimension: name, seen: make(map[string]struct{})}
				batches[key] = b
				order = append(order, key)
			}

			if _, dup := b.seen[q.values[name]]; !dup {
				b.seen[q.values[name]] = struct{}{}
				b.values = append(b.values, q.values[name])
			}
		}
	}

	return order, batches
}

// expandResolved returns the questions one collected question makes: one per
// combination of the values its resolved keys stand for.
func expandResolved(q rawQuestion, results map[string]map[string][]string, set *questionSet) ([]map[string]string, *errBodyScope) {
	combinations := []map[string]string{q.values}

	for _, name := range sortedKeys(q.resolvers) {
		resolved := results[batchKey(q.resolvers[name], name)][q.values[name]]
		if len(resolved) == 0 {
			return nil, unresolved(q.at[name], name)
		}

		if len(combinations)*len(resolved) > maxBodyScopeQuestions {
			return nil, set.tooMany()
		}

		next := make([]map[string]string, 0, len(combinations)*len(resolved))

		for _, combination := range combinations {
			for _, value := range resolved {
				question := make(map[string]string, len(combination))
				for k, v := range combination {
					question[k] = v
				}

				question[name] = value
				next = append(next, question)
			}
		}

		combinations = next
	}

	return combinations, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}
