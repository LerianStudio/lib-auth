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
	// Items are the distinct values the request carries, each with the context
	// it was read in, in the order first named: every element of a body array,
	// every value of a query parameter. The same value read with different
	// siblings is one item per context. They are batched — one call per
	// dimension and resolver per request — and never more than the per-request
	// cap of distinct sets (100).
	Items []ResolveItem
	// Known are the dimensions the request names directly, by name — those read
	// from the path, the query, headers or a form that are not themselves
	// resolved (e.g. organizationId and ledgerId from the path) — so the lookup
	// can be confined to them. Nil when the request names none.
	Known map[string][]string
}

// ResolveItem is one value to translate and the context it was read in.
type ResolveItem struct {
	// Value is the request value to translate.
	Value string
	// Siblings are, by dimension name, the values read from the same body
	// element as Value: the route's other body dimensions declared under the
	// same element (debits[].organizationId and debits[].ledgerId for
	// debits[].alias) — for a string of an array of strings, under the element
	// holding the array — that the element names and that are not themselves
	// resolved. Nil when there is none, and always for a value read outside the
	// body.
	Siblings map[string]string
}

// ScopeResolver translates request values into dimension values: a transaction
// id into the account ids of its legs, an account alias into the account id.
//
// It returns one entry per item of in.Items, in the same order: the dimension
// values the item stands for — one or several. An item mapped to no value is
// unknown: the request is refused with 403 naming where it was read, exactly as
// a resolved value outside the credential's scope is, so the answer never tells
// whether the value exists — unless the dimension is optional, when its
// question is asked without the dimension (see Dimension.Optional). A returned
// error means the lookup itself failed:
// the request is refused with 503 naming the resolver, and the error is logged,
// never sent to the caller. An answer with a different number of entries than
// items, or an empty string among the returned values, is treated as such a
// failure.
//
// A resolver runs only after the authorization service has accepted the
// request's credential on the dimensions known without resolution. ctx carries
// the request's authorization deadline and the identity that acceptance
// validated: PrincipalFromContext(ctx) returns its subject, type, client id and
// tenant (TenantID), the values a product confines its lookup to — the tenant's
// database above all.
type ScopeResolver func(ctx context.Context, in ResolveInput) ([][]string, error)

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

// MatchAny returns a copy of the resolved dimension whose request value is
// allowed when ANY of the values its resolver translates it to is allowed —
// a holder with accounts in two ledgers, for a partner scoped on one of them —
// instead of every one, the default. It never mutates the receiver.
//
// Each value the request carries is judged on its own: it is allowed when one
// of its resolved values is allowed together with everything else the request
// names, and every other question of the request must still be allowed. A
// value that resolves to none is treated exactly as with every-one matching.
// Only a resolved dimension may match any: on any other, the route is
// misdeclared.
func (d Dimension) MatchAny() Dimension {
	d.matchAny = true

	return d
}

// MatchesAny reports whether a request value of the dimension is allowed when
// any of its resolved values is (see MatchAny).
func (d Dimension) MatchesAny() bool { return d.matchAny }

// matchProblem describes a dimension that matches any of its values without
// a resolver to translate it into several, or returns "".
func (d Dimension) matchProblem() string {
	if d.matchAny && d.resolver == "" {
		return "scope dimension " + d.name + " matches any of its resolved values but names no resolver"
	}

	return ""
}

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
	// deferred, when non-nil, makes the pass that runs BEFORE the credential is
	// validated: no resolver is called, the resolved dimensions are left out of
	// the questions, and deferred records each dimension a value awaits
	// resolution for.
	deferred pendingDimensions
}

// pendingDimensions is the set of dimensions a request names values of that
// are still to be resolved.
type pendingDimensions map[string]struct{}

// names is the set in name order, nil when empty.
func (p pendingDimensions) names() []string {
	if len(p) == 0 {
		return nil
	}

	out := make([]string, 0, len(p))
	for name := range p {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}

// call asks the named resolver to translate items, validating its answer. The
// result holds, per item and in its order, its dimension values; an item mapped
// to none is the caller's to report as unknown.
func (r scopeResolution) call(resolverName, dimension string, items []ResolveItem, known map[string][]string) ([][]string, *errBodyScope) {
	if len(items) > maxBodyScopeQuestions {
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
		Items:     items,
		Known:     known,
	})
	if err != nil {
		logErrorf(r.ctx, r.auth.Logger, "Scope resolver %q failed for dimension %q; denying (fail closed): %v", resolverName, dimension, err)

		return nil, unavailable
	}

	if len(out) != len(items) {
		logErrorf(r.ctx, r.auth.Logger, "Scope resolver %q answered %d entries for %d items of dimension %q; denying (fail closed)",
			resolverName, len(out), len(items), dimension)

		return nil, unavailable
	}

	for _, values := range out {
		for _, resolved := range values {
			if resolved == "" {
				logErrorf(r.ctx, r.auth.Logger, "Scope resolver %q returned an empty value for dimension %q; denying (fail closed)", resolverName, dimension)

				return nil, unavailable
			}
		}
	}

	return out, nil
}

// outsideScope is the message a request is refused with when a value read at
// location does not resolve, or resolves to a value outside the credential's
// scope. The two answer the same, so a partner cannot learn whether a value it
// may not see exists.
func outsideScope(location string) string {
	return "scope " + location + " is outside this credential's scope or does not exist"
}

// unresolved is the refusal of a request value its resolver does not know.
func unresolved(location string) *errBodyScope {
	return &errBodyScope{status: http.StatusForbidden, message: outsideScope(location)}
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
// body and records them as the dimensions' values, joined with the values a
// carrier names directly for the same dimension: a resolved value is derived
// by the server, never asserted by the client, so the two are not checked for
// agreement — every one is asked.
func (r scopeResolution) resolvePending(readings requestValues) (requestValues, *errBodyScope) {
	known := knownValues(readings)
	pending := readings.pending
	readings.pending = nil

	if r.deferred != nil {
		for _, p := range pending {
			r.deferred[p.dim.name] = struct{}{}
		}

		pending = nil
	}

	for _, p := range pending {
		items := make([]ResolveItem, 0, len(p.values))
		for _, value := range p.values {
			items = append(items, ResolveItem{Value: value})
		}

		out, err := r.call(p.dim.resolver, p.dim.name, items, known)
		if err != nil {
			return requestValues{}, err
		}

		if resolvesToNone(out) {
			if !p.dim.optional {
				return requestValues{}, unresolved(p.dim.location())
			}

			// Asked without the dimension: a question naming a value some
			// other request value resolved to cannot make the answer looser.
			continue
		}

		if p.dim.matchAny {
			readings.addAny(p.dim, out)
		} else {
			readings.union(p.dim, distinct(out))
		}

		if readings.resolvedAt == "" {
			readings.resolvedAt = p.dim.location()
		}
	}

	if readings.problem != nil {
		return requestValues{}, readings.problem
	}

	return readings, nil
}

// resolvesToNone reports whether some item resolved to no value.
func resolvesToNone(out [][]string) bool {
	for _, resolved := range out {
		if len(resolved) == 0 {
			return true
		}
	}

	return false
}

// distinct is every value of every item, each once, in the order first named.
func distinct(items [][]string) []string {
	var values []string

	seen := make(map[string]struct{})

	for _, item := range items {
		for _, v := range item {
			if _, dup := seen[v]; !dup {
				seen[v] = struct{}{}
				values = append(values, v)
			}
		}
	}

	return values
}

// addAny records the values each request value of a MatchAny dimension
// resolved to: one of each must be allowed. A value another carrier names
// directly for the dimension joins them as a request value of its own, which
// must be allowed itself.
func (rv *requestValues) addAny(dim Dimension, items [][]string) {
	if rv.anyOf == nil {
		rv.anyOf = make(map[string][][]string)
	}

	named, ok := rv.values[dim.name]

	switch {
	case !ok:
		rv.add(dim, nil)
	case rv.anyOf[dim.name] == nil:
		for _, v := range named {
			rv.anyOf[dim.name] = append(rv.anyOf[dim.name], []string{v})
		}
	}

	rv.markDerived(dim.name)
	rv.anyOf[dim.name] = append(rv.anyOf[dim.name], items...)
	rv.values[dim.name] = distinct(rv.anyOf[dim.name])
}

// rawQuestion is one question of a body whose keys are still to be resolved:
// the values read for it, where each was read, and, per resolved dimension, the
// resolver that translates its value and the siblings it was read with.
type rawQuestion struct {
	values    map[string]string
	at        map[string]string
	resolvers map[string]string
	siblings  map[string]map[string]string
	// matchAny holds the resolved dimensions read with MatchAny.
	matchAny map[string]bool
	// optional holds the resolved dimensions read optional: a value resolving
	// to none is asked without the dimension.
	optional map[string]bool
}

// item is the resolver item a resolved dimension of the question makes.
func (q rawQuestion) item(name string) ResolveItem {
	return ResolveItem{Value: q.values[name], Siblings: q.siblings[name]}
}

// resolveBatch is one resolver call of a body: the distinct items of one
// dimension that one resolver translates, and the index of each by itemKey.
type resolveBatch struct {
	resolver, dimension string
	items               []ResolveItem
	index               map[string]int
}

func batchKey(resolver, dimension string) string { return resolver + "\x00" + dimension }

// itemKey identifies an item by its value and its siblings, injectively.
func itemKey(item ResolveItem) string {
	var b strings.Builder

	writeLengthPrefixed(&b, item.Value)
	b.WriteString(attributesCacheKey(item.Siblings))

	return b.String()
}

// resolveBody translates the resolved keys of every collected body question —
// one call per resolver and dimension, with every distinct key — and asks, for
// each question, every combination of the values its keys resolve to.
func (r scopeResolution) resolveBody(raw []rawQuestion, set *questionSet, readings requestValues) *errBodyScope {
	if r.deferred != nil {
		return deferBody(raw, set, r.deferred)
	}

	order, batches := collectBatches(raw)

	known := knownValues(readings)
	results := make(map[string]map[string][]string, len(batches))

	for _, key := range order {
		b := batches[key]

		out, err := r.call(b.resolver, b.dimension, b.items, known)
		if err != nil {
			return err
		}

		byItem := make(map[string][]string, len(b.items))
		for i, item := range b.items {
			byItem[itemKey(item)] = out[i]
		}

		results[key] = byItem
	}

	for _, q := range raw {
		groups, err := expandResolved(q, results, set)
		if err != nil {
			return err
		}

		set.resolvedAt = readings.resolvedAt
		if names := sortedKeys(q.resolvers); len(names) > 0 {
			set.resolvedAt = q.at[names[0]]
		}

		for _, alternatives := range groups {
			if err := set.addGroup(alternatives, q.at, q.resolvers); err != nil {
				return err
			}
		}
	}

	return nil
}

// deferBody adds the questions of a body without its resolved fields, and
// records the dimension of each field that awaits resolution.
func deferBody(raw []rawQuestion, set *questionSet, deferred pendingDimensions) *errBodyScope {
	for _, q := range raw {
		values := make(map[string]string, len(q.values))

		for name, value := range q.values {
			if _, resolved := q.resolvers[name]; resolved {
				deferred[name] = struct{}{}

				continue
			}

			values[name] = value
		}

		if err := set.add(values, q.at); err != nil {
			return err
		}
	}

	return nil
}

// collectBatches groups the resolved items of the questions by resolver and
// dimension, each item once, in the order first named.
func collectBatches(raw []rawQuestion) ([]string, map[string]*resolveBatch) {
	var order []string

	batches := make(map[string]*resolveBatch)

	for _, q := range raw {
		for _, name := range sortedKeys(q.resolvers) {
			key := batchKey(q.resolvers[name], name)

			b, ok := batches[key]
			if !ok {
				b = &resolveBatch{resolver: q.resolvers[name], dimension: name, index: make(map[string]int)}
				batches[key] = b
				order = append(order, key)
			}

			item := q.item(name)
			if _, dup := b.index[itemKey(item)]; !dup {
				b.index[itemKey(item)] = len(b.items)
				b.items = append(b.items, item)
			}
		}
	}

	return order, batches
}

// expandResolved returns the questions one collected question makes, in
// groups of which one must be allowed: one question per combination of the
// values its resolved keys stand for, a key resolved with MatchAny making its
// values alternatives within a group and any other key one group per value. An
// optional key resolving to none leaves its dimension out.
func expandResolved(q rawQuestion, results map[string]map[string][]string, set *questionSet) ([][]map[string]string, *errBodyScope) {
	groups := [][]map[string]string{{q.values}}
	count := 1

	for _, name := range sortedKeys(q.resolvers) {
		resolved := results[batchKey(q.resolvers[name], name)][itemKey(q.item(name))]
		if len(resolved) == 0 {
			if !q.optional[name] {
				return nil, unresolved(q.at[name])
			}

			groups = without(groups, name)

			continue
		}

		if count*len(resolved) > maxBodyScopeQuestions {
			return nil, set.tooMany()
		}

		count *= len(resolved)

		next := make([][]map[string]string, 0, len(groups)*len(resolved))

		for _, group := range groups {
			if q.matchAny[name] {
				next = append(next, withEach(group, name, resolved))

				continue
			}

			for _, value := range resolved {
				next = append(next, withEach(group, name, []string{value}))
			}
		}

		groups = next
	}

	return groups, nil
}

// without returns every question of groups with name left out.
func without(groups [][]map[string]string, name string) [][]map[string]string {
	out := make([][]map[string]string, 0, len(groups))

	for _, group := range groups {
		next := make([]map[string]string, 0, len(group))

		for _, combination := range group {
			question := make(map[string]string, len(combination))
			for k, v := range combination {
				if k != name {
					question[k] = v
				}
			}

			next = append(next, question)
		}

		out = append(out, next)
	}

	return out
}

// withEach returns every question of group with name set to each of values.
func withEach(group []map[string]string, name string, values []string) []map[string]string {
	out := make([]map[string]string, 0, len(group)*len(values))

	for _, combination := range group {
		for _, value := range values {
			question := make(map[string]string, len(combination)+1)
			for k, v := range combination {
				question[k] = v
			}

			question[name] = value
			out = append(out, question)
		}
	}

	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}
