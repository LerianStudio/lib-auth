package middleware

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// An optional resolved dimension that resolves to nothing, and a resolved
// carrier joining the other carriers of its dimension
// ---------------------------------------------------------------------------

const (
	accountRoute  = "/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id"
	accountTarget = "/v1/organizations/org-1/ledgers/led-1/accounts/acc-1"
)

// portfolioClient wires a catalog with an account and a portfolio dimension,
// registers the resolver under "portfolio", and declares dims on the route.
func portfolioClient(t *testing.T, url string, resolver *fakeResolver, method, path string, dims ...Dimension) *AuthClient {
	t.Helper()

	auth := &AuthClient{Address: url, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.RegisterScopeResolver("portfolio", resolver.resolve))
	require.NoError(t, auth.SetManifestScope("midaz", append(resolveCatalog(),
		Dim("portfolioId", FromQuery).At("portfolio_id"))...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", method, path, dims...))

	return auth
}

// newScopedAuthServer is an authorization service holding one partner scoped
// on the given dimensions: a question is allowed when it names, for every one
// of them, one of its allowed values. A question missing a dimension the
// partner is scoped on is refused, unless it declares the dimension pending.
func newScopedAuthServer(t *testing.T, scope map[string][]string) *decidingAuthServer {
	t.Helper()

	srv := newDecidingAuthServer(t)

	srv.mu.Lock()
	srv.allowPending = func(attributes map[string]string, pending []string) bool {
		for name, allowed := range scope {
			value, named := attributes[name]

			switch {
			case !named && containsValue(pending, name):
			case !named || !containsValue(allowed, value):
				return false
			}
		}

		return true
	}
	srv.mu.Unlock()

	return srv
}

// namesAttribute reports whether some call carried the attribute.
func namesAttribute(calls []map[string]string, name string) bool {
	for _, call := range calls {
		if _, ok := call[name]; ok {
			return true
		}
	}

	return false
}

// An optional resolved dimension whose value resolves to nothing — an account
// in no portfolio — is asked without the dimension: the partner is judged on
// what it is really scoped on.
func TestAuthorize_Resolve_OptionalResolvedToNothingIsAskedWithout(t *testing.T) {
	t.Parallel()

	route := Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio").Optional()

	for name, tc := range map[string]struct {
		scope map[string][]string
		want  int
	}{
		"scoped_on_the_ledger":  {map[string][]string{"ledgerId": {"led-1"}}, http.StatusOK},
		"scoped_on_the_account": {map[string][]string{"accountId": {"acc-1"}}, http.StatusOK},
		"scoped_on_a_portfolio": {map[string][]string{"portfolioId": {"pf-1"}}, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScopedAuthServer(t, tc.scope)
			resolver := &fakeResolver{table: map[string][]string{"acc-1": nil}}
			auth := portfolioClient(t, srv.URL, resolver, http.MethodGet, accountRoute, route)

			probe := &handlerProbe{}
			app := fiber.New()
			app.Get(accountRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

			got := doRequest(t, app, http.MethodGet, accountTarget, partnerToken("acme/p1"), "")
			require.Equal(t, tc.want, got.status, got.body)

			calls := srv.attributeCalls()
			require.NotEmpty(t, calls)
			assert.False(t, namesAttribute(calls, "portfolioId"), "no question names the portfolio the account is not in")
			assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
				calls[len(calls)-1], "the request is asked without the dimension")
			assert.Len(t, resolver.inputs(), 1, "the value was resolved")
		})
	}
}

// The account in a portfolio is still asked with it.
func TestAuthorize_Resolve_OptionalResolvedToAValueIsAskedWithIt(t *testing.T) {
	t.Parallel()

	srv := newScopedAuthServer(t, map[string][]string{"portfolioId": {"pf-1"}})
	resolver := &fakeResolver{table: map[string][]string{"acc-1": {"pf-1"}}}
	auth := portfolioClient(t, srv.URL, resolver, http.MethodGet, accountRoute,
		Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio").Optional())

	app := fiber.New()
	app.Get(accountRoute, auth.Authorize("midaz", "accounts", "get"), ok)

	got := doRequest(t, app, http.MethodGet, accountTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	calls := srv.attributeCalls()
	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1", "portfolioId": "pf-1"},
		calls[len(calls)-1])
}

// A resolved dimension that is NOT optional still refuses a value resolving to
// nothing, whatever the partner is scoped on.
func TestAuthorize_Resolve_RequiredResolvedToNothingIsForbidden(t *testing.T) {
	t.Parallel()

	srv := newScopedAuthServer(t, map[string][]string{"ledgerId": {"led-1"}})
	resolver := &fakeResolver{table: map[string][]string{"acc-1": nil}}
	auth := portfolioClient(t, srv.URL, resolver, http.MethodGet, accountRoute,
		Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Get(accountRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

	got := doRequest(t, app, http.MethodGet, accountTarget, partnerToken("acme/p1"), "")

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Contains(t, got.body, `path parameter "account_id" is outside this credential's scope or does not exist`)
	assert.Equal(t, int64(0), probe.calls.Load())
}

// In the body, the element whose value resolves to nothing is asked without
// the optional dimension; the element whose value resolves is asked with it.
func TestAuthorize_Resolve_OptionalBodyValueResolvedToNothingIsAskedWithout(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/ledgers/:ledger_id/batches"

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"acc-1": {"pf-1"}, "acc-2": nil}}
	auth := portfolioClient(t, srv.URL, resolver, http.MethodPost, route,
		Dim("portfolioId", FromBody).At("items[].accountId").Resolve("portfolio").Optional())

	app := fiber.New()
	app.Post(route, auth.Authorize("midaz", "batches", "post"), ok)

	got := doRequest(t, app, http.MethodPost, "/v1/organizations/org-1/ledgers/led-1/batches", partnerToken("acme/p1"),
		`{"items":[{"accountId":"acc-1"},{"accountId":"acc-2"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	calls := srv.attributeCalls()
	assert.Contains(t, calls, map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "portfolioId": "pf-1"})
	assert.Contains(t, calls, map[string]string{"organizationId": "org-1", "ledgerId": "led-1"})

	for _, call := range calls {
		assert.NotEqual(t, "acc-2", call["portfolioId"], "the key itself is never asked as the dimension's value")
	}
}

// The body element of a required resolved dimension resolving to nothing is
// still refused, naming the element.
func TestAuthorize_Resolve_RequiredBodyValueResolvedToNothingIsForbidden(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/ledgers/:ledger_id/batches"

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"acc-1": {"pf-1"}, "acc-2": nil}}
	auth := portfolioClient(t, srv.URL, resolver, http.MethodPost, route,
		Dim("portfolioId", FromBody).At("items[].accountId").Resolve("portfolio"))

	app := fiber.New()
	app.Post(route, auth.Authorize("midaz", "batches", "post"), ok)

	got := doRequest(t, app, http.MethodPost, "/v1/organizations/org-1/ledgers/led-1/batches", partnerToken("acme/p1"),
		`{"items":[{"accountId":"acc-1"},{"accountId":"acc-2"}]}`)

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Contains(t, got.body, `body field "items[1].accountId" is outside this credential's scope or does not exist`)
}

// Moving an account between portfolios: the body names the target, the path
// resolves to the current one. A resolved value is derived by the server, so
// the two are not a divergence: both are asked, and both must be allowed.
func TestAuthorize_Resolve_ResolvedCarrierIsUnionedWithTheBody(t *testing.T) {
	t.Parallel()

	dims := []Dimension{
		Dim("portfolioId", FromBody).At("portfolioId").Optional(),
		Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio").Optional(),
	}

	for name, tc := range map[string]struct {
		allowed []string
		want    int
	}{
		"source_and_target_allowed": {[]string{"pf-1", "pf-2"}, http.StatusOK},
		"only_the_source_allowed":   {[]string{"pf-1"}, http.StatusForbidden},
		"only_the_target_allowed":   {[]string{"pf-2"}, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScopedAuthServer(t, map[string][]string{"portfolioId": tc.allowed})
			resolver := &fakeResolver{table: map[string][]string{"acc-1": {"pf-1"}}}
			auth := portfolioClient(t, srv.URL, resolver, http.MethodPatch, accountRoute, dims...)

			probe := &handlerProbe{}
			app := fiber.New()
			app.Patch(accountRoute, auth.Authorize("midaz", "accounts", "patch"), probe.handle)

			got := doRequest(t, app, http.MethodPatch, accountTarget, partnerToken("acme/p1"), `{"portfolioId":"pf-2"}`)
			require.Equal(t, tc.want, got.status, got.body)

			if tc.want == http.StatusOK {
				calls := srv.attributeCalls()
				assert.Contains(t, calls, map[string]string{
					"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1", "portfolioId": "pf-1",
				}, "the current portfolio is asked")
				assert.Contains(t, calls, map[string]string{
					"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1", "portfolioId": "pf-2",
				}, "the target portfolio is asked")
				assert.Equal(t, int64(1), probe.calls.Load())

				return
			}

			assert.Equal(t, int64(0), probe.calls.Load())

			if name == "only_the_target_allowed" {
				assert.Contains(t, got.body, `path parameter "account_id" is outside`, "the current portfolio is refused")
			}
		})
	}
}

// A body naming the portfolio the account is already in asks it once.
func TestAuthorize_Resolve_ResolvedCarrierAgreeingWithTheBody(t *testing.T) {
	t.Parallel()

	srv := newScopedAuthServer(t, map[string][]string{"portfolioId": {"pf-1"}})
	resolver := &fakeResolver{table: map[string][]string{"acc-1": {"pf-1"}}}
	auth := portfolioClient(t, srv.URL, resolver, http.MethodPatch, accountRoute,
		Dim("portfolioId", FromBody).At("portfolioId").Optional(),
		Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio").Optional())

	app := fiber.New()
	app.Patch(accountRoute, auth.Authorize("midaz", "accounts", "patch"), ok)

	got := doRequest(t, app, http.MethodPatch, accountTarget, partnerToken("acme/p1"), `{"portfolioId":"pf-1"}`)
	require.Equal(t, http.StatusOK, got.status, got.body)
}

// A body leaving the portfolio out, on an account in no portfolio, is asked
// with neither.
func TestAuthorize_Resolve_ResolvedCarrierAndBodyBothWithout(t *testing.T) {
	t.Parallel()

	srv := newScopedAuthServer(t, map[string][]string{"ledgerId": {"led-1"}})
	resolver := &fakeResolver{table: map[string][]string{"acc-1": nil}}
	auth := portfolioClient(t, srv.URL, resolver, http.MethodPatch, accountRoute,
		Dim("portfolioId", FromBody).At("portfolioId").Optional(),
		Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio").Optional())

	app := fiber.New()
	app.Patch(accountRoute, auth.Authorize("midaz", "accounts", "patch"), ok)

	got := doRequest(t, app, http.MethodPatch, accountTarget, partnerToken("acme/p1"), `{"alias":"x"}`)
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.False(t, namesAttribute(srv.attributeCalls(), "portfolioId"))
}

// Outside the body too: a value resolved from the path joins the value the
// query names for the same dimension, and both must be allowed.
func TestAuthorize_Resolve_ResolvedCarrierIsUnionedWithTheQuery(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		allowed []string
		want    int
	}{
		"both_allowed":          {[]string{"pf-1", "pf-2"}, http.StatusOK},
		"only_the_query_value":  {[]string{"pf-2"}, http.StatusForbidden},
		"only_the_resolved_one": {[]string{"pf-1"}, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScopedAuthServer(t, map[string][]string{"portfolioId": tc.allowed})
			resolver := &fakeResolver{table: map[string][]string{"acc-1": {"pf-1"}}}
			auth := portfolioClient(t, srv.URL, resolver, http.MethodGet, accountRoute,
				Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio"))

			app := fiber.New()
			app.Get(accountRoute, auth.Authorize("midaz", "accounts", "get"), ok)

			got := doRequest(t, app, http.MethodGet, accountTarget+"?portfolio_id=pf-2", partnerToken("acme/p1"), "")
			require.Equal(t, tc.want, got.status, got.body)
		})
	}
}

// Two carriers the CLIENT asserts — the path and the body — still have to
// agree: the handler may act on either.
func TestAuthorize_Resolve_ClientAssertedDivergenceIsStillRefused(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"acc-1": {"pf-1"}}}
	auth := portfolioClient(t, srv.URL, resolver, http.MethodPatch, accountRoute,
		Dim("accountId", FromBody).At("accountId"),
		Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio"))

	app := fiber.New()
	app.Patch(accountRoute, auth.Authorize("midaz", "accounts", "patch"), ok)

	got := doRequest(t, app, http.MethodPatch, accountTarget, partnerToken("acme/p1"), `{"accountId":"acc-2"}`)
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `scope dimension "accountId" is given different values in path parameter "account_id" and body field "accountId"`)
}

// When both carriers are resolved, a refusal names the carrier whose resolved
// value was denied.
func TestAuthorize_Resolve_TwoResolvedCarriersNameTheirOwnRefusal(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		allowed []string
		want    int
		names   string
	}{
		"both_allowed":        {[]string{"pf-1", "pf-2"}, http.StatusOK, ""},
		"the_path_one_denied": {[]string{"pf-2"}, http.StatusForbidden, `path parameter "account_id" is outside`},
		"the_body_one_denied": {[]string{"pf-1"}, http.StatusForbidden, `body field "targetAccountId" is outside`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScopedAuthServer(t, map[string][]string{"portfolioId": tc.allowed})
			resolver := &fakeResolver{table: map[string][]string{"acc-1": {"pf-1"}, "acc-2": {"pf-2"}}}
			auth := portfolioClient(t, srv.URL, resolver, http.MethodPost, accountRoute+"/moves",
				Dim("portfolioId", FromBody).At("targetAccountId").Resolve("portfolio"),
				Dim("portfolioId", FromPath).At("account_id").Resolve("portfolio"))

			app := fiber.New()
			app.Post(accountRoute+"/moves", auth.Authorize("midaz", "accounts", "post"), ok)

			got := doRequest(t, app, http.MethodPost, accountTarget+"/moves", partnerToken("acme/p1"), `{"targetAccountId":"acc-2"}`)
			require.Equal(t, tc.want, got.status, got.body)

			if tc.names != "" {
				assert.Contains(t, got.body, tc.names)
			}
		})
	}
}
