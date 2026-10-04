package middleware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Translating a request value into dimension values (resolve)
// ---------------------------------------------------------------------------

const (
	txRoute   = "/v1/organizations/:organization_id/ledgers/:ledger_id/transactions/:transaction_id"
	txTarget  = "/v1/organizations/org-1/ledgers/led-1/transactions/tx-1"
	legsRoute = "/v1/organizations/:organization_id/ledgers/:ledger_id/transactions"
	legsPath  = "/v1/organizations/org-1/ledgers/led-1/transactions"
)

// resolveCatalog is the path catalog plus an account dimension.
func resolveCatalog() []Dimension {
	return append(manifestDims(), Dim("accountId", FromPath).At("account_id"))
}

// fakeResolver answers from a fixed table and records every input it was given.
// With bySibling set, an item is looked up as "<sibling value>/<value>".
type fakeResolver struct {
	table     map[string][]string
	err       error
	bySibling string
	// short drops the last answer, to answer fewer items than asked.
	short bool

	mu    sync.Mutex
	calls []ResolveInput
}

func (r *fakeResolver) resolve(_ context.Context, in ResolveInput) ([][]string, error) {
	r.mu.Lock()
	r.calls = append(r.calls, in)
	r.mu.Unlock()

	if r.err != nil {
		return nil, r.err
	}

	out := make([][]string, 0, len(in.Items))

	for _, item := range in.Items {
		key := item.Value
		if r.bySibling != "" {
			key = item.Siblings[r.bySibling] + "/" + item.Value
		}

		out = append(out, r.table[key])
	}

	if r.short {
		out = out[:len(out)-1]
	}

	return out, nil
}

func (r *fakeResolver) inputs() []ResolveInput {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]ResolveInput(nil), r.calls...)
}

// resolvingClient wires the catalog, registers the resolver under name, and
// declares dims on the route.
func resolvingClient(t *testing.T, url, name string, resolver *fakeResolver, method, path string, dims ...Dimension) *AuthClient {
	t.Helper()

	auth := &AuthClient{Address: url, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.RegisterScopeResolver(name, resolver.resolve))
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", method, path, dims...))

	return auth
}

func doRequest(t *testing.T, app *fiber.App, method, target, token, body string) bodyResult {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// A request asking up to twice the cap of questions outlasts the default
	// one-second test timeout under -race.
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	require.NoError(t, err)

	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return bodyResult{status: resp.StatusCode, body: string(raw)}
}

func TestRegisterScopeResolver_Validation(t *testing.T) {
	t.Parallel()

	fn := (&fakeResolver{}).resolve

	var nilClient *AuthClient
	require.Error(t, nilClient.RegisterScopeResolver("legs", fn))

	auth := &AuthClient{}
	require.Error(t, auth.RegisterScopeResolver("", fn), "a resolver needs a name")
	require.Error(t, auth.RegisterScopeResolver(" legs", fn), "a name is not padded")
	require.Error(t, auth.RegisterScopeResolver("legs", nil), "a resolver needs a function")

	require.NoError(t, auth.RegisterScopeResolver("legs", fn))
	require.Error(t, auth.RegisterScopeResolver("legs", fn), "a name is registered once")
}

// One path value resolves to several dimension values; every one is asked,
// with the dimensions the path names directly.
func TestAuthorize_Resolve_PathValueToSeveral(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1", "acc-2"}}}
	auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
		Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

	var scope RequestScope

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), func(c fiber.Ctx) error {
		scope, _ = ScopeFromContext(c.Context())

		return c.SendString("ok")
	})

	got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	want := []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-2"},
	}
	assert.Equal(t, append([]map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, want...), srv.attributeCalls(),
		"the known dimensions first, then every resolved value")
	assert.Equal(t, want, scope.Sets, "the request is authorized as the resolved sets")

	assert.Equal(t, []ResolveInput{{
		Product:   "midaz",
		Resolver:  "legs",
		Dimension: "accountId",
		Items:     []ResolveItem{{Value: "tx-1"}},
		Known:     map[string][]string{"organizationId": {"org-1"}, "ledgerId": {"led-1"}},
	}}, resolver.inputs())
}

// Every resolved value must be allowed: one denied refuses the request.
func TestAuthorize_Resolve_EveryValueMustBeAllowed(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "acc-2")
	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1", "acc-2"}}}
	auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
		Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), probe.handle)

	got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Contains(t, got.body, `path parameter "transaction_id" is outside this credential's scope or does not exist`)
	assert.Equal(t, int64(0), probe.calls.Load())
	assert.Equal(t, int64(3), srv.hits.Load(), "the known question, then the resolved ones up to the denial")
}

// A value the resolver does not know is refused with 403 naming where it was
// read, after the known question only — never a question without the
// dimension.
func TestAuthorize_Resolve_UnknownPathValueIsForbidden(t *testing.T) {
	t.Parallel()

	for name, table := range map[string]map[string][]string{
		"absent":      {},
		"empty_slice": {"tx-1": {}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			resolver := &fakeResolver{table: table}
			auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
				Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

			probe := &handlerProbe{}
			app := fiber.New()
			app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), probe.handle)

			got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")

			assert.Equal(t, http.StatusForbidden, got.status)
			assert.Contains(t, got.body, `path parameter "transaction_id" is outside this credential's scope or does not exist`)
			assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())
			assert.Equal(t, int64(0), probe.calls.Load())
		})
	}
}

// A resolver that fails is a dependency failing: 503 naming the resolver, and
// never the resolver's own error text.
func TestAuthorize_Resolve_ResolverFailureIsUnavailable(t *testing.T) {
	t.Parallel()

	for name, resolver := range map[string]*fakeResolver{
		"error":        {err: errors.New("connection refused to db-internal:5432")},
		"empty_output": {table: map[string][]string{"tx-1": {"acc-1", ""}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
				Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

			probe := &handlerProbe{}
			app := fiber.New()
			app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), probe.handle)

			got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")

			assert.Equal(t, http.StatusServiceUnavailable, got.status)
			assert.Contains(t, got.body, `scope resolver "legs"`)
			assert.NotContains(t, got.body, "db-internal")
			assert.Equal(t, int64(1), srv.hits.Load(), "only the known question")
			assert.Equal(t, int64(0), probe.calls.Load())
		})
	}
}

// A caller that is not partner-bound is decided as before: the resolver is
// never called and the resolved dimension is not sent.
func TestAuthorize_Resolve_NonPartnerNeverResolves(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1"}}}
	auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
		Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodGet, txTarget, userToken(), "")

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())
	assert.Empty(t, resolver.inputs())
}

// Body values are resolved in ONE batch of distinct values, and each element
// asks about every value its own key resolves to.
func TestAuthorize_Resolve_BodyIsBatched(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}, "@b": {"acc-b1", "acc-b2"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias"))

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"debits":[{"alias":"@a"},{"alias":"@b"},{"alias":"@a"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-a"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-b1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-b2"},
	}, srv.attributeCalls())

	inputs := resolver.inputs()
	require.Len(t, inputs, 1, "one call for the whole body")
	assert.Equal(t, []ResolveItem{{Value: "@a"}, {Value: "@b"}}, inputs[0].Items, "an element with no other field has no siblings")
	assert.Equal(t, map[string][]string{"organizationId": {"org-1"}, "ledgerId": {"led-1"}}, inputs[0].Known)
}

// A resolved body value stays with the other fields of its element.
func TestAuthorize_Resolve_BodyValueKeepsItsElement(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/transfers"

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}, "@b": {"acc-b"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, route,
		Dim("ledgerId", FromBody).At("items[].ledgerId"),
		Dim("accountId", FromBody).At("items[].alias").Resolve("alias"))

	app := fiber.New()
	app.Post(route, auth.Authorize("midaz", "transfers", "post"), ok)

	got := doRequest(t, app, http.MethodPost, "/v1/organizations/org-1/transfers", partnerToken("acme/p1"),
		`{"items":[{"ledgerId":"led-1","alias":"@a"},{"ledgerId":"led-2","alias":"@b"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-a"},
		{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "acc-b"},
	}, srv.attributeCalls())
}

// An unknown body value is refused with 403 naming its position.
func TestAuthorize_Resolve_UnknownBodyValueNamesTheElement(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"debits":[{"alias":"@a"},{"alias":"@a"},{"alias":"@zz"}]}`)

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Contains(t, got.body, `body field "debits[2].alias" is outside this credential's scope or does not exist`)
	assert.Equal(t, int64(1), srv.hits.Load(), "only the known question")
	assert.Equal(t, int64(0), probe.calls.Load())
}

// More distinct values than the cap are refused before the resolver is called.
func TestAuthorize_Resolve_TooManyValuesIsRefusedBeforeResolving(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias"))

	elements := make([]string, 0, maxBodyScopeQuestions+1)
	for i := range maxBodyScopeQuestions + 1 {
		elements = append(elements, fmt.Sprintf(`{"alias":"@%d"}`, i))
	}

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"debits":[`+strings.Join(elements, ",")+`]}`)

	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Empty(t, resolver.inputs())
	assert.Equal(t, int64(1), srv.hits.Load(), "only the known question")

	// Positive control: exactly the cap is resolved and asked.
	resolver.table = make(map[string][]string, maxBodyScopeQuestions)
	for i := range maxBodyScopeQuestions {
		resolver.table[fmt.Sprintf("@%d", i)] = []string{fmt.Sprintf("acc-%d", i)}
	}

	got = doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"debits":[`+strings.Join(elements[:maxBodyScopeQuestions], ",")+`]}`)

	assert.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, int64(1+1+maxBodyScopeQuestions), srv.hits.Load())
}

// A resolved value joins the same dimension named directly elsewhere: it is
// derived by the server, not asserted by the client, so the two are not
// checked for agreement — both are asked, and both must be allowed.
func TestAuthorize_Resolve_BodyResolvedValueJoinsThePath(t *testing.T) {
	t.Parallel()

	const (
		route  = "/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id/transfers"
		target = "/v1/organizations/org-1/ledgers/led-1/accounts/acc-a/transfers"
	)

	q := func(account string) map[string]string {
		return map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": account}
	}

	for name, tc := range map[string]struct {
		denied []string
		alias  string
		want   int
	}{
		"same_account":        {nil, "@a", http.StatusOK},
		"both_allowed":        {nil, "@b", http.StatusOK},
		"resolved_one_denied": {[]string{"acc-b"}, "@b", http.StatusForbidden},
		"the_path_one_denied": {[]string{"acc-a"}, "@b", http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t, tc.denied...)
			resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}, "@b": {"acc-b"}}}
			auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, route,
				Dim("accountId", FromBody).At("alias").Resolve("alias"))

			app := fiber.New()
			app.Post(route, auth.Authorize("midaz", "transfers", "post"), ok)

			got := doRequest(t, app, http.MethodPost, target, partnerToken("acme/p1"), `{"alias":"`+tc.alias+`"}`)
			require.Equal(t, tc.want, got.status, got.body)

			if tc.want == http.StatusOK && tc.alias == "@b" {
				assert.Contains(t, srv.attributeCalls(), q("acc-a"))
				assert.Contains(t, srv.attributeCalls(), q("acc-b"))
			}

			if name == "resolved_one_denied" {
				assert.Contains(t, got.body, `body field "alias" is outside this credential's scope`)
			}
		})
	}
}

// Values read from the query are resolved like any other carrier.
func TestAuthorize_Resolve_Query(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}, "@b": {"acc-b"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodGet, legsRoute,
		Dim("accountId", FromQuery).At("alias").Resolve("alias").Optional())

	app := fiber.New()
	app.Get(legsRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodGet, legsPath+"?alias=@a,@b", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-a"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-b"},
	}, srv.attributeCalls())

	// Optional and absent: nothing to resolve, the question goes without it.
	got = doRequest(t, app, http.MethodGet, legsPath, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Len(t, resolver.inputs(), 1, "an absent optional value is not resolved")
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls()[3:], "asked once")
}

// A resolver named but not registered fails where the scope is wired.
func TestResolve_UnregisteredResolverFailsTheWiring(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}

	err := auth.SetManifestScope("midaz", append(manifestDims(), Dim("accountId", FromHeader).At("X-Alias").Resolve("alias"))...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"alias"`)

	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))

	err = auth.SetManifestRouteScope("midaz", http.MethodPost, legsRoute, Dim("accountId", FromBody).At("alias").Resolve("alias"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"alias"`)

	// Positive control: registered, both are accepted.
	require.NoError(t, auth.RegisterScopeResolver("alias", (&fakeResolver{}).resolve))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, legsRoute, Dim("accountId", FromBody).At("alias").Resolve("alias")))
	require.NoError(t, auth.SetManifestScope("midaz", append(manifestDims(), Dim("accountId", FromHeader).At("X-Alias").Resolve("alias"))...))
}

// An explicit declaration naming an unregistered resolver is a misdeclared
// route: it refuses every request.
func TestAuthorize_Resolve_ExplicitUnregisteredRefusesEveryRequest(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get",
		RequireScope("midaz", Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))), ok)

	assert.Equal(t, http.StatusForbidden, doRequest(t, app, http.MethodGet, txTarget, userToken(), "").status)
	assert.Equal(t, int64(0), srv.hits.Load())

	// Positive control: registered before the route, the same declaration works.
	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1"}}}
	require.NoError(t, auth.RegisterScopeResolver("legs", resolver.resolve))

	app = fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get",
		RequireScope("midaz", Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))), ok)

	assert.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "").status)
	assert.Equal(t, []map[string]string{nil, {"accountId": "acc-1"}}, srv.attributeCalls(), "validated, then asked")
}

// A route path dimension is declared on the route only when it is resolved,
// and only from a parameter the route path carries.
func TestSetManifestRouteScope_ResolvedPathDimension(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}
	require.NoError(t, auth.RegisterScopeResolver("legs", (&fakeResolver{}).resolve))
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))

	err := auth.SetManifestRouteScope("midaz", http.MethodGet, txRoute, Dim("accountId", FromPath).At("transaction_id"))
	require.Error(t, err, "an unresolved path dimension is derived, not declared")

	err = auth.SetManifestRouteScope("midaz", http.MethodGet, legsRoute, Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"transaction_id"`)

	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodGet, txRoute, Dim("accountId", FromPath).At("transaction_id").Resolve("legs")))
}

// A value resolved from the query joins the same dimension named by the
// path: both are asked, and both must be allowed.
func TestAuthorize_Resolve_QueryResolvedValueJoinsThePath(t *testing.T) {
	t.Parallel()

	const (
		route  = "/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id/balances"
		target = "/v1/organizations/org-1/ledgers/led-1/accounts/acc-a/balances"
	)

	q := func(account string) map[string]string {
		return map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": account}
	}

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}, "@b": {"acc-b"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodGet, route,
		Dim("accountId", FromQuery).At("alias").Resolve("alias"))

	app := fiber.New()
	app.Get(route, auth.Authorize("midaz", "balances", "get"), ok)

	got := doRequest(t, app, http.MethodGet, target+"?alias=@a", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, []map[string]string{q("acc-a"), q("acc-a")}, srv.attributeCalls(), "the same account is asked once")

	got = doRequest(t, app, http.MethodGet, target+"?alias=@b", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, []map[string]string{q("acc-a"), q("acc-a"), q("acc-b")}, srv.attributeCalls()[2:],
		"the known question, then the account the path names and the one the alias resolves to")

	denying := newDecidingAuthServer(t, "acc-b")
	auth = resolvingClient(t, denying.URL, "alias", resolver, http.MethodGet, route,
		Dim("accountId", FromQuery).At("alias").Resolve("alias"))

	app = fiber.New()
	app.Get(route, auth.Authorize("midaz", "balances", "get"), ok)

	got = doRequest(t, app, http.MethodGet, target+"?alias=@b", partnerToken("acme/p1"), "")
	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Contains(t, got.body, `query parameter "alias" is outside this credential's scope`)
}
