package middleware

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// A resolver sees the other fields of the element its value was read from
// ---------------------------------------------------------------------------

const (
	transfersRoute = "/v1/transfers"
	transfersPath  = "/v1/transfers"
)

// legDims declares a transaction body whose debits and credits each name the
// organization, the ledger and the alias of their account.
func legDims() []Dimension {
	return []Dimension{
		Dim("organizationId", FromBody).At("debits[].organizationId"),
		Dim("ledgerId", FromBody).At("debits[].ledgerId"),
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias"),
		Dim("organizationId", FromBody).At("credits[].organizationId"),
		Dim("ledgerId", FromBody).At("credits[].ledgerId"),
		Dim("accountId", FromBody).At("credits[].alias").Resolve("alias"),
	}
}

// The same alias in two ledgers is two items, each with the fields of its own
// element, in one call; each resolved value is asked with those same fields.
func TestAuthorize_Resolve_SiblingsConfineEachValue(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{bySibling: "ledgerId", table: map[string][]string{
		"led-1/@a": {"acc-a1"},
		"led-2/@a": {"acc-a2"},
		"led-2/@b": {"acc-b2"},
	}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, transfersRoute, legDims()...)

	app := fiber.New()
	app.Post(transfersRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, transfersPath, partnerToken("acme/p1"), `{
		"debits":  [{"organizationId":"org-1","ledgerId":"led-1","alias":"@a"},
		            {"organizationId":"org-1","ledgerId":"led-2","alias":"@a"}],
		"credits": [{"organizationId":"org-1","ledgerId":"led-2","alias":"@b"},
		            {"organizationId":"org-1","ledgerId":"led-1","alias":"@a"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	inputs := resolver.inputs()
	require.Len(t, inputs, 1, "one call for the whole body, debits and credits together")
	assert.Equal(t, []ResolveItem{
		{Value: "@a", Siblings: map[string]string{"organizationId": "org-1", "ledgerId": "led-1"}},
		{Value: "@a", Siblings: map[string]string{"organizationId": "org-1", "ledgerId": "led-2"}},
		{Value: "@b", Siblings: map[string]string{"organizationId": "org-1", "ledgerId": "led-2"}},
	}, inputs[0].Items, "each distinct value-and-siblings pair once")
	assert.Nil(t, inputs[0].Known, "the route path names no dimension")

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-a1"},
		{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "acc-a2"},
		{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "acc-b2"},
	}, srv.attributeCalls())
}

// An alias that resolves in one ledger and not in the other is unknown where
// it is read with the other: 422 naming that element.
func TestAuthorize_Resolve_SiblingsMakeAnUnknownPair(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{bySibling: "ledgerId", table: map[string][]string{"led-1/@a": {"acc-a1"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, transfersRoute, legDims()...)

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(transfersRoute, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	got := doRequest(t, app, http.MethodPost, transfersPath, partnerToken("acme/p1"), `{
		"debits":  [{"organizationId":"org-1","ledgerId":"led-1","alias":"@a"}],
		"credits": [{"organizationId":"org-1","ledgerId":"led-2","alias":"@a"}]}`)

	assert.Equal(t, http.StatusUnprocessableEntity, got.status)
	assert.Contains(t, got.body, `"credits[0].alias"`)
	assert.Equal(t, int64(0), srv.hits.Load())
	assert.Equal(t, int64(0), probe.calls.Load())
}

// Siblings are the plain fields of the same element that the request names:
// not those of an enclosing element, not another resolved field, not an
// optional field left out.
func TestAuthorize_Resolve_SiblingsAreTheSameElementsPlainFields(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}, "@b": {"acc-b"}, "tx-1": {"pf-1"}}}

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.RegisterScopeResolver("alias", resolver.resolve))
	require.NoError(t, auth.SetManifestScope("midaz", append(resolveCatalog(), Dim("portfolioId", FromPath).At("portfolio_id"))...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, transfersRoute,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At("items[].ledgerId").Optional(),
		Dim("accountId", FromBody).At("items[].alias").Resolve("alias"),
		Dim("portfolioId", FromBody).At("items[].ref").Resolve("alias")))

	app := fiber.New()
	app.Post(transfersRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, transfersPath, partnerToken("acme/p1"), `{
		"organizationId":"org-1",
		"items":[{"ledgerId":"led-1","alias":"@a","ref":"tx-1"},{"alias":"@b","ref":"tx-1"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	inputs := resolver.inputs()
	require.Len(t, inputs, 2, "one call per resolved dimension")

	byDim := map[string][]ResolveItem{inputs[0].Dimension: inputs[0].Items, inputs[1].Dimension: inputs[1].Items}
	assert.Equal(t, []ResolveItem{
		{Value: "@a", Siblings: map[string]string{"ledgerId": "led-1"}},
		{Value: "@b"},
	}, byDim["accountId"])
	assert.Equal(t, []ResolveItem{
		{Value: "tx-1", Siblings: map[string]string{"ledgerId": "led-1"}},
		{Value: "tx-1"},
	}, byDim["portfolioId"])

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-a", "portfolioId": "pf-1"},
		{"organizationId": "org-1", "accountId": "acc-b", "portfolioId": "pf-1"},
	}, srv.attributeCalls())
}

// A top-level value's element is the body itself: its siblings are the other
// top-level fields.
func TestAuthorize_Resolve_TopLevelSiblings(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{bySibling: "ledgerId", table: map[string][]string{"led-1/@a": {"acc-a"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, transfersRoute,
		Dim("ledgerId", FromBody).At("ledgerId"),
		Dim("accountId", FromBody).At("alias").Resolve("alias"))

	app := fiber.New()
	app.Post(transfersRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, transfersPath, partnerToken("acme/p1"), `{"ledgerId":"led-1","alias":"@a"}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []ResolveItem{{Value: "@a", Siblings: map[string]string{"ledgerId": "led-1"}}}, resolver.inputs()[0].Items)
	assert.Equal(t, []map[string]string{{"ledgerId": "led-1", "accountId": "acc-a"}}, srv.attributeCalls())
}

// A string of an array of strings is its own element: its siblings are the
// fields of the object holding the array.
func TestAuthorize_Resolve_StringArraySiblings(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{bySibling: "ledgerId", table: map[string][]string{
		"led-1/@a": {"acc-a1"}, "led-2/@a": {"acc-a2"}, "led-2/@b": {"acc-b2"},
	}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, transfersRoute,
		Dim("ledgerId", FromBody).At("targets[].ledgerId"),
		Dim("accountId", FromBody).At("targets[].aliases[]").Resolve("alias"))

	app := fiber.New()
	app.Post(transfersRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, transfersPath, partnerToken("acme/p1"),
		`{"targets":[{"ledgerId":"led-1","aliases":["@a"]},{"ledgerId":"led-2","aliases":["@a","@b"]}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	inputs := resolver.inputs()
	require.Len(t, inputs, 1)
	assert.Equal(t, []ResolveItem{
		{Value: "@a", Siblings: map[string]string{"ledgerId": "led-1"}},
		{Value: "@a", Siblings: map[string]string{"ledgerId": "led-2"}},
		{Value: "@b", Siblings: map[string]string{"ledgerId": "led-2"}},
	}, inputs[0].Items)

	assert.Equal(t, []map[string]string{
		{"ledgerId": "led-1", "accountId": "acc-a1"},
		{"ledgerId": "led-2", "accountId": "acc-a2"},
		{"ledgerId": "led-2", "accountId": "acc-b2"},
	}, srv.attributeCalls())
}

// The cap counts distinct items: the same alias in 101 ledgers is refused
// before the resolver is called.
func TestAuthorize_Resolve_CapCountsItems(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{bySibling: "ledgerId", table: map[string][]string{}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, transfersRoute,
		Dim("ledgerId", FromBody).At("items[].ledgerId"),
		Dim("accountId", FromBody).At("items[].alias").Resolve("alias"))

	app := fiber.New()
	app.Post(transfersRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	body := func(n int) string {
		out := `{"items":[`
		for i := range n {
			if i > 0 {
				out += ","
			}

			out += `{"ledgerId":"led-` + strconv.Itoa(i) + `","alias":"@a"}`
		}

		return out + `]}`
	}

	got := doRequest(t, app, http.MethodPost, transfersPath, partnerToken("acme/p1"), body(maxBodyScopeQuestions+1))
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Empty(t, resolver.inputs())

	// Positive control: exactly the cap is resolved and asked.
	for i := range maxBodyScopeQuestions {
		resolver.table["led-"+strconv.Itoa(i)+"/@a"] = []string{"acc-" + strconv.Itoa(i)}
	}

	got = doRequest(t, app, http.MethodPost, transfersPath, partnerToken("acme/p1"), body(maxBodyScopeQuestions))
	assert.Equal(t, http.StatusOK, got.status, got.body)
	assert.Len(t, resolver.inputs()[0].Items, maxBodyScopeQuestions)
	assert.Equal(t, int64(maxBodyScopeQuestions), srv.hits.Load())
}

// An answer that does not line up with the items is a failing resolver: 503,
// never a guess at which item an answer belongs to.
func TestAuthorize_Resolve_AnswerOfTheWrongLengthIsUnavailable(t *testing.T) {
	t.Parallel()

	for name, route := range map[string]struct {
		path, target, body string
		dim                Dimension
	}{
		"body": {transfersRoute, transfersPath, `{"items":[{"alias":"@a"},{"alias":"@b"}]}`, Dim("accountId", FromBody).At("items[].alias").Resolve("alias")},
		"path": {txRoute, txTarget, "", Dim("accountId", FromPath).At("transaction_id").Resolve("alias")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			resolver := &fakeResolver{short: true, table: map[string][]string{"@a": {"acc-a"}, "@b": {"acc-b"}, "tx-1": {"acc-1"}}}
			auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, route.path, route.dim)

			probe := &handlerProbe{}
			app := fiber.New()
			app.Post(route.path, auth.Authorize("midaz", "transactions", "post"), probe.handle)

			got := doRequest(t, app, http.MethodPost, route.target, partnerToken("acme/p1"), route.body)

			assert.Equal(t, http.StatusServiceUnavailable, got.status)
			assert.Contains(t, got.body, `scope resolver "alias"`)
			assert.Equal(t, int64(0), srv.hits.Load())
			assert.Equal(t, int64(0), probe.calls.Load())

			// Positive control: the full answer is accepted.
			resolver.short = false
			assert.Equal(t, http.StatusOK, doRequest(t, app, http.MethodPost, route.target, partnerToken("acme/p1"), route.body).status)
		})
	}
}
