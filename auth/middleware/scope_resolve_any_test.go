package middleware

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// A resolved value allowed when ANY of the values it stands for is (MatchAny)
// ---------------------------------------------------------------------------

const (
	holderRoute  = "/v1/organizations/:organization_id/holders/:holder_id"
	holderTarget = "/v1/organizations/org-1/holders/h-1"
	// holderRefusal is the uniform refusal of a holder outside the scope.
	holderRefusal = `path parameter "holder_id" is outside this credential's scope or does not exist`
)

// holderApp serves the holder route, its ledgers resolved with the given
// dimension, and records the scope the handler saw.
func holderApp(t *testing.T, srv *fakeAuthServer, resolver *fakeResolver, dims ...Dimension) (*fiber.App, *handlerProbe, *RequestScope) {
	t.Helper()

	auth := resolvingClient(t, srv.URL, "holderLedgers", resolver, http.MethodGet, holderRoute, dims...)

	probe := &handlerProbe{}
	scope := &RequestScope{}

	app := fiber.New()
	app.Get(holderRoute, auth.Authorize("midaz", "holders", "get"), func(c fiber.Ctx) error {
		*scope, _ = ScopeFromContext(c.Context())

		return probe.handle(c)
	})

	return app, probe, scope
}

func holderLedgers() Dimension {
	return Dim("ledgerId", FromPath).At("holder_id").Resolve("holderLedgers")
}

func TestDimension_MatchAny(t *testing.T) {
	t.Parallel()

	base := holderLedgers()
	anyOf := base.MatchAny()

	assert.True(t, anyOf.MatchesAny())
	assert.False(t, base.MatchesAny(), "MatchAny never mutates the receiver")
	assert.Equal(t, base.Resolver(), anyOf.Resolver())
}

// One of two resolved values allowed is enough; the other is asked only when
// the first is refused.
func TestAuthorize_ResolveAny_OneAllowedOfTwoIsAllowed(t *testing.T) {
	t.Parallel()

	known := map[string]string{"organizationId": "org-1"}
	first := map[string]string{"organizationId": "org-1", "ledgerId": "led-1"}
	second := map[string]string{"organizationId": "org-1", "ledgerId": "led-2"}

	tests := []struct {
		name      string
		denied    []string
		wantCalls []map[string]string
		wantSets  []map[string]string
	}{
		{
			name:      "first_refused_second_allowed",
			denied:    []string{"led-1"},
			wantCalls: []map[string]string{known, first, second},
			wantSets:  []map[string]string{second},
		},
		{
			name:      "first_allowed_second_never_asked",
			denied:    []string{"led-2"},
			wantCalls: []map[string]string{known, first},
			wantSets:  []map[string]string{first},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t, tt.denied...)
			resolver := &fakeResolver{table: map[string][]string{"h-1": {"led-1", "led-2"}}}
			app, probe, scope := holderApp(t, srv, resolver, holderLedgers().MatchAny())

			got := doRequest(t, app, http.MethodGet, holderTarget, partnerToken("acme/p1"), "")
			require.Equal(t, http.StatusOK, got.status, got.body)

			assert.Equal(t, int64(1), probe.calls.Load())
			assert.Equal(t, tt.wantCalls, srv.attributeCalls())
			assert.Equal(t, tt.wantSets, scope.Sets, "the request is authorized as the value that was allowed")
		})
	}
}

// None of the resolved values allowed refuses the request with the same body
// as a holder that does not resolve at all.
func TestAuthorize_ResolveAny_NoneAllowedIsForbidden(t *testing.T) {
	t.Parallel()

	unknown := newDecidingAuthServer(t)
	unknownApp, _, _ := holderApp(t, unknown, &fakeResolver{table: map[string][]string{"h-1": {}}}, holderLedgers().MatchAny())
	unresolvedRefusal := doRequest(t, unknownApp, http.MethodGet, holderTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusForbidden, unresolvedRefusal.status)
	require.Contains(t, unresolvedRefusal.body, holderRefusal)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, unknown.attributeCalls(),
		"a holder resolving to nothing is refused after the known question only")

	srv := newDecidingAuthServer(t, "led-1", "led-2")
	resolver := &fakeResolver{table: map[string][]string{"h-1": {"led-1", "led-2"}}}
	app, probe, _ := holderApp(t, srv, resolver, holderLedgers().MatchAny())

	got := doRequest(t, app, http.MethodGet, holderTarget, partnerToken("acme/p1"), "")

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Equal(t, unresolvedRefusal.body, got.body, "refused exactly as a holder that does not exist")
	assert.Equal(t, int64(0), probe.calls.Load())
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1"},
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, srv.attributeCalls(), "every value is asked before refusing")
}

// Without MatchAny every resolved value must still be allowed.
func TestAuthorize_ResolveAll_IsUnchanged(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-1")
	resolver := &fakeResolver{table: map[string][]string{"h-1": {"led-1", "led-2"}}}
	app, probe, _ := holderApp(t, srv, resolver, holderLedgers())

	got := doRequest(t, app, http.MethodGet, holderTarget, partnerToken("acme/p1"), "")

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Contains(t, got.body, holderRefusal)
	assert.Equal(t, int64(0), probe.calls.Load())
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1"},
		{"organizationId": "org-1", "ledgerId": "led-1"},
	}, srv.attributeCalls(), "the first refused value ends the request")

	// Positive control: both allowed, both asked, both authorized.
	srv = newDecidingAuthServer(t)
	app, _, scope := holderApp(t, srv, resolver, holderLedgers())

	got = doRequest(t, app, http.MethodGet, holderTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, scope.Sets)
}

// Next to another dimension the request names several values of, every one of
// those values must be allowed together with at least one resolved value.
func TestAuthorize_ResolveAny_MixedWithAnotherDimension(t *testing.T) {
	t.Parallel()

	q := func(account, ledger string) map[string]string {
		return map[string]string{"organizationId": "org-1", "accountId": account, "ledgerId": ledger}
	}

	srv := newDecidingAuthServer(t, "led-1")
	resolver := &fakeResolver{table: map[string][]string{"h-1": {"led-1", "led-2"}}}

	auth := resolvingClient(t, srv.URL, "holderLedgers", resolver, http.MethodGet, holderRoute,
		holderLedgers().MatchAny(), Dim("accountId", FromQuery).At("account"))

	app := fiber.New()
	app.Get(holderRoute, auth.Authorize("midaz", "holders", "get"), ok)

	got := doRequest(t, app, http.MethodGet, holderTarget+"?account=acc-1,acc-2", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "accountId": "acc-2"},
		q("acc-1", "led-1"),
		q("acc-1", "led-2"),
		q("acc-2", "led-1"),
		q("acc-2", "led-2"),
	}, srv.attributeCalls(), "per account, one question per ledger until one is allowed")
}

// Next to another dimension the request names several values of, a value
// refused on every resolved value refuses the request.
func TestAuthorize_ResolveAny_MixedRefusedOnEveryResolvedValue(t *testing.T) {
	t.Parallel()

	q := func(account, ledger string) map[string]string {
		return map[string]string{"organizationId": "org-1", "accountId": account, "ledgerId": ledger}
	}

	// acc-2 is allowed alone, and with led-1 only: refused together with every
	// ledger the holder resolves to.
	srv := newDecidingAuthServerFunc(t, func(attrs map[string]string) bool {
		return attrs["accountId"] != "acc-2" || attrs["ledgerId"] == "" || attrs["ledgerId"] == "led-3"
	})
	resolver := &fakeResolver{table: map[string][]string{"h-1": {"led-1", "led-2"}}}

	auth := resolvingClient(t, srv.URL, "holderLedgers", resolver, http.MethodGet, holderRoute,
		holderLedgers().MatchAny(), Dim("accountId", FromQuery).At("account"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Get(holderRoute, auth.Authorize("midaz", "holders", "get"), probe.handle)

	got := doRequest(t, app, http.MethodGet, holderTarget+"?account=acc-1,acc-2", partnerToken("acme/p1"), "")

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Contains(t, got.body, holderRefusal)
	assert.Equal(t, int64(0), probe.calls.Load())
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "accountId": "acc-2"},
		q("acc-1", "led-1"),
		q("acc-2", "led-1"),
		q("acc-2", "led-2"),
	}, srv.attributeCalls())

	// Positive control: the same request with acc-2 allowed on led-2.
	srv = newDecidingAuthServerFunc(t, func(attrs map[string]string) bool {
		return attrs["accountId"] != "acc-2" || attrs["ledgerId"] != "led-1"
	})
	auth = resolvingClient(t, srv.URL, "holderLedgers", resolver, http.MethodGet, holderRoute,
		holderLedgers().MatchAny(), Dim("accountId", FromQuery).At("account"))

	app = fiber.New()
	app.Get(holderRoute, auth.Authorize("midaz", "holders", "get"), probe.handle)

	got = doRequest(t, app, http.MethodGet, holderTarget+"?account=acc-1,acc-2", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
}

// Each body element is its own any-of group: one element allowed through
// another's value is not enough.
func TestAuthorize_ResolveAny_EachBodyElementOnItsOwn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		denied     []string
		wantStatus int
		wantBody   string
	}{
		{name: "each_element_with_one_value", denied: []string{"acc-a1"}, wantStatus: http.StatusOK},
		{
			name: "second_element_refused", denied: []string{"acc-b"}, wantStatus: http.StatusForbidden,
			wantBody: `body field "debits[1].alias" is outside this credential's scope or does not exist`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t, tt.denied...)
			resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a1", "acc-a2"}, "@b": {"acc-b"}}}
			auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
				Dim("accountId", FromBody).At("debits[].alias").Resolve("alias").MatchAny())

			probe := &handlerProbe{}
			app := fiber.New()
			app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), probe.handle)

			got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
				`{"debits":[{"alias":"@a"},{"alias":"@b"}]}`)

			assert.Equal(t, tt.wantStatus, got.status, got.body)

			if tt.wantBody != "" {
				assert.Contains(t, got.body, tt.wantBody)
				assert.Equal(t, int64(0), probe.calls.Load())
			}
		})
	}
}

// The resolved value and the same dimension named directly: the named values
// are asked on their own, and each resolved item must still have one of its
// values allowed — they are not checked for agreement.
func TestAuthorize_ResolveAny_NamedDirectlyToo(t *testing.T) {
	t.Parallel()

	const (
		route  = "/v1/organizations/:organization_id/ledgers/:ledger_id/holders/:holder_id"
		target = "/v1/organizations/org-1/ledgers/led-2/holders/h-1"
	)

	resolver := &fakeResolver{table: map[string][]string{"h-1": {"led-1", "led-2"}, "h-2": {"led-1"}}}
	led := func(ledger string) map[string]string {
		return map[string]string{"organizationId": "org-1", "ledgerId": ledger}
	}

	srv := newDecidingAuthServer(t, "led-1")
	auth := resolvingClient(t, srv.URL, "holderLedgers", resolver, http.MethodGet, route,
		holderLedgers().MatchAny())

	app := fiber.New()
	app.Get(route, auth.Authorize("midaz", "holders", "get"), ok)

	got := doRequest(t, app, http.MethodGet, target, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, []map[string]string{led("led-2"), led("led-2"), led("led-1")}, srv.attributeCalls(),
		"the ledger the path names, then the holder's ledgers until one is allowed")

	got = doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-2/holders/h-2", partnerToken("acme/p1"), "")
	assert.Equal(t, http.StatusForbidden, got.status, "the holder's only ledger is denied")
	assert.Contains(t, got.body, holderRefusal)

	allowing := newDecidingAuthServer(t)
	auth = resolvingClient(t, allowing.URL, "holderLedgers", resolver, http.MethodGet, route,
		holderLedgers().MatchAny())

	app = fiber.New()
	app.Get(route, auth.Authorize("midaz", "holders", "get"), ok)

	got = doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-2/holders/h-2", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, []map[string]string{led("led-2"), led("led-2"), led("led-1")}, allowing.attributeCalls(),
		"both ledgers are asked")
}

// MatchAny names how the values of a resolver are judged: without one it is a
// misdeclaration.
func TestMatchAny_RequiresAResolver(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))

	err := auth.SetManifestRouteScope("midaz", http.MethodGet, legsRoute, Dim("accountId", FromQuery).At("account").MatchAny())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accountId")
	assert.Contains(t, err.Error(), "resolver")

	err = auth.SetManifestScope("midaz", append(manifestDims(), Dim("accountId", FromHeader).At("X-Account").MatchAny())...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolver")

	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodGet, legsRoute, Dim("accountId", FromQuery).At("account")),
		"positive control")
}

// A refusal that is not about the scope — the authorization service failing —
// ends the request at once, even when a later value would be allowed.
func TestAuthorize_ResolveAny_UnavailableEndsTheGroup(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)

		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), `"led-1"`) {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorized":true}`))
	}))
	t.Cleanup(srv.Close)

	resolver := &fakeResolver{table: map[string][]string{"h-1": {"led-1", "led-2"}}}
	auth := resolvingClient(t, srv.URL, "holderLedgers", resolver, http.MethodGet, holderRoute, holderLedgers().MatchAny())

	probe := &handlerProbe{}
	app := fiber.New()
	app.Get(holderRoute, auth.Authorize("midaz", "holders", "get"), probe.handle)

	got := doRequest(t, app, http.MethodGet, holderTarget, partnerToken("acme/p1"), "")

	assert.GreaterOrEqual(t, got.status, http.StatusInternalServerError, got.body)
	assert.NotContains(t, got.body, holderRefusal, "an outage is not reported as a value outside the scope")
	assert.Equal(t, int64(0), probe.calls.Load())
	assert.Equal(t, int64(2), calls.Load(), "the known question, then led-1; led-2 is never asked")
}

// A question two groups share is asked once.
func TestAuthorize_ResolveAny_SharedQuestionIsAskedOnce(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "acc-1")
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-1", "acc-2"}, "@b": {"acc-1", "acc-3"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias").MatchAny())

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), `{"debits":[{"alias":"@a"},{"alias":"@b"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	q := func(account string) map[string]string {
		return map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": account}
	}
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		q("acc-1"), q("acc-2"), q("acc-3"),
	}, srv.attributeCalls())
}

// A body value resolved with MatchAny next to the same dimension named by the
// path: the path's value is asked on its own, and one of the values the body
// value resolves to must be allowed besides.
func TestAuthorize_ResolveAny_BodyValueNamedByThePath(t *testing.T) {
	t.Parallel()

	const (
		route  = "/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/:account_id/transfers"
		target = "/v1/organizations/org-1/ledgers/led-1/accounts/acc-a/transfers"
	)

	q := func(account string) map[string]string {
		return map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": account}
	}

	resolver := &fakeResolver{table: map[string][]string{"@ab": {"acc-b", "acc-a"}, "@bc": {"acc-b", "acc-c"}}}

	srv := newDecidingAuthServer(t, "acc-b")
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, route,
		Dim("accountId", FromBody).At("alias").Resolve("alias").MatchAny())

	app := fiber.New()
	app.Post(route, auth.Authorize("midaz", "transfers", "post"), ok)

	got := doRequest(t, app, http.MethodPost, target, partnerToken("acme/p1"), `{"alias":"@ab"}`)
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, []map[string]string{q("acc-a"), q("acc-b"), q("acc-a")}, srv.attributeCalls(),
		"the known question, the alias's accounts until one is allowed, then the path's")

	got = doRequest(t, app, http.MethodPost, target, partnerToken("acme/p1"), `{"alias":"@bc"}`)
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Contains(t, srv.attributeCalls()[3:], q("acc-c"), "the alias's other account is asked")

	denying := newDecidingAuthServer(t, "acc-b", "acc-c")
	auth = resolvingClient(t, denying.URL, "alias", resolver, http.MethodPost, route,
		Dim("accountId", FromBody).At("alias").Resolve("alias").MatchAny())

	app = fiber.New()
	app.Post(route, auth.Authorize("midaz", "transfers", "post"), ok)

	got = doRequest(t, app, http.MethodPost, target, partnerToken("acme/p1"), `{"alias":"@bc"}`)
	assert.Equal(t, http.StatusForbidden, got.status, "no account of the alias is allowed")
	assert.Contains(t, got.body, `body field "alias" is outside this credential's scope`)
}

// Values resolved with MatchAny outside the body and the same dimension named
// by the body: the body's value is asked, and each request value must have one
// of its values allowed besides — they are not checked for agreement.
func TestAuthorize_ResolveAny_BodyNamesOneValueOfEachItem(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/holders"

	resolver := &fakeResolver{table: map[string][]string{"h-1": {"led-1", "led-2"}, "h-2": {"led-3"}}}
	led := func(ledger string) map[string]string {
		return map[string]string{"organizationId": "org-1", "ledgerId": ledger}
	}

	newApp := func(srv *fakeAuthServer) *fiber.App {
		auth := resolvingClient(t, srv.URL, "holderLedgers", resolver, http.MethodPost, route,
			Dim("ledgerId", FromQuery).At("holder").Resolve("holderLedgers").MatchAny(),
			Dim("ledgerId", FromBody).At("ledgerId"))

		app := fiber.New()
		app.Post(route, auth.Authorize("midaz", "holders", "post"), ok)

		return app
	}

	srv := newDecidingAuthServer(t, "led-1")
	app := newApp(srv)

	got := doRequest(t, app, http.MethodPost, "/v1/organizations/org-1/holders?holder=h-1", partnerToken("acme/p1"), `{"ledgerId":"led-2"}`)
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Contains(t, srv.attributeCalls(), led("led-2"))

	got = doRequest(t, app, http.MethodPost, "/v1/organizations/org-1/holders?holder=h-1,h-2", partnerToken("acme/p1"), `{"ledgerId":"led-2"}`)
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Contains(t, srv.attributeCalls(), led("led-3"), "the second holder's ledger is asked")

	denying := newDecidingAuthServer(t, "led-3")
	got = doRequest(t, newApp(denying), http.MethodPost, "/v1/organizations/org-1/holders?holder=h-1,h-2", partnerToken("acme/p1"), `{"ledgerId":"led-2"}`)
	assert.Equal(t, http.StatusForbidden, got.status, "the second holder's only ledger is denied")
	assert.Contains(t, got.body, `query parameter "holder" is outside this credential's scope`)

	got = doRequest(t, newApp(newDecidingAuthServer(t, "led-2")), http.MethodPost,
		"/v1/organizations/org-1/holders?holder=h-1", partnerToken("acme/p1"), `{"ledgerId":"led-2"}`)
	assert.Equal(t, http.StatusForbidden, got.status, "the body's ledger must be allowed itself")
}

// The values one request value resolves to count toward the cap of questions.
func TestAuthorize_ResolveAny_Cap(t *testing.T) {
	t.Parallel()

	ledgers := func(n int) []string {
		out := make([]string, 0, n)
		for i := range n {
			out = append(out, fmt.Sprintf("led-%d", i))
		}

		return out
	}

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"h-1": ledgers(maxBodyScopeQuestions + 1), "h-2": ledgers(maxBodyScopeQuestions)}}
	app, probe, _ := holderApp(t, srv, resolver, holderLedgers().MatchAny())

	got := doRequest(t, app, http.MethodGet, holderTarget, partnerToken("acme/p1"), "")
	assert.Equal(t, http.StatusBadRequest, got.status, got.body)
	assert.Contains(t, got.body, "more than 100 distinct sets")
	assert.Equal(t, int64(1), srv.hits.Load(), "only the known question")

	got = doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/holders/h-2", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, int64(1), probe.calls.Load())
}

// The cap counts every value each request value resolves to, even one another
// request value resolves to as well: what is built is bounded, not only what is
// asked.
func TestAuthorize_ResolveAny_CapCountsEveryRequestValue(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/holders"

	shared := make([]string, 0, 60)
	for i := range 60 {
		shared = append(shared, fmt.Sprintf("led-%d", i))
	}

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"h-1": shared, "h-2": shared, "h-3": shared[:40]}}
	auth := resolvingClient(t, srv.URL, "holderLedgers", resolver, http.MethodGet, route,
		Dim("ledgerId", FromQuery).At("holder").Resolve("holderLedgers").MatchAny())

	app := fiber.New()
	app.Get(route, auth.Authorize("midaz", "holders", "get"), ok)

	got := doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/holders?holder=h-1,h-2", partnerToken("acme/p1"), "")
	assert.Equal(t, http.StatusBadRequest, got.status, got.body)
	assert.Contains(t, got.body, "more than 100 distinct sets")

	// Positive control: 60 and 40 values, 100 in all.
	got = doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/holders?holder=h-1,h-3", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
}
