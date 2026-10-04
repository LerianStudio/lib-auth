package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pendingCall is one /v1/authorize body as the pending tests read it: the
// attributes asked, and the pending member — with whether it was sent at all.
type pendingCall struct {
	attributes map[string]string
	pending    []string
	sent       bool
}

// pendingAuthServer records every authorize body. With coversRule set it
// answers like a service applying the covers rule to accountId: a question
// that names no accountId and does not declare it pending is denied.
type pendingAuthServer struct {
	*httptest.Server

	coversRule bool

	mu    sync.Mutex
	calls []pendingCall
}

func newPendingAuthServer(t *testing.T, coversRule bool) *pendingAuthServer {
	t.Helper()

	srv := &pendingAuthServer{coversRule: coversRule}

	srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("mock authz server: failed to read body: %v", err)
		}

		var body struct {
			Attributes map[string]string `json:"attributes"`
			Pending    json.RawMessage   `json:"pending"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("mock authz server: failed to decode body: %v", err)
		}

		call := pendingCall{attributes: body.Attributes, sent: body.Pending != nil}
		if call.sent {
			if err := json.Unmarshal(body.Pending, &call.pending); err != nil {
				t.Errorf("mock authz server: pending is not a list of names: %s", body.Pending)
			}
		}

		srv.mu.Lock()
		srv.calls = append(srv.calls, call)
		srv.mu.Unlock()

		authorized := true

		if srv.coversRule && len(body.Attributes) > 0 {
			if _, named := body.Attributes["accountId"]; !named && !contains(call.pending, "accountId") {
				authorized = false
			}
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(AuthResponse{Authorized: authorized}); err != nil {
			t.Errorf("mock authz server: failed to encode response: %v", err)
		}
	}))

	t.Cleanup(srv.Close)

	return srv
}

func (srv *pendingAuthServer) recorded() []pendingCall {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	return append([]pendingCall(nil), srv.calls...)
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}

	return false
}

// The question asked before a body value is resolved declares the dimension
// it is about to resolve; the question about the resolved value does not.
func TestAuthorize_Pending_BodyResolvePhaseOneDeclaresIt(t *testing.T) {
	t.Parallel()

	srv := newPendingAuthServer(t, true)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias"))

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), `{"debits":[{"alias":"@a"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	calls := srv.recorded()
	require.Len(t, calls, 2)

	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1"}, calls[0].attributes)
	assert.True(t, calls[0].sent, "phase 1 sends pending")
	assert.Equal(t, []string{"accountId"}, calls[0].pending)

	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-a"}, calls[1].attributes)
	assert.False(t, calls[1].sent, "the resolved question carries no pending")
	assert.Len(t, resolver.inputs(), 1)
}

// The same for a value read outside the body.
func TestAuthorize_Pending_PathResolvePhaseOneDeclaresIt(t *testing.T) {
	t.Parallel()

	srv := newPendingAuthServer(t, true)
	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1"}}}
	auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
		Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	calls := srv.recorded()
	require.Len(t, calls, 2)
	assert.Equal(t, []string{"accountId"}, calls[0].pending)
	assert.True(t, calls[0].sent)
	assert.False(t, calls[1].sent)
	assert.Equal(t, "acc-1", calls[1].attributes["accountId"])
}

// Two resolved dimensions are both pending, once each, in name order.
func TestAuthorize_Pending_ListsEveryResolvedDimensionOnce(t *testing.T) {
	t.Parallel()

	srv := newPendingAuthServer(t, false)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"v-a"}, "@b": {"v-b"}, "@c": {"v-c"}}}
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.RegisterScopeResolver("alias", resolver.resolve))
	require.NoError(t, auth.SetManifestScope("midaz", append(manifestDims(),
		Dim("accountId", FromPath).At("account_id"), Dim("portfolioId", FromPath).At("portfolio_id"))...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, legsRoute,
		Dim("portfolioId", FromBody).At("debits[].portfolio").Resolve("alias"),
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias"),
		Dim("accountId", FromBody).At("credits[].alias").Resolve("alias"),
		Dim("portfolioId", FromBody).At("credits[].portfolio").Resolve("alias")))

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"debits":[{"alias":"@a","portfolio":"@c"}],"credits":[{"alias":"@b","portfolio":"@c"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	calls := srv.recorded()
	require.NotEmpty(t, calls)
	assert.Equal(t, []string{"accountId", "portfolioId"}, calls[0].pending)

	for _, call := range calls[1:] {
		assert.False(t, call.sent, "only phase 1 sends pending: %v", call.attributes)
	}
}

// Nothing to resolve, nothing pending: a resolving route whose request carries
// no value for the resolved dimension, a route that resolves nothing, and a
// caller that is not partner-bound all ask without the member.
func TestAuthorize_Pending_AbsentWhenNothingResolves(t *testing.T) {
	t.Parallel()

	srv := newPendingAuthServer(t, false)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias").Optional())

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), `{"debits":[{"amount":1}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	got = doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	got = doRequest(t, app, http.MethodPost, legsPath, userToken(), `{"debits":[{"alias":"@a"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	calls := srv.recorded()
	require.Len(t, calls, 3)

	for _, call := range calls {
		assert.False(t, call.sent, "no pending without a value to resolve: %v", call.attributes)
	}

	assert.Empty(t, resolver.inputs())
}

// A question asked with a dimension pending and the same question asked without
// it are two questions: the cache never answers one with the other's decision.
func TestAuthorize_Pending_IsPartOfTheCacheKey(t *testing.T) {
	t.Parallel()

	srv := newPendingAuthServer(t, true)
	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1"}}}
	auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
		Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))
	auth.cache = newDecisionCache(time.Minute)

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)
	app.Get(legsRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	// The same organization and ledger, with no account and nothing pending,
	// is denied by the covers rule — not served from the pending grant.
	got = doRequest(t, app, http.MethodGet, legsPath, partnerToken("acme/p1"), "")
	assert.Equal(t, http.StatusForbidden, got.status, got.body)
	assert.Len(t, srv.recorded(), 3, "the question without pending reached the service")
}
