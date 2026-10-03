package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Resolution runs only once the credential is validated
// ---------------------------------------------------------------------------

// A request whose known dimensions are denied is refused before any resolver
// runs: the resolver never looks up anything for a credential the
// authorization service has not accepted.
func TestAuthorize_Resolve_KnownDimensionsAreAskedFirst(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-1")
	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1"}}}
	auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
		Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), probe.handle)

	got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Empty(t, resolver.inputs(), "no resolver runs before the credential is accepted")
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls(),
		"one question, about the known dimensions only")
	assert.Equal(t, int64(0), probe.calls.Load())

	// Positive control: another ledger is accepted, then resolved, then asked.
	got = doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-2/transactions/tx-1", partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Len(t, resolver.inputs(), 1)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-2"},
		{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "acc-1"},
	}, srv.attributeCalls()[1:])
}

// A credential the authorization service calls finished is answered 401, and
// no resolver runs.
func TestAuthorize_Resolve_FinishedCredentialNeverResolves(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthResponse{Authorized: false, Reason: reasonSuspended})
	}))
	t.Cleanup(srv.Close)

	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1"}}}
	auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
		Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")

	assert.Equal(t, http.StatusUnauthorized, got.status)
	assert.Empty(t, resolver.inputs())
	assert.Equal(t, int64(1), hits.Load())
}

// The plain body dimensions are part of the first question, so a body naming
// a ledger outside the scope is refused before its aliases are looked up.
func TestAuthorize_Resolve_PlainBodyDimensionsAreAskedFirst(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-x")
	resolver := &fakeResolver{bySibling: "ledgerId", table: map[string][]string{"led-1/@a": {"acc-a"}, "led-x/@a": {"acc-x"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, transfersRoute, legDims()...)

	app := fiber.New()
	app.Post(transfersRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, transfersPath, partnerToken("acme/p1"), `{
		"debits":  [{"organizationId":"org-1","ledgerId":"led-1","alias":"@a"}],
		"credits": [{"organizationId":"org-1","ledgerId":"led-x","alias":"@a"}]}`)

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Empty(t, resolver.inputs())
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-x"},
	}, srv.attributeCalls())
}

// The resolver's context carries the identity the first question validated:
// PrincipalFromContext answers with the token's subject and tenant.
func TestAuthorize_Resolve_ResolverContextCarriesTheValidatedPrincipal(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)

	var (
		principal Principal
		found     bool
		asked     int
	)

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.RegisterScopeResolver("legs", func(ctx context.Context, in ResolveInput) ([][]string, error) {
		principal, found = PrincipalFromContext(ctx)
		asked = len(srv.attributeCalls())

		return [][]string{{"acc-1"}}, nil
	}))
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodGet, txRoute, Dim("accountId", FromPath).At("transaction_id").Resolve("legs")))

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	token := createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app", "partner": "acme/p1", "tenantId": "tenant-7"})

	got := doRequest(t, app, http.MethodGet, txTarget, token, "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	require.True(t, found, "the resolver context carries the principal")
	assert.Equal(t, "acme/app", principal.Subject)
	assert.Equal(t, "tenant-7", principal.TenantID)
	assert.Equal(t, 1, asked, "the resolver runs after the first question was granted")
}

// A value that does not resolve and a resolved value outside the scope answer
// the same: 403, the same body, naming where the value was read.
func TestAuthorize_Resolve_UnknownAndOutOfScopeAreIndistinguishable(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "acc-out")
	resolver := &fakeResolver{table: map[string][]string{"@in": {"acc-in"}, "@out": {"acc-out"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("debits[].alias").Resolve("alias"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	unknown := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), `{"debits":[{"alias":"@in"},{"alias":"@nope"}]}`)
	outside := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), `{"debits":[{"alias":"@in"},{"alias":"@out"}]}`)

	assert.Equal(t, http.StatusForbidden, unknown.status)
	assert.Equal(t, http.StatusForbidden, outside.status)
	assert.Equal(t, outside.body, unknown.body, "nothing tells a missing value from one outside the scope")
	assert.Contains(t, unknown.body, `body field "debits[1].alias" is outside this credential's scope or does not exist`)
	assert.Equal(t, int64(0), probe.calls.Load())

	// Positive control: both in scope.
	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), `{"debits":[{"alias":"@in"}]}`)
	assert.Equal(t, http.StatusOK, got.status, got.body)
}

// The same holds for a value read outside the body.
func TestAuthorize_Resolve_UnknownPathValueIsForbiddenLikeOutOfScope(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "acc-out")
	resolver := &fakeResolver{table: map[string][]string{"tx-out": {"acc-out"}}}
	auth := resolvingClient(t, srv.URL, "legs", resolver, http.MethodGet, txRoute,
		Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	unknown := doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/transactions/tx-nope", partnerToken("acme/p1"), "")
	outside := doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/transactions/tx-out", partnerToken("acme/p1"), "")

	assert.Equal(t, http.StatusForbidden, unknown.status)
	assert.Equal(t, outside.status, unknown.status)
	assert.Equal(t, outside.body, unknown.body)
	assert.Contains(t, unknown.body, `path parameter "transaction_id" is outside this credential's scope or does not exist`)
}

// The calls are bounded: one question per distinct set of known dimensions,
// then one per resolved set; the decision cache answers a repeat with none.
func TestAuthorize_Resolve_CallCountIsBounded(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{}}

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true, cache: newDecisionCache(time.Minute)}
	require.NoError(t, auth.RegisterScopeResolver("alias", resolver.resolve))
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, legsRoute, Dim("accountId", FromBody).At("debits[].alias").Resolve("alias")))

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	body := `{"debits":[`
	for i := range maxBodyScopeQuestions {
		if i > 0 {
			body += ","
		}

		alias := "@" + strconv.Itoa(i)
		resolver.table[alias] = []string{"acc-" + strconv.Itoa(i)}
		body += `{"alias":"` + alias + `"}`
	}

	body += `]}`

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), body)
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, int64(1+maxBodyScopeQuestions), srv.hits.Load(), "one known question, then one per resolved value")
	assert.Len(t, resolver.inputs(), 1)

	got = doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), body)
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, int64(1+maxBodyScopeQuestions), srv.hits.Load(), "a repeat is answered from the decision cache")
}

// With nothing to resolve, the request is asked once, as before.
func TestAuthorize_Resolve_NothingToResolveAsksOnce(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodGet, legsRoute,
		Dim("accountId", FromQuery).At("alias").Resolve("alias").Optional())

	app := fiber.New()
	app.Get(legsRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodGet, legsPath, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, int64(1), srv.hits.Load())
	assert.Empty(t, resolver.inputs())
}

// A route whose every dimension is resolved validates the credential with a
// question naming none, then asks about the resolved values.
func TestAuthorize_Resolve_OnlyResolvedDimensionsValidateFirst(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"tx-1": {"acc-1"}}}

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.RegisterScopeResolver("legs", resolver.resolve))

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get",
		RequireScope("midaz", Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))), ok)

	got := doRequest(t, app, http.MethodGet, txTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, []map[string]string{nil, {"accountId": "acc-1"}}, srv.attributeCalls())
}
