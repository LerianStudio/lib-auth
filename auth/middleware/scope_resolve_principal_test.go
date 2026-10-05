package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The resolver's principal does not depend on the M2M derivation model
// ---------------------------------------------------------------------------

// principalProbe is a resolver that records the principal its context carries.
type principalProbe struct {
	mu        sync.Mutex
	calls     int
	principal Principal
	found     bool
}

func (p *principalProbe) resolve(ctx context.Context, in ResolveInput) ([][]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++
	p.principal, p.found = PrincipalFromContext(ctx)

	out := make([][]string, len(in.Items))
	for i := range out {
		out[i] = []string{"acc-1"}
	}

	return out, nil
}

func (p *principalProbe) seen() (int, Principal, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls, p.principal, p.found
}

// legacyResolvingClient is a client on the legacy derivation model
// (M2MInversionEnabled=false) whose transaction route resolves its id.
func legacyResolvingClient(t *testing.T, url string, probe *principalProbe) *AuthClient {
	t.Helper()

	return bodyScopedClientWith(t, scopedClientSetup{
		url:       url,
		catalog:   resolveCatalog(),
		resolvers: map[string]ScopeResolver{"legs": probe.resolve},
		legacy:    true,
	}, http.MethodGet, txRoute, Dim("accountId", FromPath).At("transaction_id").Resolve("legs"))
}

func legacyPartnerToken(claims jwt.MapClaims) string {
	base := jwt.MapClaims{"type": "application", "sub": "acme/app", "azp": "client-9", "partner": "acme/p1", "tenantId": "tenant-7"}
	for k, v := range claims {
		if v == nil {
			delete(base, k)

			continue
		}

		base[k] = v
	}

	return createTestJWT(base)
}

// Under the legacy derivation a partner's application token is authorized
// under a fabricated role, which is not its identity. The resolver is still
// handed the identity the accepted token carries: its subject, type, client id
// and tenant.
func TestAuthorize_Resolve_LegacyDerivation_ResolverSeesTheValidatedPrincipal(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	probe := &principalProbe{}
	auth := legacyResolvingClient(t, srv.URL, probe)

	var handlerFound atomic.Bool

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), func(c fiber.Ctx) error {
		_, found := PrincipalFromContext(c.Context())
		handlerFound.Store(found)

		return c.SendString("ok")
	})

	got := doRequest(t, app, http.MethodGet, txTarget, legacyPartnerToken(nil), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	calls, principal, found := probe.seen()
	require.Equal(t, 1, calls)
	require.True(t, found, "the resolver context carries the principal whatever the derivation model")
	assert.Equal(t, Principal{
		Type:     application,
		Sub:      "acme/app",
		Subject:  "acme/app",
		ClientID: "client-9",
		TenantID: "tenant-7",
	}, principal)

	assert.False(t, handlerFound.Load(), "what the handler is published under the legacy derivation is unchanged")
}

// A resolver never sees the fabricated role as a subject, and the role keeps
// being what the authorization service is asked under.
func TestAuthorize_Resolve_LegacyDerivation_AuthorizationStillAsksUnderTheRole(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		subs []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Sub string `json:"sub"`
		}

		_ = json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		subs = append(subs, body.Sub)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthResponse{Authorized: true})
	}))
	t.Cleanup(srv.Close)

	probe := &principalProbe{}
	auth := legacyResolvingClient(t, srv.URL, probe)

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodGet, txTarget, legacyPartnerToken(nil), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, []string{"admin/midaz-editor-role", "admin/midaz-editor-role"}, subs)
}

// A credential the first question does not accept never reaches a resolver,
// under the legacy derivation as under the inversion.
func TestAuthorize_Resolve_LegacyDerivation_RefusedCredentialNeverResolves(t *testing.T) {
	t.Parallel()

	t.Run("known dimension denied", func(t *testing.T) {
		t.Parallel()

		srv := newDecidingAuthServer(t, "led-1")
		probe := &principalProbe{}
		auth := legacyResolvingClient(t, srv.URL, probe)

		app := fiber.New()
		app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

		got := doRequest(t, app, http.MethodGet, txTarget, legacyPartnerToken(nil), "")
		assert.Equal(t, http.StatusForbidden, got.status)

		calls, _, _ := probe.seen()
		assert.Zero(t, calls)

		// Positive control: another ledger is accepted and resolved.
		got = doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-2/transactions/tx-1", legacyPartnerToken(nil), "")
		require.Equal(t, http.StatusOK, got.status, got.body)

		calls, _, found := probe.seen()
		assert.Equal(t, 1, calls)
		assert.True(t, found)
	})

	t.Run("credential finished", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(AuthResponse{Authorized: false, Reason: reasonSuspended})
		}))
		t.Cleanup(srv.Close)

		probe := &principalProbe{}
		auth := legacyResolvingClient(t, srv.URL, probe)

		app := fiber.New()
		app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

		got := doRequest(t, app, http.MethodGet, txTarget, legacyPartnerToken(nil), "")
		assert.Equal(t, http.StatusUnauthorized, got.status)

		calls, _, _ := probe.seen()
		assert.Zero(t, calls)
	})
}

// A token the legacy derivation accepts but that names no identity — a type
// other than application, or no subject — cannot give a resolver a principal.
// It is refused 401 before any resolver runs, rather than handing the resolver
// a context it cannot confine its lookup with.
func TestAuthorize_Resolve_LegacyDerivation_UnidentifiedTokenNeverResolves(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{name: "no type", claims: jwt.MapClaims{"type": nil}},
		{name: "unknown type", claims: jwt.MapClaims{"type": "service"}},
		{name: "no subject", claims: jwt.MapClaims{"sub": nil}},
		{name: "blank subject", claims: jwt.MapClaims{"sub": "  "}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			probe := &principalProbe{}
			auth := legacyResolvingClient(t, srv.URL, probe)

			app := fiber.New()
			app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

			got := doRequest(t, app, http.MethodGet, txTarget, legacyPartnerToken(tt.claims), "")
			assert.Equal(t, http.StatusUnauthorized, got.status, got.body)

			calls, _, _ := probe.seen()
			assert.Zero(t, calls, "no resolver runs without a principal to hand it")

			// Positive control: the same route, the full token, resolves.
			got = doRequest(t, app, http.MethodGet, txTarget, legacyPartnerToken(nil), "")
			require.Equal(t, http.StatusOK, got.status, got.body)

			calls, _, found := probe.seen()
			assert.Equal(t, 1, calls)
			assert.True(t, found)
		})
	}
}

// Outside a resolved route the legacy derivation is untouched: the same
// unidentified partner token on a route that resolves nothing is decided as
// before.
func TestAuthorize_Resolve_LegacyDerivation_UnresolvedRouteUnchanged(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}}
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))

	app := fiber.New()
	app.Get(txRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	got := doRequest(t, app, http.MethodGet, txTarget, legacyPartnerToken(jwt.MapClaims{"type": "service"}), "")
	assert.Equal(t, http.StatusOK, got.status, got.body)
}

// On a route that resolves, a request carrying nothing to resolve is decided in
// one pass, as before: no resolver runs, so no principal is demanded for one.
func TestAuthorize_Resolve_LegacyDerivation_NothingToResolveUnchanged(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	probe := &principalProbe{}

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}}
	require.NoError(t, auth.RegisterScopeResolver("alias", probe.resolve))
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodGet, legsRoute,
		Dim("accountId", FromQuery).At("alias").Resolve("alias").Optional()))

	app := fiber.New()
	app.Get(legsRoute, auth.Authorize("midaz", "transactions", "get"), ok)

	token := legacyPartnerToken(jwt.MapClaims{"type": "service"})

	got := doRequest(t, app, http.MethodGet, legsPath, token, "")
	assert.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, int64(1), srv.hits.Load())

	// Control: the same token naming a value to resolve is refused.
	got = doRequest(t, app, http.MethodGet, legsPath+"?alias=@a", token, "")
	assert.Equal(t, http.StatusUnauthorized, got.status, got.body)

	calls, _, _ := probe.seen()
	assert.Zero(t, calls)
}
