package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LerianStudio/lib-commons/v7/commons/net/http/actor"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The actor's question is the one a partner calling the product directly would
// make: the product it is asked in and the instances the request names. Without
// them the access manager cannot tell which of the partner's rules apply, and a
// partner granted nothing in the product is not checked at all (opt-in) — so an
// actor question with no product is an ALLOW for every partner.

// appToken is a plain application (M2M) credential: the calling service.
func appToken() string {
	return createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"})
}

// relayedRequest sends method target with the caller's bearer and, when
// non-empty, the relayed actor.
func relayedRequest(t *testing.T, app *fiber.App, method, target, bearer, relayed, body string) int {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	if relayed != "" {
		req.Header.Set(actor.HeaderName, relayed)
	}

	resp, err := app.Test(req, capQuestionsTestConfig)
	require.NoError(t, err)

	defer resp.Body.Close()

	return resp.StatusCode
}

// The product is part of the actor's question whatever the M2M product flags
// say: they decide the CALLER's question, and the actor is a partner.
func TestAuthorize_RelayedActorAsksInTheProduct(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name               string
		inversion, forward bool
		sub                string
	}{
		{name: "inversion_off", sub: "admin/midaz-editor-role"},
		{name: "inversion_on_forward_off", inversion: true, sub: "acme/app"},
		{name: "inversion_on_forward_on", inversion: true, forward: true, sub: "acme/app"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{},
				M2MInversionEnabled: tt.inversion, ForwardM2MProduct: tt.forward}

			app := fiber.New()
			app.Get("/x", auth.Authorize("midaz", "accounts", "get"), ok)

			require.Equal(t, http.StatusOK, relayedRequest(t, app, http.MethodGet, "/x", appToken(), actorHeaderValue, ""))
			assert.Equal(t,
				`{"action":"get","actorToken":"partner.bearer.relayed","product":"midaz","resource":"accounts","sub":"`+tt.sub+`"}`,
				rec.lastBody(t))
		})
	}
}

// Without the header nothing moves: the application's question is the one it
// made before actors existed, on a route that declares a scope too, under every
// combination of the M2M product flags. Golden literals.
func TestAuthorize_ApplicationWithoutActorIsByteIdentical(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name               string
		inversion, forward bool
		want               string
	}{
		{name: "inversion_off", want: `{"action":"get","resource":"ledgers","sub":"admin/midaz-editor-role"}`},
		{name: "inversion_on_forward_off", inversion: true, want: `{"action":"get","resource":"ledgers","sub":"acme/app"}`},
		{name: "inversion_on_forward_on", inversion: true, forward: true, want: `{"action":"get","product":"midaz","resource":"ledgers","sub":"acme/app"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{},
				M2MInversionEnabled: tt.inversion, ForwardM2MProduct: tt.forward}
			require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

			app := ownRouteApp(auth.Authorize("midaz", "ledgers", "get"))

			require.Equal(t, http.StatusOK, relayedRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-2", appToken(), "", ""))
			assert.Equal(t, tt.want, rec.lastBody(t))
		})
	}
}

// The actor's question carries the instances the request names, read on the
// route that serves it exactly as for a partner calling directly — wherever the
// handler is mounted. A request on the sibling ledger asks about THAT ledger.
func TestAuthorize_RelayedActorAsksAboutTheRequestedInstances(t *testing.T) {
	t.Parallel()

	for _, name := range mountNames {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			app := mountedApps(scopedClient(t, rec).Authorize("midaz", "ledgers", "get"))[name]

			require.Equal(t, http.StatusOK,
				relayedRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-2", appToken(), actorHeaderValue, ""))
			assert.JSONEq(t,
				`{"action":"get","actorToken":"partner.bearer.relayed","product":"midaz","resource":"ledgers","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-2"}}`,
				rec.lastBody(t))
		})
	}
}

// A request naming several instances makes one actor question per instance,
// as a partner's does, and one of them outside the actor's scope refuses it.
func TestAuthorize_RelayedActorAsksOneQuestionPerInstance(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-2")
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("debits[].organizationId"),
		Dim("ledgerId", FromBody).At("debits[].ledgerId"))

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	inside := `{"debits":[{"organizationId":"org-1","ledgerId":"led-1"}]}`
	require.Equal(t, http.StatusOK, relayedRequest(t, app, http.MethodPost, directPath, appToken(), actorHeaderValue, inside))

	mixed := `{"debits":[{"organizationId":"org-1","ledgerId":"led-1"},{"organizationId":"org-1","ledgerId":"led-2"}]}`
	assert.Equal(t, http.StatusForbidden, relayedRequest(t, app, http.MethodPost, directPath, appToken(), actorHeaderValue, mixed))

	calls := srv.received()
	require.Len(t, calls, 3)

	for _, call := range calls {
		assert.Equal(t, actorHeaderValue, call.body.ActorToken, "every question carries the actor")
	}

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, srv.attributeCalls())
}

// A declared dimension the request does not carry refuses the relayed request
// before any call, as it refuses a partner's; the same request without an actor
// is decided as before.
func TestAuthorize_RelayedActorWithAnUnreadableScopeIsRefused(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/x",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("organizationId", FromHeader).At("X-Organization-Id")),
		),
		ok)

	assert.Equal(t, http.StatusForbidden, relayedRequest(t, app, http.MethodGet, "/x", appToken(), actorHeaderValue, ""))
	assert.Equal(t, int64(0), rec.hits.Load())

	assert.Equal(t, http.StatusOK, relayedRequest(t, app, http.MethodGet, "/x", appToken(), "", ""))
	assert.Equal(t, `{"action":"get","resource":"accounts","sub":"acme/app"}`, rec.lastBody(t))
}

// A user relaying a header is never an actor's relay: its question is unchanged
// and its scope is never read.
func TestAuthorize_UserWithActorHeaderIsUnchanged(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	app := ownRouteApp(scopedClient(t, rec).Authorize("midaz", "ledgers", "get"))

	require.Equal(t, http.StatusOK, relayedRequest(t, app, http.MethodGet, ledgerPath, userToken(), actorHeaderValue, ""))
	assert.Equal(t, `{"action":"get","product":"midaz","resource":"ledgers","sub":"acme-org/user-1"}`, rec.lastBody(t))
}
