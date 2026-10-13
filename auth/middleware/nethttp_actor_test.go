package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LerianStudio/lib-commons/v7/commons/net/http/actor"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveActorHTTP drives GET /x through AuthorizeHTTP with the caller's bearer
// and, when non-empty, an X-Lerian-Actor header. It returns the recorder and the
// actor the protected handler found on its context.
func serveActorHTTP(t *testing.T, auth *AuthClient, bearer, actorToken string) (rec *httptest.ResponseRecorder, token string, present bool) {
	t.Helper()

	h := auth.AuthorizeHTTP("midaz", "accounts", "get")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, present = actor.TokenFromContext(r.Context())

		w.WriteHeader(http.StatusOK)
	}))

	rec = serveGated(t, "GET /x", h, func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)

		if actorToken != "" {
			req.Header.Set(actor.HeaderName, actorToken)
		}

		return req
	})

	return rec, token, present
}

// AuthorizeHTTP relays the actor exactly as Authorize does: forwarded to the
// access manager only for a plain application caller, and published on the
// context for a partner (its own bearer) or a relaying application (the actor).
func TestAuthorizeHTTP_RelaysTheActorAsAuthorizeDoes(t *testing.T) {
	t.Parallel()

	partner := partnerToken("acme/p1")
	app := createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"})
	user := createTestJWT(jwt.MapClaims{"type": "normal-user", "owner": "acme", "sub": "u1"})

	tests := []struct {
		name      string
		bearer    string
		header    string
		wire      string
		wantActor string
	}{
		{
			name:      "application_with_actor",
			bearer:    app,
			header:    actorHeaderValue,
			wire:      `{"action":"get","actorToken":"partner.bearer.relayed","product":"midaz","resource":"accounts","sub":"acme/app"}`,
			wantActor: actorHeaderValue,
		},
		{
			name:   "application_without_actor",
			bearer: app,
			wire:   `{"action":"get","resource":"accounts","sub":"acme/app"}`,
		},
		{
			name:      "partner_is_its_own_actor",
			bearer:    partner,
			header:    actorHeaderValue,
			wire:      `{"action":"get","product":"midaz","resource":"accounts","sub":"acme/app"}`,
			wantActor: partner,
		},
		{
			name:   "normal_user_ignores_actor",
			bearer: user,
			header: actorHeaderValue,
			wire:   `{"action":"get","product":"midaz","resource":"accounts","sub":"acme/u1"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := newRecordingAuthServer(t, AuthResponse{Authorized: true})

			rec, token, present := serveActorHTTP(t, actorAuthClient(server.URL), tt.bearer, tt.header)
			require.Equal(t, http.StatusOK, rec.Code)

			calls := server.received()
			require.Len(t, calls, 1)
			assert.Equal(t, tt.wire, calls[0].raw)

			assert.Equal(t, tt.wantActor != "", present)
			assert.Equal(t, tt.wantActor, token)
		})
	}
}

// A denial the relayed actor caused is the same 403 naming the partner on the
// net/http path, carried on the RefusalError for the service's envelope.
func TestAuthorizeHTTP_ActorDenialNamesThePartner(t *testing.T) {
	t.Parallel()

	server := newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: "actor_suspended"})

	var refusal *RefusalError

	auth := actorAuthClient(server.URL).WithHTTPErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		require.True(t, errors.As(err, &refusal))
		w.WriteHeader(refusal.Status)
	})

	rec, _, present := serveActorHTTP(t, auth, createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"}), actorHeaderValue)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, present, "a refused request publishes no actor")

	require.NotNil(t, refusal)
	require.NotNil(t, refusal.Response)
	assert.Equal(t, "AUT-1017", refusal.Response.Code)
	assert.Equal(t, "the partner this request was made on behalf of is suspended", refusal.Message)
}
