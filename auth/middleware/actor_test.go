package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/LerianStudio/lib-commons/v7/commons/net/http/actor"
	observability "github.com/LerianStudio/lib-observability/v4"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// actorHeaderValue stands in for the partner bearer a calling service relays.
const actorHeaderValue = "partner.bearer.relayed"

// actorObserver records what the handler behind Authorize found on its context.
type actorObserver struct {
	mu      sync.Mutex
	reached bool
	token   string
	present bool
}

func (o *actorObserver) get() (reached bool, token string, present bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.reached, o.token, o.present
}

// newActorApp mounts Authorize on GET /x with a handler that records the actor
// token the request context carries.
func newActorApp(auth *AuthClient) (*fiber.App, *actorObserver) {
	observer := &actorObserver{}

	app := fiber.New()
	app.Get("/x", auth.Authorize("midaz", "accounts", "get"), func(c fiber.Ctx) error {
		token, present := actor.TokenFromContext(c.Context())

		observer.mu.Lock()
		observer.reached, observer.token, observer.present = true, token, present
		observer.mu.Unlock()

		return c.SendString("reached handler")
	})

	return app, observer
}

// actorRequest drives GET /x with the caller's bearer and, when non-empty, an
// X-Lerian-Actor header.
func actorRequest(t *testing.T, app *fiber.App, bearer, actorToken string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)

	if actorToken != "" {
		req.Header.Set(actor.HeaderName, actorToken)
	}

	resp, err := app.Test(req)
	require.NoError(t, err)

	return resp
}

func actorAuthClient(url string) *AuthClient {
	return &AuthClient{Address: url, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
}

// Inbound: a partner credential that is authorized leaves its own bearer on the
// request context, so the service's outbound clients can relay it. Every other
// credential leaves nothing there.
func TestAuthorize_PublishesTheActorOnlyForAPartnerCredential(t *testing.T) {
	t.Parallel()

	partner := partnerToken("acme/p1")

	tests := []struct {
		name      string
		bearer    string
		wantActor bool
	}{
		{name: "partner", bearer: partner, wantActor: true},
		{name: "application", bearer: createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"})},
		{name: "normal_user", bearer: createTestJWT(jwt.MapClaims{"type": "normal-user", "owner": "acme", "sub": "u1"})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			app, observer := newActorApp(actorAuthClient(rec.URL))

			resp := actorRequest(t, app, tt.bearer, "")
			require.Equal(t, http.StatusOK, resp.StatusCode)

			reached, token, present := observer.get()
			require.True(t, reached)
			assert.Equal(t, tt.wantActor, present)

			if tt.wantActor {
				assert.Equal(t, tt.bearer, token, "the actor is the partner's raw bearer, verbatim")
			} else {
				assert.Empty(t, token)
			}
		})
	}
}

// A partner that relays someone else's actor header is still published as
// itself: the header never becomes the actor of a partner request.
func TestAuthorize_PartnerActorIsItsOwnBearerNotTheHeader(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	app, observer := newActorApp(actorAuthClient(rec.URL))

	partner := partnerToken("acme/p1")

	resp := actorRequest(t, app, partner, actorHeaderValue)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, token, present := observer.get()
	require.True(t, present)
	assert.Equal(t, partner, token)
}

// Decision: the relayed actor reaches the access manager only when the caller
// is a plain application (M2M) credential. A partner or a user caller sends the
// same bytes as without the header.
func TestAuthorize_ForwardsTheActorOnlyForAnApplicationCaller(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims jwt.MapClaims
		header string
		want   string
	}{
		{
			name:   "application_with_actor",
			claims: jwt.MapClaims{"type": "application", "sub": "acme/app"},
			header: actorHeaderValue,
			want:   `{"action":"get","actorToken":"partner.bearer.relayed","product":"midaz","resource":"accounts","sub":"acme/app"}`,
		},
		{
			name:   "application_without_actor",
			claims: jwt.MapClaims{"type": "application", "sub": "acme/app"},
			want:   `{"action":"get","resource":"accounts","sub":"acme/app"}`,
		},
		{
			name:   "application_with_blank_actor",
			claims: jwt.MapClaims{"type": "application", "sub": "acme/app"},
			header: "   ",
			want:   `{"action":"get","resource":"accounts","sub":"acme/app"}`,
		},
		{
			name:   "partner_ignores_actor",
			claims: jwt.MapClaims{"type": "application", "sub": "acme/app", "partner": "acme/p1"},
			header: actorHeaderValue,
			want:   `{"action":"get","product":"midaz","resource":"accounts","sub":"acme/app"}`,
		},
		{
			name:   "normal_user_ignores_actor",
			claims: jwt.MapClaims{"type": "normal-user", "owner": "acme", "sub": "u1"},
			header: actorHeaderValue,
			want:   `{"action":"get","product":"midaz","resource":"accounts","sub":"acme/u1"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			app, _ := newActorApp(actorAuthClient(rec.URL))

			resp := actorRequest(t, app, createTestJWT(tt.claims), tt.header)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			calls := rec.received()
			require.Len(t, calls, 1)
			assert.Equal(t, tt.want, calls[0].raw)
		})
	}
}

// The decision depends on the actor, so the cache must never answer one actor's
// request from another's entry, nor an actor-less request from an actor's.
func TestAuthorize_ActorIsPartOfTheDecisionCacheKey(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

	auth := actorAuthClient(rec.URL)
	auth.cache = newDecisionCache(time.Minute)

	app, _ := newActorApp(auth)
	bearer := createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"})

	for _, header := range []string{"", "actor-a", "actor-b", "actor-a", ""} {
		resp := actorRequest(t, app, bearer, header)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	calls := rec.received()
	require.Len(t, calls, 3, "one call per distinct actor; the repeats are served from the cache")
	assert.Empty(t, calls[0].body.ActorToken)
	assert.Equal(t, "actor-a", calls[1].body.ActorToken)
	assert.Equal(t, "actor-b", calls[2].body.ActorToken)
}

// A denial caused by the partner the request was relayed for is a 403 that
// names the partner as the cause, never the bare 403 of the caller's own
// permission, and never the 401 that would tell the calling service to re-issue
// its own perfectly good credential. Permission and scope are not told apart.
func TestAuthorize_ActorDenialNamesThePartner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		reason  string
		code    string
		title   string
		message string
	}{
		{
			reason:  "actor_tenant",
			code:    "AUT-1016",
			title:   "Partner Of Another Tenant",
			message: "the partner this request was made on behalf of belongs to another tenant",
		},
		{
			reason:  "actor_suspended",
			code:    "AUT-1017",
			title:   "Partner Suspended",
			message: "the partner this request was made on behalf of is suspended",
		},
		{
			reason:  "actor_expired",
			code:    "AUT-1018",
			title:   "Partner Credential No Longer Valid",
			message: "the partner this request was made on behalf of is outside its validity period or its credential is no longer valid",
		},
		{
			reason:  "actor_invalid",
			code:    "AUT-1018",
			title:   "Partner Credential No Longer Valid",
			message: "the partner this request was made on behalf of is outside its validity period or its credential is no longer valid",
		},
		{
			reason:  "actor_permission",
			code:    "AUT-1019",
			title:   "Partner Not Allowed",
			message: "the partner this request was made on behalf of is not allowed to perform it",
		},
		{
			reason:  "actor_scope",
			code:    "AUT-1019",
			title:   "Partner Not Allowed",
			message: "the partner this request was made on behalf of is not allowed to perform it",
		},
		{
			reason:  "actor_reason_from_a_newer_service",
			code:    "AUT-1019",
			title:   "Partner Not Allowed",
			message: "the partner this request was made on behalf of is not allowed to perform it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: tt.reason})
			app, capture := newCapturingApp(actorAuthClient(rec.URL))

			resp := gatedRequest(t, app, createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"}))
			assert.Equal(t, http.StatusTeapot, resp.StatusCode)

			err := capture.get()
			requireFiberError(t, err, http.StatusForbidden, tt.message)

			var commonsErr commons.Response

			require.True(t, errors.As(err, &commonsErr), "the refusal must carry a code a consumer can read")
			assert.Equal(t, tt.code, commonsErr.Code)
			assert.Equal(t, tt.title, commonsErr.Title)
			assert.Equal(t, tt.message, commonsErr.Message)
		})
	}
}

// The actor is a bearer credential: it reaches the wire body, never a span.
func TestAuthorize_DoesNotTraceTheActor(t *testing.T) {
	t.Parallel()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := actorAuthClient(rec.URL)

	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.SetContext(observability.ContextWithTracer(c.Context(), tp.Tracer("test")))

		return c.Next()
	})
	app.Get("/x", auth.Authorize("midaz", "accounts", "get"), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	resp := actorRequest(t, app, createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"}), actorHeaderValue)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	calls := rec.received()
	require.Len(t, calls, 1)
	assert.Equal(t, actorHeaderValue, calls[0].body.ActorToken, "positive control: the wire body carries it")

	spans := exporter.GetSpans()
	require.NotEmpty(t, spans)

	for _, s := range spans {
		for _, attr := range s.Attributes {
			assert.NotContains(t, string(attr.Key), "actor", "span %q exposes an actor attribute", s.Name)
			assert.NotContains(t, attr.Value.AsString(), actorHeaderValue, "span %q leaks the actor in %q", s.Name, attr.Key)
		}
	}
}

// Relay: an application caller relaying a partner whose request the access
// manager authorized leaves that relayed actor on the request context, so the
// next hop's outbound clients relay it again. A partner caller is published as
// itself, a user caller relays nothing, and a blank header is no actor.
func TestAuthorize_RepublishesTheRelayedActorOfAnAuthorizedApplicationCaller(t *testing.T) {
	t.Parallel()

	partner := partnerToken("acme/p1")
	application := createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"})

	tests := []struct {
		name        string
		bearer      string
		header      string
		wantPresent bool
		wantToken   string
	}{
		{name: "application_with_actor", bearer: application, header: actorHeaderValue, wantPresent: true, wantToken: actorHeaderValue},
		{name: "application_without_actor", bearer: application},
		{name: "application_with_blank_actor", bearer: application, header: "   "},
		{name: "partner_is_its_own_actor", bearer: partner, header: actorHeaderValue, wantPresent: true, wantToken: partner},
		{
			name:   "normal_user_relays_nothing",
			bearer: createTestJWT(jwt.MapClaims{"type": "normal-user", "owner": "acme", "sub": "u1"}),
			header: actorHeaderValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			app, observer := newActorApp(actorAuthClient(rec.URL))

			resp := actorRequest(t, app, tt.bearer, tt.header)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			reached, token, present := observer.get()
			require.True(t, reached)
			assert.Equal(t, tt.wantPresent, present)
			assert.Equal(t, tt.wantToken, token)
		})
	}
}

// A refused request publishes no actor: the context the error handler sees
// carries none, whether the caller or the actor caused the refusal.
func TestAuthorize_RefusedRequestPublishesNoActor(t *testing.T) {
	t.Parallel()

	for _, reason := range []string{"", "actor_permission"} {
		t.Run("reason_"+reason, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: reason})
			auth := actorAuthClient(rec.URL)

			var (
				mu      sync.Mutex
				handled bool
				present bool
			)

			app := fiber.New(fiber.Config{
				ErrorHandler: func(c fiber.Ctx, _ error) error {
					_, ok := actor.TokenFromContext(c.Context())

					mu.Lock()
					handled, present = true, ok
					mu.Unlock()

					return c.SendStatus(http.StatusTeapot)
				},
			})
			app.Get("/x", auth.Authorize("midaz", "accounts", "get"), func(c fiber.Ctx) error {
				return c.SendString("reached handler")
			})

			resp := actorRequest(t, app, createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"}), actorHeaderValue)
			require.Equal(t, http.StatusTeapot, resp.StatusCode)

			calls := rec.received()
			require.Len(t, calls, 1)
			assert.Equal(t, actorHeaderValue, calls[0].body.ActorToken, "positive control: the actor was part of the refused question")

			mu.Lock()
			defer mu.Unlock()

			require.True(t, handled)
			assert.False(t, present)
		})
	}
}

// With authorization disabled no decision is made, so a relayed header is
// never vouched for and never republished.
func TestAuthorize_DisabledAuthPublishesNoRelayedActor(t *testing.T) {
	t.Parallel()

	app, observer := newActorApp(&AuthClient{Enabled: false, Logger: &testLogger{}})

	resp := actorRequest(t, app, createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"}), actorHeaderValue)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	reached, token, present := observer.get()
	require.True(t, reached)
	assert.False(t, present)
	assert.Empty(t, token)
}
