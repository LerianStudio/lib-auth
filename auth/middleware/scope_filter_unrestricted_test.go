package middleware

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

// ---------------------------------------------------------------------------
// A grant that says the partner is unrestricted on the product (unrestricted)
// ---------------------------------------------------------------------------

// A filter route whose request names no dimension is served unconfined only
// when the grant says so explicitly: "unrestricted": true, for a partner with
// no scope on the product. Allowed values, when the grant carries them too,
// win: they are the narrower answer. Without either, it is refused as before.
func TestAuthorize_Filter_UnrestrictedGrant(t *testing.T) {
	t.Parallel()

	type read struct {
		values  []string
		present bool
	}

	for name, tc := range map[string]struct {
		answer       string
		status       int
		organization read
		account      read
	}{
		"unrestricted": {answer: `{"authorized":true,"unrestricted":true}`, status: http.StatusOK},
		"unrestricted_with_empty_allowed": {
			answer: `{"authorized":true,"unrestricted":true,"allowed":{}}`, status: http.StatusOK,
		},
		"allowed_wins_over_unrestricted": {
			answer: `{"authorized":true,"unrestricted":true,"allowed":{"accountId":["acc-1"]}}`, status: http.StatusOK,
			account: read{values: []string{"acc-1"}, present: true},
		},
		"allowed_none_wins_over_unrestricted": {
			answer: `{"authorized":true,"unrestricted":true,"allowed":{"organizationId":[]}}`, status: http.StatusOK,
			organization: read{values: []string{}, present: true},
		},
		"unrestricted_false":       {answer: `{"authorized":true,"unrestricted":false}`, status: http.StatusForbidden},
		"no_flag_no_allowed":       {answer: `{"authorized":true}`, status: http.StatusForbidden},
		"denial_with_unrestricted": {answer: `{"authorized":false,"unrestricted":true}`, status: http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScriptedAuthServer(t, func(authorizeRequestBody) string { return tc.answer })
			auth := filteringClient(t, srv.URL, http.MethodGet, orgsRoute, "organizationId", "accountId")

			probe := &allowedProbe{}
			app := fiber.New()
			app.Get(orgsRoute, auth.Authorize("midaz", "organizations", "get"), probe.handle)

			got := doRequest(t, app, http.MethodGet, orgsRoute, partnerToken("acme/p1"), "")
			require.Equal(t, tc.status, got.status, got.body)

			require.Len(t, srv.requests(), 1)
			assert.JSONEq(t,
				`{"action":"get","product":"midaz","resource":"organizations","sub":"acme/app","filter":["organizationId","accountId"]}`,
				srv.requests()[0], "the request carries nothing new")

			if tc.status != http.StatusOK {
				assert.Zero(t, probe.calls, "a refused request never reaches the handler")

				return
			}

			require.True(t, probe.present, "the request scope is recorded")

			organizations, ok := probe.allowed("organizationId")
			assert.Equal(t, tc.organization.present, ok, "organizationId presence")
			assert.Equal(t, tc.organization.values, organizations)

			accounts, ok := probe.allowed("accountId")
			assert.Equal(t, tc.account.present, ok, "accountId presence")
			assert.Equal(t, tc.account.values, accounts)
		})
	}
}

// The flag is cached with the decision: a cached grant replayed without it
// would refuse the partner for the rest of the TTL.
func TestAuthorize_Filter_UnrestrictedGrantIsCached(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string { return `{"authorized":true,"unrestricted":true}` })

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true, cache: newDecisionCache(time.Minute)}
	require.NoError(t, auth.SetManifestScope("midaz", filterCatalog()...))
	require.NoError(t, auth.SetManifestRouteFilter("midaz", http.MethodGet, orgsRoute, "organizationId"))

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(orgsRoute, auth.Authorize("midaz", "organizations", "get"), probe.handle)

	for range 2 {
		require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, orgsRoute, partnerToken("acme/p1"), "").status)

		_, ok := probe.allowed("organizationId")
		assert.False(t, ok, "unrestricted")
	}

	assert.Len(t, srv.requests(), 1, "the second request is served from the cache")
}

// The flag means nothing outside a partner's filtered request naming no
// dimension: a route without a filter still refuses a partner request naming
// none, before any call.
func TestAuthorize_Filter_UnrestrictedIgnoredWithoutAFilter(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string { return `{"authorized":true,"unrestricted":true}` })
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(orgsRoute, auth.Authorize("midaz", "organizations", "get"), probe.handle)

	assert.Equal(t, http.StatusForbidden, doRequest(t, app, http.MethodGet, orgsRoute, partnerToken("acme/p1"), "").status)
	assert.Empty(t, srv.requests())
	assert.Zero(t, probe.calls)
}

// A caller that is not partner-bound is never filtered: the flag adds no
// request scope.
func TestAuthorize_Filter_UnrestrictedIgnoredForNonPartners(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string { return `{"authorized":true,"unrestricted":true}` })
	auth := filteringClient(t, srv.URL, http.MethodGet, orgsRoute, "organizationId")

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(orgsRoute, auth.Authorize("midaz", "organizations", "get"), probe.handle)

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, orgsRoute, userToken(), "").status)
	assert.False(t, probe.present, "no request scope for a caller that is not partner-bound")
	require.Len(t, srv.requests(), 1)
	assert.NotContains(t, srv.requests()[0], `"filter"`)
}

// The flag is read only on a grant: a denial carrying it is not unrestricted.
func TestClassifyResponse_UnrestrictedOnlyOnAGrant(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}
	span := trace.SpanFromContext(context.Background())

	for body, want := range map[string]bool{
		`{"authorized":true,"unrestricted":true}`:  true,
		`{"authorized":true}`:                      false,
		`{"authorized":true,"unrestricted":false}`: false,
		`{"authorized":false,"unrestricted":true}`: false,
	} {
		got := auth.classifyResponse(context.Background(), span, http.StatusOK, []byte(body))
		require.NoError(t, got.authErr, body)
		assert.Equal(t, want, got.unrestricted, body)
	}
}
