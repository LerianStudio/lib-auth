package middleware

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Allowed values for list filtering (filter)
// ---------------------------------------------------------------------------

const (
	accountsRoute  = "/v1/organizations/:organization_id/ledgers/:ledger_id/accounts"
	accountsTarget = "/v1/organizations/org-1/ledgers/led-1/accounts"
	orgsRoute      = "/v1/organizations"
)

// allowAccounts allows every question and, when the request asks to filter
// on accountId, answers with the allowed accounts.
func allowAccounts(accounts string) func(authorizeRequestBody) string {
	return func(body authorizeRequestBody) string {
		for _, f := range body.Filter {
			if f == "accountId" {
				return `{"authorized":true,"allowed":{"accountId":` + accounts + `}}`
			}
		}

		return `{"authorized":true}`
	}
}

// allowedProbe records what the handler reads from the request scope.
type allowedProbe struct {
	mu      sync.Mutex
	calls   int
	present bool
	scope   RequestScope
}

func (p *allowedProbe) handle(c fiber.Ctx) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls++
	p.scope, p.present = ScopeFromContext(c.Context())

	return c.SendString("ok")
}

func (p *allowedProbe) allowed(dimension string) ([]string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.scope.Allowed(dimension)
}

func filterCatalog() []Dimension {
	return append(manifestDims(),
		Dim("accountId", FromQuery).At("accountId"),
	)
}

// filteringClient wires the catalog and marks the route as filtering on dims.
func filteringClient(t *testing.T, url, method, path string, dims ...string) *AuthClient {
	t.Helper()

	auth := &AuthClient{Address: url, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", filterCatalog()...))
	require.NoError(t, auth.SetManifestRouteFilter("midaz", method, path, dims...))

	return auth
}

// On a filter route, a partner request that leaves the filtered dimension out
// asks the service to answer with the values it may see, and the handler
// reads them.
func TestAuthorize_Filter_AbsentDimensionAsksForAllowedValues(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, allowAccounts(`["acc-1","acc-2"]`))
	auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

	got := doRequest(t, app, http.MethodGet, accountsTarget, partnerToken("acme/p1"), "")
	require.Equal(t, http.StatusOK, got.status, got.body)

	require.Len(t, srv.requests(), 1)
	assert.JSONEq(t,
		`{"action":"get","product":"midaz","resource":"accounts","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1"},"filter":["accountId"]}`,
		srv.requests()[0])

	values, ok := probe.allowed("accountId")
	assert.True(t, ok)
	assert.Equal(t, []string{"acc-1", "acc-2"}, values)

	_, ok = probe.allowed("ledgerId")
	assert.False(t, ok, "no values were returned for ledgerId")
}

// A service that allows without allowed values does not confine the
// dimension: the handler reads none.
func TestAuthorize_Filter_NoAllowedValuesMeansNoConfinement(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string { return `{"authorized":true}` })
	auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, accountsTarget, partnerToken("acme/p1"), "").status)

	_, ok := probe.allowed("accountId")
	assert.False(t, ok)
}

// A service that does not know the field denies as before.
func TestAuthorize_Filter_DenialStaysADenial(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string {
		return `{"authorized":false,"allowed":{"accountId":["acc-1"]}}`
	})
	auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

	assert.Equal(t, http.StatusForbidden, doRequest(t, app, http.MethodGet, accountsTarget, partnerToken("acme/p1"), "").status)
	assert.Equal(t, 0, probe.calls)
}

// A dimension the request names is not filtered: it is asked, not listed.
func TestAuthorize_Filter_PresentDimensionIsAskedNotFiltered(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, allowAccounts(`["acc-9"]`))
	auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, accountsTarget+"?accountId=acc-1", partnerToken("acme/p1"), "").status)

	assert.JSONEq(t,
		`{"action":"get","product":"midaz","resource":"accounts","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1","accountId":"acc-1"}}`,
		srv.requests()[0])

	_, ok := probe.allowed("accountId")
	assert.False(t, ok)
}

// Values for a dimension the request did not ask to filter are ignored.
func TestAuthorize_Filter_IgnoresValuesNotAskedFor(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string {
		return `{"authorized":true,"allowed":{"accountId":["acc-1"],"ledgerId":["led-9"]}}`
	})
	auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, accountsTarget, partnerToken("acme/p1"), "").status)

	values, ok := probe.allowed("accountId")
	assert.True(t, ok)
	assert.Equal(t, []string{"acc-1"}, values)

	_, ok = probe.allowed("ledgerId")
	assert.False(t, ok)
}

// An empty list, or null, is "nothing is allowed", never "no confinement".
func TestAuthorize_Filter_EmptyAllowedMeansNothing(t *testing.T) {
	t.Parallel()

	for name, accounts := range map[string]string{"empty": `[]`, "null": `null`} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScriptedAuthServer(t, allowAccounts(accounts))
			auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

			probe := &allowedProbe{}
			app := fiber.New()
			app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

			require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, accountsTarget, partnerToken("acme/p1"), "").status)

			values, ok := probe.allowed("accountId")
			assert.True(t, ok)
			assert.NotNil(t, values)
			assert.Empty(t, values)
		})
	}
}

// A denial is a denial, whatever allowed member it carries: it is not read.
func TestAuthorize_Filter_DenialIgnoresAllowed(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string {
		return `{"authorized":false,"allowed":{"accountId":[""]}}`
	})
	auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), ok)

	assert.Equal(t, http.StatusForbidden, doRequest(t, app, http.MethodGet, accountsTarget, partnerToken("acme/p1"), "").status)
}

// The handler gets its own copy: changing it changes nothing for the next read.
func TestAuthorize_Filter_AllowedIsACopy(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, allowAccounts(`["acc-1","acc-2"]`))
	auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, accountsTarget, partnerToken("acme/p1"), "").status)

	first, ok := probe.allowed("accountId")
	require.True(t, ok)

	first[0] = "acc-x"

	again, _ := probe.allowed("accountId")
	assert.Equal(t, []string{"acc-1", "acc-2"}, again)
}

// A malformed allowed member is the service failing to answer.
func TestAuthorize_Filter_MalformedAllowedIsUnavailable(t *testing.T) {
	t.Parallel()

	for name, accounts := range map[string]string{
		"empty_value": `["acc-1",""]`,
		"not_strings": `[1]`,
		"not_array":   `"acc-1"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScriptedAuthServer(t, allowAccounts(accounts))
			auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

			probe := &allowedProbe{}
			app := fiber.New()
			app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)

			assert.Equal(t, http.StatusServiceUnavailable, doRequest(t, app, http.MethodGet, accountsTarget, partnerToken("acme/p1"), "").status)
			assert.Equal(t, 0, probe.calls)
		})
	}
}

// A route that does not filter, and a caller that is not partner-bound, send
// the same bytes as before and read no allowed values.
func TestAuthorize_Filter_OnlyPartnersOnFilterRoutes(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string {
		return `{"authorized":true,"allowed":{"accountId":["acc-1"]}}`
	})

	auth := filteringClient(t, srv.URL, http.MethodGet, accountsRoute, "accountId")

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/balances", auth.Authorize("midaz", "balances", "get"), probe.handle)

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, accountsTarget, userToken(), "").status)
	assert.False(t, probe.present, "a caller that is not partner-bound has no scope")

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/balances", partnerToken("acme/p1"), "").status)

	_, ok := probe.allowed("accountId")
	assert.False(t, ok, "a route that does not filter reads no allowed values")

	requests := srv.requests()
	require.Len(t, requests, 2)
	assert.NotContains(t, requests[0], "filter")
	assert.NotContains(t, requests[1], "filter")
}

// A filter route whose request names no dimension at all is asked instead of
// refused, and must come back with allowed values for its filtered dimension:
// without them nothing confines the list.
func TestAuthorize_Filter_NoDimensionNeedsAllowedValues(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		answer string
		status int
	}{
		"with_values":    {answer: `{"authorized":true,"allowed":{"organizationId":["org-1"]}}`, status: http.StatusOK},
		"without_values": {answer: `{"authorized":true}`, status: http.StatusForbidden},
		"other_values":   {answer: `{"authorized":true,"allowed":{"accountId":["acc-1"]}}`, status: http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScriptedAuthServer(t, func(authorizeRequestBody) string { return tc.answer })
			auth := filteringClient(t, srv.URL, http.MethodGet, orgsRoute, "organizationId")

			probe := &allowedProbe{}
			app := fiber.New()
			app.Get(orgsRoute, auth.Authorize("midaz", "organizations", "get"), probe.handle)

			got := doRequest(t, app, http.MethodGet, orgsRoute, partnerToken("acme/p1"), "")
			assert.Equal(t, tc.status, got.status)

			require.Len(t, srv.requests(), 1)
			assert.JSONEq(t,
				`{"action":"get","product":"midaz","resource":"organizations","sub":"acme/app","filter":["organizationId"]}`,
				srv.requests()[0])

			if tc.status == http.StatusOK {
				values, ok := probe.allowed("organizationId")
				assert.True(t, ok)
				assert.Equal(t, []string{"org-1"}, values)
			}
		})
	}
}

// Positive control for the test above: the same route without the filter is
// refused before any call, as every route that names no dimension is.
func TestAuthorize_Filter_WithoutFilterNoDimensionIsRefused(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(authorizeRequestBody) string { return `{"authorized":true}` })
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	app := fiber.New()
	app.Get(orgsRoute, auth.Authorize("midaz", "organizations", "get"), ok)

	assert.Equal(t, http.StatusForbidden, doRequest(t, app, http.MethodGet, orgsRoute, partnerToken("acme/p1"), "").status)
	assert.Empty(t, srv.requests())
}

// A filter route over several dimensions whose request names none of them is
// served when the answer confines AT LEAST ONE: the service answers only for
// the dimensions the partner is scoped on, and a dimension it leaves out is not
// restricted. An answer with no allowed values at all, or only for dimensions
// the request did not ask to filter, still confines nothing and is refused.
func TestAuthorize_Filter_NoDimensionNeedsAllowedValuesForOneDimension(t *testing.T) {
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
		"one_dimension": {
			answer: `{"authorized":true,"allowed":{"accountId":["acc-1","acc-2"]}}`, status: http.StatusOK,
			account: read{values: []string{"acc-1", "acc-2"}, present: true},
		},
		"other_dimension": {
			answer: `{"authorized":true,"allowed":{"organizationId":["org-1"]}}`, status: http.StatusOK,
			organization: read{values: []string{"org-1"}, present: true},
		},
		"both_dimensions": {
			answer: `{"authorized":true,"allowed":{"organizationId":["org-1"],"accountId":["acc-1"]}}`, status: http.StatusOK,
			organization: read{values: []string{"org-1"}, present: true},
			account:      read{values: []string{"acc-1"}, present: true},
		},
		"empty_list_sees_nothing": {
			answer: `{"authorized":true,"allowed":{"accountId":[]}}`, status: http.StatusOK,
			account: read{values: []string{}, present: true},
		},
		"null_sees_nothing": {
			answer: `{"authorized":true,"allowed":{"accountId":null}}`, status: http.StatusOK,
			account: read{values: []string{}, present: true},
		},
		"no_allowed":              {answer: `{"authorized":true}`, status: http.StatusForbidden},
		"empty_allowed":           {answer: `{"authorized":true,"allowed":{}}`, status: http.StatusForbidden},
		"only_unfiltered_allowed": {answer: `{"authorized":true,"allowed":{"ledgerId":["led-1"]}}`, status: http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScriptedAuthServer(t, func(authorizeRequestBody) string { return tc.answer })
			auth := filteringClient(t, srv.URL, http.MethodGet, orgsRoute, "organizationId", "accountId")

			probe := &allowedProbe{}
			app := fiber.New()
			app.Get(orgsRoute, auth.Authorize("midaz", "organizations", "get"), probe.handle)

			got := doRequest(t, app, http.MethodGet, orgsRoute, partnerToken("acme/p1"), "")
			require.Equal(t, tc.status, got.status)

			require.Len(t, srv.requests(), 1)
			assert.JSONEq(t,
				`{"action":"get","product":"midaz","resource":"organizations","sub":"acme/app","filter":["organizationId","accountId"]}`,
				srv.requests()[0])

			if tc.status != http.StatusOK {
				assert.Zero(t, probe.calls, "a refused request never reaches the handler")

				return
			}

			organizations, ok := probe.allowed("organizationId")
			assert.Equal(t, tc.organization.present, ok, "organizationId presence")
			assert.Equal(t, tc.organization.values, organizations)

			accounts, ok := probe.allowed("accountId")
			assert.Equal(t, tc.account.present, ok, "accountId presence")
			assert.Equal(t, tc.account.values, accounts)
		})
	}
}

// Several questions: the handler reads every value any of them returned.
func TestAuthorize_Filter_SeveralQuestionsAreUnited(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(body authorizeRequestBody) string {
		return `{"authorized":true,"allowed":{"accountId":["acc-` + body.Attributes["ledgerId"] + `"]}}`
	})

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz",
		Dim("organizationId", FromPath).At("organization_id"),
		Dim("ledgerId", FromQuery).At("ledgerId"),
		Dim("accountId", FromQuery).At("accountId")))
	require.NoError(t, auth.SetManifestRouteFilter("midaz", http.MethodGet, "/v1/organizations/:organization_id/accounts", "accountId"))

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/accounts", auth.Authorize("midaz", "accounts", "get"), probe.handle)

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/accounts?ledgerId=l1,l2", partnerToken("acme/p1"), "").status)

	values, ok := probe.allowed("accountId")
	assert.True(t, ok)
	assert.Equal(t, []string{"acc-l1", "acc-l2"}, values)
}

// The decision cache keeps the allowed values with the decision, and keys a
// filtered question apart from the same question unfiltered.
func TestAuthorize_Filter_CacheKeepsAllowedValuesAndKeysOnTheFilter(t *testing.T) {
	t.Parallel()

	srv := newScriptedAuthServer(t, func(body authorizeRequestBody) string {
		if len(body.Filter) == 0 {
			return `{"authorized":false}`
		}

		return `{"authorized":true,"allowed":{"accountId":["acc-1"]}}`
	})

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true, cache: newDecisionCache(time.Minute)}
	require.NoError(t, auth.SetManifestScope("midaz", filterCatalog()...))
	require.NoError(t, auth.SetManifestRouteFilter("midaz", http.MethodGet, accountsRoute, "accountId"))

	probe := &allowedProbe{}
	app := fiber.New()
	app.Get(accountsRoute, auth.Authorize("midaz", "accounts", "get"), probe.handle)
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts/unfiltered", auth.Authorize("midaz", "accounts", "get"), probe.handle)

	token := partnerToken("acme/p1")

	assert.Equal(t, http.StatusForbidden,
		doRequest(t, app, http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts/unfiltered", token, "").status)

	for range 2 {
		require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, accountsTarget, token, "").status)

		values, ok := probe.allowed("accountId")
		assert.True(t, ok)
		assert.Equal(t, []string{"acc-1"}, values)
	}

	assert.Len(t, srv.requests(), 2, "the second filtered request is served from the cache")
}

func TestFilter_Declaration(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}
	require.NoError(t, auth.SetManifestScope("midaz", filterCatalog()...))

	require.Error(t, auth.SetManifestRouteFilter("midaz", http.MethodGet, accountsRoute), "a filter names a dimension")
	require.Error(t, auth.SetManifestRouteFilter("midaz", http.MethodGet, accountsRoute, "portfolioId"), "a catalog dimension")
	require.Error(t, auth.SetManifestRouteFilter("midaz", http.MethodGet, accountsRoute, "accountId", "accountId"), "once")
	require.Error(t, auth.SetManifestRouteFilter("other", http.MethodGet, accountsRoute, "accountId"), "a product with a catalog")
	require.NoError(t, auth.SetManifestRouteFilter("midaz", http.MethodGet, accountsRoute, "accountId"))

	// An explicit declaration filters with Filter, and is held to the same rules.
	srv := newScriptedAuthServer(t, allowAccounts(`["acc-1"]`))
	explicit := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/bad/:organization_id", explicit.Authorize("midaz", "accounts", "get",
		RequireScope("midaz", Dim("organizationId", FromPath).At("organization_id")).Filter("")), ok)
	app.Get("/dup/:organization_id", explicit.Authorize("midaz", "accounts", "get",
		RequireScope("midaz", Dim("organizationId", FromPath).At("organization_id")).Filter("accountId", "accountId")), ok)

	probe := &allowedProbe{}
	app.Get("/good/:organization_id", explicit.Authorize("midaz", "accounts", "get",
		RequireScope("midaz", Dim("organizationId", FromPath).At("organization_id")).Filter("accountId")), probe.handle)

	assert.Equal(t, http.StatusForbidden, doRequest(t, app, http.MethodGet, "/bad/org-1", partnerToken("acme/p1"), "").status)
	assert.Equal(t, http.StatusForbidden, doRequest(t, app, http.MethodGet, "/dup/org-1", partnerToken("acme/p1"), "").status)
	assert.Empty(t, srv.requests(), "a misdeclared route is never asked")

	require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodGet, "/good/org-1", partnerToken("acme/p1"), "").status)

	values, ok := probe.allowed("accountId")
	assert.True(t, ok)
	assert.Equal(t, []string{"acc-1"}, values)
}

// A route keeps its filter when its dimensions are declared after it, and its
// dimensions when the filter is declared after them.
func TestFilter_SurvivesTheRouteScope(t *testing.T) {
	t.Parallel()

	for name, filterFirst := range map[string]bool{"filter_first": true, "dimensions_first": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newScriptedAuthServer(t, allowAccounts(`["acc-1"]`))

			auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
			require.NoError(t, auth.SetManifestScope("midaz", filterCatalog()...))

			setFilter := func() {
				require.NoError(t, auth.SetManifestRouteFilter("midaz", http.MethodPost, accountsRoute, "accountId"))
			}
			setDims := func() {
				require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, accountsRoute, Dim("accountId", FromBody).At("accountId").Optional()))
			}

			if filterFirst {
				setFilter()
				setDims()
			} else {
				setDims()
				setFilter()
			}

			probe := &allowedProbe{}
			app := fiber.New()
			app.Post(accountsRoute, auth.Authorize("midaz", "accounts", "post"), probe.handle)

			require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodPost, accountsTarget, partnerToken("acme/p1"), `{}`).status)

			values, ok := probe.allowed("accountId")
			assert.True(t, ok)
			assert.Equal(t, []string{"acc-1"}, values)

			// The body dimension is still read: a value there is asked, not filtered.
			require.Equal(t, http.StatusOK, doRequest(t, app, http.MethodPost, accountsTarget, partnerToken("acme/p1"), `{"accountId":"acc-7"}`).status)

			requests := srv.requests()
			assert.Contains(t, requests[len(requests)-1], `"accountId":"acc-7"`)
		})
	}
}
