package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// One dimension read from several fields of one body: every value is asked
// ---------------------------------------------------------------------------

const (
	maintenanceRoute  = "/v1/organizations/:organization_id/maintenance"
	maintenanceTarget = "/v1/organizations/org-1/maintenance"
)

// maintenanceDims names two different accounts in one body: one in a
// top-level field, the others in an array of strings of a nested object.
func maintenanceDims(creditOptional, aliasesOptional bool) []Dimension {
	credit := Dim("accountId", FromBody).At("maintenanceCreditAccount")
	if creditOptional {
		credit = credit.Optional()
	}

	aliases := Dim("accountId", FromBody).At("accountTarget.aliases[]")
	if aliasesOptional {
		aliases = aliases.Optional()
	}

	return []Dimension{credit, aliases}
}

func maintenanceApp(t *testing.T, srv *fakeAuthServer, dims ...Dimension) *fiber.App {
	t.Helper()

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, maintenanceRoute, dims...))

	app := fiber.New()
	app.Post(maintenanceRoute, auth.Authorize("midaz", "maintenance", "post"), ok)

	return app
}

// Two body fields naming the same dimension are two independent references:
// each value of each field is its own question, carrying the dimensions the
// rest of the request names.
func TestAuthorize_BodyUnion_EveryFieldIsAsked(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	app := maintenanceApp(t, srv, maintenanceDims(false, false)...)

	got := doPost(t, app, maintenanceTarget, partnerToken("acme/p1"),
		`{"maintenanceCreditAccount":"acc-m","accountTarget":{"aliases":["acc-1","acc-2","acc-m"]}}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "accountId": "acc-m"},
		{"organizationId": "org-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "accountId": "acc-2"},
	}, srv.attributeCalls(), "each distinct value once, in the order first read")
}

// Every value must be allowed: one denied value of either field refuses the
// request, and the handler never runs.
func TestAuthorize_BodyUnion_OneDeniedValueRefuses(t *testing.T) {
	t.Parallel()

	const body = `{"maintenanceCreditAccount":"acc-m","accountTarget":{"aliases":["acc-1","acc-2"]}}`

	for name, denied := range map[string]string{
		"top_level_field": "acc-m",
		"first_alias":     "acc-1",
		"last_alias":      "acc-2",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t, denied)

			auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
			require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
			require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, maintenanceRoute, maintenanceDims(false, false)...))

			probe := &handlerProbe{}
			app := fiber.New()
			app.Post(maintenanceRoute, auth.Authorize("midaz", "maintenance", "post"), probe.handle)

			assert.Equal(t, http.StatusForbidden, doPost(t, app, maintenanceTarget, partnerToken("acme/p1"), body).status)
			assert.Zero(t, probe.calls.Load())
		})
	}
}

// Optional and required apply per field: an optional field left out adds no
// value, the other field's values are still asked, and a required field left
// out is refused naming it.
func TestAuthorize_BodyUnion_OptionalPerField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		creditOptional  bool
		aliasesOptional bool
		body            string
		status          int
		calls           []map[string]string
		message         string
	}{
		{
			name: "optional_credit_absent", creditOptional: true,
			body:   `{"accountTarget":{"aliases":["acc-1"]}}`,
			status: http.StatusOK,
			calls:  []map[string]string{{"organizationId": "org-1", "accountId": "acc-1"}},
		},
		{
			name: "optional_aliases_absent", aliasesOptional: true,
			body:   `{"maintenanceCreditAccount":"acc-m"}`,
			status: http.StatusOK,
			calls:  []map[string]string{{"organizationId": "org-1", "accountId": "acc-m"}},
		},
		{
			name:   "empty_aliases",
			body:   `{"maintenanceCreditAccount":"acc-m","accountTarget":{"aliases":[]}}`,
			status: http.StatusOK,
			calls:  []map[string]string{{"organizationId": "org-1", "accountId": "acc-m"}},
		},
		{
			name: "both_optional_both_absent", creditOptional: true, aliasesOptional: true,
			body:   `{}`,
			status: http.StatusOK,
			calls:  []map[string]string{{"organizationId": "org-1"}},
		},
		{
			name: "required_credit_absent", aliasesOptional: true,
			body:    `{"accountTarget":{"aliases":["acc-1"]}}`,
			status:  http.StatusBadRequest,
			message: `"maintenanceCreditAccount"`,
		},
		{
			name: "required_aliases_absent", creditOptional: true,
			body:    `{"maintenanceCreditAccount":"acc-m"}`,
			status:  http.StatusBadRequest,
			message: `"accountTarget"`,
		},
		{
			name: "present_credit_still_validated", creditOptional: true,
			body:    `{"maintenanceCreditAccount":"","accountTarget":{"aliases":["acc-1"]}}`,
			status:  http.StatusBadRequest,
			message: `"maintenanceCreditAccount"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			app := maintenanceApp(t, srv, maintenanceDims(tt.creditOptional, tt.aliasesOptional)...)

			got := doPost(t, app, maintenanceTarget, partnerToken("acme/p1"), tt.body)
			require.Equal(t, tt.status, got.status, got.body)

			if tt.status != http.StatusOK {
				assert.Contains(t, got.body, tt.message)
				assert.Empty(t, srv.attributeCalls(), "a malformed body is refused before any call")

				return
			}

			assert.Equal(t, tt.calls, srv.attributeCalls())
		})
	}
}

// Inside an array of objects, each value is asked with the fields of its own
// element: two account fields of one leg are two questions, each carrying the
// leg's ledger.
func TestAuthorize_BodyUnion_EachValueKeepsItsElement(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	app := maintenanceApp(t, srv,
		Dim("ledgerId", FromBody).At("legs[].ledgerId"),
		Dim("accountId", FromBody).At("legs[].accountId"),
		Dim("accountId", FromBody).At("legs[].counterpartyAccountId").Optional(),
	)

	got := doPost(t, app, maintenanceTarget, partnerToken("acme/p1"), `{"legs":[
		{"ledgerId":"led-1","accountId":"acc-1","counterpartyAccountId":"acc-2"},
		{"ledgerId":"led-2","accountId":"acc-3"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-2"},
		{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "acc-3"},
	}, srv.attributeCalls())
}

// The union stays under the per-request cap: the cap counts the questions of
// every field together.
func TestAuthorize_BodyUnion_Cap(t *testing.T) {
	t.Parallel()

	aliases := func(n int) string {
		values := make([]string, 0, n)
		for i := range n {
			values = append(values, fmt.Sprintf("%q", fmt.Sprintf("acc-%d", i)))
		}

		return strings.Join(values, ",")
	}

	for name, tc := range map[string]struct {
		aliases int
		status  int
	}{
		"at_the_cap":   {aliases: maxBodyScopeQuestions - 1, status: http.StatusOK},
		"over_the_cap": {aliases: maxBodyScopeQuestions, status: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			app := maintenanceApp(t, srv, maintenanceDims(false, false)...)

			got := doRequest(t, app, http.MethodPost, maintenanceTarget, partnerToken("acme/p1"),
				`{"maintenanceCreditAccount":"acc-m","accountTarget":{"aliases":[`+aliases(tc.aliases)+`]}}`)
			require.Equal(t, tc.status, got.status, got.body)

			if tc.status == http.StatusOK {
				assert.Len(t, srv.attributeCalls(), maxBodyScopeQuestions, "the top-level value plus every alias")

				return
			}

			assert.Contains(t, got.body, "more than 100 distinct sets")
			assert.Empty(t, srv.attributeCalls(), "refused whole, never partly checked")
		})
	}
}

// A dimension the body reads from several fields and the path also carries is
// still held to the carriers agreeing: every body value must be one the path
// names.
func TestAuthorize_BodyUnion_StillAgreesWithAnotherCarrier(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/accounts/:account_id/maintenance"

	srv := newDecidingAuthServer(t)
	app := maintenanceAppOn(t, srv, route, maintenanceDims(false, false)...)

	agree := doPost(t, app, "/v1/organizations/org-1/accounts/acc-1/maintenance", partnerToken("acme/p1"),
		`{"maintenanceCreditAccount":"acc-1","accountTarget":{"aliases":["acc-1"]}}`)
	require.Equal(t, http.StatusOK, agree.status, agree.body)

	disagree := doPost(t, app, "/v1/organizations/org-1/accounts/acc-1/maintenance", partnerToken("acme/p1"),
		`{"maintenanceCreditAccount":"acc-1","accountTarget":{"aliases":["acc-2"]}}`)
	require.Equal(t, http.StatusBadRequest, disagree.status, disagree.body)
	assert.Contains(t, disagree.body, "account_id")
	assert.Len(t, srv.attributeCalls(), 1, "only the agreeing request was asked")
}

func maintenanceAppOn(t *testing.T, srv *fakeAuthServer, route string, dims ...Dimension) *fiber.App {
	t.Helper()

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, route, dims...))

	app := fiber.New()
	app.Post(route, auth.Authorize("midaz", "maintenance", "post"), ok)

	return app
}

// Resolution works per field: each field is resolved by its own resolver
// with the siblings of its own element, all in one call per resolver, and
// every resolved value is asked.
func TestAuthorize_BodyUnion_ResolvesPerField(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{bySibling: "ledgerId", table: map[string][]string{
		"led-1/@m": {"acc-m"},
		"led-1/@a": {"acc-a"},
		"led-2/@b": {"acc-b"},
	}}

	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, maintenanceRoute,
		Dim("ledgerId", FromBody).At("ledgerId"),
		Dim("accountId", FromBody).At("maintenanceCreditAccount").Resolve("alias"),
		Dim("ledgerId", FromBody).At("targets[].ledgerId"),
		Dim("accountId", FromBody).At("targets[].aliases[]").Resolve("alias"),
		Dim("accountId", FromBody).At("targets[].accountId").Optional(),
	)

	app := fiber.New()
	app.Post(maintenanceRoute, auth.Authorize("midaz", "maintenance", "post"), ok)

	got := doRequest(t, app, http.MethodPost, maintenanceTarget, partnerToken("acme/p1"), `{
		"ledgerId":"led-1","maintenanceCreditAccount":"@m",
		"targets":[{"ledgerId":"led-2","aliases":["@b"],"accountId":"acc-p"}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	inputs := resolver.inputs()
	require.Len(t, inputs, 1, "one call for both resolved fields")
	assert.Equal(t, []ResolveItem{
		{Value: "@m", Siblings: map[string]string{"ledgerId": "led-1"}},
		{Value: "@b", Siblings: map[string]string{"ledgerId": "led-2"}},
	}, inputs[0].Items, "each value with the siblings of its own element")

	calls := srv.attributeCalls()
	for _, want := range []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-m"},
		{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "acc-b"},
		{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "acc-p"},
	} {
		assert.Contains(t, calls, want)
	}

	for _, call := range calls {
		assert.NotContains(t, []string{"@m", "@b"}, call["accountId"], "a key is never asked as a value")
	}
}

// Reading one dimension from the same body field twice — the same path, in
// any letter case — is still a misdeclaration: it is the same place.
func TestSetManifestRouteScope_BodyUnion_SameFieldTwiceIsRefused(t *testing.T) {
	t.Parallel()

	for name, dims := range map[string][]Dimension{
		"same_field": {
			Dim("accountId", FromBody).At("items[].accountId"), Dim("accountId", FromBody).At("items[].accountId"),
		},
		"same_field_other_case": {
			Dim("accountId", FromBody).At("target.accountId"), Dim("accountId", FromBody).At("Target.AccountId"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			auth := &AuthClient{Logger: &testLogger{}}
			require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))

			err := auth.SetManifestRouteScope("midaz", http.MethodPost, maintenanceRoute, dims...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "more than once")
			assert.Contains(t, err.Error(), "accountId")
		})
	}

	// Positive control: two distinct fields of the same element are accepted.
	auth := &AuthClient{Logger: &testLogger{}}
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, maintenanceRoute,
		Dim("accountId", FromBody).At("items[].accountId"), Dim("accountId", FromBody).At("items[].counterpartyAccountId")))
}
