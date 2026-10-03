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
// A body field that is an array of strings ("x.ids[]")
// ---------------------------------------------------------------------------

// stringArrayClient wires the catalog with an account dimension and declares
// dims on legsRoute.
func stringArrayClient(t *testing.T, url string, dims ...Dimension) *AuthClient {
	t.Helper()

	auth := &AuthClient{Address: url, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, legsRoute, dims...))

	return auth
}

func stringArrayApp(auth *AuthClient, probe *handlerProbe) *fiber.App {
	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	return app
}

// Every string of the array is one value, asked with the dimensions the path
// names.
func TestAuthorize_StringArray_EveryElementIsAValue(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := stringArrayClient(t, srv.URL, Dim("accountId", FromBody).At("accountTarget.ids[]"))
	probe := &handlerProbe{}
	app := stringArrayApp(auth, probe)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"accountTarget":{"ids":["acc-1","acc-2","acc-1"]}}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-2"},
	}, srv.attributeCalls())
	assert.Equal(t, int64(1), probe.calls.Load())
}

// One element outside the scope refuses the request.
func TestAuthorize_StringArray_EveryElementMustBeAllowed(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "acc-2")
	auth := stringArrayClient(t, srv.URL, Dim("accountId", FromBody).At("accountTarget.ids[]"))
	probe := &handlerProbe{}
	app := stringArrayApp(auth, probe)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"accountTarget":{"ids":["acc-1","acc-2"]}}`)

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Equal(t, int64(0), probe.calls.Load())
}

// An element that is not a non-empty string is refused with 400 naming the
// element, before any authorization call.
func TestAuthorize_StringArray_MalformedElementNamesTheElement(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct{ body, want string }{
		"empty":  {`{"accountTarget":{"ids":["acc-1",""]}}`, `"accountTarget.ids[1]" must not be empty`},
		"number": {`{"accountTarget":{"ids":["acc-1",7]}}`, `"accountTarget.ids[1]" must be a JSON string`},
		"null":   {`{"accountTarget":{"ids":[null]}}`, `"accountTarget.ids[0]" must be a JSON string`},
		"object": {`{"accountTarget":{"ids":["acc-1","acc-2",{"id":"acc-3"}]}}`, `"accountTarget.ids[2]" must be a JSON string`},
		"array":  {`{"accountTarget":{"ids":[["acc-1"]]}}`, `"accountTarget.ids[0]" must be a JSON string`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := stringArrayClient(t, srv.URL, Dim("accountId", FromBody).At("accountTarget.ids[]").Optional())
			probe := &handlerProbe{}
			app := stringArrayApp(auth, probe)

			got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), tc.body)

			assert.Equal(t, http.StatusBadRequest, got.status)
			assert.Contains(t, got.body, tc.want)
			assert.Equal(t, int64(0), srv.hits.Load())
			assert.Equal(t, int64(0), probe.calls.Load())
		})
	}
}

// A value that is not an array is refused naming the field.
func TestAuthorize_StringArray_NotAnArrayIsRefused(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"string": `{"accountTarget":{"ids":"acc-1"}}`,
		"object": `{"accountTarget":{"ids":{"0":"acc-1"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := stringArrayClient(t, srv.URL, Dim("accountId", FromBody).At("accountTarget.ids[]").Optional())
			app := stringArrayApp(auth, &handlerProbe{})

			got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), body)

			assert.Equal(t, http.StatusBadRequest, got.status)
			assert.Contains(t, got.body, `"accountTarget.ids" must be a JSON array of strings`)
			assert.Equal(t, int64(0), srv.hits.Load())
		})
	}
}

// Optional applies to the array as a whole: absent or null, the dimension is
// absent and the question goes without it. Without Optional, the same bodies
// are refused naming the field.
func TestAuthorize_StringArray_OptionalCoversTheWholeArray(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct{ body, required string }{
		"absent_array":  {`{"accountTarget":{}}`, `"accountTarget.ids" is missing from the request body`},
		"null_array":    {`{"accountTarget":{"ids":null}}`, `"accountTarget.ids" must not be null`},
		"absent_parent": {`{}`, `"accountTarget" is missing from the request body`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := stringArrayClient(t, srv.URL, Dim("accountId", FromBody).At("accountTarget.ids[]").Optional())
			probe := &handlerProbe{}
			app := stringArrayApp(auth, probe)

			got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), tc.body)
			require.Equal(t, http.StatusOK, got.status, got.body)
			assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())

			required := newDecidingAuthServer(t)
			strict := stringArrayClient(t, required.URL, Dim("accountId", FromBody).At("accountTarget.ids[]"))

			got = doRequest(t, stringArrayApp(strict, &handlerProbe{}), http.MethodPost, legsPath, partnerToken("acme/p1"), tc.body)
			assert.Equal(t, http.StatusBadRequest, got.status)
			assert.Contains(t, got.body, tc.required)
			assert.Equal(t, int64(0), required.hits.Load())
		})
	}
}

// An empty array names no value: no question carries the dimension, optional
// or not, and the other dimensions are still asked.
func TestAuthorize_StringArray_EmptyArrayNamesNoValue(t *testing.T) {
	t.Parallel()

	for name, dim := range map[string]Dimension{
		"optional": Dim("accountId", FromBody).At("accountTarget.ids[]").Optional(),
		"required": Dim("accountId", FromBody).At("accountTarget.ids[]"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := stringArrayClient(t, srv.URL, dim)
			probe := &handlerProbe{}
			app := stringArrayApp(auth, probe)

			got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"), `{"accountTarget":{"ids":[]}}`)
			require.Equal(t, http.StatusOK, got.status, got.body)
			assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())
			assert.Equal(t, int64(1), probe.calls.Load())
		})
	}
}

// Inside an array of objects, each element's strings are asked with that
// element's other fields; an element with an empty array keeps its own.
func TestAuthorize_StringArray_NestedKeepsItsElement(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/transfers"

	srv := newDecidingAuthServer(t)
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, route,
		Dim("ledgerId", FromBody).At("targets[].ledgerId"),
		Dim("accountId", FromBody).At("targets[].ids[]")))

	app := fiber.New()
	app.Post(route, auth.Authorize("midaz", "transfers", "post"), ok)

	got := doRequest(t, app, http.MethodPost, "/v1/organizations/org-1/transfers", partnerToken("acme/p1"),
		`{"targets":[{"ledgerId":"led-1","ids":["acc-1","acc-2"]},{"ledgerId":"led-2","ids":["acc-3"]},{"ledgerId":"led-3","ids":[]}]}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-2"},
		{"organizationId": "org-1", "ledgerId": "led-2", "accountId": "acc-3"},
		{"organizationId": "org-1", "ledgerId": "led-3"},
	}, srv.attributeCalls())

	got = doRequest(t, app, http.MethodPost, "/v1/organizations/org-1/transfers", partnerToken("acme/p1"),
		`{"targets":[{"ledgerId":"led-1","ids":["acc-1"]},{"ledgerId":"led-2","ids":["acc-2",""]}]}`)
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `"targets[1].ids[1]"`)
}

// More distinct values than the cap are refused, never partly asked.
func TestAuthorize_StringArray_Cap(t *testing.T) {
	t.Parallel()

	ids := make([]string, 0, maxBodyScopeQuestions+1)
	for i := range maxBodyScopeQuestions + 1 {
		ids = append(ids, fmt.Sprintf(`"acc-%d"`, i))
	}

	srv := newDecidingAuthServer(t)
	auth := stringArrayClient(t, srv.URL, Dim("accountId", FromBody).At("accountTarget.ids[]"))
	app := stringArrayApp(auth, &handlerProbe{})

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"accountTarget":{"ids":[`+strings.Join(ids, ",")+`]}}`)
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Equal(t, int64(0), srv.hits.Load())

	// Positive control: exactly the cap is asked.
	got = doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"accountTarget":{"ids":[`+strings.Join(ids[:maxBodyScopeQuestions], ",")+`]}}`)
	assert.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, int64(maxBodyScopeQuestions), srv.hits.Load())
}

// A caller that is not partner-bound is decided without the body.
func TestAuthorize_StringArray_NonPartnerNeverReadsTheBody(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := stringArrayClient(t, srv.URL, Dim("accountId", FromBody).At("accountTarget.ids[]"))
	app := stringArrayApp(auth, &handlerProbe{})

	got := doRequest(t, app, http.MethodPost, legsPath, userToken(), `{"accountTarget":{"ids":[7]}}`)

	assert.Equal(t, http.StatusOK, got.status, got.body)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())
}

// The strings of the array are resolved like any body value: one batch, and
// each resolved value asked.
func TestAuthorize_StringArray_Resolved(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	resolver := &fakeResolver{table: map[string][]string{"@a": {"acc-a"}, "@b": {"acc-b"}}}
	auth := resolvingClient(t, srv.URL, "alias", resolver, http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("accountTarget.aliases[]").Resolve("alias"))

	app := fiber.New()
	app.Post(legsRoute, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"accountTarget":{"aliases":["@a","@b","@a"]}}`)
	require.Equal(t, http.StatusOK, got.status, got.body)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-a"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-b"},
	}, srv.attributeCalls())
	require.Len(t, resolver.inputs(), 1, "one call for the whole body")

	got = doRequest(t, app, http.MethodPost, legsPath, partnerToken("acme/p1"),
		`{"accountTarget":{"aliases":["@a","@zz"]}}`)
	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Contains(t, got.body, `body field "accountTarget.aliases[1]" is outside this credential's scope or does not exist`)
}

// The elements of an array are read either as strings or as objects, never
// both: a route that declares both is refused when it is wired.
func TestSetManifestRouteScope_StringArrayReadAsObjectsIsRefused(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}
	require.NoError(t, auth.SetManifestScope("midaz", resolveCatalog()...))

	for name, dims := range map[string][]Dimension{
		"key_of_element": {Dim("accountId", FromBody).At("x.ids[]"), Dim("ledgerId", FromBody).At("x.ids[].ledgerId")},
		"nested_array":   {Dim("accountId", FromBody).At("x.ids[]"), Dim("ledgerId", FromBody).At("x.ids[].y[].ledgerId")},
		"reverse_order":  {Dim("ledgerId", FromBody).At("x.ids[].ledgerId"), Dim("accountId", FromBody).At("x.ids[]")},
	} {
		err := auth.SetManifestRouteScope("midaz", http.MethodPost, legsRoute, dims...)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), `"x.ids[]"`, name)
	}

	// Positive control: the string array beside a field of its enclosing object.
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, legsRoute,
		Dim("accountId", FromBody).At("x.ids[]"), Dim("ledgerId", FromBody).At("x.ledgerId")))
}
