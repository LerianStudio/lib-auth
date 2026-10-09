package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Query and header carriers
// ---------------------------------------------------------------------------

// carrierRequest is one request to a test app: headers may repeat a name.
type carrierRequest struct {
	method  string
	target  string
	token   string
	headers [][2]string
	body    string
	ctype   string
}

func doCarrier(t *testing.T, app *fiber.App, r carrierRequest) bodyResult {
	t.Helper()

	method := r.method
	if method == "" {
		method = http.MethodPost
	}

	req := httptest.NewRequest(method, r.target, strings.NewReader(r.body))
	if r.ctype != "" {
		req.Header.Set("Content-Type", r.ctype)
	}

	req.Header.Set("Authorization", "Bearer "+r.token)

	for _, h := range r.headers {
		req.Header.Add(h[0], h[1])
	}

	resp, err := app.Test(req, capQuestionsTestConfig)
	require.NoError(t, err)

	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return bodyResult{status: resp.StatusCode, body: string(raw)}
}

const ledgersRoute = "/v1/organizations/:organization_id/ledgers"

// queryLedgerClient reads the organization from the path (catalog) and the
// ledger from the query on ledgersRoute.
func queryLedgerClient(t *testing.T, srv *fakeAuthServer, dims ...Dimension) *AuthClient {
	t.Helper()

	if len(dims) == 0 {
		dims = []Dimension{Dim("ledgerId", FromQuery).At("ledgerId")}
	}

	return bodyScopedClient(t, srv.URL, http.MethodPost, ledgersRoute, dims...)
}

func TestAuthorize_Query_SingleValue(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := queryLedgerClient(t, srv)

	app := fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

	got := doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers?ledgerId=led-1", token: partnerToken("acme/p1")})

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())
}

// A query parameter repeated, or a value listing several with commas, names
// every one of them: each is its own question, and every one must be allowed.
// Spaces around an element are not part of it, and a value named twice is
// asked once.
func TestAuthorize_Query_MultiValue(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{
		"repeated":       "ledgerId=led-1&ledgerId=led-2",
		"comma":          "ledgerId=led-1,led-2",
		"comma_spaces":   "ledgerId=" + url.QueryEscape("led-1 , led-2"),
		"mixed_and_dups": "ledgerId=led-1,led-2&ledgerId=led-1",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := queryLedgerClient(t, srv)

			app := fiber.New()
			app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

			got := doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers?" + query, token: partnerToken("acme/p1")})

			assert.Equal(t, http.StatusOK, got.status)
			assert.Equal(t, []map[string]string{
				{"organizationId": "org-1", "ledgerId": "led-1"},
				{"organizationId": "org-1", "ledgerId": "led-2"},
			}, srv.attributeCalls())
		})
	}
}

// One value outside the scope refuses the request, wherever it is listed.
func TestAuthorize_Query_MultiValueOneOutsideIsRefused(t *testing.T) {
	t.Parallel()

	for _, query := range []string{"ledgerId=led-out,led-1", "ledgerId=led-1,led-out", "ledgerId=led-1&ledgerId=led-out"} {
		srv := newDecidingAuthServer(t, "led-out")
		auth := queryLedgerClient(t, srv)

		probe := &handlerProbe{}
		app := fiber.New()
		app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), probe.handle)

		got := doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers?" + query, token: partnerToken("acme/p1")})

		assert.Equal(t, http.StatusForbidden, got.status, query)
		assert.Equal(t, int64(0), probe.calls.Load(), query)
	}
}

// A value that is there but names nothing — empty, or an empty element of a
// list — is malformed: 400 naming the parameter, no call.
func TestAuthorize_Query_EmptyElementIsABadRequest(t *testing.T) {
	t.Parallel()

	for _, optional := range []bool{false, true} {
		for _, query := range []string{"ledgerId=", "ledgerId=led-1,,led-2", "ledgerId=led-1,", "ledgerId=,led-1", "ledgerId=led-1&ledgerId=", "ledgerId=%20"} {
			dim := Dim("ledgerId", FromQuery).At("ledgerId")
			if optional {
				dim = dim.Optional()
			}

			srv := newDecidingAuthServer(t)
			auth := queryLedgerClient(t, srv, dim)

			app := fiber.New()
			app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

			got := doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers?" + query, token: partnerToken("acme/p1")})

			assert.Equal(t, http.StatusBadRequest, got.status, query)
			assert.Contains(t, got.body, `query parameter "ledgerId"`, query)
			assert.Equal(t, int64(0), srv.hits.Load(), query)
		}
	}
}

// Absent is not malformed: a required query dimension is refused as before, an
// optional one is left out of the question.
func TestAuthorize_Query_Absent(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := queryLedgerClient(t, srv)

	app := fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

	got := doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers", token: partnerToken("acme/p1")})
	assert.Equal(t, http.StatusForbidden, got.status, "required and absent fails closed")
	assert.Equal(t, int64(0), srv.hits.Load())

	srv = newDecidingAuthServer(t)
	auth = queryLedgerClient(t, srv, Dim("ledgerId", FromQuery).At("ledgerId").Optional())

	app = fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

	got = doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers", token: partnerToken("acme/p1")})
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
}

// Only the declared query key, in its declared letter case, carries the
// dimension: the key the scope checks is the one key every handler binds.
func TestAuthorize_Query_KeyIsExact(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		query string
		want  []map[string]string
	}{
		"exact":         {"organizationId=org-1", []map[string]string{{"organizationId": "org-1"}}},
		"unrelated_key": {"organizationId=org-1&organization=org-2", []map[string]string{{"organizationId": "org-1"}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
				Dim("organizationId", FromQuery).At("organizationId"))

			app := fiber.New()
			app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

			got := doCarrier(t, app, carrierRequest{target: directPath + "?" + tc.query, token: partnerToken("acme/p1")})

			assert.Equal(t, http.StatusOK, got.status)
			assert.Equal(t, tc.want, srv.attributeCalls())
		})
	}
}

// A query key equal to the declared one only without regard to letter case is
// refused before any call, naming the key the dimension must be sent under,
// whether the dimension is required or optional and whether or not the exact
// key is sent alongside it.
func TestAuthorize_Query_KeyCaseVariantIsRefused(t *testing.T) {
	t.Parallel()

	for name, query := range map[string]string{
		"variant_alone":       "ORGANIZATIONID=org-1",
		"other_variant_alone": "OrganizationID=org-1",
		"exact_then_variant":  "organizationId=org-1&ORGANIZATIONID=org-1",
		"variant_then_exact":  "ORGANIZATIONID=org-2&organizationId=org-1",
	} {
		for _, optional := range []bool{false, true} {
			t.Run(name+"/optional="+strconv.FormatBool(optional), func(t *testing.T) {
				t.Parallel()

				dim := Dim("organizationId", FromQuery).At("organizationId")
				if optional {
					dim = dim.Optional()
				}

				srv := newDecidingAuthServer(t)
				auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath, dim)

				probe := &handlerProbe{}
				app := fiber.New()
				app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

				got := doCarrier(t, app, carrierRequest{target: directPath + "?" + query, token: partnerToken("acme/p1")})

				assert.Equal(t, http.StatusBadRequest, got.status)
				assert.Contains(t, got.body, `query parameter "organizationId" must be named exactly "organizationId"`)
				assert.Equal(t, int64(0), srv.hits.Load())
				assert.Equal(t, int64(0), probe.calls.Load())
			})
		}
	}
}

// A malformed carrier is the caller's to fix and is refused with 400 even when
// another required dimension is also absent, whichever of the two the route
// declares first: the missing dimension would otherwise hide the field the
// caller has to correct behind a bare 403.
func TestAuthorize_Query_MalformedKeyIsReportedBeforeMissingDimension(t *testing.T) {
	t.Parallel()

	malformed := Dim("organizationId", FromQuery).At("organizationId")
	missing := Dim("ledgerId", FromQuery).At("ledgerId")

	for name, tc := range map[string]struct {
		query string
		want  string
	}{
		"case_variant": {"ORGANIZATIONID=org-1", `query parameter "organizationId" must be named exactly "organizationId"`},
		"empty_value":  {"organizationId=", `query parameter "organizationId" must not name an empty value`},
	} {
		for order, dims := range map[string][]Dimension{
			"malformed_first": {malformed, missing},
			"missing_first":   {missing, malformed},
		} {
			t.Run(name+"/"+order, func(t *testing.T) {
				t.Parallel()

				srv := newDecidingAuthServer(t)
				auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath, dims...)

				probe := &handlerProbe{}
				app := fiber.New()
				app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

				got := doCarrier(t, app, carrierRequest{target: directPath + "?" + tc.query, token: partnerToken("acme/p1")})

				assert.Equal(t, http.StatusBadRequest, got.status)
				assert.Contains(t, got.body, tc.want)
				assert.Equal(t, int64(0), srv.hits.Load())
				assert.Equal(t, int64(0), probe.calls.Load())
			})
		}
	}
}

// A caller that is not partner-bound has no scope read, so a key in another
// letter case changes nothing for it.
func TestAuthorize_Query_KeyCaseVariantIgnoredForNonPartner(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromQuery).At("organizationId"))

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doCarrier(t, app, carrierRequest{target: directPath + "?ORGANIZATIONID=org-1", token: userToken()})

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, int64(1), srv.hits.Load())
	assert.Equal(t, []map[string]string{nil}, srv.attributeCalls())
}

// Header names are case-insensitive, both as declared and as sent.
func TestAuthorize_Header_NameIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ declared, sent string }{
		{"X-Ledger-Id", "x-ledger-id"},
		{"x-ledger-id", "X-LEDGER-ID"},
		{"X-LEDGER-ID", "X-Ledger-Id"},
	} {
		srv := newDecidingAuthServer(t)
		auth := queryLedgerClient(t, srv, Dim("ledgerId", FromHeader).At(tc.declared))

		app := fiber.New()
		app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

		got := doCarrier(t, app, carrierRequest{
			target: "/v1/organizations/org-1/ledgers", token: partnerToken("acme/p1"),
			headers: [][2]string{{tc.sent, "led-1"}},
		})

		assert.Equal(t, http.StatusOK, got.status, tc)
		assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls(), tc)
	}
}

// A header repeated, or a header value listing several with commas, names every
// one of them, exactly as a query parameter does.
func TestAuthorize_Header_MultiValue(t *testing.T) {
	t.Parallel()

	for name, headers := range map[string][][2]string{
		"repeated": {{"X-Ledger-Id", "led-1"}, {"x-ledger-id", "led-2"}},
		"comma":    {{"X-Ledger-Id", "led-1, led-2"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t, "led-out")
			auth := queryLedgerClient(t, srv, Dim("ledgerId", FromHeader).At("X-Ledger-Id"))

			app := fiber.New()
			app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

			got := doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers", token: partnerToken("acme/p1"), headers: headers})

			assert.Equal(t, http.StatusOK, got.status)
			assert.Equal(t, []map[string]string{
				{"organizationId": "org-1", "ledgerId": "led-1"},
				{"organizationId": "org-1", "ledgerId": "led-2"},
			}, srv.attributeCalls())
		})
	}

	srv := newDecidingAuthServer(t, "led-out")
	auth := queryLedgerClient(t, srv, Dim("ledgerId", FromHeader).At("X-Ledger-Id"))

	app := fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

	got := doCarrier(t, app, carrierRequest{
		target: "/v1/organizations/org-1/ledgers", token: partnerToken("acme/p1"),
		headers: [][2]string{{"X-Ledger-Id", "led-1"}, {"X-Ledger-Id", "led-out"}},
	})
	assert.Equal(t, http.StatusForbidden, got.status, "the second header line is asked about too")

	got = doCarrier(t, app, carrierRequest{
		target: "/v1/organizations/org-1/ledgers", token: partnerToken("acme/p1"),
		headers: [][2]string{{"X-Ledger-Id", "led-1,"}},
	})
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `header "X-Ledger-Id"`)
}

// Several multi-valued dimensions ask about every combination of their values.
func TestAuthorize_MultiValue_EveryCombination(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromQuery).At("organizationId"),
		Dim("ledgerId", FromHeader).At("X-Ledger-Id"))

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doCarrier(t, app, carrierRequest{
		target: directPath + "?organizationId=org-1,org-2", token: partnerToken("acme/p1"),
		headers: [][2]string{{"X-Ledger-Id", "led-1,led-2"}},
	})

	assert.Equal(t, http.StatusOK, got.status)
	assert.ElementsMatch(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
		{"organizationId": "org-2", "ledgerId": "led-1"},
		{"organizationId": "org-2", "ledgerId": "led-2"},
	}, srv.attributeCalls())
}

// A list cannot fan one request out into an unbounded number of decisions.
func TestAuthorize_MultiValue_TooManyIsABadRequest(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := queryLedgerClient(t, srv)

	app := fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

	values := make([]string, 0, maxBodyScopeQuestions+1)
	for i := range maxBodyScopeQuestions + 1 {
		values = append(values, "led-"+strconv.Itoa(i))
	}

	got := doCarrier(t, app, carrierRequest{
		target: "/v1/organizations/org-1/ledgers?ledgerId=" + strings.Join(values, ","), token: partnerToken("acme/p1"),
	})
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `query parameter "ledgerId"`)
	assert.Equal(t, int64(0), srv.hits.Load())

	got = doCarrier(t, app, carrierRequest{
		target: "/v1/organizations/org-1/ledgers?ledgerId=" + strings.Join(values[:maxBodyScopeQuestions], ","), token: partnerToken("acme/p1"),
	})
	assert.Equal(t, http.StatusOK, got.status, "positive control: exactly at the limit is decided")
	assert.Equal(t, int64(maxBodyScopeQuestions), srv.hits.Load())
}

// Path values are one value each: a comma in a path segment is not a list.
func TestAuthorize_Path_IsNeverSplit(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := queryLedgerClient(t, srv)

	app := fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), ok)

	got := doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1,org-2/ledgers?ledgerId=led-1", token: partnerToken("acme/p1")})

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1,org-2", "ledgerId": "led-1"}}, srv.attributeCalls())
}

// ---------------------------------------------------------------------------
// One dimension, several carriers
// ---------------------------------------------------------------------------

// A dimension a route reads from several places must name the same value in
// each. When they disagree the request is refused with 400 naming both places —
// the handler may act on either, and the scope cannot check both at once.
func TestAuthorize_Divergence_PathAndQuery(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := queryLedgerClient(t, srv, Dim("organizationId", FromQuery).At("organizationId").Optional())

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), probe.handle)

	got := doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers?organizationId=org-2", token: partnerToken("acme/p1")})

	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `path parameter "organization_id"`)
	assert.Contains(t, got.body, `query parameter "organizationId"`)
	assert.Equal(t, int64(0), srv.hits.Load())
	assert.Equal(t, int64(0), probe.calls.Load())

	// A credential that is not partner-bound never has its scope read: it is
	// asked once, without attributes, whatever the carriers say.
	got = doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers?organizationId=org-2", token: userToken()})
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{nil}, srv.attributeCalls())

	srv = newDecidingAuthServer(t)
	auth = queryLedgerClient(t, srv, Dim("organizationId", FromQuery).At("organizationId").Optional())
	app = fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), probe.handle)

	// Positive control: agreeing carriers ask one question.
	got = doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers?organizationId=org-1", token: partnerToken("acme/p1")})
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())

	// The other carrier being absent is not a disagreement.
	got = doCarrier(t, app, carrierRequest{target: "/v1/organizations/org-1/ledgers", token: partnerToken("acme/p1")})
	assert.Equal(t, http.StatusOK, got.status)
}

// Lists agree when they name the same values, in any order.
func TestAuthorize_Divergence_QueryAndHeaderLists(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("ledgerId", FromQuery).At("ledgerId").Optional(),
		Dim("ledgerId", FromHeader).At("X-Ledger-Id").Optional())

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doCarrier(t, app, carrierRequest{
		target: directPath + "?ledgerId=led-2,led-1", token: partnerToken("acme/p1"),
		headers: [][2]string{{"X-Ledger-Id", "led-1"}, {"X-Ledger-Id", "led-2"}},
	})
	assert.Equal(t, http.StatusOK, got.status)
	assert.ElementsMatch(t, []map[string]string{{"ledgerId": "led-1"}, {"ledgerId": "led-2"}}, srv.attributeCalls())

	got = doCarrier(t, app, carrierRequest{
		target: directPath + "?ledgerId=led-1,led-2", token: partnerToken("acme/p1"),
		headers: [][2]string{{"X-Ledger-Id", "led-1"}},
	})
	assert.Equal(t, http.StatusBadRequest, got.status, "a value one carrier names and the other does not is a disagreement")
	assert.Contains(t, got.body, `query parameter "ledgerId"`)
	assert.Contains(t, got.body, `header "X-Ledger-Id"`)
}

// The body is one more carrier: each body value must be one the other carrier
// names, and every value the other carrier names must be in the body.
func TestAuthorize_Divergence_PathAndBody(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/transactions"

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, route,
		Dim("organizationId", FromBody).At("items[].organizationId"),
		Dim("ledgerId", FromBody).At("items[].ledgerId"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(route, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	got := doPost(t, app, "/v1/organizations/org-1/transactions", partnerToken("acme/p1"),
		`{"items":[{"organizationId":"org-1","ledgerId":"led-1"},{"organizationId":"org-2","ledgerId":"led-2"}]}`)

	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `path parameter "organization_id"`)
	assert.Contains(t, got.body, `body field "items[1].organizationId"`)
	assert.Equal(t, int64(0), srv.hits.Load())
	assert.Equal(t, int64(0), probe.calls.Load())

	got = doPost(t, app, "/v1/organizations/org-1/transactions", partnerToken("acme/p1"),
		`{"items":[{"organizationId":"org-1","ledgerId":"led-1"},{"organizationId":"org-1","ledgerId":"led-2"}]}`)

	assert.Equal(t, http.StatusOK, got.status, "positive control")
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, srv.attributeCalls())
}

func TestAuthorize_Divergence_QueryListAndBody(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("ledgerId", FromQuery).At("ledgerId"),
		Dim("ledgerId", FromBody).At("items[].ledgerId").Optional())

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, directPath+"?ledgerId=led-1,led-2", partnerToken("acme/p1"), `{"items":[{"ledgerId":"led-1"}]}`)
	assert.Equal(t, http.StatusBadRequest, got.status, "the query names led-2, the body never does")
	assert.Contains(t, got.body, `query parameter "ledgerId"`)
	assert.Contains(t, got.body, `body field "items[].ledgerId"`)

	got = doPost(t, app, directPath+"?ledgerId=led-1,led-2", partnerToken("acme/p1"), `{"items":[{"ledgerId":"led-2"},{"ledgerId":"led-1"}]}`)
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"ledgerId": "led-2"}, {"ledgerId": "led-1"}}, srv.attributeCalls())

	// An element that leaves the optional field out asks with what the other
	// carrier names.
	srv2 := newDecidingAuthServer(t)
	auth2 := bodyScopedClient(t, srv2.URL, http.MethodPost, directPath,
		Dim("ledgerId", FromQuery).At("ledgerId"),
		Dim("ledgerId", FromBody).At("items[].ledgerId").Optional())

	app2 := fiber.New()
	app2.Post(directPath, auth2.Authorize("midaz", "transactions", "post"), ok)

	got = doPost(t, app2, directPath+"?ledgerId=led-1", partnerToken("acme/p1"), `{"items":[{}]}`)
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"ledgerId": "led-1"}}, srv2.attributeCalls())
}

// ---------------------------------------------------------------------------
// Catalog dimensions read from the query or a header
// ---------------------------------------------------------------------------

func headerCatalogClient(t *testing.T, url string) *AuthClient {
	t.Helper()

	auth := &AuthClient{Address: url, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz",
		Dim("organizationId", FromHeader).At("X-Organization-Id"),
		Dim("ledgerId", FromPath).At("ledger_id"),
		Dim("accountId", FromQuery).At("accountId")))

	return auth
}

// A catalog dimension read from a header or the query is read on every route
// of the product, when the request carries it: a route path cannot say whether
// it does.
func TestAuthorize_CatalogHeaderAndQuery(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := headerCatalogClient(t, srv.URL)

	app := fiber.New()
	app.Get("/v1/ledgers/:ledger_id/accounts", auth.Authorize("midaz", "accounts", "get"), ok)

	got := doCarrier(t, app, carrierRequest{
		method: http.MethodGet, target: "/v1/ledgers/led-1/accounts?accountId=acc-1,acc-2", token: partnerToken("acme/p1"),
		headers: [][2]string{{"x-organization-id", "org-1"}},
	})

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-1"},
		{"organizationId": "org-1", "ledgerId": "led-1", "accountId": "acc-2"},
	}, srv.attributeCalls())

	got = doCarrier(t, app, carrierRequest{method: http.MethodGet, target: "/v1/ledgers/led-1/accounts", token: partnerToken("acme/p1")})
	assert.Equal(t, http.StatusOK, got.status, "absent catalog header and query are left out")
	assert.Equal(t, map[string]string{"ledgerId": "led-1"}, srv.attributeCalls()[2])

	got = doCarrier(t, app, carrierRequest{
		method: http.MethodGet, target: "/v1/ledgers/led-1/accounts", token: partnerToken("acme/p1"),
		headers: [][2]string{{"X-Organization-Id", ""}},
	})
	assert.Equal(t, http.StatusBadRequest, got.status, "present but empty is malformed")
	assert.Contains(t, got.body, `header "X-Organization-Id"`)
}

// A route of the product whose path carries no catalog parameter, on a request
// that carries no catalog header or query, names nothing: a partner is asked
// with no attributes, as on a route that declares nothing, and any other caller
// sends the same bytes as before.
func TestAuthorize_CatalogHeaderAndQuery_NothingNamed(t *testing.T) {
	t.Parallel()

	rec := newScopedPartnerAuthServer(t)
	auth := headerCatalogClient(t, rec.URL)

	app := fiber.New()
	app.Get("/v1/settings", auth.Authorize("midaz", "settings", "get"), ok)

	assert.Equal(t, http.StatusForbidden, doGet(t, app, "/v1/settings", partnerToken("acme/p1")))
	assert.Equal(t, `{"action":"get","product":"midaz","resource":"settings","sub":"acme/app"}`, rec.lastBody(t))

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/settings", userToken()))
	assert.Equal(t, `{"action":"get","product":"midaz","resource":"settings","sub":"acme-org/user-1"}`, rec.lastBody(t))

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/settings?accountId=acc-1", partnerToken("acme/p1")),
		"positive control: the same route scopes a partner once the request names a dimension")
	assert.JSONEq(t, `{"accountId":"acc-1"}`, attributesOf(t, rec.lastBody(t)))
}

// A route that declares a catalog dimension from another carrier too is held to
// the same agreement.
func TestAuthorize_CatalogHeader_DivergesFromRouteBody(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := headerCatalogClient(t, srv.URL)
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId")))

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doCarrier(t, app, carrierRequest{
		target: directPath, token: partnerToken("acme/p1"), body: `{"organizationId":"org-2"}`, ctype: "application/json",
		headers: [][2]string{{"X-Organization-Id", "org-1"}},
	})
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `header "X-Organization-Id"`)
	assert.Contains(t, got.body, `body field "organizationId"`)

	got = doCarrier(t, app, carrierRequest{
		target: directPath, token: partnerToken("acme/p1"), body: `{"organizationId":"org-1"}`, ctype: "application/json",
		headers: [][2]string{{"X-Organization-Id", "org-1"}},
	})
	assert.Equal(t, http.StatusOK, got.status, "positive control")
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func TestSetManifestScope_Carriers(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}

	require.NoError(t, auth.SetManifestScope("midaz",
		Dim("organizationId", FromHeader).At("X-Organization-Id"),
		Dim("ledgerId", FromQuery).At("ledgerId"),
		Dim("accountId", FromPath).At("ledgerId")), "a query key and a path parameter are different places")

	err := auth.SetManifestScope("midaz", Dim("organizationId", FromBody).At("organizationId"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organizationId")

	err = auth.SetManifestScope("midaz",
		Dim("organizationId", FromHeader).At("X-Org"),
		Dim("ledgerId", FromHeader).At("x-org"))
	require.Error(t, err, "one header, two names")
	assert.Contains(t, err.Error(), "more than once")

	err = auth.SetManifestScope("midaz",
		Dim("organizationId", FromQuery).At("org"),
		Dim("ledgerId", FromQuery).At("org"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than once")
}

// The catalog dimensions read from the query or a header are derived on every
// route, optional; those from the path only where the path carries them.
func TestDeriveRouteDimensions_QueryAndHeader(t *testing.T) {
	t.Parallel()

	catalog := []Dimension{
		Dim("organizationId", FromHeader).At("X-Organization-Id"),
		Dim("ledgerId", FromPath).At("ledger_id"),
		Dim("accountId", FromQuery).At("accountId"),
	}

	got := deriveRouteDimensions(catalog, "/v1/health")
	assert.Equal(t, []string{"organizationId", "accountId"}, dimNames(got))

	for _, d := range got {
		assert.True(t, d.IsOptional(), d.Name())
	}

	got = deriveRouteDimensions(catalog, "/v1/ledgers/:ledger_id")
	require.Equal(t, []string{"organizationId", "ledgerId", "accountId"}, dimNames(got))
	assert.False(t, got[1].IsOptional(), "a path dimension the path carries is never optional")
}

// One name from several carriers is a declaration; the same carrier and key
// twice is a mistake.
func TestResolveDeclaration_SameNameSeveralCarriers(t *testing.T) {
	t.Parallel()

	_, declErr := resolveDeclaration("midaz", []ScopeDeclaration{RequireScope("midaz",
		Dim("organizationId", FromPath).At("organization_id"),
		Dim("organizationId", FromHeader).At("X-Organization-Id"),
		Dim("organizationId", FromQuery).At("organizationId"),
	)})
	assert.Empty(t, declErr)

	for name, dims := range map[string][]Dimension{
		"same_path":             {Dim("organizationId", FromPath).At("organization_id"), Dim("organizationId", FromPath).At("organization_id")},
		"same_query":            {Dim("organizationId", FromQuery).At("org"), Dim("organizationId", FromQuery).At("org")},
		"same_query_other_case": {Dim("organizationId", FromQuery).At("org"), Dim("organizationId", FromQuery).At("ORG")},
		"same_header":           {Dim("organizationId", FromHeader).At("X-Org"), Dim("organizationId", FromHeader).At("x-org")},
		// Σ and ς are one key to strings.EqualFold, which the readers match
		// with, but lower-case to different runes.
		"same_query_folded":  {Dim("organizationId", FromQuery).At("Σ"), Dim("organizationId", FromQuery).At("ς")},
		"same_header_folded": {Dim("organizationId", FromHeader).At("Σ"), Dim("organizationId", FromHeader).At("ς")},
	} {
		_, declErr := resolveDeclaration("midaz", []ScopeDeclaration{RequireScope("midaz", dims...)})
		assert.Contains(t, declErr, "organizationId", name)
		assert.Contains(t, declErr, "more than once", name)
	}
}

// foldKey is the identity the duplicate check keys carriers by, and
// strings.EqualFold is how the readers match them: two keys share an identity
// exactly when the readers would read both for one dimension.
func TestFoldKey_AgreesWithEqualFold(t *testing.T) {
	t.Parallel()

	for r := rune(0); r < 0x3000; r++ {
		for _, other := range []rune{unicode.SimpleFold(r), unicode.ToLower(r), unicode.ToUpper(r), unicode.ToTitle(r), r + 1} {
			a, b := string(r), string(other)
			require.Equal(t, strings.EqualFold(a, b), foldKey(a) == foldKey(b), "%q vs %q", a, b)
		}
	}
}

// The cap is enforced before the combinations are built: two lists of a few
// hundred values each would otherwise build tens of thousands of questions
// only to refuse them. The refusal must cost about what a small request does.
// Not parallel: testing.AllocsPerRun refuses to run in a parallel test.
func TestQuestionSet_CombinationsAreRefusedBeforeTheyAreBuilt(t *testing.T) {
	values := func(prefix string) []string {
		out := make([]string, 0, 300)
		for i := range 300 {
			out = append(out, prefix+strconv.Itoa(i))
		}

		return out
	}

	var readings requestValues
	readings.add(Dim("organizationId", FromQuery), values("org-"))
	readings.add(Dim("ledgerId", FromHeader).At("X-Ledger-Id"), values("led-"))

	allocs := testing.AllocsPerRun(5, func() {
		err := newQuestionSet(nil, readings).add(map[string]string{}, nil)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "more than 100 distinct sets")
	})

	assert.Less(t, allocs, float64(maxBodyScopeQuestions), "the refusal allocates no question")
}
