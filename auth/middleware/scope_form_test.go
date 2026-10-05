package middleware

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Form carrier
// ---------------------------------------------------------------------------

const formType = "application/x-www-form-urlencoded"

// formClient reads the organization from the path (catalog) and the given
// dimensions on ledgersRoute.
func formClient(t *testing.T, srv *fakeAuthServer, dims ...Dimension) *AuthClient {
	t.Helper()

	if len(dims) == 0 {
		dims = []Dimension{Dim("ledgerId", FromForm).At("ledgerId")}
	}

	return bodyScopedClient(t, srv.URL, http.MethodPost, ledgersRoute, dims...)
}

func formApp(auth *AuthClient, probe *handlerProbe) *fiber.App {
	app := fiber.New()
	app.Post(ledgersRoute, auth.Authorize("midaz", "ledgers", "post"), probe.handle)

	return app
}

const formTarget = "/v1/organizations/org-1/ledgers"

func TestAuthorize_Form_SingleAndMultiValue(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		ctype string
		body  string
		want  []map[string]string
	}{
		"single":   {formType, "ledgerId=led-1&amount=10", []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}},
		"charset":  {formType + "; charset=utf-8", "ledgerId=led-1", []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}},
		"repeated": {formType, "ledgerId=led-1&ledgerId=led-2", []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}, {"organizationId": "org-1", "ledgerId": "led-2"}}},
		"comma":    {formType, "ledgerId=led-1%2C+led-2", []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}, {"organizationId": "org-1", "ledgerId": "led-2"}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			probe := &handlerProbe{}
			app := formApp(formClient(t, srv), probe)

			got := doCarrier(t, app, carrierRequest{target: formTarget, token: partnerToken("acme/p1"), ctype: tc.ctype, body: tc.body})

			assert.Equal(t, http.StatusOK, got.status)
			assert.Equal(t, tc.want, srv.attributeCalls())
			assert.Equal(t, tc.body, string(probe.body), "the handler reads the body intact")
		})
	}
}

// One value outside the scope refuses the request.
func TestAuthorize_Form_OneOutsideIsRefused(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-out")
	probe := &handlerProbe{}
	app := formApp(formClient(t, srv), probe)

	got := doCarrier(t, app, carrierRequest{target: formTarget, token: partnerToken("acme/p1"), ctype: formType, body: "ledgerId=led-1&ledgerId=led-out"})

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Equal(t, int64(0), probe.calls.Load())
}

// Only a urlencoded form is read. Any other body that may carry form fields — a
// multipart form above all — cannot be checked, so it is refused naming the
// field, whether or not the field is optional.
func TestAuthorize_Form_OtherBodiesAreABadRequest(t *testing.T) {
	t.Parallel()

	for _, optional := range []bool{false, true} {
		for name, tc := range map[string]struct{ ctype, body string }{
			"multipart":   {"multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"ledgerId\"\r\n\r\nled-1\r\n--x--\r\n"},
			"json":        {"application/json", `{"ledgerId":"led-1"}`},
			"no_type":     {"", "ledgerId=led-1"},
			"malformed":   {formType, "ledgerId=%zz"},
			"text":        {"text/plain", "ledgerId=led-1"},
			"form_suffix": {"application/x-www-form-urlencoded-x", "ledgerId=led-1"},
		} {
			dim := Dim("ledgerId", FromForm).At("ledgerId")
			if optional {
				dim = dim.Optional()
			}

			srv := newDecidingAuthServer(t)
			probe := &handlerProbe{}
			app := formApp(formClient(t, srv, dim), probe)

			got := doCarrier(t, app, carrierRequest{target: formTarget, token: partnerToken("acme/p1"), ctype: tc.ctype, body: tc.body})

			assert.Equal(t, http.StatusBadRequest, got.status, name)
			assert.Contains(t, got.body, `form field "ledgerId"`, name)
			assert.Equal(t, int64(0), srv.hits.Load(), name)
			assert.Equal(t, int64(0), probe.calls.Load(), name)
		}
	}
}

// Absent and present are told apart exactly as in a JSON body.
func TestAuthorize_Form_OptionalAndRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		optional bool
		ctype    string
		body     string
		status   int
		want     []map[string]string
	}{
		{name: "optional_absent", optional: true, ctype: formType, body: "amount=10", status: http.StatusOK, want: []map[string]string{{"organizationId": "org-1"}}},
		{name: "optional_no_body", optional: true, status: http.StatusOK, want: []map[string]string{{"organizationId": "org-1"}}},
		{name: "optional_no_body_any_type", optional: true, ctype: "application/json", status: http.StatusOK, want: []map[string]string{{"organizationId": "org-1"}}},
		{name: "optional_empty", optional: true, ctype: formType, body: "ledgerId=", status: http.StatusBadRequest},
		{name: "optional_empty_element", optional: true, ctype: formType, body: "ledgerId=led-1,", status: http.StatusBadRequest},
		{name: "required_absent", ctype: formType, body: "amount=10", status: http.StatusBadRequest},
		{name: "required_no_body", status: http.StatusBadRequest},
		{name: "required_empty", ctype: formType, body: "ledgerId=", status: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dim := Dim("ledgerId", FromForm).At("ledgerId")
			if tt.optional {
				dim = dim.Optional()
			}

			srv := newDecidingAuthServer(t)
			app := formApp(formClient(t, srv, dim), &handlerProbe{})

			got := doCarrier(t, app, carrierRequest{target: formTarget, token: partnerToken("acme/p1"), ctype: tt.ctype, body: tt.body})

			assert.Equal(t, tt.status, got.status)

			if tt.status == http.StatusBadRequest {
				assert.Contains(t, got.body, `form field "ledgerId"`)
				assert.Equal(t, int64(0), srv.hits.Load())

				return
			}

			assert.Equal(t, tt.want, srv.attributeCalls())
		})
	}
}

// A form field is one more carrier: it must agree with the path, the query and
// headers.
func TestAuthorize_Form_Divergence(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	probe := &handlerProbe{}
	app := formApp(formClient(t, srv,
		Dim("organizationId", FromForm).At("organizationId").Optional(),
		Dim("ledgerId", FromForm).At("ledgerId").Optional(),
		Dim("ledgerId", FromQuery).At("ledgerId").Optional()), probe)

	got := doCarrier(t, app, carrierRequest{target: formTarget, token: partnerToken("acme/p1"), ctype: formType, body: "organizationId=org-2"})
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `path parameter "organization_id"`)
	assert.Contains(t, got.body, `form field "organizationId"`)

	got = doCarrier(t, app, carrierRequest{target: formTarget + "?ledgerId=led-1", token: partnerToken("acme/p1"), ctype: formType, body: "ledgerId=led-2"})
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `query parameter "ledgerId"`)
	assert.Contains(t, got.body, `form field "ledgerId"`)

	assert.Equal(t, int64(0), srv.hits.Load())
	assert.Equal(t, int64(0), probe.calls.Load())

	got = doCarrier(t, app, carrierRequest{target: formTarget + "?ledgerId=led-1", token: partnerToken("acme/p1"), ctype: formType, body: "organizationId=org-1&ledgerId=led-1"})
	assert.Equal(t, http.StatusOK, got.status, "positive control")
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())
}

// The form is read only for a partner-bound credential, as the JSON body is:
// any other caller is decided on the path, query and headers alone, and its
// body is never parsed.
func TestAuthorize_Form_NonPartnerIsDecidedWithoutTheBody(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	app := formApp(formClient(t, srv), &handlerProbe{})

	got := doCarrier(t, app, carrierRequest{target: formTarget, token: userToken(), ctype: "multipart/form-data; boundary=x", body: "--x--\r\n"})

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
}

func TestFormRegistration(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	err := auth.SetManifestRouteScope("midaz", http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromForm).At("ledgerId"))
	require.Error(t, err, "one body cannot be JSON and a form")
	assert.Contains(t, err.Error(), "form")

	err = auth.SetManifestRouteScope("midaz", http.MethodPost, directPath,
		Dim("ledgerId", FromForm).At("ledgerId"), Dim("ledgerId", FromForm).At("ledgerId"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than once")

	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, directPath,
		Dim("organizationId", FromForm).At("organizationId"), Dim("ledgerId", FromForm).At("ledgerId")), "positive control")

	err = (&AuthClient{Logger: &testLogger{}}).SetManifestScope("midaz", Dim("organizationId", FromForm).At("organizationId"))
	require.Error(t, err, "the catalog reads no body")
}
