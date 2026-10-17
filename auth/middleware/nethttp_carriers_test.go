package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
)

// doCarrierHTTP serves r through AuthorizeHTTP mounted on a ServeMux pattern,
// the net/http twin of doCarrier.
func doCarrierHTTP(t *testing.T, pattern string, h http.Handler, r carrierRequest) bodyResult {
	t.Helper()

	method := r.method
	if method == "" {
		method = http.MethodPost
	}

	rec := serveGated(t, pattern, h, func() *http.Request {
		req := httptest.NewRequest(method, r.target, strings.NewReader(r.body))
		if r.ctype != "" {
			req.Header.Set("Content-Type", r.ctype)
		}

		req.Header.Set("Authorization", "Bearer "+r.token)

		for _, hdr := range r.headers {
			req.Header.Add(hdr[0], hdr[1])
		}

		return req
	})

	return bodyResult{status: rec.Code, body: strings.TrimSpace(rec.Body.String())}
}

// AuthorizeHTTP reads every carrier the way Authorize does: the same request,
// served by a Fiber route and by a ServeMux pattern, gets the same status and
// asks the authorization service the same questions.
func TestAuthorizeHTTP_CarriersMatchFiber(t *testing.T) {
	t.Parallel()

	const pattern = "POST /v1/organizations/{organization_id}/ledgers"

	tests := []struct {
		name       string
		dims       []Dimension
		req        carrierRequest
		wantStatus int
	}{
		{
			name:       "query_single",
			req:        carrierRequest{target: "/v1/organizations/org-1/ledgers?ledgerId=led-1"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "query_repeated_and_comma",
			req:        carrierRequest{target: "/v1/organizations/org-1/ledgers?ledgerId=led-1,led-2&ledgerId=led-3"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "query_key_in_another_case_is_refused",
			req:        carrierRequest{target: "/v1/organizations/org-1/ledgers?LedgerId=led-1"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "query_empty_element_is_refused",
			req:        carrierRequest{target: "/v1/organizations/org-1/ledgers?ledgerId=led-1,"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "header_lines_and_comma_any_case",
			dims: []Dimension{Dim("ledgerId", FromHeader).At("X-Ledger-Id")},
			req: carrierRequest{
				target:  "/v1/organizations/org-1/ledgers",
				headers: [][2]string{{"X-Ledger-Id", "led-1, led-2"}, {"x-ledger-id", "led-3"}},
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "form_field",
			dims: []Dimension{Dim("ledgerId", FromForm).At("ledger")},
			req: carrierRequest{
				target: "/v1/organizations/org-1/ledgers",
				body:   "ledger=led-1&ledger=led-2",
				ctype:  formMediaType,
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "form_field_in_a_json_body_is_refused",
			dims: []Dimension{Dim("ledgerId", FromForm).At("ledger")},
			req: carrierRequest{
				target: "/v1/organizations/org-1/ledgers",
				body:   `{"ledger":"led-1"}`,
				ctype:  "application/json",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.req.token = partnerToken("acme/p1")

			fiberSrv := newDecidingAuthServer(t)
			fiberAuth := queryLedgerClient(t, fiberSrv, tt.dims...)

			app := fiber.New()
			app.Post(ledgersRoute, fiberAuth.Authorize("midaz", "ledgers", "post"), ok)

			viaFiber := doCarrier(t, app, tt.req)

			httpSrv := newDecidingAuthServer(t)
			httpAuth := queryLedgerClient(t, httpSrv, tt.dims...)

			viaHTTP := doCarrierHTTP(t, pattern, httpAuth.AuthorizeHTTP("midaz", "ledgers", "post")(principalEcho(nil)), tt.req)

			assert.Equal(t, tt.wantStatus, viaFiber.status, "fiber: %s", viaFiber.body)
			assert.Equal(t, tt.wantStatus, viaHTTP.status, "net/http: %s", viaHTTP.body)

			if tt.wantStatus != http.StatusOK {
				assert.Equal(t, viaFiber.body, viaHTTP.body, "both adapters render the same refusal message")
			}

			assert.Equal(t, fiberSrv.attributeCalls(), httpSrv.attributeCalls(), "both adapters ask the same questions")
		})
	}
}
