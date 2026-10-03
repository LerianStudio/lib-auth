package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Body scope test helpers
// ---------------------------------------------------------------------------

// decidingAuthServer answers POST /v1/authorize with ALLOW unless the request's
// attributes carry one of the denied values, and records the attributes of every
// call in order. It is what lets a batch test prove that ONE value outside the
// scope refuses the whole request.
type decidingAuthServer struct {
	*httptest.Server

	denied map[string]bool

	mu    sync.Mutex
	calls []map[string]string
	hits  atomic.Int64
}

func newDecidingAuthServer(t *testing.T, denied ...string) *decidingAuthServer {
	t.Helper()

	srv := &decidingAuthServer{denied: make(map[string]bool, len(denied))}
	for _, v := range denied {
		srv.denied[v] = true
	}

	srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("mock authz server: failed to read body: %v", err)
		}

		var body struct {
			Attributes map[string]string `json:"attributes"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("mock authz server: failed to decode body: %v", err)
		}

		srv.mu.Lock()
		srv.calls = append(srv.calls, body.Attributes)
		srv.mu.Unlock()
		srv.hits.Add(1)

		authorized := true

		for _, v := range body.Attributes {
			if srv.denied[v] {
				authorized = false
			}
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(AuthResponse{Authorized: authorized}); err != nil {
			t.Errorf("mock authz server: failed to encode response: %v", err)
		}
	}))

	t.Cleanup(srv.Close)

	return srv
}

func (srv *decidingAuthServer) attributeCalls() []map[string]string {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	return append([]map[string]string(nil), srv.calls...)
}

// bodyScopedClient is a client with the path catalog AND the body dimensions of
// the given route.
func bodyScopedClient(t *testing.T, url, method, path string, dims ...Dimension) *AuthClient {
	t.Helper()

	auth := &AuthClient{Address: url, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", method, path, dims...))

	return auth
}

type bodyResult struct {
	status int
	body   string
}

func doPost(t *testing.T, app *fiber.App, target, token, body string) bodyResult {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return bodyResult{status: resp.StatusCode, body: string(raw)}
}

// handlerProbe counts handler invocations and keeps the body the handler read.
type handlerProbe struct {
	calls atomic.Int64
	mu    sync.Mutex
	body  []byte
}

func (p *handlerProbe) handle(c fiber.Ctx) error {
	p.calls.Add(1)

	p.mu.Lock()
	p.body = append([]byte(nil), c.Body()...)
	p.mu.Unlock()

	return c.SendString("ok")
}

const directPath = "/v2/transactions/direct"

// ---------------------------------------------------------------------------
// Single value
// ---------------------------------------------------------------------------

func TestAuthorize_BodyScope_SingleValue(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At("ledgerId"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	got := doPost(t, app, directPath, partnerToken("acme/p1"), `{"organizationId":"org-1","ledgerId":"led-1","amount":"10"}`)

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())
	assert.Equal(t, int64(1), probe.calls.Load())
}

// The decision for the body values is the authorization service's: the same
// single-value request with a value outside the scope is refused.
func TestAuthorize_BodyScope_SingleValueOutsideIsRefused(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-out")
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At("ledgerId"))

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	got := doPost(t, app, directPath, partnerToken("acme/p1"), `{"organizationId":"org-1","ledgerId":"led-out"}`)

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Equal(t, int64(0), probe.calls.Load(), "a refused request never reaches the handler")
}

// ---------------------------------------------------------------------------
// Batches
// ---------------------------------------------------------------------------

const batchPath = "/v2/transactions/batch"

func batchClient(t *testing.T, srv *decidingAuthServer) *AuthClient {
	t.Helper()

	return bodyScopedClient(t, srv.URL, http.MethodPost, batchPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At("items[].ledgerId"))
}

// Every value of a batch is asked about. Repeated values are asked once.
func TestAuthorize_BodyScope_BatchAllInside(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-out")
	auth := batchClient(t, srv)

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	got := doPost(t, app, batchPath, partnerToken("acme/p1"),
		`{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"},{"ledgerId":"led-1"}]}`)

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, srv.attributeCalls())
	assert.Equal(t, int64(1), probe.calls.Load())
}

// One value outside the scope refuses the whole request, wherever it sits in
// the batch.
func TestAuthorize_BodyScope_BatchOneOutsideIsRefused(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"organizationId":"org-1","items":[{"ledgerId":"led-out"},{"ledgerId":"led-1"},{"ledgerId":"led-2"}]}`,
		`{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-out"},{"ledgerId":"led-2"}]}`,
		`{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"},{"ledgerId":"led-out"}]}`,
	} {
		srv := newDecidingAuthServer(t, "led-out")
		auth := batchClient(t, srv)

		probe := &handlerProbe{}
		app := fiber.New()
		app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

		got := doPost(t, app, batchPath, partnerToken("acme/p1"), body)

		assert.Equal(t, http.StatusForbidden, got.status, body)
		assert.Equal(t, int64(0), probe.calls.Load(), body)
	}
}

// Fields that sit in the same array element travel together: each element is
// one question. Two legs naming (org-1, led-1) and (org-2, led-2) ask exactly
// those two pairs, never the cross pairs a partner may legitimately not hold.
func TestAuthorize_BodyScope_FieldsOfOneElementTravelTogether(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("debits[].organizationId"),
		Dim("ledgerId", FromBody).At("debits[].ledgerId"),
		Dim("organizationId", FromBody).At("credits[].organizationId"),
		Dim("ledgerId", FromBody).At("credits[].ledgerId"))

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, directPath, partnerToken("acme/p1"), `{
		"debits":  [{"organizationId":"org-1","ledgerId":"led-1"}],
		"credits": [{"organizationId":"org-2","ledgerId":"led-2"},{"organizationId":"org-1","ledgerId":"led-1"}]}`)

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-2", "ledgerId": "led-2"},
	}, srv.attributeCalls())
}

// A field of an enclosing element is carried into every element nested in it.
func TestAuthorize_BodyScope_NestedArraysInheritTheEnclosingElement(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-out")
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, batchPath,
		Dim("organizationId", FromBody).At("transactions[].organizationId"),
		Dim("ledgerId", FromBody).At("transactions[].legs[].ledgerId"))

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, batchPath, partnerToken("acme/p1"), `{"transactions":[
		{"organizationId":"org-1","legs":[{"ledgerId":"led-1"},{"ledgerId":"led-2"}]},
		{"organizationId":"org-2","legs":[{"ledgerId":"led-3"}]}]}`)

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
		{"organizationId": "org-2", "ledgerId": "led-3"},
	}, srv.attributeCalls())

	got = doPost(t, app, batchPath, partnerToken("acme/p1"), `{"transactions":[
		{"organizationId":"org-1","legs":[{"ledgerId":"led-1"}]},
		{"organizationId":"org-2","legs":[{"ledgerId":"led-3"},{"ledgerId":"led-out"}]}]}`)

	assert.Equal(t, http.StatusForbidden, got.status)
}

// A batch cannot fan one request out into an unbounded number of decisions.
func TestAuthorize_BodyScope_TooManyDistinctValuesIsABadRequest(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := batchClient(t, srv)

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	items := make([]string, 0, maxBodyScopeQuestions+1)
	for i := range maxBodyScopeQuestions + 1 {
		items = append(items, `{"ledgerId":"led-`+strings.Repeat("x", i+1)+`"}`)
	}

	got := doPost(t, app, batchPath, partnerToken("acme/p1"),
		`{"organizationId":"org-1","items":[`+strings.Join(items, ",")+`]}`)

	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, "items[].ledgerId")
	assert.Equal(t, int64(0), srv.hits.Load())

	// Positive control: exactly at the limit is decided.
	got = doPost(t, app, batchPath, partnerToken("acme/p1"),
		`{"organizationId":"org-1","items":[`+strings.Join(items[:maxBodyScopeQuestions], ",")+`]}`)

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, int64(maxBodyScopeQuestions), srv.hits.Load())
}

// ---------------------------------------------------------------------------
// Bad bodies: 400 naming the field, no authorization call, no handler call
// ---------------------------------------------------------------------------

func TestAuthorize_BodyScope_BadBodyIsABadRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		body  string
		field string
	}{
		{name: "malformed_json", body: `{"organizationId":"org-1","items":[`, field: "organizationId"},
		{name: "empty_body", body: ``, field: "organizationId"},
		{name: "not_an_object", body: `["org-1"]`, field: "items"},
		{name: "missing_scalar", body: `{"items":[{"ledgerId":"led-1"}]}`, field: "organizationId"},
		{name: "missing_in_one_item", body: `{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{}]}`, field: "items[1].ledgerId"},
		{name: "missing_array", body: `{"organizationId":"org-1"}`, field: "items"},
		{name: "empty_array", body: `{"organizationId":"org-1","items":[]}`, field: "items"},
		{name: "array_is_not_an_array", body: `{"organizationId":"org-1","items":{"ledgerId":"led-1"}}`, field: "items"},
		{name: "item_is_not_an_object", body: `{"organizationId":"org-1","items":["led-1"]}`, field: "items[0].ledgerId"},
		{name: "number", body: `{"organizationId":42,"items":[{"ledgerId":"led-1"}]}`, field: "organizationId"},
		{name: "null", body: `{"organizationId":null,"items":[{"ledgerId":"led-1"}]}`, field: "organizationId"},
		{name: "object", body: `{"organizationId":{"id":"org-1"},"items":[{"ledgerId":"led-1"}]}`, field: "organizationId"},
		{name: "empty_string", body: `{"organizationId":"","items":[{"ledgerId":"led-1"}]}`, field: "organizationId"},
		{name: "non_string_in_one_item", body: `{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":true}]}`, field: "items[1].ledgerId"},
		// A struct decoder matches keys without regard to case, so a second key
		// spelled differently would be the value the handler reads while the
		// scope checked the first one.
		{name: "case_variant_twin", body: `{"organizationId":"org-1","OrganizationID":"org-2","items":[{"ledgerId":"led-1"}]}`, field: "organizationId"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := batchClient(t, srv)

			probe := &handlerProbe{}
			app := fiber.New()
			app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

			got := doPost(t, app, batchPath, partnerToken("acme/p1"), tt.body)

			assert.Equal(t, http.StatusBadRequest, got.status)
			assert.Contains(t, got.body, `"`+tt.field+`"`, "the refusal names the field")

			assert.Equal(t, int64(0), srv.hits.Load(), "no authorization call")
			assert.Equal(t, int64(0), probe.calls.Load(), "no handler call")
		})
	}
}

// A key spelled in another letter case is the value a struct decoder reads, so
// it is the value the scope checks.
func TestAuthorize_BodyScope_ReadsTheKeyTheHandlerReads(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "org-out")
	auth := batchClient(t, srv)

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, batchPath, partnerToken("acme/p1"), `{"OrganizationID":"org-out","items":[{"ledgerId":"led-1"}]}`)

	assert.Equal(t, http.StatusForbidden, got.status)
}

// An unauthenticated caller is told it is unauthenticated, not how its body is
// wrong.
func TestAuthorize_BodyScope_MissingTokenComesFirst(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := batchClient(t, srv)

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	req := httptest.NewRequest(http.MethodPost, batchPath, strings.NewReader(`{`))

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Path and body on one route
// ---------------------------------------------------------------------------

func TestAuthorize_BodyScope_PathAndBodyOnOneRoute(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/transactions"

	srv := newDecidingAuthServer(t, "led-out")
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, route, Dim("ledgerId", FromBody).At("items[].ledgerId"))

	app := fiber.New()
	app.Post(route, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, "/v1/organizations/org-1/transactions", partnerToken("acme/p1"),
		`{"items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"}]}`)

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, srv.attributeCalls())

	got = doPost(t, app, "/v1/organizations/org-1/transactions", partnerToken("acme/p1"),
		`{"items":[{"ledgerId":"led-1"},{"ledgerId":"led-out"}]}`)

	assert.Equal(t, http.StatusForbidden, got.status)
}

// The body dimensions belong to the route they were declared for: the same
// handler on another method or path reads nothing from the body.
func TestAuthorize_BodyScope_OnlyForItsRoute(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath, Dim("organizationId", FromBody).At("organizationId"))

	handler := auth.Authorize("midaz", "transactions", "post")

	app := fiber.New()
	app.Post(directPath, handler, ok)
	app.Put(directPath, handler, ok)
	app.Post("/v2/transactions/hold", handler, ok)

	assert.Equal(t, http.StatusOK, doPost(t, app, directPath, partnerToken("acme/p1"), `{"organizationId":"org-1"}`).status)

	// No dimension on the other two routes: a partner credential is refused
	// before the call, exactly as an undeclared route.
	assert.Equal(t, http.StatusForbidden, doPost(t, app, "/v2/transactions/hold", partnerToken("acme/p1"), `{"organizationId":"org-1"}`).status)

	req := httptest.NewRequest(http.MethodPut, directPath, strings.NewReader(`{"organizationId":"org-1"}`))
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, int64(1), srv.hits.Load())
}

// ---------------------------------------------------------------------------
// The handler still reads the body
// ---------------------------------------------------------------------------

func TestAuthorize_BodyScope_HandlerReadsTheBodyIntact(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := batchClient(t, srv)

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	const body = `{"organizationId":"org-1",  "items":[{"ledgerId":"led-1","amount":"10.00"}],"metadata":{"k":"v"}}`

	got := doPost(t, app, batchPath, partnerToken("acme/p1"), body)

	require.Equal(t, http.StatusOK, got.status)

	probe.mu.Lock()
	defer probe.mu.Unlock()

	assert.Equal(t, body, string(probe.body), "the handler reads the exact bytes the caller sent")
}

// ---------------------------------------------------------------------------
// Explicit declaration
// ---------------------------------------------------------------------------

func TestAuthorize_BodyScope_ExplicitDeclaration(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-out")
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post",
		RequireScope("midaz", Dim("organizationId", FromBody).At("organizationId"), Dim("ledgerId", FromBody).At("items[].ledgerId"))), ok)

	got := doPost(t, app, batchPath, partnerToken("acme/p1"), `{"organizationId":"org-1","items":[{"ledgerId":"led-1"}]}`)
	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1", "ledgerId": "led-1"}}, srv.attributeCalls())

	got = doPost(t, app, batchPath, partnerToken("acme/p1"), `{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-out"}]}`)
	assert.Equal(t, http.StatusForbidden, got.status)

	got = doPost(t, app, batchPath, partnerToken("acme/p1"), `{"organizationId":"org-1","items":[{}]}`)
	assert.Equal(t, http.StatusBadRequest, got.status)
}

// The scope a handler reads back lists every question that was allowed.
func TestAuthorize_BodyScope_RequestScopeListsEveryQuestion(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := batchClient(t, srv)

	var seen RequestScope

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), func(c fiber.Ctx) error {
		seen, _ = ScopeFromContext(c.Context())

		return c.SendString("ok")
	})

	got := doPost(t, app, batchPath, partnerToken("acme/p1"),
		`{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"}]}`)

	require.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, "acme/p1", seen.Partner)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, seen.Sets)
	assert.Equal(t, map[string]string{"organizationId": "org-1"}, seen.Attributes,
		"Attributes keeps only what every question shares")
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func TestSetManifestRouteScope_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		path    string
		dims    []Dimension
		wantErr string
	}{
		{name: "no_dims", method: "POST", path: directPath, wantErr: "no dimension"},
		{name: "empty_method", method: "", path: directPath, dims: []Dimension{Dim("organizationId", FromBody).At("organizationId")}, wantErr: "method"},
		{name: "relative_path", method: "POST", path: "v2/x", dims: []Dimension{Dim("organizationId", FromBody).At("organizationId")}, wantErr: "path"},
		{name: "path_dim", method: "POST", path: directPath, dims: []Dimension{Dim("organizationId", FromPath).At("organization_id")}, wantErr: "derived from the path"},
		{name: "outside_catalog", method: "POST", path: directPath, dims: []Dimension{Dim("portfolioId", FromBody).At("portfolioId")}, wantErr: "portfolioId"},
		{name: "empty_field", method: "POST", path: directPath, dims: []Dimension{Dim("organizationId", FromBody).At("")}, wantErr: "empty request key"},
		{name: "empty_segment", method: "POST", path: directPath, dims: []Dimension{Dim("organizationId", FromBody).At("a..b")}, wantErr: "a..b"},
		{name: "empty_key_after_array", method: "POST", path: directPath, dims: []Dimension{Dim("organizationId", FromBody).At("ids[].")}, wantErr: `"ids[]."`},
		{name: "bad_brackets", method: "POST", path: directPath, dims: []Dimension{Dim("organizationId", FromBody).At("a[0].b")}, wantErr: "a[0].b"},
		{name: "same_name_same_field", method: "POST", path: directPath, dims: []Dimension{
			Dim("organizationId", FromBody).At("items[].organizationId"), Dim("organizationId", FromBody).At("items[].organizationId"),
		}, wantErr: "more than once"},
		{name: "element_misses_a_dimension", method: "POST", path: directPath, dims: []Dimension{
			Dim("organizationId", FromBody).At("debits[].organizationId"), Dim("ledgerId", FromBody).At("debits[].ledgerId"),
			Dim("organizationId", FromBody).At("credits[].organizationId"),
		}, wantErr: "ledgerId"},
		{name: "same_header_twice", method: "POST", path: directPath, dims: []Dimension{
			Dim("organizationId", FromHeader).At("X-Org"), Dim("organizationId", FromHeader).At("x-org"),
		}, wantErr: "more than once"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auth := &AuthClient{Logger: &testLogger{}}
			require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

			err := auth.SetManifestRouteScope("midaz", tt.method, tt.path, tt.dims...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestSetManifestRouteScope_NeedsTheCatalog(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Logger: &testLogger{}}

	err := auth.SetManifestRouteScope("midaz", http.MethodPost, directPath, Dim("organizationId", FromBody).At("organizationId"))
	require.Error(t, err)

	var nilAuth *AuthClient
	require.Error(t, nilAuth.SetManifestRouteScope("midaz", http.MethodPost, directPath, Dim("organizationId", FromBody).At("organizationId")))
}

// Resetting the catalog drops the routes declared against it.
func TestSetManifestScope_ResetDropsRouteScopes(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath, Dim("organizationId", FromBody).At("organizationId"))
	require.NoError(t, auth.SetManifestScope("midaz"))
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	assert.Equal(t, http.StatusForbidden, doPost(t, app, directPath, partnerToken("acme/p1"), `{"organizationId":"org-1"}`).status)
	assert.Equal(t, int64(0), srv.hits.Load())
}

func TestRequireScope_BodyFieldValidation(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Post("/bad", auth.Authorize("midaz", "transactions", "post",
		RequireScope("midaz", Dim("organizationId", FromBody).At("items[]."))), ok)
	app.Post("/split", auth.Authorize("midaz", "transactions", "post",
		RequireScope("midaz", Dim("organizationId", FromBody).At("a[].organizationId"), Dim("ledgerId", FromBody).At("b[].ledgerId"))), ok)

	assert.Equal(t, http.StatusForbidden, doPost(t, app, "/bad", userToken(), `{"items":["x"]}`).status)
	assert.Equal(t, http.StatusForbidden, doPost(t, app, "/split", userToken(),
		`{"a":[{"organizationId":"o"}],"b":[{"ledgerId":"l"}]}`).status)
	assert.Equal(t, int64(0), srv.hits.Load(), "a misdeclared route refuses before the call")
}

// A route's dimensions go through one pipeline whatever their source: a header
// dimension declared on the route joins every question its body makes.
func TestAuthorize_RouteScope_HeaderAndBodyShareOnePipeline(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, batchPath,
		Dim("organizationId", FromHeader).At("X-Organization-Id"),
		Dim("ledgerId", FromBody).At("items[].ledgerId"))

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	req := httptest.NewRequest(http.MethodPost, batchPath, strings.NewReader(`{"items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"}]}`))
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))
	req.Header.Set("X-Organization-Id", "org-1")

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, srv.attributeCalls())
}

// A catalog reset after a route was registered reaches that route: it never
// keeps reading the body with the plan the reset dropped.
func TestSetManifestScope_ResetAfterRegistrationReachesTheRoute(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, batchPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At("items[].ledgerId"))

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	const body = `{"organizationId":"org-1","items":[{"ledgerId":"led-1"}],"target":{"id":"led-9"}}`

	// Positive control: the route reads the body as declared.
	require.Equal(t, http.StatusOK, doPost(t, app, batchPath, partnerToken("acme/p1"), body).status)
	require.Equal(t, int64(1), srv.hits.Load())

	// Reset: no catalog, no route scope. The partner request is refused before
	// the call, as on any route that declares nothing.
	require.NoError(t, auth.SetManifestScope("midaz"))
	assert.Equal(t, http.StatusForbidden, doPost(t, app, batchPath, partnerToken("acme/p1"), body).status)
	assert.Equal(t, int64(1), srv.hits.Load(), "the dropped plan is not used")

	// Redeclared with another field: the route reads the new one.
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, batchPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At("target.id")))

	assert.Equal(t, http.StatusOK, doPost(t, app, batchPath, partnerToken("acme/p1"), body).status)
	calls := srv.attributeCalls()
	assert.Equal(t, map[string]string{"organizationId": "org-1", "ledgerId": "led-9"}, calls[len(calls)-1])
}

// A route scope declared after the route already served a request reaches it.
func TestSetManifestRouteScope_AfterARequestReachesTheRoute(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	const body = `{"organizationId":"org-1"}`

	// Nothing declared yet: refused before the call.
	require.Equal(t, http.StatusForbidden, doPost(t, app, batchPath, partnerToken("acme/p1"), body).status)
	require.Equal(t, int64(0), srv.hits.Load())

	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, batchPath,
		Dim("organizationId", FromBody).At("organizationId")))

	assert.Equal(t, http.StatusOK, doPost(t, app, batchPath, partnerToken("acme/p1"), body).status)
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
}
