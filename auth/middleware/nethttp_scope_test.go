package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// net/http adapter - manifest scope and body scope, in parity with Authorize
// ---------------------------------------------------------------------------

// bodyEcho is a net/http handler that records how often it ran and the body it
// read.
type bodyEcho struct {
	calls atomic.Int64
	mu    sync.Mutex
	body  []byte
}

func (e *bodyEcho) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.calls.Add(1)

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	e.mu.Lock()
	e.body = raw
	e.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func postWithBearer(target, token, body string) func() *http.Request {
	return func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		return req
	}
}

// A route that passes no RequireScope, on a client with a manifest scope, sends
// the dimensions its ServeMux pattern carries, exactly as Authorize does with
// the Fiber route path.
func TestAuthorizeHTTP_ManifestScope_DerivesAttributesFromThePattern(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{
		"GET /v1/organizations/{organization_id}/ledgers/{ledger_id}/accounts",
		"/v1/organizations/{organization_id}/ledgers/{ledger_id}/accounts",
		"example.com/v1/organizations/{organization_id}/ledgers/{ledger_id}/accounts",
	} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := scopedClient(t, rec)

			var reached atomic.Bool

			got := serveGated(t, pattern, auth.AuthorizeHTTP("midaz", "accounts", "get")(principalEcho(&reached)), func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/v1/organizations/org-1/ledgers/led-1/accounts", nil)
				req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

				return req
			})

			require.Equal(t, http.StatusOK, got.Code)
			assert.True(t, reached.Load())
			assert.JSONEq(t,
				`{"action":"get","product":"midaz","resource":"accounts","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1"}}`,
				rec.lastBody(t))
		})
	}
}

// A pattern whose path carries no catalog parameter derives nothing, so a
// partner is refused before the call, as on a Fiber route.
func TestAuthorizeHTTP_ManifestScope_PatternWithoutParamsIsUndeclared(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	got := serveGated(t, "GET /v1/health-of-things", auth.AuthorizeHTTP("midaz", "things", "get")(principalEcho(nil)), func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/health-of-things", nil)
		req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

		return req
	})

	assert.Equal(t, http.StatusForbidden, got.Code)
	assert.Empty(t, rec.recordedBodies(), "an unscopeable partner request never reaches the Access Manager")
}

// A body-scoped route asks one question per element and refuses the whole
// request when one is denied; an allowed request reaches the handler with the
// exact bytes the caller sent.
func TestAuthorizeHTTP_BodyScope_Batch(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-out")
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At("items[].ledgerId"))

	echo := &bodyEcho{}
	gated := auth.AuthorizeHTTP("midaz", "transactions", "post")(echo)
	pattern := "POST " + directPath

	const allowed = `{"organizationId":"org-1",  "items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"}]}`

	got := serveGated(t, pattern, gated, postWithBearer(directPath, partnerToken("acme/p1"), allowed))
	require.Equal(t, http.StatusOK, got.Code)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-2"},
	}, srv.attributeCalls())

	echo.mu.Lock()
	assert.Equal(t, allowed, string(echo.body), "the handler reads the exact bytes the caller sent")
	echo.mu.Unlock()

	got = serveGated(t, pattern, gated, postWithBearer(directPath, partnerToken("acme/p1"),
		`{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-out"}]}`))
	assert.Equal(t, http.StatusForbidden, got.Code)
	assert.Equal(t, int64(1), echo.calls.Load(), "a refused request never reaches the handler")
}

// A body that cannot be read for the declared dimensions is a 400 naming the
// field, before any call; a body over the limit is a 413, before any call.
func TestAuthorizeHTTP_BodyScope_UnreadableBodies(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId"))

	echo := &bodyEcho{}
	gated := auth.AuthorizeHTTP("midaz", "transactions", "post")(echo)
	pattern := "POST " + directPath

	got := serveGated(t, pattern, gated, postWithBearer(directPath, partnerToken("acme/p1"), `{"ledgerId":"led-1"}`))
	assert.Equal(t, http.StatusBadRequest, got.Code)
	assert.Contains(t, got.Body.String(), `"organizationId"`)

	got = serveGated(t, pattern, gated, postWithBearer(directPath, partnerToken("acme/p1"), "not json"))
	assert.Equal(t, http.StatusBadRequest, got.Code)

	oversized := `{"organizationId":"org-1","pad":"` + strings.Repeat("x", maxAuthorizeHTTPBodyBytes) + `"}`

	got = serveGated(t, pattern, gated, postWithBearer(directPath, partnerToken("acme/p1"), oversized))
	assert.Equal(t, http.StatusRequestEntityTooLarge, got.Code)

	assert.Zero(t, srv.hits.Load(), "an unreadable body never reaches the Access Manager")
	assert.Zero(t, echo.calls.Load(), "an unreadable body never reaches the handler")
}

// The body is read only for a partner-bound credential: any other caller is
// decided without it, and its handler still reads the body untouched.
func TestAuthorizeHTTP_BodyScope_NotReadForANonPartner(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId"))

	echo := &bodyEcho{}

	got := serveGated(t, "POST "+directPath, auth.AuthorizeHTTP("midaz", "transactions", "post")(echo),
		postWithBearer(directPath, createTestJWT(appTokenClaims("acme/app")), "not json"))

	require.Equal(t, http.StatusOK, got.Code)
	assert.Equal(t, int64(1), srv.hits.Load(), "a non-partner is decided on one question")

	echo.mu.Lock()
	assert.Equal(t, "not json", string(echo.body))
	echo.mu.Unlock()
}

func TestServeMuxRoutePath(t *testing.T) {
	t.Parallel()

	for pattern, want := range map[string]string{
		"":                             "",
		"/":                            "/",
		"GET /a/{b}/c":                 "/a/:b/c",
		"POST /a/{b}/{c...}":           "/a/:b/:c",
		"example.com/a/{b}":            "/a/:b",
		"GET example.com/a/{b}/{$}":    "/a/:b/",
		"/v1/organizations/{org}/x{y}": "/v1/organizations/:org/x{y}",
	} {
		assert.Equal(t, want, serveMuxRoutePath(pattern), pattern)
	}
}
