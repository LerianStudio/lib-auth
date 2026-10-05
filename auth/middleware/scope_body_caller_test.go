package middleware

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The body is read for partner-bound credentials only
// ---------------------------------------------------------------------------

// A credential that is not partner-bound is decided exactly as on a route with
// no scope: one call without attributes, and the body left to the handler,
// however it is shaped.
func TestAuthorize_BodyScope_NonPartnerIsDecidedWithoutTheBody(t *testing.T) {
	t.Parallel()

	const route = "/v1/organizations/:organization_id/transactions"

	for _, body := range []string{
		`{"items":[`,
		`{}`,
		`{"items":[{"ledgerId":42}]}`,
		`{"items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"},{"ledgerId":"led-3"}]}`,
	} {
		srv := newDecidingAuthServer(t)
		auth := bodyScopedClient(t, srv.URL, http.MethodPost, route, Dim("ledgerId", FromBody).At("items[].ledgerId"))

		probe := &handlerProbe{}
		app := fiber.New()
		app.Post(route, auth.Authorize("midaz", "transactions", "post"), probe.handle)

		got := doPost(t, app, "/v1/organizations/org-1/transactions", userToken(), body)

		assert.Equal(t, http.StatusOK, got.status, body)
		assert.Equal(t, []map[string]string{nil}, srv.attributeCalls(), body)
		assert.Equal(t, int64(1), probe.calls.Load(), body)

		probe.mu.Lock()
		assert.Equal(t, body, string(probe.body), "the handler reads the body untouched")
		probe.mu.Unlock()
	}
}

// With no dimension outside the body, a non-partner request sends no attributes
// at all — the bytes it sent before the route declared any.
func TestAuthorize_BodyScope_NonPartnerOnABodyOnlyRouteSendsNoAttributes(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := bodyScopedClient(t, rec.URL, http.MethodPost, batchPath, Dim("ledgerId", FromBody).At("items[].ledgerId"))

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, batchPath, userToken(), `not json`)

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, `{"action":"post","product":"midaz","resource":"transactions","sub":"acme-org/user-1"}`, rec.lastBody(t))
	assert.Equal(t, int64(1), rec.hits.Load())
}

// The positive control of the two above: the same malformed body from a
// partner-bound credential is refused with 400 and makes no call.
func TestAuthorize_BodyScope_PartnerWithAMalformedBodyIsABadRequest(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := batchClient(t, srv)

	probe := &handlerProbe{}
	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

	got := doPost(t, app, batchPath, partnerToken("acme/p1"), `{"items":[`)

	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Equal(t, int64(0), srv.hits.Load())
	assert.Equal(t, int64(0), probe.calls.Load())
}

// ---------------------------------------------------------------------------
// One request, one deadline, one principal, first deny wins
// ---------------------------------------------------------------------------

// slowAuthServer allows every call after delay.
func slowAuthServer(t *testing.T, delay time.Duration) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)

		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthResponse{Authorized: true})
	}))
	t.Cleanup(srv.Close)

	return srv, &hits
}

// Every question of a request shares ONE timeout: a slow authorization service
// spends the request's budget once, not once per question.
func TestAuthorize_BodyScope_OneDeadlineForTheWholeRequest(t *testing.T) {
	t.Parallel()

	const (
		delay   = 100 * time.Millisecond
		timeout = 250 * time.Millisecond
	)

	srv, hits := slowAuthServer(t, delay)

	auth := &AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true, timeout: timeout}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, batchPath,
		Dim("organizationId", FromBody).At("organizationId"), Dim("ledgerId", FromBody).At("items[].ledgerId")))

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	body := `{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"},{"ledgerId":"led-3"}]}`

	req := httptest.NewRequest(http.MethodPost, batchPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

	start := time.Now()

	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	require.NoError(t, err)

	defer resp.Body.Close()

	elapsed := time.Since(start)

	// Each call alone fits the timeout with room to spare; three in a row
	// (3 x delay) do not fit one.
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Less(t, elapsed, 2*timeout, "the request is bounded by one budget, not one per question")
	assert.LessOrEqual(t, hits.Load(), int64(3))

	// Positive control: one question fits the same budget.
	req = httptest.NewRequest(http.MethodPost, batchPath,
		strings.NewReader(`{"organizationId":"org-1","items":[{"ledgerId":"led-1"}]}`))
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

	resp, err = app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// The token is verified once per request, however many questions the body
// makes.
func TestAuthorize_BodyScope_PrincipalIsDerivedOnce(t *testing.T) {
	t.Parallel()

	key, _ := pubKeyOf(t)
	source := &fakeKeySource{keys: []*rsa.PublicKey{&key.PublicKey}}

	srv := newDecidingAuthServer(t)
	auth := (&AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}).WithKeySource(source)
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))
	require.NoError(t, auth.SetManifestRouteScope("midaz", http.MethodPost, batchPath,
		Dim("organizationId", FromBody).At("organizationId"), Dim("ledgerId", FromBody).At("items[].ledgerId")))

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	token := signRS256(t, key, jwt.MapClaims{
		"type": "application", "sub": "acme/app", "partner": "acme/p1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	got := doPost(t, app, batchPath, token,
		`{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"},{"ledgerId":"led-3"}]}`)

	require.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, int64(3), srv.hits.Load(), "three questions were asked")

	source.mu.Lock()
	defer source.mu.Unlock()

	assert.Equal(t, 1, source.keysCount, "and the token was verified once")
}

// The first denied question ends the request: nothing after it is asked.
func TestAuthorize_BodyScope_StopsAtTheFirstDeny(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-out")
	auth := batchClient(t, srv)

	app := fiber.New()
	app.Post(batchPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, batchPath, partnerToken("acme/p1"),
		`{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{"ledgerId":"led-out"},{"ledgerId":"led-2"},{"ledgerId":"led-3"}]}`)

	assert.Equal(t, http.StatusForbidden, got.status)
	assert.Equal(t, int64(2), srv.hits.Load())
}
