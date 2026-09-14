package middleware

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Scope test helpers
// ---------------------------------------------------------------------------

// recordingAuthServer answers POST /v1/authorize with the supplied decision and
// records every raw request body it received, in order. The RAW bytes are what
// the payload-compatibility assertions compare, so an added member, a reordered
// key or a changed encoding all show up.
type recordingAuthServer struct {
	*httptest.Server

	bodies atomic.Value // []string
	hits   atomic.Int64
}

func newRecordingAuthServer(t *testing.T, resp AuthResponse) *recordingAuthServer {
	t.Helper()

	rec := &recordingAuthServer{}
	rec.bodies.Store([]string{})

	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("mock authz server: failed to read body: %v", err)
		}

		rec.bodies.Store(append(rec.bodies.Load().([]string), string(raw)))
		rec.hits.Add(1)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("mock authz server: failed to encode response: %v", err)
		}
	}))

	t.Cleanup(rec.Server.Close)

	return rec
}

func (rec *recordingAuthServer) lastBody(t *testing.T) string {
	t.Helper()

	bodies := rec.bodies.Load().([]string)
	require.NotEmpty(t, bodies, "authz server was never called")

	return bodies[len(bodies)-1]
}

// partnerToken is an application token carrying the "partner" claim the access
// manager mints for a partner-bound credential.
func partnerToken(partner string) string {
	return createTestJWT(jwt.MapClaims{
		"type":    "application",
		"sub":     "acme/app",
		"partner": partner,
	})
}

// ---------------------------------------------------------------------------
// (1) Payload compatibility: a route that declares nothing sends the SAME bytes
// ---------------------------------------------------------------------------

// The acceptance criterion of the change: every deployed caller that does not
// declare a dimension must put the exact same bytes on the wire as before. The
// expectations are golden literals, not round-trips through the same encoder, so
// an extra member (even an empty "attributes":{}) fails.
func TestAuthorizePayload_WithoutDeclaration_IsByteIdentical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claims   jwt.MapClaims
		clientIP string
		want     string
	}{
		{
			name:   "normal_user_forwards_product",
			claims: jwt.MapClaims{"type": "normal-user", "owner": "acme", "sub": "u1"},
			want:   `{"action":"get","product":"midaz","resource":"accounts","sub":"acme/u1"}`,
		},
		{
			name:   "application_does_not_forward_product",
			claims: jwt.MapClaims{"type": "application", "sub": "acme/app"},
			want:   `{"action":"get","resource":"accounts","sub":"acme/app"}`,
		},
		{
			name:     "normal_user_with_client_ip",
			claims:   jwt.MapClaims{"type": "normal-user", "owner": "acme", "sub": "u1"},
			clientIP: "203.0.113.7",
			want:     `{"action":"get","clientIp":"203.0.113.7","product":"midaz","resource":"accounts","sub":"acme/u1"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

			auth := &AuthClient{
				Address:             rec.URL,
				Enabled:             true,
				Logger:              &testLogger{},
				M2MInversionEnabled: true,
			}

			authorized, status, err := auth.checkAuthorization(
				context.Background(), "midaz", "accounts", "get", createTestJWT(tt.claims), tt.clientIP,
			)

			require.NoError(t, err)
			assert.True(t, authorized)
			assert.Equal(t, http.StatusOK, status)
			assert.JSONEq(t, tt.want, rec.lastBody(t))
			assert.Equal(t, tt.want, rec.lastBody(t), "wire body must be byte-identical to the pre-attributes payload")
		})
	}
}

// ---------------------------------------------------------------------------
// (2) A route that DOES declare dimensions sends them as attributes
// ---------------------------------------------------------------------------

func TestAuthorize_SendsDeclaredAttributes(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz",
				Dim("organizationId", FromPath).At("organization_id"),
				Dim("ledgerId", FromPath).At("ledger_id"),
			),
		),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/ledgers/led-1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.JSONEq(t,
		`{"action":"get","resource":"accounts","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1"}}`,
		rec.lastBody(t))
}

func TestAuthorize_AttributeSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		dim    Dimension
		target string
		header string
		want   string
	}{
		{
			name:   "from_path",
			dim:    Dim("organizationId", FromPath).At("organization_id"),
			target: "/p/org-1",
			want:   `{"organizationId":"org-1"}`,
		},
		{
			name:   "from_header",
			dim:    Dim("organizationId", FromHeader).At("X-Organization-Id"),
			target: "/h",
			header: "org-2",
			want:   `{"organizationId":"org-2"}`,
		},
		{
			name:   "from_query",
			dim:    Dim("organizationId", FromQuery),
			target: "/q?organizationId=org-3",
			want:   `{"organizationId":"org-3"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

			handler := auth.Authorize("midaz", "accounts", "get", RequireScope("midaz", tt.dim))

			app := fiber.New()
			app.Get("/p/:organization_id", handler, func(c fiber.Ctx) error { return c.SendString("ok") })
			app.Get("/h", handler, func(c fiber.Ctx) error { return c.SendString("ok") })
			app.Get("/q", handler, func(c fiber.Ctx) error { return c.SendString("ok") })

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

			if tt.header != "" {
				req.Header.Set("X-Organization-Id", tt.header)
			}

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var body struct {
				Attributes map[string]string `json:"attributes"`
			}
			require.NoError(t, json.Unmarshal([]byte(rec.lastBody(t)), &body))

			got, err := json.Marshal(body.Attributes)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

// ---------------------------------------------------------------------------
// (3) The decision cache keys on the attributes
// ---------------------------------------------------------------------------

// Two requests that differ ONLY in an instance identifier are two different
// questions. Without the attributes in the key the second one is answered from
// the first one's entry — a partner scoped to one ledger reading another's.
func TestDecisionCache_KeyIncludesAttributes(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

	auth := &AuthClient{
		Address:             rec.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
		cache:               newDecisionCache(time.Minute),
	}

	app := fiber.New()
	app.Get("/v1/ledgers/:ledger_id/accounts",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("ledgerId", FromPath).At("ledger_id")),
		),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	token := partnerToken("acme/p1")

	for _, ledger := range []string{"led-1", "led-2", "led-1"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/ledgers/"+ledger+"/accounts", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// led-1, led-2, then led-1 again from cache: two round-trips, not one, not three.
	assert.Equal(t, int64(2), rec.hits.Load(),
		"a different instance identifier must miss the cache; the repeat must hit it")
}

// ---------------------------------------------------------------------------
// (4) Denial reason -> HTTP status
// ---------------------------------------------------------------------------

func TestAuthorize_DenialReasonMapsToStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		reason string
		want   int
	}{
		{name: "no_reason_stays_403", reason: "", want: http.StatusForbidden},
		{name: "permission_stays_403", reason: "permission", want: http.StatusForbidden},
		{name: "scope_stays_403", reason: "scope", want: http.StatusForbidden},
		{name: "suspended_is_401", reason: "suspended", want: http.StatusUnauthorized},
		{name: "expired_is_401", reason: "expired", want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: tt.reason})
			auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

			app := fiber.New()
			app.Get("/x", auth.Authorize("midaz", "accounts", "get"),
				func(c fiber.Ctx) error { return c.SendString("reached") })

			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+userToken())

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, tt.want, resp.StatusCode)
		})
	}
}

// A denial cached with a re-issue reason must replay the same status. Caching
// only the boolean would downgrade the second 401 to a 403.
func TestAuthorize_CachedDenialKeepsItsReason(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: "suspended"})

	auth := &AuthClient{
		Address:             rec.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
		cache:               newDecisionCache(time.Minute),
	}

	app := fiber.New()
	app.Get("/x", auth.Authorize("midaz", "accounts", "get"),
		func(c fiber.Ctx) error { return c.SendString("reached") })

	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+userToken())

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}

	assert.Equal(t, int64(1), rec.hits.Load(), "the second request must be served from the cache")
}

// ---------------------------------------------------------------------------
// (5) Fail-closed guard, both halves
// ---------------------------------------------------------------------------

func TestAuthorize_GuardDeniesPartnerTokenOnUndeclaredRoute(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/x", auth.Authorize("midaz", "accounts", "get"),
		func(c fiber.Ctx) error { return c.SendString("reached") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, int64(0), rec.hits.Load(),
		"an undeclared route cannot be scoped, so the decision is taken here and never asked")

	// Positive control, same route and same rig: a token with no partner claim is
	// authorized normally. Without this the 403 above could be an unrelated denial.
	ctrl := httptest.NewRequest(http.MethodGet, "/x", nil)
	ctrl.Header.Set("Authorization", "Bearer "+userToken())

	ctrlResp, err := app.Test(ctrl)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, ctrlResp.StatusCode)
	assert.Equal(t, int64(1), rec.hits.Load())
}

func TestAuthorize_GuardDeniesEmptyDeclaredSource(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/x",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("organizationId", FromHeader).At("X-Organization-Id")),
		),
		func(c fiber.Ctx) error { return c.SendString("reached") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, int64(0), rec.hits.Load(),
		"a declared dimension with no value cannot be matched, so the request is denied before the call")

	// Positive control: the same route with the header present is authorized.
	ctrl := httptest.NewRequest(http.MethodGet, "/x", nil)
	ctrl.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))
	ctrl.Header.Set("X-Organization-Id", "org-1")

	ctrlResp, err := app.Test(ctrl)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, ctrlResp.StatusCode)
	assert.Equal(t, int64(1), rec.hits.Load())
}

// The empty-source guard is a property of the DECLARATION, not of the token: a
// route that declares a dimension it cannot always read is misdeclared, and a
// non-partner caller must not be the one to discover it in production.
func TestAuthorize_EmptyDeclaredSourceDeniesNonPartnerToo(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/x",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("organizationId", FromHeader).At("X-Organization-Id")),
		),
		func(c fiber.Ctx) error { return c.SendString("reached") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+userToken())

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, int64(0), rec.hits.Load())
}

// A declaration whose product does not match the route's product describes a
// different product's dimensions. Honouring it would send one product's
// identifiers under another's name, which the access manager matches against
// nothing — and a dimension nobody matches never denies.
func TestAuthorize_GuardDeniesProductMismatch(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/x/:organization_id",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("other-product", Dim("organizationId", FromPath).At("organization_id")),
		),
		func(c fiber.Ctx) error { return c.SendString("reached") })

	req := httptest.NewRequest(http.MethodGet, "/x/org-1", nil)
	req.Header.Set("Authorization", "Bearer "+userToken())

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, int64(0), rec.hits.Load())
}

// ---------------------------------------------------------------------------
// (6) and (7): what the handler can read back
// ---------------------------------------------------------------------------

func TestAuthorize_ExposesScopeAndPartnerToTheHandler(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	var (
		gotScope  RequestScope
		gotOK     bool
		gotLocals any
	)

	app := fiber.New()
	app.Get("/v1/ledgers/:ledger_id/accounts",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("ledgerId", FromPath).At("ledger_id")),
		),
		func(c fiber.Ctx) error {
			gotScope, gotOK = ScopeFromContext(c.Context())
			gotLocals = c.Locals(PartnerLocalsKey)

			return c.SendString("ok")
		})

	req := httptest.NewRequest(http.MethodGet, "/v1/ledgers/led-1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.True(t, gotOK)
	assert.Equal(t, "acme/p1", gotScope.Partner)
	assert.Equal(t, map[string]string{"ledgerId": "led-1"}, gotScope.Attributes)
	assert.Equal(t, "acme/p1", gotLocals)
}

// Both context values Authorize publishes must survive the SAME request.
//
// This seam was created by the merge of the scoped-access work into develop and
// was covered by NEITHER side: develop added the Principal and its
// publishPrincipal call, this branch added the RequestScope and its own, and each
// side tested only its own value on its own request. The two run back to back and
// BOTH build their new context from c.Context(), so the second read has to observe
// what the first wrote. Reorder them, drop one, or rebuild either from a context
// captured before the other, and one value silently overwrites the other: the
// handler still gets a 200, still reads one of the two, and nothing turns red
// unless a test reads both on one request.
func TestAuthorize_PublishesPrincipalAndScopeOnTheSameRequest(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	var (
		gotScope     RequestScope
		scopeOK      bool
		gotPrincipal Principal
		principalOK  bool
	)

	app := fiber.New()
	app.Get("/v1/ledgers/:ledger_id/accounts",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("ledgerId", FromPath).At("ledger_id")),
		),
		func(c fiber.Ctx) error {
			// Read BOTH off the same context, in the one handler invocation: that
			// is the whole point of the test.
			gotScope, scopeOK = ScopeFromContext(c.Context())
			gotPrincipal, principalOK = PrincipalFromContext(c.Context())

			return c.SendString("ok")
		})

	req := httptest.NewRequest(http.MethodGet, "/v1/ledgers/led-1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.True(t, scopeOK, "RequestScope must be readable on a request that also publishes a Principal")
	assert.Equal(t, "acme/p1", gotScope.Partner)
	assert.Equal(t, map[string]string{"ledgerId": "led-1"}, gotScope.Attributes)

	require.True(t, principalOK, "Principal must be readable on a request that also publishes a RequestScope")
	assert.Equal(t, application, gotPrincipal.Type)
	assert.Equal(t, "acme/app", gotPrincipal.Subject)
	assert.Equal(t, "acme/app", gotPrincipal.Sub)
}

// A request with no partner claim reaches the handler with no scope recorded, so
// a handler cannot mistake "not a partner" for "a partner with no restriction".
func TestScopeFromContext_AbsentWithoutPartner(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	var (
		gotOK     bool
		gotLocals any
	)

	app := fiber.New()
	app.Get("/x", auth.Authorize("midaz", "accounts", "get"), func(c fiber.Ctx) error {
		_, gotOK = ScopeFromContext(c.Context())
		gotLocals = c.Locals(PartnerLocalsKey)

		return c.SendString("ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+userToken())

	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	assert.False(t, gotOK)
	assert.Nil(t, gotLocals)
}

func TestScopeFromContext_EmptyContext(t *testing.T) {
	t.Parallel()

	_, ok := ScopeFromContext(context.Background())
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// Declaration helpers
// ---------------------------------------------------------------------------

func TestDim_DefaultsRequestKeyToTheFieldName(t *testing.T) {
	t.Parallel()

	d := Dim("organizationId", FromQuery)
	assert.Equal(t, "organizationId", d.Name())
	assert.Equal(t, "organizationId", d.Key())
	assert.Equal(t, FromQuery, d.Source())

	renamed := d.At("organization_id")
	assert.Equal(t, "organizationId", renamed.Name())
	assert.Equal(t, "organization_id", renamed.Key())
	assert.Equal(t, "organizationId", d.Key(), "At must not mutate the original declaration")
}

// ---------------------------------------------------------------------------
// Cache-key injectivity
// ---------------------------------------------------------------------------

// The folded cache key must be injective: no two DIFFERENT attribute maps may
// fold to the same string. Separator bytes are not a guarantee — a caller can put
// them inside a value — so the encoding has to distinguish the boundaries by
// construction.
func TestAttributesCacheKey_IsInjectiveAcrossSeparatorBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    map[string]string
		b    map[string]string
	}{
		{
			name: "value carrying both separators vs two fields",
			a:    map[string]string{"a": "b\x1ec\x1fd"},
			b:    map[string]string{"a": "b", "c": "d"},
		},
		{
			name: "value carrying the pair separator",
			a:    map[string]string{"a": "b\x1e"},
			b:    map[string]string{"a": "b"},
		},
		{
			name: "name/value boundary moved",
			a:    map[string]string{"a": "b"},
			b:    map[string]string{"ab": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.NotEqual(t, attributesCacheKey(tt.a), attributesCacheKey(tt.b),
				"two different attribute maps must never fold to the same cache key")
		})
	}
}

// The same collision, driven through a real request: a caller percent-encodes the
// separator bytes in a query value, and the folded key must still differ from the
// key of a genuine two-field scope. If it does not, the second request is answered
// from the first one's cache entry and the access manager is never consulted —
// one partner's decision serving another partner's question.
func TestDecisionCache_SeparatorBytesInAValueDoNotForgeAnotherScopesKey(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

	auth := &AuthClient{
		Address:             rec.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
		cache:               newDecisionCache(time.Minute),
	}

	app := fiber.New()
	app.Get("/one",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("a", FromQuery)),
		),
		func(c fiber.Ctx) error { return c.SendString("ok") })
	app.Get("/two",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("a", FromQuery), Dim("c", FromQuery)),
		),
		func(c fiber.Ctx) error { return c.SendString("ok") })

	token := partnerToken("acme/p1")

	// First the crafted single field: the value carries the two separator bytes.
	crafted := httptest.NewRequest(http.MethodGet, "/one?a=b%1Ec%1Fd", nil)
	crafted.Header.Set("Authorization", "Bearer "+token)

	craftedResp, err := app.Test(crafted)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, craftedResp.StatusCode)

	// Then the genuine two-field scope it was shaped to impersonate.
	genuine := httptest.NewRequest(http.MethodGet, "/two?a=b&c=d", nil)
	genuine.Header.Set("Authorization", "Bearer "+token)

	genuineResp, err := app.Test(genuine)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, genuineResp.StatusCode)

	assert.Equal(t, int64(2), rec.hits.Load(),
		"the crafted value must not key as the genuine two-field scope; both questions must reach the access manager")
}
