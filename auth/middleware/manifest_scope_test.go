package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// manifestDims is the scope catalog the tests wire, in tree order.
func manifestDims() []Dimension {
	return []Dimension{
		Dim("organizationId", FromPath).At("organization_id"),
		Dim("ledgerId", FromPath).At("ledger_id"),
	}
}

func dimNames(dims []Dimension) []string {
	out := make([]string, 0, len(dims))
	for _, d := range dims {
		out = append(out, d.Name())
	}

	return out
}

// errorCapturingLogger records every message logged at ERROR.
type errorCapturingLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *errorCapturingLogger) Log(_ context.Context, level int, msg string, _ ...any) {
	if level != obs.LevelError {
		return
	}

	l.mu.Lock()
	l.msgs = append(l.msgs, msg)
	l.mu.Unlock()
}

func (l *errorCapturingLogger) Enabled(_ int) bool           { return true }
func (l *errorCapturingLogger) Sync(_ context.Context) error { return nil }

func (l *errorCapturingLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return strings.Join(l.msgs, "\n")
}

// ---------------------------------------------------------------------------
// Path derivation
// ---------------------------------------------------------------------------

func TestDeriveRouteDimensions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want []string
	}{
		{name: "both_params", path: "/v1/organizations/:organization_id/ledgers/:ledger_id/accounts", want: []string{"organizationId", "ledgerId"}},
		{name: "top_only", path: "/v1/organizations/:organization_id", want: []string{"organizationId"}},
		// Tree order is the manifest's, never the path's.
		{name: "order_is_manifest_order", path: "/x/:ledger_id/y/:organization_id", want: []string{"organizationId", "ledgerId"}},
		{name: "no_params", path: "/v1/health", want: []string{}},
		{name: "other_params_only", path: "/v1/things/:thing_id", want: []string{}},
		// The ':' marker is required: a literal segment spelling the param is text.
		{name: "literal_segment_is_not_a_param", path: "/v1/organization_id/ledgers/:ledger_id", want: []string{"ledgerId"}},
		// The WHOLE segment must be the parameter.
		{name: "longer_param_name", path: "/v1/organizations/:organization_id_x", want: []string{}},
		{name: "param_prefix_of_segment", path: "/v1/organizations/:organization_id.json", want: []string{}},
		{name: "param_suffix_of_segment", path: "/v1/organizations/x:organization_id", want: []string{}},
		{name: "optional_param_is_not_the_param", path: "/v1/organizations/:organization_id?", want: []string{}},
		{name: "trailing_slash", path: "/v1/organizations/:organization_id/", want: []string{"organizationId"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := deriveRouteDimensions(manifestDims(), tt.path)
			assert.Equal(t, tt.want, dimNames(got))

			for _, d := range got {
				assert.Equal(t, FromPath, d.Source())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SetManifestScope validation
// ---------------------------------------------------------------------------

func TestSetManifestScope_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		product string
		dims    []Dimension
		wantErr string
	}{
		{name: "valid", product: "midaz", dims: manifestDims()},
		{name: "empty_is_valid", product: "midaz"},
		{name: "empty_product", product: " ", dims: manifestDims(), wantErr: "product"},
		{name: "empty_name", product: "midaz", dims: []Dimension{Dim("", FromPath).At("x")}, wantErr: "no name"},
		{name: "from_body", product: "midaz", dims: []Dimension{Dim("organizationId", FromBody)}, wantErr: "path, the query or a header"},
		{name: "empty_key", product: "midaz", dims: []Dimension{Dim("organizationId", FromPath).At("")}, wantErr: "empty"},
		{
			name: "duplicate_name", product: "midaz",
			dims:    []Dimension{Dim("organizationId", FromPath).At("a"), Dim("organizationId", FromPath).At("b")},
			wantErr: "more than once",
		},
		{
			name: "duplicate_param", product: "midaz",
			dims:    []Dimension{Dim("organizationId", FromPath).At("a"), Dim("ledgerId", FromPath).At("a")},
			wantErr: "more than once",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auth := &AuthClient{Logger: &testLogger{}}

			err := auth.SetManifestScope(tt.product, tt.dims...)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestSetManifestScope_NilReceiver(t *testing.T) {
	t.Parallel()

	var auth *AuthClient

	require.Error(t, auth.SetManifestScope("midaz", manifestDims()...))
}

// ---------------------------------------------------------------------------
// Authorize with a manifest scope
// ---------------------------------------------------------------------------

func scopedClient(t *testing.T, rec *fakeAuthServer) *AuthClient {
	t.Helper()

	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	return auth
}

func ok(c fiber.Ctx) error { return c.SendString("ok") }

func doGet(t *testing.T, app *fiber.App, target, token string) int {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	require.NoError(t, err)

	return resp.StatusCode
}

// A route that declares nothing, on a client with a manifest scope, sends the
// dimensions its path carries — on the same wire as an explicit declaration.
func TestAuthorize_ManifestScope_DerivesAttributesFromThePath(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id/accounts",
		auth.Authorize("midaz", "accounts", "get"), ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1/accounts", partnerToken("acme/p1")))
	assert.JSONEq(t,
		`{"action":"get","product":"midaz","resource":"accounts","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1"}}`,
		rec.lastBody(t))
}

// Parameters declared on a group prefix are part of the route's path too.
func TestAuthorize_ManifestScope_SeesGroupPrefixParams(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := fiber.New()
	group := app.Group("/v1/organizations/:organization_id")
	group.Get("/ledgers/:ledger_id", auth.Authorize("midaz", "ledgers", "get"), ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1", partnerToken("acme/p1")))
	assert.JSONEq(t,
		`{"action":"get","product":"midaz","resource":"ledgers","sub":"acme/app","attributes":{"organizationId":"org-1","ledgerId":"led-1"}}`,
		rec.lastBody(t))
}

// One handler registered on several routes derives per route.
func TestAuthorize_ManifestScope_SharedHandlerDerivesPerRoute(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	handler := auth.Authorize("midaz", "ledgers", "get")

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id", handler, ok)
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id", handler, ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1", partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1","ledgerId":"led-1"}`, attributesOf(t, rec.lastBody(t)))

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-2", partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-2"}`, attributesOf(t, rec.lastBody(t)))
}

// A path with none of the manifest's parameters derives nothing and behaves as
// an undeclared route: a partner credential is asked with no attributes, while a
// non-partner caller sends the same bytes as before.
func TestAuthorize_ManifestScope_PathWithoutParamsIsUndeclared(t *testing.T) {
	t.Parallel()

	rec := newScopedPartnerAuthServer(t)
	auth := scopedClient(t, rec)

	app := fiber.New()
	app.Get("/v1/organization_id/settings", auth.Authorize("midaz", "settings", "get"), ok)

	assert.Equal(t, http.StatusForbidden, doGet(t, app, "/v1/organization_id/settings", partnerToken("acme/p1")))
	assert.Equal(t, []map[string]string{nil}, rec.attributeCalls(), "asked, with no attributes")

	// Positive control: same route, non-partner caller.
	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organization_id/settings", userToken()))
	assert.Equal(t, `{"action":"get","product":"midaz","resource":"settings","sub":"acme-org/user-1"}`, rec.lastBody(t))
}

// The manifest scope belongs to its product: a route of another product on the
// same client derives nothing.
func TestAuthorize_ManifestScope_OnlyForItsProduct(t *testing.T) {
	t.Parallel()

	rec := newScopedPartnerAuthServer(t)
	auth := scopedClient(t, rec)

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/routes", auth.Authorize("routing", "routes", "get"), ok)

	assert.Equal(t, http.StatusForbidden, doGet(t, app, "/v1/organizations/org-1/routes", partnerToken("acme/p1")))
	assert.Equal(t, []map[string]string{nil}, rec.attributeCalls(), "asked, with no attributes")

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/routes", userToken()))
	assert.NotContains(t, rec.lastBody(t), "attributes")
}

// An explicit declaration keeps working and wins over derivation.
func TestAuthorize_ManifestScope_ExplicitDeclarationStillWorks(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := scopedClient(t, rec)

	app := fiber.New()
	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id",
		auth.Authorize("midaz", "ledgers", "get",
			RequireScope("midaz", Dim("organizationId", FromPath).At("organization_id"))),
		ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1/ledgers/led-1", partnerToken("acme/p1")))
	assert.JSONEq(t, `{"organizationId":"org-1"}`, attributesOf(t, rec.lastBody(t)))
}

// An explicit declaration naming a dimension the manifest scope does not
// declare refuses every request, and says so in the log on the route's first
// request — whichever of the catalog and the route was wired first.
func TestAuthorize_ManifestScope_ExplicitDimensionOutsideTheCatalogIsRefused(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	logger := &errorCapturingLogger{}

	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: logger, M2MInversionEnabled: true}
	require.NoError(t, auth.SetManifestScope("midaz", manifestDims()...))

	handler := auth.Authorize("midaz", "accounts", "get",
		RequireScope("midaz", Dim("portfolioId", FromPath).At("portfolio_id")))

	app := fiber.New()
	app.Get("/v1/portfolios/:portfolio_id", handler, ok)

	assert.Equal(t, http.StatusForbidden, doGet(t, app, "/v1/portfolios/pf-1", userToken()))
	assert.Equal(t, int64(0), rec.hits.Load())
	assert.Contains(t, logger.all(), "portfolioId", "the misdeclaration is logged")

	// Positive control: a declared dimension on the same client is honoured.
	app.Get("/v1/organizations/:organization_id",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("organizationId", FromPath).At("organization_id"))),
		ok)
	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/organizations/org-1", userToken()))
}

// Without a manifest scope an explicit declaration is not checked against any
// catalog — exactly as before.
func TestAuthorize_NoManifestScope_ExplicitDeclarationUnchecked(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	app := fiber.New()
	app.Get("/v1/portfolios/:portfolio_id",
		auth.Authorize("midaz", "accounts", "get",
			RequireScope("midaz", Dim("portfolioId", FromPath).At("portfolio_id"))),
		ok)

	assert.Equal(t, http.StatusOK, doGet(t, app, "/v1/portfolios/pf-1", partnerToken("acme/p1")))
	assert.JSONEq(t, `{"portfolioId":"pf-1"}`, attributesOf(t, rec.lastBody(t)))
}

// attributesOf returns the attributes member of an authorize body, re-encoded.
func attributesOf(t *testing.T, body string) string {
	t.Helper()

	var parsed struct {
		Attributes json.RawMessage `json:"attributes"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))

	return string(parsed.Attributes)
}
