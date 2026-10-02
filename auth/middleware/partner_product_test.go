package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// m2mForwardingModes are the M2M product-forwarding switch combinations that do
// NOT forward the product for a plain application: forwarding needs both keys on.
var m2mForwardingModes = []struct {
	name             string
	forwardM2M       bool
	inversionEnabled bool
}{
	{name: "both_keys_off", forwardM2M: false, inversionEnabled: false},
	{name: "inversion_only", forwardM2M: false, inversionEnabled: true},
	{name: "forward_only", forwardM2M: true, inversionEnabled: false},
}

// A partner-bound credential is an application token, but the access manager
// resolves a partner's grants BY PRODUCT. Without the product in the body it
// looks the grants up under an empty product, finds none, and denies every
// route — even one inside the partner's own scope. The product therefore goes
// on the wire for a partner regardless of the M2M forwarding keys.
func TestAuthorize_PartnerForwardsProductRegardlessOfM2MKeys(t *testing.T) {
	t.Parallel()

	for _, mode := range m2mForwardingModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

			auth := &AuthClient{
				Address:             rec.URL,
				Enabled:             true,
				Logger:              &testLogger{},
				ForwardM2MProduct:   mode.forwardM2M,
				M2MInversionEnabled: mode.inversionEnabled,
			}

			app := fiber.New()
			app.Get("/v1/organizations/:organization_id/accounts",
				auth.Authorize("midaz", "accounts", "get",
					RequireScope("midaz", Dim("organizationId", FromPath).At("organization_id")),
				),
				func(c fiber.Ctx) error { return c.SendString("ok") })

			req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org-1/accounts", nil)
			req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var body map[string]any
			require.NoError(t, json.Unmarshal([]byte(rec.lastBody(t)), &body))
			assert.Equal(t, "midaz", body["product"], "partner body must carry the route product; got %s", rec.lastBody(t))
			assert.Equal(t, map[string]any{"organizationId": "org-1"}, body["attributes"])
		})
	}
}

// Regression control: the partner fix must not leak into the plain M2M path.
// An application WITHOUT a partner, with the forwarding keys not both on, sends
// the same bytes every deployed access manager receives today — no product.
func TestAuthorize_ApplicationWithoutPartnerDoesNotForwardProduct(t *testing.T) {
	t.Parallel()

	for _, mode := range m2mForwardingModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

			auth := &AuthClient{
				Address:             rec.URL,
				Enabled:             true,
				Logger:              &testLogger{},
				ForwardM2MProduct:   mode.forwardM2M,
				M2MInversionEnabled: mode.inversionEnabled,
			}

			token := createTestJWT(jwt.MapClaims{"type": "application", "sub": "acme/app"})

			authorized, status, err := auth.checkAuthorization(context.Background(), "midaz", "accounts", "get", token, "")
			require.NoError(t, err)
			assert.True(t, authorized)
			assert.Equal(t, http.StatusOK, status)

			var body map[string]any
			require.NoError(t, json.Unmarshal([]byte(rec.lastBody(t)), &body))
			assert.NotContains(t, body, "product", "plain application body must not carry product; got %s", rec.lastBody(t))
		})
	}
}

// A normal user keeps forwarding the product, whatever the M2M keys say.
func TestAuthorize_NormalUserForwardsProduct(t *testing.T) {
	t.Parallel()

	for _, mode := range m2mForwardingModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

			auth := &AuthClient{
				Address:             rec.URL,
				Enabled:             true,
				Logger:              &testLogger{},
				ForwardM2MProduct:   mode.forwardM2M,
				M2MInversionEnabled: mode.inversionEnabled,
			}

			authorized, status, err := auth.checkAuthorization(context.Background(), "midaz", "accounts", "get", userToken(), "")
			require.NoError(t, err)
			assert.True(t, authorized)
			assert.Equal(t, http.StatusOK, status)

			var body map[string]any
			require.NoError(t, json.Unmarshal([]byte(rec.lastBody(t)), &body))
			assert.Equal(t, "midaz", body["product"])
		})
	}
}

// The decision cache keys on the product actually forwarded. For a partner that
// is now the route product, so the same partner asking the same question of two
// products is two questions, and a repeat of either is answered from the cache.
func TestDecisionCache_PartnerKeyIncludesProduct(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})

	// Inversion on (forwarding key off) so the subject is the token's own sub for
	// both products: the product is then the ONLY thing that can tell the keys apart.
	auth := &AuthClient{
		Address:             rec.URL,
		Enabled:             true,
		Logger:              &testLogger{},
		M2MInversionEnabled: true,
		cache:               newDecisionCache(time.Minute),
	}

	app := fiber.New()

	for _, product := range []string{"midaz", "reporter"} {
		app.Get("/"+product+"/:organization_id",
			auth.Authorize(product, "accounts", "get",
				RequireScope(product, Dim("organizationId", FromPath).At("organization_id")),
			),
			func(c fiber.Ctx) error { return c.SendString("ok") })
	}

	token := partnerToken("acme/p1")

	for _, target := range []string{"/midaz/org-1", "/reporter/org-1", "/midaz/org-1", "/reporter/org-1"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// midaz and reporter miss (two round-trips); both repeats hit.
	assert.Equal(t, int64(2), rec.hits.Load(),
		"a different product must miss the partner cache; an identical repeat must hit it")

	bodies := rec.recordedBodies()
	require.Len(t, bodies, 2)

	for i, product := range []string{"midaz", "reporter"} {
		var body map[string]any
		require.NoError(t, json.Unmarshal([]byte(bodies[i]), &body))
		assert.Equal(t, product, body["product"])
	}
}
