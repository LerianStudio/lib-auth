package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// PrincipalFromContext
// ---------------------------------------------------------------------------

func TestPrincipalFromContext(t *testing.T) {
	t.Parallel()

	t.Run("present", func(t *testing.T) {
		t.Parallel()

		want := Principal{
			Type:     normalUser,
			Owner:    "acme-org",
			Sub:      "user123",
			Subject:  "acme-org/user123",
			ClientID: "66bac70fbea746daa760",
		}

		ctx := context.WithValue(context.Background(), principalContextKey{}, want)

		got, ok := PrincipalFromContext(ctx)
		assert.True(t, ok)
		assert.Equal(t, want, got)
	})

	t.Run("absent_when_no_value_stored", func(t *testing.T) {
		t.Parallel()

		got, ok := PrincipalFromContext(context.Background())
		assert.False(t, ok)
		assert.Equal(t, Principal{}, got)
	})

	t.Run("absent_when_sub_is_empty", func(t *testing.T) {
		t.Parallel()

		// The legacy derivation (M2MInversionEnabled=false) publishes a fabricated
		// role as Subject with no real sub behind it. A half-populated principal
		// must never read as an identified caller.
		stored := Principal{Type: "service", Subject: "admin/midaz-editor-role"}

		ctx := context.WithValue(context.Background(), principalContextKey{}, stored)

		got, ok := PrincipalFromContext(ctx)
		assert.False(t, ok)
		assert.Equal(t, Principal{}, got)
	})

	t.Run("absent_when_sub_is_whitespace_only", func(t *testing.T) {
		t.Parallel()

		// A sub made only of whitespace names nobody. Spaces and tabs/newlines
		// alike must read as absent, exactly as an empty sub does.
		for _, blank := range []string{"   ", "\t\n"} {
			stored := Principal{Type: normalUser, Owner: "acme-org", Sub: blank}

			ctx := context.WithValue(context.Background(), principalContextKey{}, stored)

			got, ok := PrincipalFromContext(ctx)
			assert.False(t, ok, "sub %q must read as absent", blank)
			assert.Equal(t, Principal{}, got)
		}
	})

	t.Run("absent_when_value_is_of_another_type", func(t *testing.T) {
		t.Parallel()

		ctx := context.WithValue(context.Background(), principalContextKey{}, "not-a-principal")

		got, ok := PrincipalFromContext(ctx)
		assert.False(t, ok)
		assert.Equal(t, Principal{}, got)
	})

	t.Run("absent_when_legacy_application_subject_is_a_fabricated_role", func(t *testing.T) {
		t.Parallel()

		stored := Principal{
			Type:    application,
			Sub:     "admin/robot",
			Subject: "admin/midaz-editor-role",
		}

		ctx := context.WithValue(context.Background(), principalContextKey{}, stored)

		got, ok := PrincipalFromContext(ctx)
		assert.False(t, ok)
		assert.Equal(t, Principal{}, got)
	})
}

// ---------------------------------------------------------------------------
// principalFromClaims
// ---------------------------------------------------------------------------

func TestPrincipalFromClaims(t *testing.T) {
	t.Parallel()

	t.Run("normal_user_carries_owner_sub_and_derived_subject", func(t *testing.T) {
		t.Parallel()

		claims := jwt.MapClaims{
			"type":  normalUser,
			"owner": "acme-org",
			"sub":   "user123",
			"azp":   "66bac70fbea746daa760",
		}

		assert.Equal(t, Principal{
			Type:     normalUser,
			Owner:    "acme-org",
			Sub:      "user123",
			Subject:  "acme-org/user123",
			ClientID: "66bac70fbea746daa760",
		}, principalFromClaims(claims, "acme-org/user123"))
	})

	t.Run("application_has_no_owner_and_subject_equals_sub", func(t *testing.T) {
		t.Parallel()

		claims := jwt.MapClaims{
			"type":  application,
			"owner": "must-not-be-published",
			"sub":   "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
			"azp":   "66bac70fbea746daa760",
		}

		assert.Equal(t, Principal{
			Type:     application,
			Sub:      "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
			Subject:  "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
			ClientID: "66bac70fbea746daa760",
		}, principalFromClaims(claims, "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc"))
	})

	t.Run("missing_azp_leaves_client_id_empty", func(t *testing.T) {
		t.Parallel()

		claims := jwt.MapClaims{
			"type":  normalUser,
			"owner": "acme-org",
			"sub":   "user123",
		}

		assert.Empty(t, principalFromClaims(claims, "acme-org/user123").ClientID)
	})

	t.Run("claims_are_verbatim_no_trimming", func(t *testing.T) {
		t.Parallel()

		claims := jwt.MapClaims{
			"type":  " normal-user ",
			"owner": "  acme-org  ",
			"sub":   " user123 ",
			"azp":   " client ",
		}

		assert.Equal(t, Principal{
			Type:     " normal-user ",
			Owner:    "  acme-org  ",
			Sub:      " user123 ",
			Subject:  "  acme-org  / user123 ",
			ClientID: " client ",
		}, principalFromClaims(claims, "  acme-org  / user123 "))
	})

	t.Run("normal_user_keeps_edge_whitespace_verbatim", func(t *testing.T) {
		t.Parallel()

		// Blank is the only bar the identity claims must clear. A padded but real
		// claim is published exactly as the token wrote it, edge whitespace included.
		claims := jwt.MapClaims{
			"type":  normalUser,
			"owner": " alice ",
			"sub":   " u1 ",
		}

		assert.Equal(t, Principal{
			Type:    normalUser,
			Owner:   " alice ",
			Sub:     " u1 ",
			Subject: " alice / u1 ",
		}, principalFromClaims(claims, " alice / u1 "))
	})

	t.Run("non_string_claims_degrade_to_empty", func(t *testing.T) {
		t.Parallel()

		claims := jwt.MapClaims{
			"type":  normalUser,
			"owner": 42,
			"sub":   nil,
			"azp":   []string{"x"},
		}

		assert.Equal(t, Principal{Type: normalUser, Subject: "admin/midaz-editor-role"},
			principalFromClaims(claims, "admin/midaz-editor-role"))
	})
}

// TestPrincipalFromClaims_MalformedShapes walks the JSON shapes a decoded JWT can
// actually carry for a claim that is supposed to be a string: a number (every JSON
// number decodes to float64), an array, an explicit null, a bool. None of them is a
// string, so each degrades to the empty string in its own field and none may panic.
// The subject is the caller's, already derived, and is copied through untouched.
func TestPrincipalFromClaims_MalformedShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		claims  jwt.MapClaims
		subject string
		want    Principal
	}{
		{
			name:    "type_is_a_number",
			claims:  jwt.MapClaims{"type": float64(7), "owner": "acme-org", "sub": "user123"},
			subject: "acme-org/user123",
			want:    Principal{Owner: "acme-org", Sub: "user123", Subject: "acme-org/user123"},
		},
		{
			name:    "sub_is_an_array",
			claims:  jwt.MapClaims{"type": normalUser, "owner": "acme-org", "sub": []any{"user123"}},
			subject: "acme-org/",
			want:    Principal{Type: normalUser, Owner: "acme-org", Subject: "acme-org/"},
		},
		{
			name:    "owner_is_nil",
			claims:  jwt.MapClaims{"type": normalUser, "owner": nil, "sub": "user123"},
			subject: "/user123",
			want:    Principal{Type: normalUser, Sub: "user123", Subject: "/user123"},
		},
		{
			name:    "azp_is_a_bool",
			claims:  jwt.MapClaims{"type": application, "sub": "admin/robot", "azp": true},
			subject: "admin/robot",
			want:    Principal{Type: application, Sub: "admin/robot", Subject: "admin/robot"},
		},
		{
			name:    "every_claim_malformed_at_once",
			claims:  jwt.MapClaims{"type": float64(7), "owner": nil, "sub": []any{1}, "azp": false},
			subject: "",
			want:    Principal{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.NotPanics(t, func() {
				assert.Equal(t, tt.want, principalFromClaims(tt.claims, tt.subject))
			})
		})
	}
}

// ---------------------------------------------------------------------------
// RequireHuman / RequireApplication
// ---------------------------------------------------------------------------

// newGuardApp mounts a type guard on a route with no Authorize in front, and seeds
// the request context with the given Principal when one is supplied. It isolates
// the guard's own rules from the derivation that normally feeds it.
func newGuardApp(guard fiber.Handler, seed *Principal) *fiber.App {
	app := fiber.New()

	app.Use(func(c fiber.Ctx) error {
		if seed != nil {
			c.SetContext(context.WithValue(c.Context(), principalContextKey{}, *seed))
		}

		return c.Next()
	})
	app.Get("/x", guard, func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	return app
}

func guardResponse(t *testing.T, guard fiber.Handler, seed *Principal) *http.Response {
	t.Helper()

	resp, err := newGuardApp(guard, seed).Test(httptest.NewRequest(http.MethodGet, "/x", nil))
	require.NoError(t, err)

	return resp
}

func TestRequireHuman(t *testing.T) {
	t.Parallel()

	t.Run("missing_principal_is_401", func(t *testing.T) {
		t.Parallel()

		resp := guardResponse(t, RequireHuman(), nil)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("application_is_403", func(t *testing.T) {
		t.Parallel()

		resp := guardResponse(t, RequireHuman(), &Principal{
			Type: application, Sub: "admin/robot", Subject: "admin/robot",
		})
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("normal_user_reaches_the_handler", func(t *testing.T) {
		t.Parallel()

		resp := guardResponse(t, RequireHuman(), &Principal{
			Type: normalUser, Owner: "acme-org", Sub: "user123", Subject: "acme-org/user123",
		})
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "reached handler", string(body))
	})
}

func TestRequireApplication(t *testing.T) {
	t.Parallel()

	t.Run("missing_principal_is_401", func(t *testing.T) {
		t.Parallel()

		resp := guardResponse(t, RequireApplication(), nil)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("normal_user_is_403", func(t *testing.T) {
		t.Parallel()

		resp := guardResponse(t, RequireApplication(), &Principal{
			Type: normalUser, Owner: "acme-org", Sub: "user123", Subject: "acme-org/user123",
		})
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("application_reaches_the_handler", func(t *testing.T) {
		t.Parallel()

		resp := guardResponse(t, RequireApplication(), &Principal{
			Type: application, Sub: "admin/robot", Subject: "admin/robot",
		})
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestRequirePrincipalType_ReturnsFiberErrors proves the guards hand the error to
// the service's own ErrorHandler instead of writing a body past it. A rail that
// answers problem+json therefore keeps its envelope on a guard rejection; under
// Fiber's default handler the rendered 401/403 is unchanged.
func TestRequirePrincipalType_ReturnsFiberErrors(t *testing.T) {
	t.Parallel()

	// The sentinel handler stands in for a service error handler: it records what
	// it received and writes an envelope of its own, which a guard that wrote the
	// response itself would never let it do.
	newSentinelApp := func(guard fiber.Handler, seed *Principal) *fiber.App {
		app := fiber.New(fiber.Config{
			ErrorHandler: func(c fiber.Ctx, err error) error {
				var fiberErr *fiber.Error
				if !errors.As(err, &fiberErr) {
					return c.Status(http.StatusTeapot).SendString("error handler got a non-fiber error")
				}

				c.Set("X-Sentinel-Error", fiberErr.Message)

				return c.Status(fiberErr.Code).SendString("service envelope")
			},
		})

		app.Use(func(c fiber.Ctx) error {
			if seed != nil {
				c.SetContext(context.WithValue(c.Context(), principalContextKey{}, *seed))
			}

			return c.Next()
		})
		app.Get("/x", guard, func(c fiber.Ctx) error {
			return c.SendString("reached handler")
		})

		return app
	}

	do := func(t *testing.T, guard fiber.Handler, seed *Principal) *http.Response {
		t.Helper()

		resp, err := newSentinelApp(guard, seed).Test(httptest.NewRequest(http.MethodGet, "/x", nil))
		require.NoError(t, err)

		return resp
	}

	assertEnvelope := func(t *testing.T, resp *http.Response, wantStatus int, wantMessage string) {
		t.Helper()

		assert.Equal(t, wantStatus, resp.StatusCode)
		assert.Equal(t, wantMessage, resp.Header.Get("X-Sentinel-Error"),
			"the service error handler must receive the fiber error the guard returned")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "service envelope", string(body),
			"the guard must not write its own body past the service error handler")
	}

	t.Run("missing_principal_returns_fiber_err_unauthorized", func(t *testing.T) {
		t.Parallel()

		assertEnvelope(t, do(t, RequireHuman(), nil), http.StatusUnauthorized, fiber.ErrUnauthorized.Message)
		assertEnvelope(t, do(t, RequireApplication(), nil), http.StatusUnauthorized, fiber.ErrUnauthorized.Message)
		assertEnvelope(t, do(t, RequireSourceService("jd-courier"), nil), http.StatusUnauthorized, fiber.ErrUnauthorized.Message)
	})

	t.Run("wrong_type_returns_fiber_err_forbidden", func(t *testing.T) {
		t.Parallel()

		assertEnvelope(t, do(t, RequireHuman(), &Principal{
			Type: application, Sub: "admin/robot", Subject: "admin/robot",
		}), http.StatusForbidden, fiber.ErrForbidden.Message)

		assertEnvelope(t, do(t, RequireApplication(), &Principal{
			Type: normalUser, Owner: "acme-org", Sub: "user123", Subject: "acme-org/user123",
		}), http.StatusForbidden, fiber.ErrForbidden.Message)

		assertEnvelope(t, do(t, RequireSourceService("jd-courier"), &Principal{
			Type: application, Sub: "admin/robot", Subject: "admin/robot", SourceService: UndeclaredSourceService,
		}), http.StatusForbidden, fiber.ErrForbidden.Message)
	})
}

// TestRequireHuman_BehindAuthorize drives the real chain: Authorize derives and
// publishes, RequireHuman decides. An application token that Authorize accepts is
// still refused by the human-only guard mounted after it.
func TestRequireHuman_BehindAuthorize(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{
		Enabled:                       false,
		M2MInversionEnabled:           true,
		PrincipalRequiredWhenDisabled: true,
		Logger:                        &testLogger{},
	}

	app := fiber.New()
	app.Get("/x", auth.Authorize("midaz", "resource", "get"), RequireHuman(), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	do := func(claims jwt.MapClaims) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+createTestJWT(claims))

		resp, err := app.Test(req)
		require.NoError(t, err)

		return resp
	}

	assert.Equal(t, http.StatusForbidden, do(jwt.MapClaims{
		"type": application,
		"sub":  "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
	}).StatusCode, "a machine must not pass a human-only route")

	assert.Equal(t, http.StatusOK, do(jwt.MapClaims{
		"type":  normalUser,
		"owner": "acme-org",
		"sub":   "user123",
	}).StatusCode)
}

// ---------------------------------------------------------------------------
// RequireSourceService
// ---------------------------------------------------------------------------

func TestRequireSourceService(t *testing.T) {
	t.Parallel()

	courier := func(source string) *Principal {
		return &Principal{Type: application, Sub: "admin/jd-courier-m2m-pix-org", Subject: "admin/jd-courier-m2m-pix-org", SourceService: source}
	}

	// The legacy model publishes a fabricated Subject that PrincipalFromContext
	// refuses; the guard decides on the claims, so the role must not matter.
	legacy := courier("jd-courier")
	legacy.Subject = "admin/plugin-br-pix-jd-editor-role"

	cases := []struct {
		name    string
		service string
		seed    *Principal
		want    int
	}{
		{name: "missing_principal_is_401", service: "jd-courier", seed: nil, want: http.StatusUnauthorized},
		{name: "the_service_reaches_the_handler", service: "jd-courier", seed: courier("jd-courier"), want: http.StatusOK},
		{name: "legacy_fabricated_subject_reaches_the_handler", service: "jd-courier", seed: legacy, want: http.StatusOK},
		{name: "another_source_is_403", service: "jd-courier", seed: courier("plugin-br-pix-jd"), want: http.StatusForbidden},
		{name: "undeclared_is_403", service: "jd-courier", seed: courier(UndeclaredSourceService), want: http.StatusForbidden},
		{name: "absent_claim_is_403", service: "jd-courier", seed: courier(""), want: http.StatusForbidden},
		{name: "match_is_exact", service: "jd-courier", seed: courier(" JD-Courier"), want: http.StatusForbidden},
		{name: "empty_service_admits_nobody", service: "", seed: courier(""), want: http.StatusForbidden},
		{name: "marker_service_admits_nobody", service: UndeclaredSourceService, seed: courier(UndeclaredSourceService), want: http.StatusForbidden},
		{
			name: "normal_user_is_403", service: "jd-courier", want: http.StatusForbidden,
			seed: &Principal{Type: normalUser, Owner: "acme-org", Sub: "user123", Subject: "acme-org/user123", SourceService: "jd-courier"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := guardResponse(t, RequireSourceService(tc.service), tc.seed)
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

// TestRequireSourceService_BehindAuthorize drives the real chain under both
// authorization models: only an application the authorization service allowed
// and whose sourceService names the service passes.
func TestRequireSourceService_BehindAuthorize(t *testing.T) {
	t.Parallel()

	for _, inversion := range []bool{false, true} {
		server := mockAuthServer(t, true, http.StatusOK)
		t.Cleanup(server.Close)

		auth := &AuthClient{Address: server.URL, Enabled: true, M2MInversionEnabled: inversion, Logger: &testLogger{}}

		app := fiber.New()
		app.Post("/x", auth.Authorize("plugin-br-pix-jd", "cross-core", "post"), RequireSourceService("jd-courier"),
			func(c fiber.Ctx) error { return c.SendString("reached handler") })

		do := func(claims jwt.MapClaims) int {
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+createTestJWT(claims))

			resp, err := app.Test(req)
			require.NoError(t, err)

			return resp.StatusCode
		}

		appToken := func(source string) jwt.MapClaims {
			return jwt.MapClaims{"type": application, "sub": "admin/robot", "azp": "cid", "sourceService": source}
		}

		assert.Equal(t, http.StatusOK, do(appToken("jd-courier")), "inversion=%v: the Courier passes", inversion)
		assert.Equal(t, http.StatusForbidden, do(appToken(UndeclaredSourceService)), "inversion=%v: an undeclared app is refused", inversion)
		assert.Equal(t, http.StatusForbidden, do(appToken("plugin-br-pix-jd")), "inversion=%v: another source is refused", inversion)
		assert.Equal(t, http.StatusForbidden, do(jwt.MapClaims{
			"type": normalUser, "owner": "acme-org", "sub": "user123", "sourceService": "jd-courier",
		}), "inversion=%v: a person is refused", inversion)
	}
}

// ---------------------------------------------------------------------------
// Principal.TenantID — the "tenantId" claim, published through the real chain
// ---------------------------------------------------------------------------

type tenantEcho struct {
	Found    bool   `json:"found"`
	TenantID string `json:"tenantId"`
}

// newTenantEchoApp gates one route with Authorize and returns, as JSON, whether a
// Principal was published and the TenantID it carries. JSON rather than headers so
// edge whitespace survives the trip and the verbatim promise is actually observed.
// The ErrorHandler reads the same context, so a refusal that published anything
// would show up in its body too.
func newTenantEchoApp(auth *AuthClient) *fiber.App {
	echo := func(c fiber.Ctx) tenantEcho {
		p, ok := PrincipalFromContext(c.Context())

		return tenantEcho{Found: ok, TenantID: p.TenantID}
	}

	app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, err error) error {
		code := http.StatusInternalServerError

		var fe *fiber.Error
		if errors.As(err, &fe) {
			code = fe.Code
		}

		return c.Status(code).JSON(echo(c))
	}})

	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.JSON(echo(c))
	})

	return app
}

func tenantEchoRequest(t *testing.T, app *fiber.App, claims jwt.MapClaims) (int, tenantEcho) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+createTestJWT(claims))

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var got tenantEcho
	require.NoError(t, json.Unmarshal(body, &got), "body: %s", body)

	return resp.StatusCode, got
}

// TestAuthorize_PublishesTenantIDVerbatim drives every path that publishes a
// Principal — the Access Manager round-trip under inversion and under the legacy
// derivation, and the no-round-trip PrincipalRequiredWhenDisabled path — with
// each claim shape on each token type. The claim is copied verbatim (case and
// edge whitespace kept), and an absent or non-string claim publishes an empty
// TenantID on a Principal that is still valid: tenant presence never decides
// identity.
func TestAuthorize_PublishesTenantIDVerbatim(t *testing.T) {
	t.Parallel()

	modes := []struct {
		name     string
		auth     func(address string) *AuthClient
		appFound bool // whether an application token yields an identified principal
	}{
		{
			name: "round_trip_inversion",
			auth: func(address string) *AuthClient {
				return &AuthClient{Address: address, Enabled: true, M2MInversionEnabled: true, Logger: &testLogger{}}
			},
			appFound: true,
		},
		{
			name: "round_trip_legacy",
			auth: func(address string) *AuthClient {
				return &AuthClient{Address: address, Enabled: true, Logger: &testLogger{}}
			},
			appFound: false, // fabricated role: pinned absent by TestAuthorize_PublishesPrincipal
		},
		{
			name: "disabled_principal_required",
			auth: func(string) *AuthClient {
				return &AuthClient{
					Enabled:                       false,
					M2MInversionEnabled:           true,
					PrincipalRequiredWhenDisabled: true,
					Logger:                        &testLogger{},
				}
			},
			appFound: true,
		},
	}

	tokens := []struct {
		name   string
		claims jwt.MapClaims
		isApp  bool
	}{
		{name: "normal_user", claims: jwt.MapClaims{"type": normalUser, "owner": "acme-org", "sub": "user123"}},
		{name: "application", claims: jwt.MapClaims{"type": application, "sub": "admin/robot", "azp": "cid"}, isApp: true},
	}

	shapes := []struct {
		name  string
		claim any // nil means the claim is absent
		want  string
	}{
		{name: "present_verbatim", claim: " Tenant-01 ", want: " Tenant-01 "},
		{name: "absent", claim: nil, want: ""},
		{name: "non_string", claim: 42, want: ""},
	}

	for _, mode := range modes {
		for _, tok := range tokens {
			if tok.isApp && !mode.appFound {
				continue
			}

			for _, shape := range shapes {
				t.Run(mode.name+"/"+tok.name+"/"+shape.name, func(t *testing.T) {
					t.Parallel()

					server := mockAuthServer(t, true, http.StatusOK)
					defer server.Close()

					claims := jwt.MapClaims{}
					for k, v := range tok.claims {
						claims[k] = v
					}

					if shape.claim != nil {
						claims["tenantId"] = shape.claim
					}

					status, got := tenantEchoRequest(t, newTenantEchoApp(mode.auth(server.URL)), claims)

					assert.Equal(t, http.StatusOK, status)
					assert.True(t, got.Found, "an empty or odd tenantId must not invalidate the principal")
					assert.Equal(t, shape.want, got.TenantID)
				})
			}
		}
	}
}

// TestAuthorize_RefusalPublishesNoTenantID pins that a refused request publishes
// nothing — no Principal, so no TenantID — even to the service's ErrorHandler,
// which runs on the same request context.
func TestAuthorize_RefusalPublishesNoTenantID(t *testing.T) {
	t.Parallel()

	server := mockAuthServer(t, false, http.StatusOK)
	defer server.Close()

	auth := &AuthClient{Address: server.URL, Enabled: true, M2MInversionEnabled: true, Logger: &testLogger{}}

	status, got := tenantEchoRequest(t, newTenantEchoApp(auth), jwt.MapClaims{
		"type": normalUser, "owner": "acme-org", "sub": "user123", "tenantId": "tenant-01",
	})

	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, tenantEcho{}, got)
}

// ---------------------------------------------------------------------------
// Principal.SourceService — the "sourceService" claim, published through the real chain
// ---------------------------------------------------------------------------

type sourceServiceEcho struct {
	Found         bool   `json:"found"`
	SourceService string `json:"sourceService"`
}

// newSourceServiceEchoApp gates one route with Authorize and returns, as JSON,
// whether a Principal was published and the SourceService it carries. The
// ErrorHandler reads the same context, so a refusal that published anything would
// show up in its body too.
func newSourceServiceEchoApp(auth *AuthClient) *fiber.App {
	echo := func(c fiber.Ctx) sourceServiceEcho {
		p, ok := PrincipalFromContext(c.Context())

		return sourceServiceEcho{Found: ok, SourceService: p.SourceService}
	}

	app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, err error) error {
		code := http.StatusInternalServerError

		var fe *fiber.Error
		if errors.As(err, &fe) {
			code = fe.Code
		}

		return c.Status(code).JSON(echo(c))
	}})

	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.JSON(echo(c))
	})

	return app
}

func sourceServiceEchoRequest(t *testing.T, app *fiber.App, claims jwt.MapClaims) (int, sourceServiceEcho) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+createTestJWT(claims))

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var got sourceServiceEcho
	require.NoError(t, json.Unmarshal(body, &got), "body: %s", body)

	return resp.StatusCode, got
}

// TestAuthorize_PublishesSourceServiceForApplicationsOnly drives every path that
// publishes a Principal with each claim shape on each token type. The claim is
// copied verbatim (case, edge whitespace and marker values kept) for application
// tokens; a normal-user token never exposes it, even when it carries the claim; an
// absent or non-string claim publishes an empty SourceService on a Principal that
// is still valid, because the claim never decides whether a principal exists.
func TestAuthorize_PublishesSourceServiceForApplicationsOnly(t *testing.T) {
	t.Parallel()

	modes := []struct {
		name     string
		auth     func(address string) *AuthClient
		appFound bool // whether an application token yields an identified principal
	}{
		{
			name: "round_trip_inversion",
			auth: func(address string) *AuthClient {
				return &AuthClient{Address: address, Enabled: true, M2MInversionEnabled: true, Logger: &testLogger{}}
			},
			appFound: true,
		},
		{
			name: "round_trip_legacy",
			auth: func(address string) *AuthClient {
				return &AuthClient{Address: address, Enabled: true, Logger: &testLogger{}}
			},
			appFound: false, // fabricated role: pinned absent by TestAuthorize_PublishesPrincipal
		},
		{
			name: "disabled_principal_required",
			auth: func(string) *AuthClient {
				return &AuthClient{
					Enabled:                       false,
					M2MInversionEnabled:           true,
					PrincipalRequiredWhenDisabled: true,
					Logger:                        &testLogger{},
				}
			},
			appFound: true,
		},
	}

	tokens := []struct {
		name   string
		claims jwt.MapClaims
		isApp  bool
	}{
		{name: "normal_user", claims: jwt.MapClaims{"type": normalUser, "owner": "acme-org", "sub": "user123"}},
		{name: "application", claims: jwt.MapClaims{"type": application, "sub": "admin/robot", "azp": "cid"}, isApp: true},
	}

	shapes := []struct {
		name  string
		claim any // nil means the claim is absent
		want  string
	}{
		{name: "present_verbatim", claim: " Pix-JD ", want: " Pix-JD "},
		{name: "marker_verbatim", claim: "undeclared", want: "undeclared"},
		{name: "absent", claim: nil, want: ""},
		{name: "non_string", claim: 42, want: ""},
	}

	for _, mode := range modes {
		for _, tok := range tokens {
			if tok.isApp && !mode.appFound {
				continue
			}

			for _, shape := range shapes {
				t.Run(mode.name+"/"+tok.name+"/"+shape.name, func(t *testing.T) {
					t.Parallel()

					server := mockAuthServer(t, true, http.StatusOK)
					defer server.Close()

					claims := jwt.MapClaims{}
					for k, v := range tok.claims {
						claims[k] = v
					}

					if shape.claim != nil {
						claims["sourceService"] = shape.claim
					}

					want := shape.want
					if !tok.isApp {
						want = "" // a user token never exposes the claim
					}

					status, got := sourceServiceEchoRequest(t, newSourceServiceEchoApp(mode.auth(server.URL)), claims)

					assert.Equal(t, http.StatusOK, status)
					assert.True(t, got.Found, "an empty or odd sourceService must not invalidate the principal")
					assert.Equal(t, want, got.SourceService)
				})
			}
		}
	}
}

// TestAuthorize_RefusalPublishesNoSourceService pins that a refused request
// publishes nothing — no Principal, so no SourceService — even to the service's
// ErrorHandler, which runs on the same request context.
func TestAuthorize_RefusalPublishesNoSourceService(t *testing.T) {
	t.Parallel()

	server := mockAuthServer(t, false, http.StatusOK)
	defer server.Close()

	auth := &AuthClient{Address: server.URL, Enabled: true, M2MInversionEnabled: true, Logger: &testLogger{}}

	status, got := sourceServiceEchoRequest(t, newSourceServiceEchoApp(auth), jwt.MapClaims{
		"type": application, "sub": "admin/robot", "sourceService": "pix-jd",
	})

	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, sourceServiceEcho{}, got)
}

// TestIsDeclaredSourceService pins the refusal rule a consumer applies before using
// Principal.SourceService as an identity: empty, whitespace-only and the issuer's
// marker (any case, any edge whitespace) name nobody; everything else does.
func TestIsDeclaredSourceService(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "empty", in: "", want: false},
		{name: "whitespace_only", in: " \t\n", want: false},
		{name: "marker", in: UndeclaredSourceService, want: false},
		{name: "marker_upper", in: "UNDECLARED", want: false},
		{name: "marker_padded", in: "  undeclared ", want: false},
		{name: "declared", in: "pix-jd", want: true},
		{name: "declared_padded", in: " Pix-JD ", want: true},
		{name: "marker_prefix_is_a_name", in: "undeclared-svc", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, IsDeclaredSourceService(tc.in))
		})
	}
}

// TestAuthorize_DecisionCacheHitPublishesSourceService proves the Principal is
// derived from the request's own token even when the authorization decision is
// served from the decision cache: the second request never reaches the
// authorization service, yet its SourceService is its own, not the first
// request's, and a user token on the same cached path still exposes none.
func TestAuthorize_DecisionCacheHitPublishesSourceService(t *testing.T) {
	t.Parallel()

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		writeAuthorized(w, true)
	})

	auth := &AuthClient{
		Address:             server.URL,
		Enabled:             true,
		M2MInversionEnabled: true,
		Logger:              &testLogger{},
		cache:               newDecisionCache(time.Minute),
	}
	app := newSourceServiceEchoApp(auth)

	appClaims := func(source string) jwt.MapClaims {
		return jwt.MapClaims{"type": application, "sub": "admin/robot", "azp": "cid", "sourceService": source}
	}

	status, got := sourceServiceEchoRequest(t, app, appClaims("pix-jd"))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "pix-jd", got.SourceService)
	require.Equal(t, int64(1), hits.Load(), "the first request is a cache miss")

	status, got = sourceServiceEchoRequest(t, app, appClaims("pix-jd"))
	assert.Equal(t, http.StatusOK, status)
	assert.True(t, got.Found)
	assert.Equal(t, "pix-jd", got.SourceService, "a cache hit must still publish the claim")
	assert.Equal(t, int64(1), hits.Load(), "the repeat request must be served from the decision cache")

	// A different token for the same sub misses (the key digests the token) and
	// carries its own claim.
	status, got = sourceServiceEchoRequest(t, app, appClaims("pix-btg"))
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "pix-btg", got.SourceService, "the claim comes from this request's token, never from a cached one")

	// A cached application decision never lends its claim to a normal-user token.
	userClaims := jwt.MapClaims{"type": normalUser, "owner": "acme-org", "sub": "user123", "sourceService": "pix-jd"}

	for range 2 {
		status, got = sourceServiceEchoRequest(t, app, userClaims)
		assert.Equal(t, http.StatusOK, status)
		assert.True(t, got.Found)
		assert.Empty(t, got.SourceService)
	}
}
