package middleware

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
	})

	t.Run("wrong_type_returns_fiber_err_forbidden", func(t *testing.T) {
		t.Parallel()

		assertEnvelope(t, do(t, RequireHuman(), &Principal{
			Type: application, Sub: "admin/robot", Subject: "admin/robot",
		}), http.StatusForbidden, fiber.ErrForbidden.Message)

		assertEnvelope(t, do(t, RequireApplication(), &Principal{
			Type: normalUser, Owner: "acme-org", Sub: "user123", Subject: "acme-org/user123",
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
