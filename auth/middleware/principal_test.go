package middleware

import (
	"context"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
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

	t.Run("absent_when_value_is_of_another_type", func(t *testing.T) {
		t.Parallel()

		ctx := context.WithValue(context.Background(), principalContextKey{}, "not-a-principal")

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
			"type": application,
			"sub":  "admin/3a09ac44-1faf-4e66-843c-5152b09b19dc",
			"azp":  "66bac70fbea746daa760",
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
