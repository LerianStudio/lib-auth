package middleware

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorize_PartnerDenialNamesWhatHappened pins the refusal of a credential
// whose partner is no longer honoured: still 401, but carrying a code and message
// of its own, so the holder of a perfectly valid token is not told to fix it.
func TestAuthorize_PartnerDenialNamesWhatHappened(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		reason  string
		code    string
		title   string
		message string
	}{
		{
			name:    "suspended",
			reason:  "suspended",
			code:    "AUT-1009",
			title:   "Partner Suspended",
			message: "the partner of this credential is suspended",
		},
		{
			name:    "expired",
			reason:  "expired",
			code:    "AUT-1010",
			title:   "Partner Outside Its Validity Period",
			message: "the partner of this credential is outside its validity period",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: tt.reason})
			app, capture := newCapturingApp(&AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}})

			resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))
			assert.Equal(t, http.StatusTeapot, resp.StatusCode)

			err := capture.get()
			requireFiberError(t, err, http.StatusUnauthorized, tt.message)

			var commonsErr commons.Response

			require.True(t, errors.As(err, &commonsErr), "the refusal must carry a code a consumer can read")
			assert.Equal(t, tt.code, commonsErr.Code)
			assert.Equal(t, tt.title, commonsErr.Title)
			assert.Equal(t, tt.message, commonsErr.Message)
		})
	}
}

// A cached partner denial replays with the same code, not the bare 401.
func TestAuthorize_CachedPartnerDenialKeepsItsCode(t *testing.T) {
	t.Parallel()

	rec := newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: "suspended"})
	app, capture := newCapturingApp(&AuthClient{
		Address: rec.URL,
		Enabled: true,
		Logger:  &testLogger{},
		cache:   newDecisionCache(time.Minute),
	})

	// One token for both requests: normalUserClaims stamps the current second,
	// and a token minted on each side of a second boundary is a different
	// credential, which the cache rightly does not share.
	token := createTestJWT(normalUserClaims())

	for range 2 {
		gatedRequest(t, app, token)

		var commonsErr commons.Response

		require.True(t, errors.As(capture.get(), &commonsErr))
		assert.Equal(t, "AUT-1009", commonsErr.Code)
	}

	assert.Len(t, rec.requests(), 1, "the second request must be served from the cache")
}

// Every other denial and every token failure keeps the refusal it always had: no
// partner code leaks onto them.
func TestAuthorize_NonPartnerRefusalsCarryNoPartnerCode(t *testing.T) {
	t.Parallel()

	t.Run("invalid_token", func(t *testing.T) {
		t.Parallel()

		rec := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		app, capture := newCapturingApp(&AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}})

		gatedRequest(t, app, "not-a-valid-jwt")

		err := capture.get()
		requireFiberError(t, err, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))

		var commonsErr commons.Response
		assert.False(t, errors.As(err, &commonsErr), "a bad token carries no partner code")
	})

	for _, reason := range []string{"", "permission", "scope", "unknown"} {
		t.Run("reason_"+reason, func(t *testing.T) {
			t.Parallel()

			rec := newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: reason})
			app, capture := newCapturingApp(&AuthClient{Address: rec.URL, Enabled: true, Logger: &testLogger{}})

			gatedRequest(t, app, createTestJWT(normalUserClaims()))

			err := capture.get()
			requireFiberError(t, err, http.StatusForbidden, http.StatusText(http.StatusForbidden))

			var commonsErr commons.Response
			assert.False(t, errors.As(err, &commonsErr))
		})
	}
}
