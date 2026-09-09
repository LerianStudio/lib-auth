package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAuthorize_ARedirectIsNeverFollowed closes a fail-open of the same class as
// the refusal-body-claiming-authorized case, reached by a different route: if the
// HTTP client follows a redirect, the status handed to the classifier is the
// status of whatever the Location named, NOT the status the Access Manager sent.
// A 302 pointing at anything that answers 200 {"authorized":true} is then a grant,
// and the address in PLUGIN_AUTH_ADDRESS never has to be wrong for it — a
// compromised or misconfigured hop in front of the Access Manager is enough.
//
// Deciding on the status is only sound if the status belongs to the dependency
// this library addressed, so the client refuses to follow redirects and the
// classifier sees the 3xx itself, which it already reports as 503.
//
// This case is NOT covered by TestAuthorize_EveryNon2xxStillRefuses. That test
// writes its 3xx with no Location header, and Go returns such a response as-is
// rather than following it, so its 3xx entry only ever exercised the classifier —
// never the redirect machinery. Verified by running both shapes against a stock
// client: without Location the caller sees 301; with Location it sees the final
// 200 and the grant body.
func TestAuthorize_ARedirectIsNeverFollowed(t *testing.T) {
	t.Parallel()

	for _, status := range []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			// The Location target answers a clean, fully valid grant. Nothing about
			// it is malformed; only its identity is wrong.
			granting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"authorized":true}`)
			}))
			t.Cleanup(granting.Close)

			redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					_, _ = io.WriteString(w, "healthy")

					return
				}

				w.Header().Set("Location", granting.URL+"/v1/authorize")
				w.WriteHeader(status)
			}))
			t.Cleanup(redirecting.Close)

			app, capture := newCapturingApp(&AuthClient{Address: redirecting.URL, Enabled: true, Logger: &testLogger{}})

			resp := gatedRequest(t, app, createTestJWT(normalUserClaims()))

			require.Equal(t, http.StatusTeapot, resp.StatusCode,
				"a %d must never reach the protected handler, whatever its Location answers", status)
			requireFiberError(t, capture.get(), http.StatusServiceUnavailable, "Service Unavailable")
		})
	}
}
