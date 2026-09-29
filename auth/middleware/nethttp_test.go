package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// net/http adapter - helpers
// ---------------------------------------------------------------------------

// principalEcho is a net/http handler that records whether it ran and echoes the
// Principal and RequestScope it finds on the request context as response headers.
func principalEcho(reached *atomic.Bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reached != nil {
			reached.Store(true)
		}

		p, ok := PrincipalFromContext(r.Context())
		scope, scoped := ScopeFromContext(r.Context())

		w.Header().Set("X-P-Found", fmt.Sprint(ok))
		w.Header().Set("X-P-Type", p.Type)
		w.Header().Set("X-P-Owner", p.Owner)
		w.Header().Set("X-P-Sub", p.Sub)
		w.Header().Set("X-P-Subject", p.Subject)
		w.Header().Set("X-P-Client-Id", p.ClientID)
		w.Header().Set("X-S-Found", fmt.Sprint(scoped))
		w.Header().Set("X-S-Partner", scope.Partner)

		w.WriteHeader(http.StatusOK)
	})
}

// serveGated mounts h on a Go 1.22 ServeMux under pattern and serves one request
// built by build. It never opens a socket: the protected handler runs in process.
func serveGated(t *testing.T, pattern string, h http.Handler, build func() *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	mux := http.NewServeMux()
	mux.Handle(pattern, h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, build())

	return rec
}

func getWithBearer(token string) func() *http.Request {
	return func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		return req
	}
}

func appTokenClaims(sub string) jwt.MapClaims {
	return jwt.MapClaims{"type": "application", "sub": sub, "azp": "client-1", "tenantId": "t-1"}
}

// bodyOf decodes the last /v1/authorize body the recording server received.
func bodyOf(t *testing.T, rec *recordingAuthServer) map[string]any {
	t.Helper()

	var body map[string]any

	require.NoError(t, json.Unmarshal([]byte(rec.lastBody(t)), &body))

	return body
}

// ---------------------------------------------------------------------------
// net/http adapter - parity with the Fiber adapter
// ---------------------------------------------------------------------------

// The net/http adapter must publish the SAME Principal the Fiber adapter
// publishes for the same token and client configuration, and put the same body
// on the wire: the two share one decision flow, and this is what proves it.
func TestAuthorizeHTTP_MatchesFiberForTheSameToken(t *testing.T) {
	t.Parallel()

	tokens := map[string]string{
		"normal_user": createTestJWT(jwt.MapClaims{"type": "normal-user", "owner": "acme", "sub": "u1", "azp": "web", "tenantId": "t-9"}),
		"application": createTestJWT(appTokenClaims("acme/app")),
	}

	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fiberAM := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			httpAM := newRecordingAuthServer(t, AuthResponse{Authorized: true})

			fiberAuth := &AuthClient{Address: fiberAM.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}
			httpAuth := &AuthClient{Address: httpAM.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

			var (
				mu         sync.Mutex
				fiberP     Principal
				fiberFound bool
			)

			app := fiber.New()
			app.Get("/x", fiberAuth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
				mu.Lock()
				defer mu.Unlock()

				fiberP, fiberFound = PrincipalFromContext(c.Context())

				return c.SendStatus(http.StatusOK)
			})

			fiberResp := authorizedRequest(t, app, token)
			require.Equal(t, http.StatusOK, fiberResp.StatusCode)

			var (
				httpP     Principal
				httpFound bool
			)

			handler := httpAuth.AuthorizeHTTP("midaz", "resource", "get")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpP, httpFound = PrincipalFromContext(r.Context())

				w.WriteHeader(http.StatusOK)
			}))

			rec := serveGated(t, "GET /x", handler, getWithBearer(token))
			require.Equal(t, http.StatusOK, rec.Code)

			mu.Lock()
			defer mu.Unlock()

			require.True(t, fiberFound)
			require.True(t, httpFound)
			assert.Equal(t, fiberP, httpP, "both adapters must publish the same principal")
			assert.JSONEq(t, fiberAM.lastBody(t), httpAM.lastBody(t), "both adapters must ask the same question")
		})
	}
}

// ---------------------------------------------------------------------------
// net/http adapter - decisions
// ---------------------------------------------------------------------------

func TestAuthorizeHTTP_Decisions(t *testing.T) {
	t.Parallel()

	token := createTestJWT(normalUserClaims())

	cases := []struct {
		name       string
		server     func(t *testing.T) string
		wantStatus int
		wantBody   string
	}{
		{
			name: "denied_is_403",
			server: func(t *testing.T) string {
				t.Helper()

				return newRecordingAuthServer(t, AuthResponse{Authorized: false}).URL
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "Forbidden",
		},
		{
			name: "suspended_credential_is_401",
			server: func(t *testing.T) string {
				t.Helper()

				return newRecordingAuthServer(t, AuthResponse{Authorized: false, Reason: reasonSuspended}).URL
			},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Unauthorized",
		},
		{
			name: "access_manager_5xx_is_503",
			server: func(t *testing.T) string {
				t.Helper()

				srv := mockAuthServer(t, true, http.StatusInternalServerError)
				t.Cleanup(srv.Close)

				return srv.URL
			},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "Service Unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var reached atomic.Bool

			auth := &AuthClient{Address: tc.server(t), Enabled: true, Logger: &testLogger{}}

			rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(&reached)), getWithBearer(token))

			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, tc.wantBody, strings.TrimSpace(rec.Body.String()))
			assert.False(t, reached.Load(), "a refused request must never reach the handler")
		})
	}

	t.Run("authorized_reaches_the_handler_with_the_principal", func(t *testing.T) {
		t.Parallel()

		var reached atomic.Bool

		am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(&reached)), getWithBearer(token))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached.Load())
		assert.Equal(t, "true", rec.Header().Get("X-P-Found"))
		assert.Equal(t, "acme-org/user-123", rec.Header().Get("X-P-Subject"))
		assert.Equal(t, "false", rec.Header().Get("X-S-Found"), "no scope for a credential that is not partner-bound")
		assert.Equal(t, int64(1), am.hits.Load())
	})

	t.Run("access_manager_refusal_body_is_recoverable", func(t *testing.T) {
		t.Parallel()

		srv := mockAccessManagerErrorBody(t, http.StatusConflict, map[string]string{
			"code":    "CONFLICT",
			"title":   "Conflicting Request",
			"message": "Conflicting grant",
		})
		t.Cleanup(srv.Close)

		var got error

		auth := (&AuthClient{Address: srv.URL, Enabled: true, Logger: &testLogger{}}).
			WithHTTPErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
				got = err

				w.WriteHeader(http.StatusTeapot)
			})

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)), getWithBearer(token))
		assert.Equal(t, http.StatusTeapot, rec.Code, "the custom handler owns the response")

		var refusal *RefusalError

		require.True(t, errors.As(got, &refusal), "the handler must receive a *RefusalError, got %T", got)
		assert.Equal(t, http.StatusConflict, refusal.Status, "the Access Manager's status is kept")
		assert.Equal(t, "Conflicting grant", refusal.Message)
		require.NotNil(t, refusal.Response)
		assert.Equal(t, "CONFLICT", refusal.Response.Code)

		var commonsErr commons.Response

		require.True(t, errors.As(got, &commonsErr), "the decoded body must be reachable with errors.As, as on the Fiber path")
		assert.Equal(t, "Conflicting grant", commonsErr.Message)
	})
}

// ---------------------------------------------------------------------------
// net/http adapter - bearer refusals never reach the Access Manager
// ---------------------------------------------------------------------------

func TestAuthorizeHTTP_TokenRefusalsNeverCallTheAccessManager(t *testing.T) {
	t.Parallel()

	valid := createTestJWT(normalUserClaims())
	parts := strings.Split(valid, ".")
	unsigned := parts[0] + "." + parts[1] + "."

	cases := []struct {
		name     string
		header   []string
		wantBody string
	}{
		{name: "missing", header: nil, wantBody: "Missing Token"},
		{name: "blank", header: []string{"   "}, wantBody: "Missing Token"},
		{name: "bare_token_without_scheme", header: []string{valid}, wantBody: "Unauthorized"},
		{name: "basic_scheme", header: []string{"Basic " + valid}, wantBody: "Unauthorized"},
		{name: "two_tokens", header: []string{"Bearer " + valid + " " + valid}, wantBody: "Unauthorized"},
		{name: "two_authorization_lines", header: []string{"Bearer " + valid, "Bearer " + valid}, wantBody: "Unauthorized"},
		{name: "oversize", header: []string{"Bearer " + parts[0] + "." + strings.Repeat("A", 9000) + "." + parts[2]}, wantBody: "Unauthorized"},
		{name: "crlf", header: []string{"Bearer " + valid + "\r\nX-Evil: 1"}, wantBody: "Unauthorized"},
		{name: "unsigned_token", header: []string{"Bearer " + unsigned}, wantBody: "Unauthorized"},
		{name: "not_a_jwt", header: []string{"Bearer not-a-valid-jwt"}, wantBody: "Unauthorized"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var reached atomic.Bool

			am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}}

			rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(&reached)), func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/x", nil)
				if tc.header != nil {
					req.Header["Authorization"] = tc.header
				}

				return req
			})

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, tc.wantBody, strings.TrimSpace(rec.Body.String()))
			assert.False(t, reached.Load())
			assert.Zero(t, am.hits.Load(), "a token refused locally must never reach the Access Manager")
		})
	}
}

// ---------------------------------------------------------------------------
// net/http adapter - posture (required, disabled, principal without round-trip)
// ---------------------------------------------------------------------------

func TestAuthorizeHTTP_Posture(t *testing.T) {
	t.Parallel()

	token := createTestJWT(normalUserClaims())

	t.Run("required_and_disabled_is_503", func(t *testing.T) {
		t.Parallel()

		var reached atomic.Bool

		auth := &AuthClient{Enabled: false, Required: true, Logger: &testLogger{}}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(&reached)), getWithBearer(token))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.False(t, reached.Load())
	})

	t.Run("disabled_passes_through_without_a_principal", func(t *testing.T) {
		t.Parallel()

		var reached atomic.Bool

		auth := &AuthClient{Enabled: false, Logger: &testLogger{}}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(&reached)), getWithBearer(""))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached.Load())
		assert.Equal(t, "false", rec.Header().Get("X-P-Found"))
	})

	t.Run("principal_required_while_disabled_publishes_without_a_round_trip", func(t *testing.T) {
		t.Parallel()

		var reached atomic.Bool

		am := newRecordingAuthServer(t, AuthResponse{Authorized: false})
		auth := &AuthClient{Address: am.URL, Enabled: false, PrincipalRequiredWhenDisabled: true, Logger: &testLogger{}}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(&reached)), getWithBearer(token))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached.Load())
		assert.Equal(t, "true", rec.Header().Get("X-P-Found"))
		assert.Equal(t, "acme-org/user-123", rec.Header().Get("X-P-Subject"))
		assert.Zero(t, am.hits.Load(), "the disabled path never calls the Access Manager")
	})

	t.Run("principal_required_while_disabled_still_demands_a_token", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Enabled: false, PrincipalRequiredWhenDisabled: true, Logger: &testLogger{}}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)), getWithBearer(""))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "Missing Token", strings.TrimSpace(rec.Body.String()))
	})

	t.Run("enabled_without_address_is_503", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Enabled: true, PrincipalRequiredWhenDisabled: true, Logger: &testLogger{}}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)), getWithBearer(token))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
}

// ---------------------------------------------------------------------------
// net/http adapter - scope dimensions
// ---------------------------------------------------------------------------

func TestAuthorizeHTTP_Scope(t *testing.T) {
	t.Parallel()

	t.Run("misdeclared_scope_is_403_even_with_auth_disabled", func(t *testing.T) {
		t.Parallel()

		var reached atomic.Bool

		auth := &AuthClient{Enabled: false, Logger: &testLogger{}}
		mw := auth.AuthorizeHTTP("midaz", "accounts", "get", RequireScope("other", Dim("organizationId", FromPath)))

		rec := serveGated(t, "GET /x", mw(principalEcho(&reached)), getWithBearer(""))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.False(t, reached.Load())
	})

	t.Run("servemux_path_value_is_sent_as_an_attribute", func(t *testing.T) {
		t.Parallel()

		am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}}
		mw := auth.AuthorizeHTTP("midaz", "accounts", "get",
			RequireScope("midaz",
				Dim("organizationId", FromPath).At("org"),
				Dim("ledgerId", FromHeader).At("X-Ledger-Id"),
				Dim("portfolioId", FromQuery).At("portfolio"),
			))

		rec := serveGated(t, "GET /v1/orgs/{org}/accounts", mw(principalEcho(nil)), func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/v1/orgs/org-1/accounts?portfolio=pf-1", nil)
			req.Header.Set("Authorization", "Bearer "+createTestJWT(normalUserClaims()))
			req.Header.Set("X-Ledger-Id", "led-1")

			return req
		})

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t,
			map[string]any{"organizationId": "org-1", "ledgerId": "led-1", "portfolioId": "pf-1"},
			bodyOf(t, am)["attributes"])
	})

	t.Run("missing_dimension_is_403_before_the_round_trip", func(t *testing.T) {
		t.Parallel()

		am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}}
		mw := auth.AuthorizeHTTP("midaz", "accounts", "get", RequireScope("midaz", Dim("ledgerId", FromHeader).At("X-Ledger-Id")))

		rec := serveGated(t, "GET /x", mw(principalEcho(nil)), getWithBearer(createTestJWT(normalUserClaims())))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Zero(t, am.hits.Load())
	})

	t.Run("path_dimension_under_another_router_resolves_empty_and_is_refused", func(t *testing.T) {
		t.Parallel()

		am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}}
		mw := auth.AuthorizeHTTP("midaz", "accounts", "get", RequireScope("midaz", Dim("organizationId", FromPath).At("org")))

		// Served directly, not through a ServeMux pattern: r.PathValue is empty.
		req := httptest.NewRequest(http.MethodGet, "/v1/orgs/org-1/accounts", nil)
		req.Header.Set("Authorization", "Bearer "+createTestJWT(normalUserClaims()))

		rec := httptest.NewRecorder()
		mw(principalEcho(nil)).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Zero(t, am.hits.Load())
	})

	t.Run("partner_credential_publishes_the_request_scope", func(t *testing.T) {
		t.Parallel()

		am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

		var (
			gotScope RequestScope
			scoped   bool
			found    bool
		)

		mw := auth.AuthorizeHTTP("midaz", "accounts", "get", RequireScope("midaz", Dim("ledgerId", FromPath).At("ledger_id")))
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotScope, scoped = ScopeFromContext(r.Context())
			_, found = PrincipalFromContext(r.Context())

			w.WriteHeader(http.StatusOK)
		}))

		rec := serveGated(t, "GET /v1/ledgers/{ledger_id}/accounts", h, func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/v1/ledgers/led-1/accounts", nil)
			req.Header.Set("Authorization", "Bearer "+partnerToken("acme/p1"))

			return req
		})

		require.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, scoped)
		assert.True(t, found, "principal and scope must both survive on the same request")
		assert.Equal(t, "acme/p1", gotScope.Partner)
		assert.Equal(t, map[string]string{"ledgerId": "led-1"}, gotScope.Attributes)
	})
}

// ---------------------------------------------------------------------------
// net/http adapter - client IP from TRUSTED_PROXIES
// ---------------------------------------------------------------------------

func TestAuthorizeHTTP_ClientIP(t *testing.T) {
	t.Parallel()

	token := createTestJWT(normalUserClaims())

	cases := []struct {
		name       string
		trusted    []string
		remoteAddr string
		forwarded  []string
		want       string // "" means clientIp absent
	}{
		{name: "forwarded_hop_behind_a_trusted_proxy", trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.1.2.3:5555", forwarded: []string{"203.0.113.7"}, want: "203.0.113.7"},
		{
			name:       "every_forwarded_line_is_read_in_order",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:5555",
			forwarded:  []string{"198.51.100.9", "203.0.113.7, 10.0.0.5"},
			want:       "203.0.113.7",
		},
		{name: "untrusted_peer_is_the_caller", trusted: []string{"10.0.0.0/8"}, remoteAddr: "192.0.2.44:5555", forwarded: []string{"203.0.113.7"}, want: "192.0.2.44"},
		{name: "ipv6_peer", trusted: []string{"10.0.0.0/8"}, remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "no_trusted_proxies_forwards_nothing", remoteAddr: "192.0.2.44:5555", forwarded: []string{"203.0.113.7"}},
		{name: "unparseable_peer_forwards_nothing", trusted: []string{"10.0.0.0/8"}, remoteAddr: "pipe", forwarded: []string{"203.0.113.7"}},
		{name: "unspecified_ipv4_peer_forwards_nothing", trusted: []string{"10.0.0.0/8"}, remoteAddr: "0.0.0.0:5555", forwarded: []string{"203.0.113.7"}},
		{name: "unspecified_ipv6_peer_forwards_nothing", trusted: []string{"10.0.0.0/8"}, remoteAddr: "[::]:443", forwarded: []string{"203.0.113.7"}},
		{name: "unspecified_mapped_peer_forwards_nothing", trusted: []string{"10.0.0.0/8"}, remoteAddr: "[::ffff:0.0.0.0]:443"},
		{name: "empty_forwarded_position_stops_the_walk", trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.1.2.3:5555", forwarded: []string{"203.0.113.7, "}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
			auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}, trustedProxies: mustPrefixes(t, tc.trusted...)}

			rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)), func() *http.Request {
				req := getWithBearer(token)()
				req.RemoteAddr = tc.remoteAddr

				for _, line := range tc.forwarded {
					req.Header.Add("X-Forwarded-For", line)
				}

				return req
			})

			require.Equal(t, http.StatusOK, rec.Code)

			got, present := bodyOf(t, am)["clientIp"]
			if tc.want == "" {
				assert.False(t, present, "clientIp must be absent, got %v", got)

				return
			}

			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// net/http adapter - M2M inversion
// ---------------------------------------------------------------------------

func TestAuthorizeHTTP_M2MInversion(t *testing.T) {
	t.Parallel()

	t.Run("on_application_authorizes_under_its_own_sub", func(t *testing.T) {
		t.Parallel()

		am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)),
			getWithBearer(createTestJWT(appTokenClaims("acme/app"))))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "acme/app", bodyOf(t, am)["sub"])
		assert.Equal(t, "application", rec.Header().Get("X-P-Type"))
	})

	t.Run("on_unknown_token_type_is_401_without_a_round_trip", func(t *testing.T) {
		t.Parallel()

		am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)),
			getWithBearer(createTestJWT(jwt.MapClaims{"type": "robot", "sub": "acme/bot"})))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Zero(t, am.hits.Load())
	})

	t.Run("off_application_uses_the_fabricated_role", func(t *testing.T) {
		t.Parallel()

		am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
		auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)),
			getWithBearer(createTestJWT(appTokenClaims("acme/app"))))

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "admin/midaz-editor-role", bodyOf(t, am)["sub"])
		assert.Equal(t, "false", rec.Header().Get("X-P-Found"), "the fabricated role is not an identity")
	})
}

// ---------------------------------------------------------------------------
// net/http adapter - error handler, nil safety, concurrency
// ---------------------------------------------------------------------------

func TestAuthorizeHTTP_ErrorHandlerAndNilSafety(t *testing.T) {
	t.Parallel()

	t.Run("custom_handler_receives_the_refusal", func(t *testing.T) {
		t.Parallel()

		var got error

		am := newRecordingAuthServer(t, AuthResponse{Authorized: false})
		auth := (&AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}}).
			WithHTTPErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
				got = err

				w.WriteHeader(http.StatusTeapot)
			})

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)),
			getWithBearer(createTestJWT(normalUserClaims())))

		assert.Equal(t, http.StatusTeapot, rec.Code)

		var refusal *RefusalError

		require.True(t, errors.As(got, &refusal))
		assert.Equal(t, http.StatusForbidden, refusal.Status)
		assert.Equal(t, "Forbidden", refusal.Message)
		assert.Nil(t, refusal.Response)
		assert.Nil(t, refusal.Unwrap(), "no Access Manager body, nothing to unwrap")
		assert.Equal(t, "Forbidden", refusal.Error())
	})

	t.Run("nil_error_handler_keeps_the_default", func(t *testing.T) {
		t.Parallel()

		auth := (&AuthClient{Enabled: false, Required: true, Logger: &testLogger{}}).WithHTTPErrorHandler(nil)

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)), getWithBearer(""))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "Service Unavailable", strings.TrimSpace(rec.Body.String()))
	})

	t.Run("nil_client_passes_through", func(t *testing.T) {
		t.Parallel()

		var (
			reached atomic.Bool
			auth    *AuthClient
		)

		require.Nil(t, auth.WithHTTPErrorHandler(func(http.ResponseWriter, *http.Request, error) {}))

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(&reached)), getWithBearer(""))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached.Load())
	})

	t.Run("nil_next_answers_500", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Enabled: false, Logger: &testLogger{}}

		rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(nil), getWithBearer(""))
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("nil_refusal_error_is_safe", func(t *testing.T) {
		t.Parallel()

		var refusal *RefusalError

		assert.Empty(t, refusal.Error())
		assert.Nil(t, refusal.Unwrap())
	})
}

// One mounted middleware serves many requests at once: every caller must get
// its own principal back, and -race must stay quiet.
func TestAuthorizeHTTP_ConcurrentRequestsKeepTheirOwnPrincipal(t *testing.T) {
	t.Parallel()

	am := newRecordingAuthServer(t, AuthResponse{Authorized: true})
	auth := &AuthClient{Address: am.URL, Enabled: true, Logger: &testLogger{}, M2MInversionEnabled: true}

	mux := http.NewServeMux()
	mux.Handle("GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)))

	const callers = 16

	var wg sync.WaitGroup

	for i := range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			sub := fmt.Sprintf("acme/app-%d", i)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, getWithBearer(createTestJWT(appTokenClaims(sub)))())

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, sub, rec.Header().Get("X-P-Sub"))
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(callers), am.hits.Load())
	assert.Len(t, am.recordedBodies(), callers, "every concurrent authorize body must be recorded")
}

// The default handler renders exactly what Fiber's default renders for the same
// refusal: the status and its message as plain text.
func TestAuthorizeHTTP_DefaultRenderingIsPlainText(t *testing.T) {
	t.Parallel()

	auth := &AuthClient{Enabled: false, Required: true, Logger: &testLogger{}}

	rec := serveGated(t, "GET /x", auth.AuthorizeHTTP("midaz", "resource", "get")(principalEcho(nil)), getWithBearer(""))

	body, err := io.ReadAll(rec.Result().Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "Service Unavailable", strings.TrimSpace(string(body)))
	assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain"))
}
