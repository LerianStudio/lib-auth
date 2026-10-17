package authtest_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/authtest"
	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// principalRequiredClient is the posture a service such as br-sfn's SILOC pins:
// auth disabled, a bearer still demanded and its principal derived by the real
// Authorize. No address is set, so nothing is ever dialled.
func principalRequiredClient(t *testing.T, source middleware.KeySource) *middleware.AuthClient {
	t.Helper()

	client := middleware.NewAuthClient("", false, nil)
	require.NotNil(t, client)

	client.PrincipalRequiredWhenDisabled = true
	client.M2MInversionEnabled = true

	if source != nil {
		client.WithKeySource(source)
	}

	return client
}

// authorizeThrough serves one request carrying token through the real
// Authorize and returns the status and the principal the handler saw.
func authorizeThrough(t *testing.T, client *middleware.AuthClient, token string) (int, middleware.Principal) {
	t.Helper()

	var got middleware.Principal

	app := fiber.New()
	app.Get("/", client.Authorize("product", "resource", "action"), func(c fiber.Ctx) error {
		p, ok := middleware.PrincipalFromContext(c.Context())
		if !ok {
			return fiber.ErrTeapot
		}

		got = p

		return c.SendStatus(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	return resp.StatusCode, got
}

func TestIssuer_TokenPassesTheRealAuthorize(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t, "")

	for name, want := range map[string]middleware.Principal{
		"user":             tenantUser(),
		"application":      tenantApp(),
		"user, bare claim": authtest.User("acme-org", "user-2"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := principalRequiredClient(t, iss.KeySource())

			status, got := authorizeThrough(t, client, iss.Token(t, want))

			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, want, got)
		})
	}
}

func TestIssuer_TokenIsSignedRS256WithAShortExpiry(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t, "")

	claims := jwt.MapClaims{}
	token, _, err := new(jwt.Parser).ParseUnverified(iss.Token(t, authtest.App("acme-org/bot")), claims)
	require.NoError(t, err)

	assert.Equal(t, "RS256", token.Method.Alg())
	assert.Equal(t, "application", claims["type"])
	assert.Equal(t, "acme-org/bot", claims["sub"])
	assert.NotContains(t, claims, "owner", "an application token carries no owner")
	assert.NotContains(t, claims, "iss", "an issuer built with no iss sets none")

	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	require.NotNil(t, exp)

	iat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	require.NotNil(t, iat)
	assert.True(t, exp.After(iat.Time))
}

func TestIssuer_TokenFromAnotherIssuerIsRefused(t *testing.T) {
	t.Parallel()

	trusted := authtest.NewIssuer(t, "")
	stranger := authtest.NewIssuer(t, "")

	client := principalRequiredClient(t, trusted.KeySource())

	status, _ := authorizeThrough(t, client, stranger.Token(t, tenantUser()))
	assert.Equal(t, http.StatusUnauthorized, status)
}

func TestIssuer_TokenWithTheWrongIssIsRefused(t *testing.T) {
	t.Setenv("AUTH_JWT_ISSUER", "https://idp.expected.test")

	iss := authtest.NewIssuer(t, "https://idp.other.test")
	client := principalRequiredClient(t, iss.KeySource())

	status, _ := authorizeThrough(t, client, iss.Token(t, tenantUser()))
	assert.Equal(t, http.StatusUnauthorized, status)
}

func TestIssuer_TokenWithTheMatchingIssPasses(t *testing.T) {
	t.Setenv("AUTH_JWT_ISSUER", "https://idp.expected.test")

	iss := authtest.NewIssuer(t, "https://idp.expected.test")
	client := principalRequiredClient(t, iss.KeySource())

	want := tenantUser()

	status, got := authorizeThrough(t, client, iss.Token(t, want))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, want, got)
}

func TestIssuer_PublicKeyPEMConfiguresTheEnvironmentPath(t *testing.T) {
	iss := authtest.NewIssuer(t, "")

	pemKey := iss.PublicKeyPEM()
	require.True(t, strings.HasPrefix(pemKey, "-----BEGIN PUBLIC KEY-----"))

	t.Setenv("AUTH_JWT_VERIFY_CERT", pemKey)

	client := principalRequiredClient(t, nil)

	want := tenantApp()

	status, got := authorizeThrough(t, client, iss.Token(t, want))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, want, got)

	status, _ = authorizeThrough(t, client, authtest.NewIssuer(t, "").Token(t, want))
	assert.Equal(t, http.StatusUnauthorized, status)
}

func TestIssuer_TokenRefusesAnInvalidPrincipal(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t, "")

	for name, p := range invalidPrincipals() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &recordingTB{}

			assert.Empty(t, iss.Token(rec, p))
			assert.Len(t, rec.failures(), 1)
		})
	}
}

func TestIssuer_TokenOnANilTBPanics(t *testing.T) {
	t.Parallel()

	iss := authtest.NewIssuer(t, "")

	assert.PanicsWithValue(t, "authtest: Token called with a nil testing.TB", func() {
		iss.Token(nil, tenantUser())
	})
}
