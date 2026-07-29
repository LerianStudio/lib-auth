package declaration

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/LerianStudio/lib-auth/v3/auth/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time contract lock: the real v3 *middleware.AuthClient MUST satisfy
// TokenMinter. This is the whole point of the interface — the publisher must not
// be coupled to a specific lib-auth major, and both v2 and v3 AuthClient expose an
// identical GetApplicationToken signature. If this stops compiling, the decoupling
// has regressed.
var _ TokenMinter = (*middleware.AuthClient)(nil)

// fakeMinter is a lightweight TokenMinter test double that exercises the mint path
// without any HTTP round-trip: it returns a canned token or a canned error.
type fakeMinter struct {
	token string
	err   error
	calls int
}

func (f *fakeMinter) GetApplicationToken(_ context.Context, _, _ string) (string, error) {
	f.calls++

	return f.token, f.err
}

// TestConfigAuth_AcceptsRealAuthClient proves the concrete v3 *middleware.AuthClient
// still satisfies Config.Auth (now typed as TokenMinter) end-to-end: it mints against
// a real httptest AUTH server and the publish succeeds against a real identity server.
func TestConfigAuth_AcceptsRealAuthClient(t *testing.T) {
	auth := newAuthServer(t)
	t.Cleanup(auth.Close)

	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	cfg := testConfig(t, auth.URL, identity.URL)

	// The field accepts the concrete *middleware.AuthClient built by testConfig.
	realClient, ok := cfg.Auth.(*middleware.AuthClient)
	require.True(t, ok, "testConfig must wire a real *middleware.AuthClient into Config.Auth")
	require.NotNil(t, realClient)

	p := newFastPublisher(t, cfg)

	require.NoError(t, p.Publish(context.Background()))
	assert.Equal(t, 1, identity.count())
	assert.Equal(t, "Bearer "+testToken, identity.gotAuth)
}

// TestPublish_MintFailure_Transient_WithFakeMinter exercises the mint-failure path
// through the TokenMinter seam (no HTTP), asserting it is classified transient and
// never reaches the identity server.
func TestPublish_MintFailure_Transient_WithFakeMinter(t *testing.T) {
	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	fm := &fakeMinter{err: errors.New("auth boom")}
	cfg := Config{
		Slug:         "plugin-fees",
		Manifest:     []byte(feesJSON),
		IdentityAddr: identity.URL,
		Auth:         fm,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
	}
	p := newFastPublisher(t, cfg)

	err := p.Publish(context.Background())
	require.Error(t, err)

	var pe *PublishError
	require.ErrorAs(t, err, &pe)
	assert.False(t, pe.Deterministic, "mint failure must be transient")
	assert.Equal(t, "mint m2m token", pe.Op)
	assert.Equal(t, 1, fm.calls, "the minter must have been called exactly once")
	assert.Equal(t, 0, identity.count(), "a mint failure must never reach the identity server")
}

// TestPublish_EmptyToken_Deterministic_WithFakeMinter exercises the empty-token path
// (auth disabled/misconfigured) through the seam: deterministic, no PUT.
func TestPublish_EmptyToken_Deterministic_WithFakeMinter(t *testing.T) {
	identity := newIdentityServer(t, http.StatusOK, `{"status":"accepted"}`)
	t.Cleanup(identity.Close)

	fm := &fakeMinter{token: ""}
	cfg := Config{
		Slug:         "plugin-fees",
		Manifest:     []byte(feesJSON),
		IdentityAddr: identity.URL,
		Auth:         fm,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
	}
	p := newFastPublisher(t, cfg)

	err := p.Publish(context.Background())
	require.Error(t, err)

	var pe *PublishError
	require.ErrorAs(t, err, &pe)
	assert.True(t, pe.Deterministic, "empty token must be deterministic (no retry)")
	assert.Equal(t, 0, identity.count(), "an empty token must never reach the identity server")
}
