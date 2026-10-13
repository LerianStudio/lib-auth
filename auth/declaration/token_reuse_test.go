package declaration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingMinter mints token-1, token-2, ... and counts the mints.
type countingMinter struct {
	mu    sync.Mutex
	calls int
}

func (m *countingMinter) GetApplicationToken(_ context.Context, _, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++

	return fmt.Sprintf("token-%d", m.calls), nil
}

func (m *countingMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.calls
}

// scriptedIdentity answers the n-th PUT with statuses[n-1], then 200.
func scriptedIdentity(t *testing.T, statuses ...int) (*httptest.Server, func() []string) {
	t.Helper()

	var (
		mu      sync.Mutex
		bearers []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		bearers = append(bearers, r.Header.Get("Authorization"))
		n := len(bearers)
		mu.Unlock()

		if n <= len(statuses) {
			w.WriteHeader(statuses[n-1])
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()

		return append([]string(nil), bearers...)
	}
}

func minterConfig(minter TokenMinter, identityURL string) Config {
	return Config{
		Slug:         "plugin-fees",
		Manifest:     []byte(feesJSON),
		IdentityAddr: identityURL,
		Auth:         minter,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
	}
}

func tokenPublisher(t *testing.T, minter TokenMinter, identityURL string) *Publisher {
	t.Helper()

	return newFastPublisher(t, minterConfig(minter, identityURL))
}

// Transient PUT failures reuse the token: an access manager in a rollout is not
// also asked for a token on every attempt.
func TestPublish_ReusesTheTokenAcrossTransientPutFailures(t *testing.T) {
	identity, bearers := scriptedIdentity(t, http.StatusServiceUnavailable, http.StatusConflict)
	minter := &countingMinter{}

	require.NoError(t, tokenPublisher(t, minter, identity.URL).Publish(context.Background()))

	assert.Equal(t, 1, minter.count())
	assert.Equal(t, []string{"Bearer token-1", "Bearer token-1", "Bearer token-1"}, bearers())
}

func TestPublish_MintsAgainOnceTheTokenAged(t *testing.T) {
	identity, bearers := scriptedIdentity(t, http.StatusServiceUnavailable)
	minter := &countingMinter{}

	p := tokenPublisher(t, minter, identity.URL)
	p.tokenMaxAge = 0

	require.NoError(t, p.Publish(context.Background()))
	assert.Equal(t, []string{"Bearer token-1", "Bearer token-2"}, bearers())
}

// A 401 on a reused token (the access manager restarted with new keys) mints a
// fresh one instead of reading as a refused declaration.
func TestPublish_ReusedTokenRefused_MintsAFreshOne(t *testing.T) {
	identity, bearers := scriptedIdentity(t, http.StatusServiceUnavailable, http.StatusUnauthorized)
	minter := &countingMinter{}

	require.NoError(t, tokenPublisher(t, minter, identity.URL).Publish(context.Background()))
	assert.Equal(t, []string{"Bearer token-1", "Bearer token-1", "Bearer token-2"}, bearers())
}

// A token endpoint refusing the credential (4xx but 429) is final: a wrong or
// revoked M2M secret reads failed, not pending forever.
func TestPublish_MintRefusal(t *testing.T) {
	cases := map[int]bool{
		http.StatusBadRequest:          true,
		http.StatusUnauthorized:        true,
		http.StatusForbidden:           true,
		http.StatusNotFound:            true,
		http.StatusTooManyRequests:     false,
		http.StatusServiceUnavailable:  false,
		http.StatusInternalServerError: false,
	}

	for status, final := range cases {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			identity := newIdentityServer(t, http.StatusOK, `{}`)
			t.Cleanup(identity.Close)

			refusal := middleware.TokenRefusal{StatusCode: status, Response: commons.Response{Message: "invalid client"}}
			minter := &fakeMinter{err: refusal}

			var st Status

			logs := &captureLogger{}
			cfg := minterConfig(minter, identity.URL)
			cfg.Status, cfg.Logger = &st, logs
			p := newFastPublisher(t, cfg)

			err := p.Publish(context.Background())

			var pubErr *PublishError
			require.ErrorAs(t, err, &pubErr)
			assert.Equal(t, final, pubErr.Deterministic)
			assert.Equal(t, 0, identity.count())

			if !final {
				assert.Equal(t, int(p.maxTries), minter.calls, "a transient mint failure is retried")
				assert.Equal(t, StateIdle, st.State())

				return
			}

			assert.Equal(t, 1, minter.calls, "a refused credential is not retried")
			assert.Equal(t, StateFailed, st.State())

			_, level, found := logs.find(fmt.Sprintf("status=%d", status))
			require.True(t, found, "the refusal must be logged; got:\n%s", logs.all())
			assert.Equal(t, obs.LevelError, level)
		})
	}
}
