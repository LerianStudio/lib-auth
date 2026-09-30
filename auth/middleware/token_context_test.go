package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetApplicationToken_HonoursCallerContextCancellation pins that cancelling the
// caller's context aborts an in-flight mint.
//
// The mint runs on sharedHTTPClient, whose only bound is a 30s timeout. Building the
// outbound request without the caller's context leaves cancellation with nothing to
// act on: the call blocks until the authorization service answers or those 30s
// elapse. The declaration publisher stops by cancelling and waiting, so a service
// shutting down while a mint is in flight waits up to 30s to exit.
func TestGetApplicationToken_HonoursCallerContextCancellation(t *testing.T) {
	t.Parallel()

	// The handler holds the response until the CLIENT disconnects, which is what a
	// cancelled caller context must cause. The deadline is the test's own escape
	// hatch: with the defect present nobody ever disconnects, and waiting out the
	// shared client's 30s timeout would make this failure slow instead of loud.
	const handlerHold = 3 * time.Second

	// Closed on handler entry so the cancel below lands on a request that is
	// already blocked server-side, not on one the transport has yet to send.
	handlerEntered := make(chan struct{})

	var enteredOnce sync.Once

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(handlerEntered) })

		select {
		case <-r.Context().Done():
			return
		case <-time.After(handlerHold):
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accessToken":"the-token","tokenType":"Bearer","expiresIn":3600}`)
	}))

	t.Cleanup(server.Close)

	auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	type mintResult struct {
		token string
		err   error
	}

	done := make(chan mintResult, 1)

	go func() {
		token, err := auth.GetApplicationToken(ctx, "client-id", "client-secret")
		done <- mintResult{token: token, err: err}
	}()

	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("the authorization service never received the mint request")
	}

	cancel()

	select {
	case got := <-done:
		require.Error(t, got.err, "a cancelled caller must never be handed a bearer")
		assert.ErrorIs(t, got.err, context.Canceled, "the caller must be able to tell cancellation from a refusal")
		assert.Empty(t, got.token)
		assert.NotContains(t, got.err.Error(), "client-secret", "the refusal must not carry the OAuth secret")
	case <-time.After(2 * time.Second):
		t.Fatal("GetApplicationToken did not return after its context was cancelled: the mint ignores the caller context, so it holds until the shared client's 30s timeout and a shutdown that cancels-and-waits blocks for 30s")
	}
}
