package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// grpcAccessManager stands in for an Access Manager answering every authorization
// with the given status and body, while staying healthy on /health.
func grpcAccessManager(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, "healthy")

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = io.WriteString(w, body)
	}))

	t.Cleanup(server.Close)

	return server
}

// callUnaryInterceptor drives one RPC through the unary policy interceptor and
// reports whether the handler ran and what the interceptor answered.
func callUnaryInterceptor(t *testing.T, server *httptest.Server) (reached bool, err error) {
	t.Helper()

	interceptor := NewGRPCAuthUnaryPolicy(
		&AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}},
		PolicyConfig{MethodPolicies: map[string]Policy{
			"/svc/Method": {Resource: "resource", Action: "get"},
		}},
	)

	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+userToken()))

	_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"},
		func(ctx context.Context, req any) (any, error) {
			reached = true

			return "ok", nil
		})

	return reached, err
}

// TestGRPCAuthUnaryPolicy_OutageIsUnavailable pins the word an outage gets on the
// gRPC surface. Refusing is not enough: a caller and an alarm have to tell "the
// authorization service said no" from "the authorization service could not
// answer". Internal claims the fault is local and is not retryable; Unavailable
// names the dependency, which is what retry policies and paging rules are written
// against.
//
// The two shapes are kept apart deliberately — an outage answering nothing and an
// outage answering a decision — because it is the second that used to be read as a
// grant on this surface.
func TestGRPCAuthUnaryPolicy_OutageIsUnavailable(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"5xx with no decision in the body": "",
		"5xx carrying authorized true":     `{"authorized":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reached, err := callUnaryInterceptor(t, grpcAccessManager(t, http.StatusBadGateway, body))

			assert.False(t, reached, "an unanswered authorization must never reach the handler")
			require.Error(t, err)
			assert.Equal(t, codes.Unavailable, status.Code(err),
				"an outage is Unavailable, not Internal and not PermissionDenied")
		})
	}
}

// TestGRPCAuthUnaryPolicy_RefusalStaysPermissionDenied is the control for the test
// above: widening Unavailable must not swallow a genuine refusal. An Access
// Manager that answered, and answered no, still denies with PermissionDenied.
func TestGRPCAuthUnaryPolicy_RefusalStaysPermissionDenied(t *testing.T) {
	t.Parallel()

	t.Run("authoritative 403", func(t *testing.T) {
		t.Parallel()

		reached, err := callUnaryInterceptor(t, grpcAccessManager(t, http.StatusForbidden, `{"code":"AUT-0001"}`))

		assert.False(t, reached)
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("decision of not authorized", func(t *testing.T) {
		t.Parallel()

		reached, err := callUnaryInterceptor(t, grpcAccessManager(t, http.StatusOK, `{"authorized":false}`))

		assert.False(t, reached)
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}
