package middleware

import (
	"context"
	"net/http"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// stripBearer
// ---------------------------------------------------------------------------

func Test_stripBearer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard_bearer_prefix",
			input: "Bearer token123",
			want:  "token123",
		},
		{
			name:  "lowercase_bearer_prefix",
			input: "bearer token123",
			want:  "token123",
		},
		{
			name:  "uppercase_bearer_prefix",
			input: "BEARER token123",
			want:  "token123",
		},
		{
			name:  "no_prefix_returns_token_as_is",
			input: "token123",
			want:  "token123",
		},
		{
			name:  "whitespace_around_bearer_and_token",
			input: "  Bearer   token123  ",
			want:  "token123",
		},
		{
			name:  "empty_string",
			input: "",
			want:  "",
		},
		{
			// NOTE: "Bearer " is trimmed to "Bearer" (6 chars), which is shorter
			// than the 7-char "bearer " prefix check, so stripBearer returns
			// the trimmed value as-is. This documents actual behavior.
			name:  "bearer_prefix_with_no_token_returns_bearer_literal",
			input: "Bearer ",
			want:  "Bearer",
		},
		{
			// Same trimming behavior as above.
			name:  "bearer_prefix_only_trailing_spaces_returns_bearer_literal",
			input: "Bearer   ",
			want:  "Bearer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := stripBearer(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// policyForMethod
// ---------------------------------------------------------------------------

func Test_policyForMethod(t *testing.T) {
	t.Parallel()

	defaultPol := Policy{Resource: "default-res", Action: "default-act"}
	specificPol := Policy{Resource: "users", Action: "read"}

	tests := []struct {
		name       string
		cfg        PolicyConfig
		fullMethod string
		wantPolicy Policy
		wantFound  bool
	}{
		{
			name: "method_found_in_method_policies",
			cfg: PolicyConfig{
				MethodPolicies: map[string]Policy{
					"/pkg.Service/GetUser": specificPol,
				},
			},
			fullMethod: "/pkg.Service/GetUser",
			wantPolicy: specificPol,
			wantFound:  true,
		},
		{
			name: "method_not_found_falls_back_to_default_policy",
			cfg: PolicyConfig{
				MethodPolicies: map[string]Policy{
					"/pkg.Service/GetUser": specificPol,
				},
				DefaultPolicy: &defaultPol,
			},
			fullMethod: "/pkg.Service/DeleteUser",
			wantPolicy: defaultPol,
			wantFound:  true,
		},
		{
			name: "method_not_found_no_default_returns_false",
			cfg: PolicyConfig{
				MethodPolicies: map[string]Policy{
					"/pkg.Service/GetUser": specificPol,
				},
			},
			fullMethod: "/pkg.Service/DeleteUser",
			wantPolicy: Policy{},
			wantFound:  false,
		},
		{
			name: "nil_method_policies_with_default_returns_default",
			cfg: PolicyConfig{
				MethodPolicies: nil,
				DefaultPolicy:  &defaultPol,
			},
			fullMethod: "/pkg.Service/AnyMethod",
			wantPolicy: defaultPol,
			wantFound:  true,
		},
		{
			name: "nil_method_policies_no_default_returns_false",
			cfg: PolicyConfig{
				MethodPolicies: nil,
				DefaultPolicy:  nil,
			},
			fullMethod: "/pkg.Service/AnyMethod",
			wantPolicy: Policy{},
			wantFound:  false,
		},
		{
			name: "empty_method_policies_with_default",
			cfg: PolicyConfig{
				MethodPolicies: map[string]Policy{},
				DefaultPolicy:  &defaultPol,
			},
			fullMethod: "/pkg.Service/AnyMethod",
			wantPolicy: defaultPol,
			wantFound:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotPolicy, gotFound := policyForMethod(tt.cfg, tt.fullMethod)
			assert.Equal(t, tt.wantFound, gotFound)
			assert.Equal(t, tt.wantPolicy, gotPolicy)
		})
	}
}

// ---------------------------------------------------------------------------
// grpcErrorFromHTTP
// ---------------------------------------------------------------------------

func Test_grpcErrorFromHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		httpStatus int
		wantCode   codes.Code
		wantMsg    string
	}{
		{
			name:       "401_maps_to_unauthenticated",
			httpStatus: http.StatusUnauthorized,
			wantCode:   codes.Unauthenticated,
			wantMsg:    "unauthenticated",
		},
		{
			name:       "403_maps_to_permission_denied",
			httpStatus: http.StatusForbidden,
			wantCode:   codes.PermissionDenied,
			wantMsg:    "forbidden",
		},
		{
			name:       "500_maps_to_internal",
			httpStatus: http.StatusInternalServerError,
			wantCode:   codes.Internal,
			wantMsg:    "internal error",
		},
		{
			name:       "0_default_maps_to_internal",
			httpStatus: 0,
			wantCode:   codes.Internal,
			wantMsg:    "internal error",
		},
		{
			name:       "404_unmapped_maps_to_internal",
			httpStatus: http.StatusNotFound,
			wantCode:   codes.Internal,
			wantMsg:    "internal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := grpcErrorFromHTTP(tt.httpStatus)
			require.Error(t, err)

			st, ok := status.FromError(err)
			require.True(t, ok, "expected a gRPC status error")
			assert.Equal(t, tt.wantCode, st.Code())
			assert.Equal(t, tt.wantMsg, st.Message())
		})
	}
}

// ---------------------------------------------------------------------------
// extractTokenFromMD
// ---------------------------------------------------------------------------

func Test_extractTokenFromMD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ctx       context.Context
		wantToken string
		wantOK    bool
	}{
		{
			name: "valid_bearer_token_in_metadata",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer token123"),
			),
			wantToken: "token123",
			wantOK:    true,
		},
		{
			name:      "no_metadata_in_context",
			ctx:       context.Background(),
			wantToken: "",
			wantOK:    false,
		},
		{
			name: "empty_authorization_value",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", ""),
			),
			wantToken: "",
			wantOK:    false,
		},
		{
			// NOTE: "Bearer " trimmed to "Bearer" (6 chars) which is below the
			// 7-char prefix check threshold. stripBearer returns "Bearer" as a
			// literal token and extractTokenFromMD treats it as non-empty.
			name: "authorization_with_bearer_prefix_only_returns_bearer_literal",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "Bearer "),
			),
			wantToken: "Bearer",
			wantOK:    true,
		},
		{
			name: "multiple_authorization_values_takes_first",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs(
					"authorization", "Bearer first-token",
					"authorization", "Bearer second-token",
				),
			),
			wantToken: "first-token",
			wantOK:    true,
		},
		{
			name: "token_without_bearer_prefix",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("authorization", "raw-token-value"),
			),
			wantToken: "raw-token-value",
			wantOK:    true,
		},
		{
			name: "metadata_present_but_no_authorization_key",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("content-type", "application/json"),
			),
			wantToken: "",
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotToken, gotOK := extractTokenFromMD(tt.ctx)
			assert.Equal(t, tt.wantOK, gotOK)
			assert.Equal(t, tt.wantToken, gotToken)
		})
	}
}

// ---------------------------------------------------------------------------
// SubFromMetadata
// ---------------------------------------------------------------------------

func TestSubFromMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		ctx     context.Context
		wantSub string
		wantErr bool
	}{
		{
			name: "key_present_in_metadata",
			key:  "x-tenant-id",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("x-tenant-id", "tenant-abc"),
			),
			wantSub: "tenant-abc",
			wantErr: false,
		},
		{
			name: "key_absent_in_metadata",
			key:  "x-tenant-id",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("other-key", "value"),
			),
			wantSub: "",
			wantErr: false,
		},
		{
			name:    "no_metadata_in_context",
			key:     "x-tenant-id",
			ctx:     context.Background(),
			wantSub: "",
			wantErr: false,
		},
		{
			name: "case_insensitive_key_lookup",
			key:  "X-Tenant-ID",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("x-tenant-id", "tenant-xyz"),
			),
			wantSub: "tenant-xyz",
			wantErr: false,
		},
		{
			name: "key_with_leading_trailing_whitespace",
			key:  "  x-tenant-id  ",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("x-tenant-id", "tenant-trimmed"),
			),
			wantSub: "tenant-trimmed",
			wantErr: false,
		},
		{
			name: "multiple_values_returns_first",
			key:  "x-scope",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("x-scope", "first", "x-scope", "second"),
			),
			wantSub: "first",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resolver := SubFromMetadata(tt.key)
			gotSub, err := resolver(tt.ctx, "/unused.Method", nil)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantSub, gotSub)
		})
	}
}

// ---------------------------------------------------------------------------
// NewGRPCAuthUnaryPolicy (integration-level)
// ---------------------------------------------------------------------------

func TestNewGRPCAuthUnaryPolicy(t *testing.T) {
	t.Parallel()

	handlerCalled := false

	noopHandler := func(_ context.Context, _ any) (any, error) {
		handlerCalled = true
		return "ok", nil
	}

	dummyInfo := &grpc.UnaryServerInfo{
		FullMethod: "/pkg.Service/DoThing",
	}

	t.Run("auth_disabled_passes_through", func(t *testing.T) {
		t.Parallel()

		called := false
		handler := func(_ context.Context, _ any) (any, error) {
			called = true
			return "ok", nil
		}

		auth := &AuthClient{Address: "http://localhost:9999", Enabled: false}
		interceptor := NewGRPCAuthUnaryPolicy(auth, PolicyConfig{})

		resp, err := interceptor(context.Background(), "req", dummyInfo, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
		assert.True(t, called)
	})

	t.Run("auth_nil_passes_through", func(t *testing.T) {
		t.Parallel()

		called := false
		handler := func(_ context.Context, _ any) (any, error) {
			called = true
			return "ok", nil
		}

		interceptor := NewGRPCAuthUnaryPolicy(nil, PolicyConfig{})

		resp, err := interceptor(context.Background(), "req", dummyInfo, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
		assert.True(t, called)
	})

	t.Run("auth_enabled_but_empty_address_passes_through", func(t *testing.T) {
		t.Parallel()

		called := false
		handler := func(_ context.Context, _ any) (any, error) {
			called = true
			return "ok", nil
		}

		auth := &AuthClient{Address: "", Enabled: true}
		interceptor := NewGRPCAuthUnaryPolicy(auth, PolicyConfig{})

		resp, err := interceptor(context.Background(), "req", dummyInfo, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
		assert.True(t, called)
	})

	t.Run("missing_token_returns_unauthenticated", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Address: "http://localhost:9999", Enabled: true}
		interceptor := NewGRPCAuthUnaryPolicy(auth, PolicyConfig{})

		// Context without any metadata -> no token
		resp, err := interceptor(context.Background(), "req", dummyInfo, noopHandler)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "missing token")
	})

	t.Run("bearer_prefix_only_passes_token_check_but_fails_policy_lookup", func(t *testing.T) {
		t.Parallel()

		// NOTE: "Bearer " is trimmed to "Bearer" (6 chars) by stripBearer,
		// which is treated as a non-empty token. The interceptor then proceeds
		// to the policy lookup phase, which fails because no policy is
		// configured for the method.
		auth := &AuthClient{Address: "http://localhost:9999", Enabled: true}
		interceptor := NewGRPCAuthUnaryPolicy(auth, PolicyConfig{})

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer "),
		)

		resp, err := interceptor(ctx, "req", dummyInfo, noopHandler)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, st.Message(), "internal configuration error")
	})

	t.Run("no_policy_for_method_and_no_default_returns_internal", func(t *testing.T) {
		t.Parallel()

		auth := &AuthClient{Address: "http://localhost:9999", Enabled: true}
		cfg := PolicyConfig{
			MethodPolicies: map[string]Policy{
				"/pkg.Service/OtherMethod": {Resource: "other", Action: "read"},
			},
			// No DefaultPolicy
		}
		interceptor := NewGRPCAuthUnaryPolicy(auth, cfg)

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer valid-token"),
		)

		resp, err := interceptor(ctx, "req", dummyInfo, noopHandler)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, st.Message(), "internal configuration error")
	})

	// Prevent compiler from optimizing away the handlerCalled variable
	_ = handlerCalled
}

// ---------------------------------------------------------------------------
// extractTenantClaims
// ---------------------------------------------------------------------------

func Test_extractTenantClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		tokenString    string
		wantTenantID   string
		wantTenantSlug string
		wantOwner      string
		wantErr        bool
	}{
		{
			name: "valid_jwt_with_all_tenant_claims",
			tokenString: createTestJWT(jwt.MapClaims{
				"tenantId":   "tid-123",
				"tenantSlug": "acme-corp",
				"owner":      "owner-456",
			}),
			wantTenantID:   "tid-123",
			wantTenantSlug: "acme-corp",
			wantOwner:      "owner-456",
			wantErr:        false,
		},
		{
			name: "jwt_with_only_owner",
			tokenString: createTestJWT(jwt.MapClaims{
				"owner": "owner-only",
			}),
			wantTenantID:   "",
			wantTenantSlug: "",
			wantOwner:      "owner-only",
			wantErr:        false,
		},
		{
			name: "jwt_with_only_tenantId",
			tokenString: createTestJWT(jwt.MapClaims{
				"tenantId": "tid-only",
			}),
			wantTenantID:   "tid-only",
			wantTenantSlug: "",
			wantOwner:      "",
			wantErr:        false,
		},
		{
			name:           "invalid_token",
			tokenString:    "not.a.valid.jwt",
			wantTenantID:   "",
			wantTenantSlug: "",
			wantOwner:      "",
			wantErr:        true,
		},
		{
			name:           "empty_token",
			tokenString:    "",
			wantTenantID:   "",
			wantTenantSlug: "",
			wantOwner:      "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tenantID, tenantSlug, owner, err := extractTenantClaims(tt.tokenString)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantTenantID, tenantID)
			assert.Equal(t, tt.wantTenantSlug, tenantSlug)
			assert.Equal(t, tt.wantOwner, owner)
		})
	}
}

// ---------------------------------------------------------------------------
// NewGRPCAuthUnaryPolicy - tenant propagation
// ---------------------------------------------------------------------------

func TestNewGRPCAuthUnaryPolicy_TenantPropagation(t *testing.T) {
	// Cannot use t.Parallel() because subtests use t.Setenv which modifies process env.

	t.Run("multi_tenant_enabled_propagates_tenant_metadata", func(t *testing.T) {
		t.Setenv("MULTI_TENANT_ENABLED", "true")

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{
			Address: server.URL,
			Enabled: true,
			Logger:  &testLogger{},
		}

		token := createTestJWT(jwt.MapClaims{
			"type":       "normal-user",
			"owner":      "org-owner",
			"sub":        "user1",
			"tenantId":   "tid-100",
			"tenantSlug": "acme",
		})

		defaultPol := Policy{Resource: "res", Action: "read"}
		cfg := PolicyConfig{DefaultPolicy: &defaultPol}
		interceptor := NewGRPCAuthUnaryPolicy(auth, cfg)

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer "+token),
		)

		var capturedCtx context.Context

		handler := func(ctx context.Context, _ any) (any, error) {
			capturedCtx = ctx
			return "ok", nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Service/DoThing"}

		resp, err := interceptor(ctx, "req", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		// Verify tenant metadata was propagated
		md, ok := metadata.FromIncomingContext(capturedCtx)
		require.True(t, ok)
		assert.Equal(t, []string{"tid-100"}, md.Get("md-tenant-id"))
		assert.Equal(t, []string{"acme"}, md.Get("md-tenant-slug"))
		assert.Equal(t, []string{"org-owner"}, md.Get("md-tenant-owner"))
	})

	t.Run("multi_tenant_disabled_no_tenant_metadata", func(t *testing.T) {
		t.Setenv("MULTI_TENANT_ENABLED", "false")

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{
			Address: server.URL,
			Enabled: true,
			Logger:  &testLogger{},
		}

		token := createTestJWT(jwt.MapClaims{
			"type":       "normal-user",
			"owner":      "org-owner",
			"sub":        "user1",
			"tenantId":   "tid-100",
			"tenantSlug": "acme",
		})

		defaultPol := Policy{Resource: "res", Action: "read"}
		cfg := PolicyConfig{DefaultPolicy: &defaultPol}
		interceptor := NewGRPCAuthUnaryPolicy(auth, cfg)

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer "+token),
		)

		var capturedCtx context.Context

		handler := func(ctx context.Context, _ any) (any, error) {
			capturedCtx = ctx
			return "ok", nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/pkg.Service/DoThing"}

		resp, err := interceptor(ctx, "req", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		// Verify no tenant metadata was added
		md, ok := metadata.FromIncomingContext(capturedCtx)
		require.True(t, ok)
		assert.Empty(t, md.Get("md-tenant-id"))
		assert.Empty(t, md.Get("md-tenant-slug"))
		assert.Empty(t, md.Get("md-tenant-owner"))
	})
}

// ---------------------------------------------------------------------------
// NewGRPCAuthStreamPolicy
// ---------------------------------------------------------------------------

// fakeServerStream is a minimal grpc.ServerStream for testing.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context {
	return f.ctx
}

func TestNewGRPCAuthStreamPolicy(t *testing.T) {
	// Cannot use t.Parallel() because a subtest uses t.Setenv which modifies process env.

	dummyInfo := &grpc.StreamServerInfo{
		FullMethod: "/pkg.Service/StreamThing",
	}

	t.Run("auth_disabled_passes_through", func(t *testing.T) {
		t.Parallel()

		called := false

		handler := func(_ any, _ grpc.ServerStream) error {
			called = true
			return nil
		}

		auth := &AuthClient{Address: "http://localhost:9999", Enabled: false}
		interceptor := NewGRPCAuthStreamPolicy(auth, PolicyConfig{})

		ss := &fakeServerStream{ctx: context.Background()}

		err := interceptor(nil, ss, dummyInfo, handler)
		require.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("auth_nil_passes_through", func(t *testing.T) {
		t.Parallel()

		called := false

		handler := func(_ any, _ grpc.ServerStream) error {
			called = true
			return nil
		}

		interceptor := NewGRPCAuthStreamPolicy(nil, PolicyConfig{})

		ss := &fakeServerStream{ctx: context.Background()}

		err := interceptor(nil, ss, dummyInfo, handler)
		require.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("missing_token_returns_unauthenticated", func(t *testing.T) {
		t.Parallel()

		handler := func(_ any, _ grpc.ServerStream) error {
			return nil
		}

		auth := &AuthClient{Address: "http://localhost:9999", Enabled: true}
		interceptor := NewGRPCAuthStreamPolicy(auth, PolicyConfig{})

		// Context without any metadata -> no token
		ss := &fakeServerStream{ctx: context.Background()}

		err := interceptor(nil, ss, dummyInfo, handler)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "missing token")
	})

	t.Run("no_policy_for_method_returns_internal", func(t *testing.T) {
		t.Parallel()

		handler := func(_ any, _ grpc.ServerStream) error {
			return nil
		}

		auth := &AuthClient{Address: "http://localhost:9999", Enabled: true}
		cfg := PolicyConfig{
			MethodPolicies: map[string]Policy{
				"/pkg.Service/OtherMethod": {Resource: "other", Action: "read"},
			},
			// No DefaultPolicy
		}
		interceptor := NewGRPCAuthStreamPolicy(auth, cfg)

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer valid-token"),
		)
		ss := &fakeServerStream{ctx: ctx}

		err := interceptor(nil, ss, dummyInfo, handler)
		require.Error(t, err)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		assert.Contains(t, st.Message(), "internal configuration error")
	})

	t.Run("multi_tenant_enabled_propagates_tenant_metadata_in_stream", func(t *testing.T) {
		t.Setenv("MULTI_TENANT_ENABLED", "true")

		server := mockAuthServer(t, true, http.StatusOK)
		defer server.Close()

		auth := &AuthClient{
			Address: server.URL,
			Enabled: true,
			Logger:  &testLogger{},
		}

		token := createTestJWT(jwt.MapClaims{
			"type":       "normal-user",
			"owner":      "stream-owner",
			"sub":        "user1",
			"tenantId":   "tid-stream",
			"tenantSlug": "stream-org",
		})

		defaultPol := Policy{Resource: "res", Action: "read"}
		cfg := PolicyConfig{DefaultPolicy: &defaultPol}
		interceptor := NewGRPCAuthStreamPolicy(auth, cfg)

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer "+token),
		)
		ss := &fakeServerStream{ctx: ctx}

		var capturedStream grpc.ServerStream

		handler := func(_ any, ss grpc.ServerStream) error {
			capturedStream = ss
			return nil
		}

		err := interceptor(nil, ss, dummyInfo, handler)
		require.NoError(t, err)

		// Verify tenant metadata was propagated via the wrapped stream context
		md, ok := metadata.FromIncomingContext(capturedStream.Context())
		require.True(t, ok)
		assert.Equal(t, []string{"tid-stream"}, md.Get("md-tenant-id"))
		assert.Equal(t, []string{"stream-org"}, md.Get("md-tenant-slug"))
		assert.Equal(t, []string{"stream-owner"}, md.Get("md-tenant-owner"))
	})
}

// ---------------------------------------------------------------------------
// wrappedServerStream
// ---------------------------------------------------------------------------

func TestWrappedServerStream_Context(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), struct{}{}, "test-value") //nolint:staticcheck // test-only context key
	inner := &fakeServerStream{ctx: context.Background()}
	wrapped := &wrappedServerStream{ServerStream: inner, ctx: ctx}

	assert.Equal(t, ctx, wrapped.Context())
	assert.NotEqual(t, inner.Context(), wrapped.Context())
}
