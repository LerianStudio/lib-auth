package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/LerianStudio/lib-commons/v2/commons"
	"github.com/LerianStudio/lib-commons/v2/commons/opentelemetry"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Policy defines the authorization target within the authz domain.
// Keep minimal to avoid leaking service semantics across layers.
type Policy struct {
	Resource string
	Action   string
}

// PolicyConfig binds gRPC methods to Policies and optional subject resolution.
// - MethodPolicies keyed by info.FullMethod ("/pkg.Service/Method").
// - DefaultPolicy used when a method mapping is absent.
// - SubResolver derives the subject base (e.g., editor scope). Return "" when not applicable.
type PolicyConfig struct {
	MethodPolicies map[string]Policy
	DefaultPolicy  *Policy
	SubResolver    func(ctx context.Context, fullMethod string, req any) (string, error)
}

// NewGRPCAuthUnaryPolicy authorizes unary RPCs via per-method Policy.
// Behavior:
// - Resolves the Policy by info.FullMethod; falls back to DefaultPolicy when provided.
// - Optionally derives the subject using cfg.SubResolver (e.g., editor roles). Empty subject is valid.
// - Rejects missing tokens with codes.Unauthenticated; misconfiguration returns codes.Internal.
// Telemetry:
// - Sets app.request.request_id.
// - Sets app.request.payload with {sub, resource, action} per standard.
func NewGRPCAuthUnaryPolicy(auth *AuthClient, cfg PolicyConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if auth == nil || !auth.Enabled || auth.Address == "" {
			return handler(ctx, req)
		}

		token, ok := extractTokenFromMD(ctx)
		tracer := commons.NewTracerFromContext(ctx)
		reqID := commons.NewHeaderIDFromContext(ctx)

		ctx, span := tracer.Start(ctx, "lib_auth.authorize_grpc_unary_policy")
		defer span.End()

		span.SetAttributes(attribute.String("app.request.request_id", reqID))

		if !ok || commons.IsNilOrEmpty(&token) {
			return nil, status.Error(codes.Unauthenticated, "missing token")
		}

		pol, found := policyForMethod(cfg, info.FullMethod)
		if !found {
			opentelemetry.HandleSpanError(&span, "no policy configured for method", fmt.Errorf("%s", info.FullMethod))

			return nil, status.Error(codes.Internal, "internal configuration error")
		}

		var sub string
		if cfg.SubResolver != nil {
			var err error
			sub, err = cfg.SubResolver(ctx, info.FullMethod, req)
			if err != nil {
				opentelemetry.HandleSpanError(&span, "failed to resolve subject", err)

				return nil, status.Error(codes.Internal, "internal configuration error")
			}
		}

		payload := map[string]string{
			"sub":      sub,
			"resource": pol.Resource,
			"action":   pol.Action,
		}
		if err := opentelemetry.SetSpanAttributesFromStruct(&span, "app.request.payload", payload); err != nil {
			opentelemetry.HandleSpanError(&span, "failed to set span payload", err)
		}

		authorized, httpStatus, err := auth.checkAuthorization(ctx, sub, pol.Resource, pol.Action, token)
		if err != nil {
			return nil, grpcErrorFromHTTP(httpStatus)
		}

		if !authorized {
			return nil, status.Error(codes.PermissionDenied, "forbidden")
		}

		return handler(ctx, req)
	}
}

// extractTokenFromMD returns the bearer token from incoming metadata "authorization".
// Returns false when absent or empty.
func extractTokenFromMD(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}

	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", false
	}

	token := stripBearer(vals[0])
	if token == "" {
		return "", false
	}

	return token, true
}

// stripBearer removes a leading "Bearer " (case-insensitive) from v.
func stripBearer(v string) string {
	s := strings.TrimSpace(v)
	if len(s) >= 7 && strings.EqualFold(s[:7], "bearer ") {
		return strings.TrimSpace(s[7:])
	}

	return s
}

// policyForMethod resolves the Policy for fullMethod from cfg.MethodPolicies,
// falling back to cfg.DefaultPolicy when present.
func policyForMethod(cfg PolicyConfig, fullMethod string) (Policy, bool) {
	if cfg.MethodPolicies != nil {
		if p, ok := cfg.MethodPolicies[fullMethod]; ok {
			return p, true
		}
	}

	if cfg.DefaultPolicy != nil {
		return *cfg.DefaultPolicy, true
	}

	return Policy{}, false
}

// grpcErrorFromHTTP maps HTTP status codes from the auth service to gRPC errors.
func grpcErrorFromHTTP(httpStatus int) error {
	switch httpStatus {
	case http.StatusUnauthorized:
		return status.Error(codes.Unauthenticated, "unauthenticated")
	case http.StatusForbidden:
		return status.Error(codes.PermissionDenied, "forbidden")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}

// SubFromMetadata creates a SubResolver that extracts the subject base from
// incoming metadata by key (key is normalized to lower-case). Returns "" when missing.
func SubFromMetadata(key string) func(ctx context.Context, fullMethod string, req any) (string, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	return func(ctx context.Context, _ string, _ any) (string, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return "", nil
		}

		vals := md.Get(key)
		if len(vals) == 0 {
			return "", nil
		}

		return vals[0], nil
	}
}
