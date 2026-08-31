package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/LerianStudio/lib-commons/v6/commons"
	observability "github.com/LerianStudio/lib-observability/v4"
	"github.com/LerianStudio/lib-observability/v4/tracing"
	jwt "github.com/golang-jwt/jwt/v5"
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

// PolicyConfig binds gRPC methods to Policies and optional product resolution.
//   - MethodPolicies keyed by info.FullMethod ("/pkg.Service/Method").
//   - DefaultPolicy used when a method mapping is absent.
//   - SubResolver derives the product identifier (e.g., "midaz") passed to
//     checkAuthorization as its product argument. It is forwarded for normal-user
//     tokens, and for M2M (application) tokens when AUTH_M2M_PRODUCT_FORWARD_ENABLED
//     is set; M2M tokens are identified by their own subject claim. Return ""
//     when not applicable.
type PolicyConfig struct {
	MethodPolicies map[string]Policy
	DefaultPolicy  *Policy
	SubResolver    func(ctx context.Context, fullMethod string, req any) (string, error)
}

// NewGRPCAuthUnaryPolicy authorizes unary RPCs via per-method Policy.
// Behavior:
// - Resolves the Policy by info.FullMethod; falls back to DefaultPolicy when provided.
// - Optionally derives the product using cfg.SubResolver (e.g., "midaz"). Empty product is valid.
// - Rejects missing tokens with codes.Unauthenticated; misconfiguration returns codes.Internal.
// Telemetry:
//   - Sets app.request.request_id.
//   - Sets app.request.payload with {resource, action}, including product only when
//     it is actually forwarded to the auth service (normal-user, or M2M when
//     AUTH_M2M_PRODUCT_FORWARD_ENABLED is set), mirroring the request body.
func NewGRPCAuthUnaryPolicy(auth *AuthClient, cfg PolicyConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if auth.mustRefuse() {
			// AUTH_REQUIRED opted in but auth is disabled/misconfigured: refuse the
			// RPC (fail closed) instead of silently passing it through.
			return nil, status.Error(codes.Unavailable, "service unavailable")
		}

		if !auth.canAuthorize() {
			return handler(ctx, req)
		}

		token, ok := extractTokenFromMD(ctx)
		_, tracer, reqID, _ := observability.NewTrackingFromContext(ctx)

		ctx, span := tracer.Start(ctx, "lib_auth.authorize_grpc_unary_policy")
		defer span.End()

		span.SetAttributes(attribute.String("app.request.request_id", reqID))

		if !ok || commons.IsNilOrEmpty(&token) {
			return nil, status.Error(codes.Unauthenticated, "missing token")
		}

		pol, found := policyForMethod(cfg, info.FullMethod)
		if !found {
			tracing.HandleSpanError(span, "no policy configured for method", fmt.Errorf("%s", info.FullMethod))

			return nil, status.Error(codes.Internal, "internal configuration error")
		}

		// product is the resolved product identifier passed as checkAuthorization's
		// product argument. It is forwarded for normal-user flows, and for M2M
		// (application) flows when AUTH_M2M_PRODUCT_FORWARD_ENABLED is set.
		var product string

		if cfg.SubResolver != nil {
			var err error

			product, err = cfg.SubResolver(ctx, info.FullMethod, req)
			if err != nil {
				tracing.HandleSpanError(span, "failed to resolve product", err)

				return nil, status.Error(codes.Internal, "internal configuration error")
			}
		}

		payload := authPayload(token, product, pol.Resource, pol.Action, auth.ForwardM2MProduct)
		if err := tracing.SetSpanAttributesFromValue(span, "app.request.payload", payload, nil); err != nil {
			tracing.HandleSpanError(span, "failed to set span payload", err)
		}

		// clientIP is empty for gRPC: peer/metadata IP extraction is the approved
		// follow-up epic, out of v1 scope, so no clientIp is forwarded here.
		authorized, httpStatus, err := auth.checkAuthorization(ctx, product, pol.Resource, pol.Action, token, "")
		if err != nil {
			return nil, grpcErrorFromHTTP(httpStatus)
		}

		if !authorized {
			return nil, status.Error(codes.PermissionDenied, "forbidden")
		}

		// Propagate tenant claims if multi-tenant mode is enabled
		ctx, _ = tenantContext(ctx, token)

		return handler(ctx, req)
	}
}

// tenantContext returns ctx augmented with tenant metadata (md-tenant-id/slug/owner)
// extracted from the token when MULTI_TENANT_ENABLED is set, along with whether it
// added anything. When multi-tenant mode is off it returns ctx unchanged and false.
// Shared by the unary and stream interceptors to avoid duplicating the propagation
// logic; the bool lets the stream interceptor decide whether to wrap its stream.
func tenantContext(ctx context.Context, token string) (context.Context, bool) {
	if os.Getenv("MULTI_TENANT_ENABLED") != "true" {
		return ctx, false
	}

	tenantID, tenantSlug, tOwner, _ := extractTenantClaims(token)
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()

	if tenantID != "" {
		md.Set("md-tenant-id", tenantID)
	}

	if tenantSlug != "" {
		md.Set("md-tenant-slug", tenantSlug)
	}

	if tOwner != "" {
		md.Set("md-tenant-owner", tOwner)
	}

	return metadata.NewIncomingContext(ctx, md), true
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

// authPayload builds the telemetry payload mirroring the request body sent to the
// auth service by checkAuthorization: product is included only when it is actually
// forwarded — normal-user flows with a non-empty product, or M2M (application)
// flows with a non-empty product when forwardM2MProduct is enabled.
func authPayload(token, product, resource, action string, forwardM2MProduct bool) map[string]string {
	payload := map[string]string{
		"resource": resource,
		"action":   action,
	}

	if shouldForwardProduct(tokenTypeClaim(token), product, forwardM2MProduct) {
		payload["product"] = product
	}

	return payload
}

// tokenTypeClaim returns the "type" claim from an unverified JWT, or "" when the
// token cannot be parsed. Best-effort and telemetry-only: the authorization
// decision (and its fail-closed handling) still goes through checkAuthorization,
// which re-parses and validates the token.
func tokenTypeClaim(tokenString string) string {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return ""
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}

	t, _ := claims["type"].(string)

	return t
}

// extractTenantClaims extracts tenant-related claims from a JWT without signature verification.
// Returns tenantID, tenantSlug, and owner from the token's custom claims.
// Used by gRPC interceptors to propagate tenant context to downstream services.
func extractTenantClaims(tokenString string) (tenantID, tenantSlug, owner string, err error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", "", "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", "", errors.New("invalid token claims")
	}

	tenantID, _ = claims["tenantId"].(string)
	tenantSlug, _ = claims["tenantSlug"].(string)
	owner, _ = claims["owner"].(string)

	return tenantID, tenantSlug, owner, nil
}

// NewGRPCAuthStreamPolicy authorizes streaming RPCs via per-method Policy.
// Mirrors NewGRPCAuthUnaryPolicy behavior for streaming calls:
// - Resolves Policy by info.FullMethod; falls back to DefaultPolicy.
// - Rejects missing tokens with codes.Unauthenticated.
// - Propagates tenant claims when MULTI_TENANT_ENABLED=true.
func NewGRPCAuthStreamPolicy(auth *AuthClient, cfg PolicyConfig) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if auth.mustRefuse() {
			// AUTH_REQUIRED opted in but auth is disabled/misconfigured: refuse the
			// stream (fail closed) instead of silently passing it through.
			return status.Error(codes.Unavailable, "service unavailable")
		}

		if !auth.canAuthorize() {
			return handler(srv, ss)
		}

		ctx := ss.Context()
		token, ok := extractTokenFromMD(ctx)

		if !ok || commons.IsNilOrEmpty(&token) {
			return status.Error(codes.Unauthenticated, "missing token")
		}

		pol, found := policyForMethod(cfg, info.FullMethod)
		if !found {
			return status.Error(codes.Internal, "internal configuration error")
		}

		// product is the resolved product identifier passed as checkAuthorization's
		// product argument. It is forwarded for normal-user flows, and for M2M
		// (application) flows when AUTH_M2M_PRODUCT_FORWARD_ENABLED is set.
		var product string

		if cfg.SubResolver != nil {
			var err error

			product, err = cfg.SubResolver(ctx, info.FullMethod, nil)
			if err != nil {
				return status.Error(codes.Internal, "internal configuration error")
			}
		}

		// clientIP is empty for gRPC: peer/metadata IP extraction is the approved
		// follow-up epic, out of v1 scope, so no clientIp is forwarded here.
		authorized, httpStatus, err := auth.checkAuthorization(ctx, product, pol.Resource, pol.Action, token, "")
		if err != nil {
			return grpcErrorFromHTTP(httpStatus)
		}

		if !authorized {
			return status.Error(codes.PermissionDenied, "forbidden")
		}

		// Propagate tenant claims if multi-tenant mode is enabled
		if tenantCtx, wrapped := tenantContext(ctx, token); wrapped {
			ss = &wrappedServerStream{ServerStream: ss, ctx: tenantCtx}
		}

		return handler(srv, ss)
	}
}

// wrappedServerStream wraps grpc.ServerStream to override Context().
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
