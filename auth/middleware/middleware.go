package middleware

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"strings"
	"time"

	observability "github.com/LerianStudio/lib-observability/v2"
	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/LerianStudio/lib-observability/v2/tracing"
	"github.com/LerianStudio/lib-observability/v2/zap"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/LerianStudio/lib-commons/v6/commons"
	libHTTP "github.com/LerianStudio/lib-commons/v6/commons/net/http"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/sony/gobreaker"
)

type AuthClient struct {
	Address string
	Enabled bool
	Logger  log.Logger

	// ForwardM2MProduct, when true, forwards the route product on M2M
	// (application-token) authorization calls, letting the auth service strip the
	// "{product}/" prefix from stored resources and dual-match a bare request.
	// It is read once from AUTH_M2M_PRODUCT_FORWARD_ENABLED at construction; the
	// default (false) preserves the prior behavior of sending no product for M2M.
	// Gating it by env keeps deploy != release: flipping the flag activates M2M
	// product isolation without a code change in consumers.
	ForwardM2MProduct bool

	// Required, when true, makes the middleware fail closed: if auth is disabled
	// or misconfigured (!Enabled || Address == ""), every protected route refuses
	// to serve (HTTP 503 / gRPC Unavailable) instead of passing through with
	// c.Next()/handler(). It is read once from AUTH_REQUIRED at construction; the
	// default (false) preserves the prior fail-open pass-through behavior exactly.
	// This inverts the default posture only for deployments that opt in, so a
	// missing/typo'd address can no longer silently downgrade a protected service
	// to fully open.
	Required bool

	// timeout bounds each authorization round-trip via a per-request context
	// deadline. Read once from AUTH_TIMEOUT; defaults to 30s (behavior-neutral,
	// matching the prior client-wide HTTP timeout) when unset/invalid. It also caps
	// the retry budget.
	timeout time.Duration

	// cache, when non-nil, memoizes authorization decisions for a short TTL keyed by
	// (sub, resource, action, product) — NEVER the raw token. Enabled by
	// AUTH_CACHE_TTL > 0 (opt-in; nil = no caching, prior behavior). It trades a
	// bounded revocation-propagation lag (= TTL) for load shedding and outage
	// resilience.
	cache *decisionCache

	// breaker, when non-nil, short-circuits the authorization call after sustained
	// failures (opt-in via AUTH_BREAKER_ENABLED). While open it serves only a fresh
	// positive cache hit and otherwise denies — it never fails open.
	breaker *gobreaker.CircuitBreaker

	// retryMax is the maximum number of retries applied to TRANSIENT authorization
	// failures (network/timeout/5xx). Read once from AUTH_RETRY_MAX; 0 disables
	// retry (opt-in). Authoritative decisions (401/403) are never retried.
	retryMax uint

	// verifyKeys holds the RSA public keys used to cryptographically verify the
	// bearer token locally before its claims are trusted. When empty (the default)
	// the general path preserves the historical ParseUnverified behavior and the
	// authz round-trip remains the trust anchor. It is populated from
	// AUTH_JWT_VERIFY_CERT / AUTH_JWT_VERIFY_CERT_PATH at construction; carrying more
	// than one key supports zero-downtime cert rotation (any key may verify).
	verifyKeys []*rsa.PublicKey

	// verifyIssuer, when non-empty, pins the accepted token "iss" claim during local
	// verification. Read once from AUTH_JWT_ISSUER; inert when verifyKeys is empty.
	verifyIssuer string
}

type AuthResponse struct {
	Authorized bool      `json:"authorized"`
	Timestamp  time.Time `json:"timestamp"`
}

type oauth2Token struct {
	AccessToken  string  `json:"accessToken"`
	IDToken      *string `json:"idToken,omitempty"`
	TokenType    string  `json:"tokenType"`
	ExpiresIn    int     `json:"expiresIn"`
	RefreshToken string  `json:"refreshToken"`
	Scope        *string `json:"scope,omitempty"`
}

const (
	normalUser  string = "normal-user"
	application string = "application"
	pluginName  string = "plugin-auth"
)

// sharedHTTPClient is a package-level HTTP client with a custom transport
// that prevents HTTP/2 hpack panics under concurrent access. HTTP clients
// are safe for concurrent use and should be reused across requests.
var sharedHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// unmarshalErrorResponse unmarshals a JSON response body into commons.Response,
// tolerating a numeric "code" field (the auth service may return code as a number).
func unmarshalErrorResponse(body []byte) (commons.Response, error) {
	var raw struct {
		EntityType string          `json:"entityType,omitempty"`
		Title      string          `json:"title,omitempty"`
		Message    string          `json:"message,omitempty"`
		Code       json.RawMessage `json:"code,omitempty"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return commons.Response{}, err
	}

	resp := commons.Response{
		EntityType: raw.EntityType,
		Title:      raw.Title,
		Message:    raw.Message,
	}

	if len(raw.Code) > 0 {
		var code string
		if err := json.Unmarshal(raw.Code, &code); err == nil {
			resp.Code = code
		} else {
			// Numeric code — use raw representation (e.g. "401")
			resp.Code = string(raw.Code)
		}
	}

	return resp, nil
}

func logErrorf(ctx context.Context, logger log.Logger, format string, args ...any) {
	if logger == nil {
		return
	}

	logger.Log(ctx, log.LevelError, fmt.Sprintf(format, args...))
}

func logInfof(ctx context.Context, logger log.Logger, format string, args ...any) {
	if logger == nil {
		return
	}

	logger.Log(ctx, log.LevelInfo, fmt.Sprintf(format, args...))
}

func initializeDefaultLogger() (log.Logger, error) {
	envName := strings.ToLower(strings.TrimSpace(os.Getenv("ENV_NAME")))

	environment := zap.EnvironmentLocal

	switch envName {
	case string(zap.EnvironmentProduction):
		environment = zap.EnvironmentProduction
	case string(zap.EnvironmentStaging):
		environment = zap.EnvironmentStaging
	case string(zap.EnvironmentUAT):
		environment = zap.EnvironmentUAT
	case string(zap.EnvironmentDevelopment), "dev":
		environment = zap.EnvironmentDevelopment
	}

	otelLibraryName := strings.TrimSpace(os.Getenv("OTEL_LIBRARY_NAME"))
	if otelLibraryName == "" {
		otelLibraryName = "lib-auth"
	}

	logger, err := zap.New(zap.Config{
		Environment:     environment,
		OTelLibraryName: otelLibraryName,
	})
	if err != nil {
		return nil, err
	}

	return logger, nil
}

// NewAuthClient creates a new instance of AuthClient.
// It checks the health of the authorization service if the client is enabled and the address is provided.
// If the service is healthy, it logs a successful connection message; otherwise, it logs the failure reason.
func NewAuthClient(address string, enabled bool, logger *log.Logger) *AuthClient {
	var l log.Logger

	var err error

	if logger != nil {
		l = *logger
	} else {
		l, err = initializeDefaultLogger()
		if err != nil {
			stdlog.Printf("failed to initialize logger, using NopLogger: %v", err)

			l = log.NewNop()
		}
	}

	verifyKeys, verifyIssuer := loadVerification(l)

	// Build the client once with all env-derived config, then return it from every
	// path below; the health check only logs, it never changes these fields.
	c := &AuthClient{
		Address:           address,
		Enabled:           enabled,
		Logger:            l,
		ForwardM2MProduct: os.Getenv("AUTH_M2M_PRODUCT_FORWARD_ENABLED") == "true",
		Required:          os.Getenv("AUTH_REQUIRED") == "true",
		timeout:           parseAuthTimeout(),
		cache:             newDecisionCacheFromEnv(),
		breaker:           newBreakerFromEnv(),
		retryMax:          parseRetryMax(),
		verifyKeys:        verifyKeys,
		verifyIssuer:      verifyIssuer,
	}

	if !enabled || address == "" {
		if c.Required {
			logErrorf(context.Background(), l,
				"AUTH_REQUIRED is set but auth is disabled or address is empty: middleware will fail closed (refuse to serve)")
		}

		return c
	}

	client := sharedHTTPClient
	healthURL := fmt.Sprintf("%s/health", address)

	failedToConnectMsg := fmt.Sprintf("Failed to connect to %s: %%v\n", pluginName)

	resp, err := client.Get(healthURL)
	if err != nil {
		logErrorf(context.Background(), l, failedToConnectMsg, err)

		return c
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logErrorf(context.Background(), l, failedToConnectMsg, resp.Status)

		return c
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logErrorf(context.Background(), l, "Failed to read response body: %v", err)

		return c
	}

	if string(body) == "healthy" {
		logInfof(context.Background(), l, "Connected to %s", pluginName)
	} else {
		logErrorf(context.Background(), l, failedToConnectMsg, string(body))
	}

	return c
}

// canAuthorize reports whether the client is able to perform an authorization
// check: non-nil, Enabled, and holding an Address. When it returns false the
// caller passes the request through (default, fail open) unless Required is set.
// A nil receiver is safe and reports false, so a nil client is never usable.
func (auth *AuthClient) canAuthorize() bool {
	return auth != nil && auth.Enabled && auth.Address != ""
}

// mustRefuse reports whether a client that cannot authorize must fail closed
// (refuse to serve) instead of passing the request through. It is true only when
// the client is non-nil, opted in via Required (AUTH_REQUIRED), and cannot
// authorize (disabled or no address). This is the fail-closed switch from #107.
func (auth *AuthClient) mustRefuse() bool {
	return auth != nil && auth.Required && !auth.canAuthorize()
}

// Authorize is a middleware function for the Fiber framework that checks if a user is authorized to perform a specific action on a resource.
// product identifies the product/application owning the route (e.g. "midaz"); it is forwarded for normal-user flows, and for M2M (application)
// flows when AUTH_M2M_PRODUCT_FORWARD_ENABLED is set, so the auth service can isolate permissions by product. M2M tokens are identified by their own subject claim.
// If the user is authorized, the request is passed to the next handler; otherwise, a 403 Forbidden status is returned.
func (auth *AuthClient) Authorize(product, resource, action string) fiber.Handler {
	return func(c fiber.Ctx) error {
		ctx := tracing.ExtractHTTPContext(c.Context(), c)

		_, tracer, reqID, _ := observability.NewTrackingFromContext(ctx)

		if auth.mustRefuse() {
			// AUTH_REQUIRED opted in but auth is disabled/misconfigured: refuse to
			// serve (fail closed) instead of silently passing the request through.
			return c.Status(http.StatusServiceUnavailable).SendString("Service Unavailable")
		}

		if !auth.canAuthorize() {
			return c.Next()
		}

		ctx, span := tracer.Start(ctx, "lib_auth.authorize")

		span.SetAttributes(
			attribute.String("app.request.request_id", reqID),
		)

		accessToken := libHTTP.ExtractTokenFromHeader(c)

		if commons.IsNilOrEmpty(&accessToken) {
			span.End()

			return c.Status(http.StatusUnauthorized).SendString("Missing Token")
		}

		// Capture the caller IP resolved by Fiber (honoring the configured trusted
		// proxy / ProxyHeader chain) and forward it so the auth service can apply
		// IP-based policy. It is optional end-to-end: an empty value is omitted from
		// the request body (see checkAuthorization).
		clientIP := c.IP()

		if authorized, statusCode, err := auth.checkAuthorization(ctx, product, resource, action, accessToken, clientIP); err != nil {
			var commonsErr commons.Response
			if errors.As(err, &commonsErr) {
				span.End()

				return c.Status(statusCode).JSON(commonsErr)
			}

			span.End()

			return c.Status(statusCode).SendString(http.StatusText(statusCode))
		} else if authorized {
			span.End()

			return c.Next()
		}

		span.End()

		return c.Status(http.StatusForbidden).SendString("Forbidden")
	}
}

// deriveSubject builds the authorization subject from the token claims based on
// the whitelisted token type. It fails closed (401) for any type outside
// {normal-user, application}:
//   - normal-user: the JWT identity ("<owner>/<userID>"), failing closed with 401
//     when the owner or sub claim is missing.
//   - application (M2M): the token's own sub claim (already in "<owner>/<name>"
//     form), failing closed with 401 when sub is missing. No product-scoped role
//     is fabricated, since M2M has no product isolation.
//   - any other type (including empty/absent): rejected with 401.
func (auth *AuthClient) deriveSubject(ctx context.Context, span trace.Span, claims jwt.MapClaims, userType string) (string, int, error) {
	switch userType {
	case normalUser:
		owner, _ := claims["owner"].(string)
		if owner == "" {
			logErrorf(ctx, auth.Logger, "Missing owner claim in token")

			err := errors.New("missing owner claim in token")

			tracing.HandleSpanError(span, "Missing owner claim in token", err)

			return "", http.StatusUnauthorized, err
		}

		userID, _ := claims["sub"].(string)
		if userID == "" {
			logErrorf(ctx, auth.Logger, "Missing sub claim in token")

			err := errors.New("missing sub claim in token")

			tracing.HandleSpanError(span, "Missing sub claim in token", err)

			return "", http.StatusUnauthorized, err
		}

		return fmt.Sprintf("%s/%s", owner, userID), http.StatusOK, nil
	case application:
		sub, _ := claims["sub"].(string)
		if sub == "" {
			logErrorf(ctx, auth.Logger, "Missing sub claim in application token")

			err := errors.New("missing sub claim in token")

			tracing.HandleSpanError(span, "Missing sub claim in application token", err)

			return "", http.StatusUnauthorized, err
		}

		return sub, http.StatusOK, nil
	default:
		logErrorf(ctx, auth.Logger, "Unsupported token type: %q", userType)

		err := errors.New("unsupported token type")

		tracing.HandleSpanError(span, "Unsupported token type", err)

		return "", http.StatusUnauthorized, err
	}
}

// shouldForwardProduct reports whether the route product must be forwarded to the
// auth service so it can isolate permissions by product (strip the "{product}/"
// prefix from stored resources and dual-match a bare request). It is forwarded for
// normal-user flows, and for M2M (application) flows when forwardM2MProduct is
// enabled; an empty product is never forwarded (gate-by-presence).
func shouldForwardProduct(userType, product string, forwardM2MProduct bool) bool {
	if product == "" {
		return false
	}

	return userType == normalUser || (userType == application && forwardM2MProduct)
}

// checkAuthorization builds and sends the authorization request to the auth
// service. clientIP is the resolved caller IP forwarded as the OPTIONAL
// "clientIp" body field; when empty (e.g. gRPC callers, which do not extract a
// peer IP in v1) the field is omitted so the wire body stays byte-identical to
// the pre-IP behavior for every deployed access-manager. The auth service
// interprets the IP; this layer never parses or validates it.
func (auth *AuthClient) checkAuthorization(ctx context.Context, product, resource, action, accessToken, clientIP string) (bool, int, error) {
	_, tracer, reqID, _ := observability.NewTrackingFromContext(ctx)

	ctx, span := tracer.Start(ctx, "lib_auth.check_authorization")
	defer span.End()

	span.SetAttributes(
		attribute.String("app.request.request_id", reqID),
	)

	// Per-request deadline: propagate the caller's cancellation/deadline to the
	// authz call (the request was previously built without a context, so an upstream
	// cancel could not abort it) and cap the retry budget. Defaults to 30s.
	ctx, cancel := context.WithTimeout(ctx, auth.requestTimeout())
	defer cancel()

	claims, statusCode, err := auth.extractClaims(ctx, span, accessToken)
	if err != nil {
		return false, statusCode, err
	}

	userType, _ := claims["type"].(string)

	sub, statusCode, err := auth.deriveSubject(ctx, span, claims, userType)
	if err != nil {
		return false, statusCode, err
	}

	requestBody := map[string]string{
		"sub":      sub,
		"resource": resource,
		"action":   action,
	}

	if shouldForwardProduct(userType, product, auth.ForwardM2MProduct) {
		requestBody["product"] = product
	}

	// clientIp is optional: the field is omitted when empty, so callers that don't
	// resolve a client IP send the same request body (no clientIp key) as before.
	if clientIP != "" {
		requestBody["clientIp"] = clientIP
	}

	err = tracing.SetSpanAttributesFromValue(span, "app.request.payload", requestBody, nil)
	if err != nil {
		tracing.HandleSpanError(span, "Failed to convert request body to JSON string", err)

		return false, http.StatusInternalServerError, err
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to marshal request body: %v", err)

		tracing.HandleSpanError(span, "Failed to marshal request body", err)

		return false, http.StatusInternalServerError, err
	}

	// Cache key = exactly the authz request inputs (never the raw token). product is
	// the value actually forwarded ("" when not forwarded), so the key matches the
	// decision the authz service made. clientIP is in the key because the decision is
	// IP-dependent (tenant IP-allowlist): a cross-IP cache hit would bypass it.
	key := cacheKey{sub: sub, resource: resource, action: action, product: requestBody["product"], clientIP: clientIP}

	// A fresh cache hit (positive OR negative) short-circuits before the breaker, so
	// the breaker only ever runs on a miss — its open state then denies (never
	// serving a stale grant).
	if auth.cache != nil {
		if authorized, hit := auth.cache.get(key); hit {
			return authorized, http.StatusOK, nil
		}
	}

	return auth.resolveAuthz(ctx, span, accessToken, requestBodyJSON, key)
}

// GetApplicationToken sends a POST request to the authorization service to get a token for the application.
// It takes the client ID and client secret as parameters and returns the access token if the request is successful.
// If the request fails at any step, an error is returned with a descriptive message.
func (auth *AuthClient) GetApplicationToken(ctx context.Context, clientID, clientSecret string) (string, error) {
	_, tracer, reqID, _ := observability.NewTrackingFromContext(ctx)

	ctx, span := tracer.Start(ctx, "lib_auth.get_application_token")
	defer span.End()

	span.SetAttributes(
		attribute.String("app.request.request_id", reqID),
	)

	if !auth.Enabled || auth.Address == "" {
		return "", nil
	}

	client := sharedHTTPClient

	requestBody := map[string]string{
		"grantType":    "client_credentials",
		"clientId":     clientID,
		"clientSecret": clientSecret,
	}

	// tracePayload mirrors requestBody but omits clientSecret so the OAuth secret
	// never flows into telemetry. Do not collapse these two maps.
	tracePayload := map[string]string{
		"grantType": "client_credentials",
		"clientId":  clientID,
	}

	err := tracing.SetSpanAttributesFromValue(span, "app.request.payload", tracePayload, nil)
	if err != nil {
		tracing.HandleSpanError(span, "Failed to convert request body to JSON string", err)

		return "", fmt.Errorf("failed to convert request body to JSON string: %w", err)
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to marshal request body: %v", err)

		tracing.HandleSpanError(span, "Failed to marshal request body", err)

		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/login/oauth/access_token", auth.Address), bytes.NewBuffer(requestBodyJSON))
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to create request: %v", err)

		tracing.HandleSpanError(span, "Failed to create request", err)

		return "", fmt.Errorf("failed to create request: %w", err)
	}

	tracing.InjectHTTPContext(ctx, req.Header)

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to make request: %v", err)

		tracing.HandleSpanError(span, "Failed to make request", err)

		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to read response body: %v", err)

		tracing.HandleSpanError(span, "Failed to read response body", err)

		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	respError, err := unmarshalErrorResponse(body)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to unmarshal auth error response: %v", err)

		tracing.HandleSpanError(span, "Failed to unmarshal auth error response", err)

		return "", fmt.Errorf("failed to unmarshal auth error response: %w", err)
	}

	if respError.Code != "" && resp.StatusCode != http.StatusInternalServerError {
		logErrorf(ctx, auth.Logger, "Failed to get application token: %s", respError.Message)

		tracing.HandleSpanError(span, "Failed to get application token", respError)

		return "", respError
	}

	var response oauth2Token
	if err := json.Unmarshal(body, &response); err != nil {
		logErrorf(ctx, auth.Logger, "Failed to unmarshal response: %v", err)

		tracing.HandleSpanError(span, "Failed to unmarshal response", err)

		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response.AccessToken, nil
}
