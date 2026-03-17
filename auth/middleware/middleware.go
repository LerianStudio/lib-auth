package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LerianStudio/lib-commons/v4/commons/log"
	"github.com/LerianStudio/lib-commons/v4/commons/opentelemetry"
	"github.com/LerianStudio/lib-commons/v4/commons/zap"
	"go.opentelemetry.io/otel/attribute"

	"github.com/LerianStudio/lib-commons/v4/commons"
	libHTTP "github.com/LerianStudio/lib-commons/v4/commons/net/http"
	"github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"
)

type AuthClient struct {
	Address string
	Enabled bool
	Logger  log.Logger
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
	normalUser string = "normal-user"
	pluginName string = "plugin-auth"
)

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

	if !enabled || address == "" {
		return &AuthClient{
			Address: address,
			Enabled: enabled,
			Logger:  l,
		}
	}

	client := &http.Client{}
	healthURL := fmt.Sprintf("%s/health", address)

	failedToConnectMsg := fmt.Sprintf("Failed to connect to %s: %%v\n", pluginName)

	resp, err := client.Get(healthURL)
	if err != nil {
		logErrorf(context.Background(), l, failedToConnectMsg, err)

		return &AuthClient{Address: address, Enabled: enabled, Logger: l}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logErrorf(context.Background(), l, failedToConnectMsg, resp.Status)

		return &AuthClient{Address: address, Enabled: enabled, Logger: l}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logErrorf(context.Background(), l, "Failed to read response body: %v", err)

		return &AuthClient{Address: address, Enabled: enabled, Logger: l}
	}

	if string(body) == "healthy" {
		logInfof(context.Background(), l, "Connected to %s", pluginName)
	} else {
		logErrorf(context.Background(), l, failedToConnectMsg, string(body))
	}

	return &AuthClient{
		Address: address,
		Enabled: enabled,
		Logger:  l,
	}
}

// Authorize is a middleware function for the Fiber framework that checks if a user is authorized to perform a specific action on a resource.
// It sends a POST request to the authorization service with the subject, resource, and action details.
// If the user is authorized, the request is passed to the next handler; otherwise, a 403 Forbidden status is returned.
func (auth *AuthClient) Authorize(sub, resource, action string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := opentelemetry.ExtractHTTPContext(c.UserContext(), c)

		_, tracer, reqID, _ := commons.NewTrackingFromContext(ctx)

		if !auth.Enabled || auth.Address == "" {
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

		if authorized, statusCode, err := auth.checkAuthorization(ctx, sub, resource, action, accessToken); err != nil {
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

// checkAuthorization sends an authorization request to the external service and returns whether the action is authorized.
func (auth *AuthClient) checkAuthorization(ctx context.Context, sub, resource, action, accessToken string) (bool, int, error) {
	_, tracer, reqID, _ := commons.NewTrackingFromContext(ctx)

	ctx, span := tracer.Start(ctx, "lib_auth.check_authorization")
	defer span.End()

	span.SetAttributes(
		attribute.String("app.request.request_id", reqID),
	)

	client := &http.Client{}

	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to parse token: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to parse token", err)

		return false, http.StatusUnauthorized, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logErrorf(ctx, auth.Logger, "Failed to parse claims: token.Claims is not of type jwt.MapClaims")

		err := errors.New("token claims are not in the expected format")

		opentelemetry.HandleSpanError(span, "Failed to parse claims", err)

		return false, http.StatusUnauthorized, err
	}

	userType, _ := claims["type"].(string)

	if userType != normalUser {
		sub = fmt.Sprintf("admin/%s-editor-role", sub)
	} else {
		owner, _ := claims["owner"].(string)
		if owner == "" {
			logErrorf(ctx, auth.Logger, "Missing owner claim in token")

			err := errors.New("missing owner claim in token")

			opentelemetry.HandleSpanError(span, "Missing owner claim in token", err)

			return false, http.StatusUnauthorized, err
		}

		sub, _ = claims["sub"].(string)
		sub = fmt.Sprintf("%s/%s", owner, sub)
	}

	requestBody := map[string]string{
		"sub":      sub,
		"resource": resource,
		"action":   action,
	}

	err = opentelemetry.SetSpanAttributesFromValue(span, "app.request.payload", requestBody, nil)
	if err != nil {
		opentelemetry.HandleSpanError(span, "Failed to convert request body to JSON string", err)

		return false, http.StatusInternalServerError, err
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to marshal request body: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to marshal request body", err)

		return false, http.StatusInternalServerError, err
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/authorize", auth.Address), bytes.NewBuffer(requestBodyJSON))
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to create request: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to create request", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to create request: %w", err)
	}

	opentelemetry.InjectHTTPContext(ctx, req.Header)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", accessToken)

	resp, err := client.Do(req)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to make request: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to make request", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to read response body: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to read response body", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to read response body: %w", err)
	}

	var respError commons.Response
	if err := json.Unmarshal(body, &respError); err != nil {
		logErrorf(ctx, auth.Logger, "Failed to unmarshal auth error response: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to unmarshal auth error response", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal auth error response: %w", err)
	}

	if respError.Code != "" && resp.StatusCode != http.StatusInternalServerError {
		logErrorf(ctx, auth.Logger, "Authorization request failed: %s", respError.Message)

		opentelemetry.HandleSpanError(span, "Authorization request failed", respError)

		return false, resp.StatusCode, respError
	}

	var response AuthResponse
	if err := json.Unmarshal(body, &response); err != nil {
		logErrorf(ctx, auth.Logger, "Failed to unmarshal response: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to unmarshal response", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response.Authorized, resp.StatusCode, nil
}

// GetApplicationToken sends a POST request to the authorization service to get a token for the application.
// It takes the client ID and client secret as parameters and returns the access token if the request is successful.
// If the request fails at any step, an error is returned with a descriptive message.
func (auth *AuthClient) GetApplicationToken(ctx context.Context, clientID, clientSecret string) (string, error) {
	_, tracer, reqID, _ := commons.NewTrackingFromContext(ctx)

	ctx, span := tracer.Start(ctx, "lib_auth.get_application_token")
	defer span.End()

	span.SetAttributes(
		attribute.String("app.request.request_id", reqID),
	)

	if !auth.Enabled || auth.Address == "" {
		return "", nil
	}

	client := &http.Client{}

	requestBody := map[string]string{
		"grantType":    "client_credentials",
		"clientId":     clientID,
		"clientSecret": clientSecret,
	}

	err := opentelemetry.SetSpanAttributesFromValue(span, "app.request.payload", requestBody, nil)
	if err != nil {
		opentelemetry.HandleSpanError(span, "Failed to convert request body to JSON string", err)

		return "", fmt.Errorf("failed to convert request body to JSON string: %w", err)
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to marshal request body: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to marshal request body", err)

		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/login/oauth/access_token", auth.Address), bytes.NewBuffer(requestBodyJSON))
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to create request: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to create request", err)

		return "", fmt.Errorf("failed to create request: %w", err)
	}

	opentelemetry.InjectHTTPContext(ctx, req.Header)

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to make request: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to make request", err)

		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to read response body: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to read response body", err)

		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var respError commons.Response
	if err := json.Unmarshal(body, &respError); err != nil {
		logErrorf(ctx, auth.Logger, "Failed to unmarshal auth error response: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to unmarshal auth error response", err)

		return "", fmt.Errorf("failed to unmarshal auth error response: %w", err)
	}

	if respError.Code != "" && resp.StatusCode != http.StatusInternalServerError {
		logErrorf(ctx, auth.Logger, "Failed to get application token: %s", respError.Message)

		opentelemetry.HandleSpanError(span, "Failed to get application token", respError)

		return "", respError
	}

	var response oauth2Token
	if err := json.Unmarshal(body, &response); err != nil {
		logErrorf(ctx, auth.Logger, "Failed to unmarshal response: %v", err)

		opentelemetry.HandleSpanError(span, "Failed to unmarshal response", err)

		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response.AccessToken, nil
}
