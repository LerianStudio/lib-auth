package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/LerianStudio/lib-commons/commons/log"
	"github.com/LerianStudio/lib-commons/commons/opentelemetry"
	"github.com/LerianStudio/lib-commons/commons/zap"

	"github.com/LerianStudio/lib-commons/commons"
	libHTTP "github.com/LerianStudio/lib-commons/commons/net/http"
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

// NewAuthClient creates a new instance of AuthClient.
// It checks the health of the authorization service if the client is enabled and the address is provided.
// If the service is healthy, it logs a successful connection message; otherwise, it logs the failure reason.
func NewAuthClient(address string, enabled bool, logger *log.Logger) *AuthClient {
	if !enabled || address == "" {
		return &AuthClient{
			Address: address,
			Enabled: enabled,
			Logger:  nil,
		}
	}

	client := &http.Client{}
	healthURL := fmt.Sprintf("%s/health", address)

	failedToConnectMsg := fmt.Sprintf("Failed to connect to %s: %%v\n", pluginName)

	var l log.Logger

	if logger != nil {
		l = *logger
	} else {
		l = zap.InitializeLogger()
	}

	resp, err := client.Get(healthURL)
	if err != nil {
		l.Errorf(failedToConnectMsg, err)

		return &AuthClient{Address: address, Enabled: enabled}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		l.Errorf(failedToConnectMsg, resp.Status)

		return &AuthClient{Address: address, Enabled: enabled}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		l.Errorf("Failed to read response body: %v\n", err)

		return &AuthClient{Address: address, Enabled: enabled}
	}

	if string(body) == "healthy" {
		l.Infof("Connected to %s ✅ \n", pluginName)
	} else {
		l.Errorf(failedToConnectMsg, string(body))
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
		ctx := opentelemetry.ExtractHTTPContext(c)

		tracer := commons.NewTracerFromContext(ctx)

		ctx, span := tracer.Start(ctx, "lib_auth.authorize")
		defer span.End()

		if !auth.Enabled || auth.Address == "" {
			return c.Next()
		}

		accessToken := libHTTP.ExtractTokenFromHeader(c)

		if commons.IsNilOrEmpty(&accessToken) {
			return c.Status(http.StatusUnauthorized).SendString("Missing Token")
		}

		if authorized, statusCode, err := auth.checkAuthorization(ctx, sub, resource, action, accessToken); err != nil {
			var commonsErr commons.Response
			if errors.As(err, &commonsErr) {
				return c.Status(statusCode).JSON(commonsErr)
			}

			return c.Status(http.StatusInternalServerError).SendString("Internal Server Error")
		} else if authorized {
			return c.Next()
		}

		return c.Status(http.StatusForbidden).SendString("Forbidden")
	}
}

// checkAuthorization sends an authorization request to the external service and returns whether the action is authorized.
func (auth *AuthClient) checkAuthorization(ctx context.Context, sub, resource, action, accessToken string) (bool, int, error) {
	tracer := commons.NewTracerFromContext(ctx)

	ctx, span := tracer.Start(ctx, "lib_auth.check_authorization")
	defer span.End()

	client := &http.Client{}

	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		auth.Logger.Errorf("Failed to parse token: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to parse token", err)

		return false, http.StatusInternalServerError, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		auth.Logger.Errorf("Failed to parse claims: token.Claims is not of type jwt.MapClaims")

		opentelemetry.HandleSpanError(&span, "Failed to parse claims", err)

		return false, http.StatusInternalServerError, errors.New("token claims are not in the expected format")
	}

	userType, _ := claims["type"].(string)

	if userType != normalUser {
		sub = fmt.Sprintf("lerian/%s-editor-role", sub)
	} else {
		sub, _ = claims["sub"].(string)
		sub = fmt.Sprintf("lerian/%s", sub)
	}

	requestBody := map[string]string{
		"sub":      sub,
		"resource": resource,
		"action":   action,
	}

	err = opentelemetry.SetSpanAttributesFromStruct(&span, "auth_request_body", requestBody)
	if err != nil {
		opentelemetry.HandleSpanError(&span, "Failed to convert request body to JSON string", err)

		return false, http.StatusInternalServerError, err
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		auth.Logger.Errorf("Failed to marshal request body: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to marshal request body", err)

		return false, http.StatusInternalServerError, err
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/authorize", auth.Address), bytes.NewBuffer(requestBodyJSON))
	if err != nil {
		auth.Logger.Errorf("Failed to create request: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to create request", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to create request: %w", err)
	}

	opentelemetry.InjectHTTPContext(&req.Header, ctx)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", accessToken)

	resp, err := client.Do(req)
	if err != nil {
		auth.Logger.Errorf("Failed to make request: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to make request", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		auth.Logger.Errorf("Failed to read response body: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to read response body", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to read response body: %w", err)
	}

	var respError commons.Response
	if err := json.Unmarshal(body, &respError); err != nil {
		auth.Logger.Errorf("Failed to unmarshal auth error response: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to unmarshal auth error response", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal auth error response: %w", err)
	}

	if respError.Code != "" && resp.StatusCode != http.StatusInternalServerError {
		auth.Logger.Errorf("Authorization request failed: %s", respError.Message)

		errMsg := "authorization request failed"
		opentelemetry.HandleSpanError(&span, errMsg, errors.New(errMsg))

		return false, resp.StatusCode, respError
	}

	var response AuthResponse
	if err := json.Unmarshal(body, &response); err != nil {
		auth.Logger.Errorf("Failed to unmarshal response: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to unmarshal response", err)

		return false, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response.Authorized, resp.StatusCode, nil
}

// GetApplicationToken sends a POST request to the authorization service to get a token for the application.
// It takes the client ID and client secret as parameters and returns the access token if the request is successful.
// If the request fails at any step, an error is returned with a descriptive message.
func (auth *AuthClient) GetApplicationToken(ctx context.Context, clientID, clientSecret string) (string, error) {
	tracer := commons.NewTracerFromContext(ctx)

	ctx, span := tracer.Start(ctx, "lib_auth.get_application_token")
	defer span.End()

	if !auth.Enabled || auth.Address == "" {
		return "", nil
	}

	client := &http.Client{}

	requestBody, err := json.Marshal(map[string]string{
		"grantType":    "client_credentials",
		"clientId":     clientID,
		"clientSecret": clientSecret,
	})

	if err != nil {
		auth.Logger.Errorf("Failed to marshal request body: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to marshal request body", err)

		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/login/oauth/access_token", auth.Address), bytes.NewBuffer(requestBody))
	if err != nil {
		auth.Logger.Errorf("Failed to create request: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to create request", err)

		return "", fmt.Errorf("failed to create request: %w", err)
	}

	opentelemetry.InjectHTTPContext(&req.Header, ctx)

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		auth.Logger.Errorf("Failed to make request: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to make request", err)

		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		auth.Logger.Errorf("Failed to read response body: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to read response body", err)

		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var respError commons.Response
	if err := json.Unmarshal(body, &respError); err != nil {
		auth.Logger.Errorf("Failed to unmarshal auth error response: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to unmarshal auth error response", err)

		return "", fmt.Errorf("failed to unmarshal auth error response: %w", err)
	}

	if respError.Code != "" && resp.StatusCode != http.StatusInternalServerError {
		auth.Logger.Errorf("Failed to get application token: %s", respError.Message)

		opentelemetry.HandleSpanError(&span, "Failed to get application token", nil)

		return "", respError
	}

	var response oauth2Token
	if err := json.Unmarshal(body, &response); err != nil {
		auth.Logger.Errorf("Failed to unmarshal response: %v", err)

		opentelemetry.HandleSpanError(&span, "Failed to unmarshal response", err)

		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response.AccessToken, nil
}
