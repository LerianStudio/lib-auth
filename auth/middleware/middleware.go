package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
)

type AuthClient struct {
	Address string
	Enabled bool
}

type AuthResponse struct {
	Authorized bool      `json:"authorized"`
	Timestamp  time.Time `json:"timestamp"`
}

type oauth2Token struct {
	AccessToken  string  `json:"access_token"`
	IDToken      *string `json:"id_token,omitempty"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
	Scope        *string `json:"scope,omitempty"`
}

const (
	typeOfSub  string = "normal-user"
	pluginName string = "plugin-auth"
)

func NewAuthClient(address string, enabled bool) *AuthClient {
	if !enabled || address == "" {
		return &AuthClient{
			Address: address,
			Enabled: enabled,
		}
	}

	client := &http.Client{}
	healthURL := fmt.Sprintf("%s/health", address)

	resp, err := client.Get(healthURL)
	if err != nil {
		log.Printf("Failed to connect to %s: %v\n", pluginName, err)

		return &AuthClient{Address: address, Enabled: enabled}
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v\n", err)

		return &AuthClient{Address: address, Enabled: enabled}
	}

	if string(body) == "healthy" {
		log.Printf("Connected to %s ✅ \n", pluginName)
	} else {
		log.Printf("Failed to connect to %s: %s\n", pluginName, string(body))
	}

	return &AuthClient{
		Address: address,
		Enabled: enabled,
	}
}

// Authorize is a middleware function for the Fiber framework that checks if a user is authorized to perform a specific action on a resource.
// It sends a POST request to the authorization service with the subject, resource, and action details.
// If the user is authorized, the request is passed to the next handler; otherwise, a 403 Forbidden status is returned.
func (auth *AuthClient) Authorize(sub, resource, action string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !auth.Enabled || auth.Address == "" {
			return c.Next()
		}

		accessToken := c.Get("Authorization")

		if authorized, err := auth.checkAuthorization(sub, resource, action, accessToken); err != nil {
			log.Printf("Authorization request failed %v", err)
			return c.Status(http.StatusInternalServerError).SendString("Internal Server Error")
		} else if authorized {
			return c.Next()
		}

		return c.Status(http.StatusForbidden).SendString("Forbidden")
	}
}

// checkAuthorization sends an authorization request to the external service and returns whether the action is authorized.
func (auth *AuthClient) checkAuthorization(sub, resource, action, accessToken string) (bool, error) {
	client := &http.Client{}

	requestBody, err := json.Marshal(map[string]string{
		"sub":      fmt.Sprintf("lerian/%s-editor-role", sub),
		"resource": resource,
		"action":   action,
	})

	if err != nil {
		return false, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/authorize", auth.Address), bytes.NewBuffer(requestBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	var response AuthResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return false, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response.Authorized, nil
}

// GetApplicationToken sends a POST request to the authorization service to get a token for the application.
// It takes the client ID and client secret as parameters and returns the access token if the request is successful.
// If the request fails at any step, an error is returned with a descriptive message.
func (auth *AuthClient) GetApplicationToken(clientID, clientSecret string) (string, error) {
	client := &http.Client{}

	requestBody, err := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
	})

	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/login/oauth/access_token", auth.Address), bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var response oauth2Token
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return response.AccessToken, nil
}
