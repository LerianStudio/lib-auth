package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

type AuthClient struct {
	AuthAddress string
}

type AuthResponse struct {
	Authorized bool      `json:"authorized"`
	Timestamp  time.Time `json:"timestamp"`
}

func (auth *AuthClient) Authorize(resource string, action string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		client := http.Client{}

		accessToken := c.Get("Authorization")

		reqBody := strings.NewReader(fmt.Sprintf(`{
				"resource": "%s",
				"action": "%s"
			}`, resource, action))

		req, err := http.NewRequest(http.MethodPost, auth.AuthAddress+"/v1/authorize", reqBody)
		if err != nil {
			log.Printf("Failed to create request: %v", err)
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		// req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		req.Header.Set("Authorization", accessToken)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to make request: %v", err)

			return err
		}

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response body: %v", err)
			return err
		}

		response := &AuthResponse{}

		err = json.Unmarshal(body, &response)
		if err != nil {
			log.Printf("Failed to unmarshal response: %v", err)
			return err
		}

		if response.Authorized {
			return c.Next()
		} else {
			return c.Status(http.StatusForbidden).SendString("Forbidden")
		}

	}

}
