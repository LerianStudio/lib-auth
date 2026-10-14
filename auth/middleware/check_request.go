package middleware

import (
	libHTTP "github.com/LerianStudio/lib-commons/v7/commons/net/http"
	"github.com/gofiber/fiber/v3"
)

// CheckRequest is Check for the request in flight: the token and the caller IP
// come from c exactly as Authorize derives them (TRUSTED_PROXIES walk included),
// so the caller cannot choose the address the IP allowlist matches.
func (auth *AuthClient) CheckRequest(c fiber.Ctx, product, resource, action string) (bool, int, error) {
	return auth.Check(c.Context(), product, resource, action, libHTTP.ExtractTokenFromHeader(c), auth.resolveClientIP(c))
}
