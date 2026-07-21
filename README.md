# Lib Auth Middleware

This repository contains an authorization middleware for the Fiber framework in Go, allowing you to check if a user is authorized to perform a specific action on a resource. The middleware sends a POST request to an authorization service, passing the user's details, resource, and desired action.

Repository: [lib-auth](https://github.com/LerianStudio/lib-auth)

## 📦 Installation

```bash
go get github.com/LerianStudio/lib-auth/v3@latest
```

## 🚀 How to Use

### 1. Set the needed environment variables:

In your environment configuration or `.env` file, set the following environment variables:

```dotenv
PLUGIN_AUTH_ADDRESS=http://localhost:4000
PLUGIN_AUTH_ENABLED=true

# Optional. When "true", the client also forwards the route product on M2M
# (application-token) authorization calls, so the auth service can isolate
# permissions by product (matching product-prefixed resources). Defaults to
# false, preserving the previous behavior of sending no product for M2M.
AUTH_M2M_PRODUCT_FORWARD_ENABLED=false

# Optional. When "true", the middleware fails closed: if auth is disabled
# (PLUGIN_AUTH_ENABLED=false) or misconfigured (empty PLUGIN_AUTH_ADDRESS),
# every protected route refuses to serve (HTTP 503 / gRPC Unavailable) instead
# of passing through unauthenticated. Defaults to false, preserving the prior
# fail-open behavior. Set it in security-sensitive deployments so a
# missing/typo'd address cannot silently downgrade a protected service to open.
AUTH_REQUIRED=false

# Optional authorization resilience (all opt-in; defaults preserve prior behavior).
# Every fallback denies (fail closed) — no path serves a request on an outage.
#
# AUTH_TIMEOUT bounds each authorization round-trip with a per-request deadline
# (Go duration). Defaults to 30s (behavior-neutral). It also caps the retry budget.
AUTH_TIMEOUT=30s
# AUTH_CACHE_TTL enables a short-lived decision cache when > 0, keyed by
# (subject, resource, action, product) — never the token. Empty/0 disables it
# (default). Security tradeoff: a permission revocation takes up to the TTL to
# propagate, so keep it small (5–15s). It sheds load and, with the breaker,
# survives brief authz outages by serving fresh positive decisions.
AUTH_CACHE_TTL=
# AUTH_BREAKER_ENABLED opens a circuit breaker after sustained authz failures.
# While open it serves ONLY a fresh positive cache hit and otherwise denies;
# it never serves a stale decision. Defaults to disabled.
AUTH_BREAKER_ENABLED=false
# AUTH_RETRY_MAX retries only TRANSIENT failures (network/timeout/5xx) up to N
# times within AUTH_TIMEOUT; authoritative 401/403 are never retried. 0 disables.
AUTH_RETRY_MAX=0
```

### 2. Create a new instance of the middleware:

In your `config.go` file, configure the environment variables for the Auth Service:

```go
type Config struct {
    Address             string `env:"PLUGIN_AUTH_ADDRESS"`
    Enabled             bool   `env:"PLUGIN_AUTH_ENABLED"`
}

cfg := &Config{}

logger := zap.InitializeLogger()
```

```go
import "github.com/LerianStudio/lib-auth/v3/auth/middleware"

authClient := middleware.NewAuthClient(cfg.Address, cfg.Enabled, &logger)
```

### 2. Use the middleware in your Fiber application:

```go
func NewRoutes(auth *authMiddleware.AuthClient, [...]) *fiber.App {
    f := fiber.New(fiber.Config{
        DisableStartupMessage: true,
    })
    
    applicationName := os.Getenv("APPLICATION_NAME")
    
    // Applications routes
    f.Get("/v1/applications", auth.Authorize(applicationName, "ledger", "get"), applicationHandler.GetApplications)
}
```

## 🛠️ How It Works

The `Authorize` function:

* Receives the `sub` (user), `resource` (resource), and `action` (desired action).
* Sends a POST request to the authorization service.
* Checks if the response indicates that the user is authorized.
* Allows the normal application flow or returns a 403 (Forbidden) error.

## 📥 Example Request to Auth

```http
POST /v1/authorize
Content-Type: application/json
Authorization: Bearer your_token_here

{
    "sub":      "lerian/userId",
    "resource": "resourceName",
    "action":   "get"
}
```

## 📡 Expected Authorization Service Response

The authorization service should return a JSON response in the following format:

```json
{
    "authorized": true,
    "timestamp": "2025-03-03T12:00:00Z"
}
```

## 🔒 gRPC usage

Secure a gRPC server with the unary interceptor using per-method policies. It reuses the same auth service and tracing used by the HTTP middleware.

```go
import (
    "context"
    "google.golang.org/grpc"
    "github.com/LerianStudio/lib-auth/v3/auth/middleware"
)

// Create the auth client once (same as HTTP)
authClient := middleware.NewAuthClient(cfg.Address, cfg.Enabled, &logger)

// Map full gRPC method names to authorization policies
policies := middleware.PolicyConfig{
    MethodPolicies: map[string]middleware.Policy{
        "/balance.BalanceProto/CreateBalance": {Resource: "balances", Action: "post"},
    },
    // Constant subject base, matching HTTP usage (e.g., "midaz")
    SubResolver: func(ctx context.Context, _ string, _ any) (string, error) { return "midaz", nil },
}

srv := grpc.NewServer(
    grpc.UnaryInterceptor(middleware.NewGRPCAuthUnaryPolicy(authClient, policies)),
)
```

Notes:
- Keys in `MethodPolicies` must be full method names in the form `/package.Service/Method`.
- When `SubResolver` returns an empty string, the subject is derived from token claims.
 - If you already use multiple interceptors, prefer `grpc.ChainUnaryInterceptor(...)` and include the auth interceptor alongside telemetry/logging.

## 🚧 Error Handling

The middleware captures and logs the following error types:

* Failure to create the request
* Failure to send the request
* Failure to read the response body
* Failure to deserialize the response JSON
* Errors from the authorization service (e.g., 401 Unauthorized, 403 Forbidden)

## 📧 Contact

For questions or support, contact us at: [contato@lerian.studio](mailto:contato@lerian.studio).
