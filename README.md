# Authorization Middleware for Fiber

This repository contains an authorization middleware for the Fiber framework in Go, allowing you to check if a user is authorized to perform a specific action on a resource. The middleware sends a POST request to an authorization service, passing the user's details, resource, and desired action.

Repository: [auth-sdk](https://github.com/LerianStudio/auth-sdk)

## 📦 Installation

```bash
go get -u github.com/gofiber/fiber/v2
```

## 🚀 How to Use

### 1. Create an `AuthClient` instance:

In your `config.go` file, configure the environment variables for the Auth Service:

```go
type Config struct {
    AuthAddress             string `env:"AUTH_ADDRESS"`
    AuthEnabled             bool   `env:"AUTH_ENABLED"`
}
```

```go
import "github.com/LerianStudio/auth-sdk/middleware"

authClient := &middleware.AuthClient{
    AuthAddress: "http://localhost:4000",
    AuthEnabled: true,
}
```

### 2. Use the middleware in your Fiber application:

```go
f := fiber.New(fiber.Config{
    DisableStartupMessage: true,
})

// Applications routes
f.Get("/v1/applications", auth.Authorize("identity", "applications", "get"), applicationHandler.GetApplications)
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
    "sub": "lerian/user123_role",
    "resource": "resource_name",
    "action": "read"
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

## 🚧 Error Handling

The middleware captures and logs the following error types:

* Failure to create the request
* Failure to send the request
* Failure to read the response body
* Failure to deserialize the response JSON

## 📧 Contact

For questions or support, contact us at: [contato@lerian.studio](mailto:contato@lerian.studio).
