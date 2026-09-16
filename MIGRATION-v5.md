# Migrating from lib-auth v4 to v5

lib-auth v5 changes the Go module path and makes the `Authorize` error contract explicit.

## Module path

Update imports and the required module:

```go
require github.com/LerianStudio/lib-auth/v5 v5.0.0
```

```go
import "github.com/LerianStudio/lib-auth/v5/auth/middleware"
```

## Fiber error handling

In v4, `Authorize` writes refusal responses directly by default. In v5, it returns
`*fiber.Error` to the application's configured `ErrorHandler`.

Custom handlers must preserve the status carried by Fiber errors instead of mapping
all middleware errors to 500:

```go
func errorHandler(c fiber.Ctx, err error) error {
	status := fiber.StatusInternalServerError

	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		status = fiberErr.Code
	}

	return c.Status(status).JSON(problemFrom(err))
}
```

Authorization-service error responses also remain recoverable as
`commons.Response` through `errors.As`.

## Recommended rollout

1. Keep existing consumers on the latest v4 patch until their custom Fiber
   `ErrorHandler` preserves `*fiber.Error.Code`.
2. Change the module/import path to `/v5`.
3. Run refusal-path tests for missing tokens, denials, authorization-service outages,
   and coded authorization-service errors.
