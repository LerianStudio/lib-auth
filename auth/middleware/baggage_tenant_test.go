package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	observability "github.com/LerianStudio/lib-observability/v4"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestAuthorize_PropagatesAmbientBaggageNotCallerSuppliedHeaders pins where
// lib-auth's outbound baggage comes from: the ambient request context the
// application established, never the raw inbound headers.
//
// Two properties ride on this. The security one: a caller-supplied
// `tenant.id` baggage member must never reach the Access Manager, because
// AttrBagSpanProcessor would otherwise stamp a forged tenant on every span
// before auth has run. The correctness one: a legitimate baggage member the
// application seeded (from a validated claim, say) must survive the
// authorization hop rather than being replaced by whatever the caller sent —
// propagation.Baggage.Extract REPLACES the whole baggage value rather than
// merging, so self-extracting here silently overwrote the trusted set.
//
// Fails while lib-auth calls tracing.ExtractHTTPContext itself: the
// caller's `team=payments` displaces the application's `team=platform`.
func TestAuthorize_PropagatesAmbientBaggageNotCallerSuppliedHeaders(t *testing.T) {
	useCompositePropagator(t)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })

	var outboundTraceparent, outboundBaggage string

	server := authorizedAccessManager(t, &outboundTraceparent, &outboundBaggage)
	defer server.Close()

	auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

	// The application's trusted baggage, as its own middleware would seed it.
	trusted, err := baggage.Parse("team=platform")
	require.NoError(t, err)

	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		ctx := observability.ContextWithTracer(c.Context(), tp.Tracer("test"))
		c.SetContext(baggage.ContextWithBaggage(ctx, trusted))

		return c.Next()
	})
	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	}))
	req.Header.Set("Baggage", "tenant.id=forged-tenant,team=payments")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.NotContains(t, outboundBaggage, "tenant.id",
		"a caller-supplied tenant.id baggage member must never be propagated onward")
	assert.NotContains(t, outboundBaggage, "team=payments",
		"a caller-supplied baggage member must not displace the application's own")
	assert.Contains(t, outboundBaggage, "team=platform",
		"baggage the application seeded must survive the authorization hop")
}
