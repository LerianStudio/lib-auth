package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	observability "github.com/LerianStudio/lib-observability/v2"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// forgedInboundTraceID is the trace an untrusted caller tries to pin this
// service's spans onto by setting a `traceparent` header itself.
const forgedInboundTraceID = "1111111111111111111111111111111f"

// useCompositePropagator installs the same propagator lib-observability's
// NewTelemetry installs at bootstrap. Inbound extraction reads the GLOBAL
// propagator (tracing.ExtractTraceContext -> otel.GetTextMapPropagator), so
// without this a test cannot tell extraction from non-extraction: the default
// global propagator is a no-op and every traceparent silently disappears.
// Not parallel-safe — callers must not t.Parallel().
func useCompositePropagator(t *testing.T) {
	t.Helper()

	prev := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })
}

// appTelemetryMiddleware stands in for the application's own telemetry
// middleware (lib-observability's TelemetryMiddleware.WithTelemetry) on the
// posture where the inbound traceparent is NOT trusted: it starts a LOCAL root
// server span and deliberately does not extract the inbound traceparent. It
// reports the local trace ID through the returned pointer.
func appTelemetryMiddleware(tp *sdktrace.TracerProvider) (fiber.Handler, *trace.TraceID) {
	var localTraceID trace.TraceID

	return func(c fiber.Ctx) error {
		tracer := tp.Tracer("test")

		ctx, span := tracer.Start(
			observability.ContextWithTracer(c.Context(), tracer),
			"server",
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		localTraceID = span.SpanContext().TraceID()

		c.SetContext(ctx)

		return c.Next()
	}, &localTraceID
}

// findSpan returns the exported span with the given name.
func findSpan(t *testing.T, exporter *tracetest.InMemoryExporter, name string) tracetest.SpanStub {
	t.Helper()

	for _, s := range exporter.GetSpans() {
		if s.Name == name {
			return s
		}
	}

	require.FailNowf(t, "span not exported", "no span named %q among %d exported", name, len(exporter.GetSpans()))

	return tracetest.SpanStub{}
}

// authorizedAccessManager is a stub Access Manager that authorizes everything
// and records the trace context and baggage lib-auth propagates to it.
func authorizedAccessManager(t *testing.T, traceparent, baggageHeader *string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*traceparent = r.Header.Get("Traceparent")
		*baggageHeader = r.Header.Get("Baggage")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		require.NoError(t, json.NewEncoder(w).Encode(AuthResponse{Authorized: true}))
	}))
}

// TestAuthorize_StaysInLocalTraceDespiteInboundTraceparent pins the trust
// posture lib-auth must inherit rather than override.
//
// Honoring an inbound traceparent is the APPLICATION's decision — an untrusted
// caller that can set the header can otherwise choose this service's trace ID
// and force its sampling decision, which is why lib-observability gates it
// behind tracing.TelemetryConfig.TrustInboundTraceContext (default false) from
// v2.1.2 on. lib-auth has no view of that setting, so it must not extract
// inbound trace context on its own: it starts its span from the ambient request
// context and inherits whatever parent the application's telemetry middleware
// already decided on. An app that DOES trust the inbound trace already has its
// server span parented to it, so lib-auth joins automatically; an app that does
// not stays local, and so does lib-auth.
//
// Fails while lib-auth calls tracing.ExtractHTTPContext itself: the authorize
// span re-parents to the caller-supplied trace, detaching from the
// application's server span.
func TestAuthorize_StaysInLocalTraceDespiteInboundTraceparent(t *testing.T) {
	useCompositePropagator(t)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })

	var outboundTraceparent, outboundBaggage string

	server := authorizedAccessManager(t, &outboundTraceparent, &outboundBaggage)
	defer server.Close()

	auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

	telemetry, localTraceID := appTelemetryMiddleware(tp)

	app := fiber.New()
	app.Use(telemetry)
	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	}))
	req.Header.Set("Traceparent", "00-"+forgedInboundTraceID+"-2222222222222222-01")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	authorizeSpan := findSpan(t, exporter, "lib_auth.authorize")
	gotTraceID := authorizeSpan.SpanContext.TraceID().String()

	assert.NotEqual(t, forgedInboundTraceID, gotTraceID,
		"the authorize span must never join a trace chosen by a caller-supplied traceparent")
	assert.Equal(t, localTraceID.String(), gotTraceID,
		"the authorize span must nest under the application's own server span")

	require.NotEmpty(t, outboundTraceparent, "trace context must still propagate to the Access Manager")
	assert.Contains(t, outboundTraceparent, localTraceID.String(),
		"the Access Manager call must be reported inside the local trace, not the forged one")
}

// TestRequireM2M_StaysInLocalTraceDespiteInboundTraceparent pins the same
// posture on the M2M authentication middleware, which shared the same
// self-extraction defect.
func TestRequireM2M_StaysInLocalTraceDespiteInboundTraceparent(t *testing.T) {
	useCompositePropagator(t)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))

	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })

	key, pubPEM := newTestRSAKeyPEM(t)
	authenticator := newTestM2MAuthenticator(t, pubPEM)

	telemetry, localTraceID := appTelemetryMiddleware(tp)

	app := fiber.New()
	app.Use(telemetry)
	app.Get("/x", authenticator.RequireM2M(), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+signRS256(t, key, applicationClaims()))
	req.Header.Set("Traceparent", "00-"+forgedInboundTraceID+"-2222222222222222-01")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	m2mSpan := findSpan(t, exporter, "lib_auth.require_m2m")
	gotTraceID := m2mSpan.SpanContext.TraceID().String()

	assert.NotEqual(t, forgedInboundTraceID, gotTraceID,
		"the require_m2m span must never join a trace chosen by a caller-supplied traceparent")
	assert.Equal(t, localTraceID.String(), gotTraceID,
		"the require_m2m span must nest under the application's own server span")
}
