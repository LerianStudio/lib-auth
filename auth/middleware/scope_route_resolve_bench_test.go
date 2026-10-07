package middleware

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
)

// benchRoutes is the number of routes the benchmark apps register, about the
// size of a product's API.
const benchRoutes = 200

func benchApp(b testing.TB, prefixMounted bool) fasthttp.RequestHandler {
	b.Helper()

	// Auth disabled: the request does nothing but work out its scope and pass,
	// which isolates the cost a mounted handler adds to every request.
	auth := &AuthClient{Enabled: false, Logger: &testLogger{}}
	if err := auth.SetManifestScope("midaz", manifestDims()...); err != nil {
		b.Fatal(err)
	}

	handler := auth.Authorize("midaz", "ledgers", "get")

	app := fiber.New()
	if prefixMounted {
		app.Use("/v1/organizations", handler)
	}

	for i := range benchRoutes {
		path := fmt.Sprintf("/v1/organizations/:organization_id/resource%d/:id", i)
		if prefixMounted {
			app.Get(path, ok)
		} else {
			app.Get(path, handler, ok)
		}
	}

	return app.Handler()
}

func benchServe(b *testing.B, h fasthttp.RequestHandler) {
	b.Helper()

	var ctx fasthttp.RequestCtx

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		serveOnce(b, h, &ctx)
	}
}

func serveOnce(tb testing.TB, h fasthttp.RequestHandler, ctx *fasthttp.RequestCtx) {
	ctx.Request.Reset()
	ctx.Response.Reset()
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/v1/organizations/org-1/resource150/id-1")
	h(ctx)

	if ctx.Response.StatusCode() != http.StatusOK {
		tb.Fatalf("status %d", ctx.Response.StatusCode())
	}
}

// A request no scope is read for is never resolved: a mounted handler costs it
// no more allocations than a handler on its own route, however many routes the
// app registers.
func TestAuthorize_MountedHandler_UnreadScopeIsNeverResolved(t *testing.T) {
	var ctx fasthttp.RequestCtx

	own := benchApp(t, false)
	mounted := benchApp(t, true)

	// AllocsPerRun counts every allocation in the process, so another
	// goroutine can only add to a run: the least of several runs is the
	// request's own cost.
	leastAllocs := func(h fasthttp.RequestHandler) float64 {
		least := testing.AllocsPerRun(100, func() { serveOnce(t, h, &ctx) })
		for range 4 {
			least = min(least, testing.AllocsPerRun(100, func() { serveOnce(t, h, &ctx) }))
		}

		return least
	}

	ownAllocs := leastAllocs(own)
	mountedAllocs := leastAllocs(mounted)

	if mountedAllocs > ownAllocs {
		t.Fatalf("mounted handler allocates %.0f per request, own route %.0f", mountedAllocs, ownAllocs)
	}
}

// BenchmarkAuthorize_NonPartnerOverhead measures what a request costs when no
// scope is read for it: a handler on its own route against one mounted on a
// prefix in front of benchRoutes routes.
func BenchmarkAuthorize_NonPartnerOverhead(b *testing.B) {
	b.Run("own_route", func(b *testing.B) { benchServe(b, benchApp(b, false)) })
	b.Run("prefix_mounted", func(b *testing.B) { benchServe(b, benchApp(b, true)) })
}

// BenchmarkRouteTable_Resolve measures resolving one request among
// benchRoutes routes, the cost a partner-bound request pays on a mounted
// handler.
func BenchmarkRouteTable_Resolve(b *testing.B) {
	app := fiber.New()
	for i := range benchRoutes {
		app.Get(fmt.Sprintf("/v1/organizations/:organization_id/resource%d/:id", i), ok)
	}

	table := buildRouteTable(app, 0, nil)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, problem := table.resolve(http.MethodGet, "/v1/organizations/org-1/resource150/id-1"); problem != "" {
			b.Fatal(problem)
		}
	}
}
