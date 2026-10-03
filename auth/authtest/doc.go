// Package authtest is TEST-ONLY. Never import it from production wiring.
//
// It lets a consumer of lib-auth write an end-to-end test of a route that
// requires an authenticated principal without contacting the Access Manager.
// It offers two ways in, for two kinds of test:
//
//   - WithPrincipal, Fiber and HTTP place a Principal on the request context
//     exactly as Authorize and AuthorizeHTTP publish it. Use them in a handler
//     test where the authorization middleware is not under test: mount Fiber or
//     HTTP where Authorize or AuthorizeHTTP would be, then the type guards
//     (RequireHuman, RequireApplication) and the handler see an identified caller.
//   - Issuer signs RS256 tokens with a key generated in the test process. Its
//     tokens go through the REAL Authorize with signature verification on, by
//     wiring Issuer.KeySource with AuthClient.WithKeySource or by setting
//     AUTH_JWT_VERIFY_CERT to Issuer.PublicKeyPEM. Use it when the router under
//     test mounts the real Authorize, and in particular when the service pins
//     PrincipalRequiredWhenDisabled: Authorize then derives the principal from the
//     bearer token and never trusts one already on the context, so a context-only
//     helper cannot reach the handler.
//
// An application principal on the Authorize path needs M2MInversionEnabled: the
// legacy model authorizes every non-human token under a fabricated role and
// refuses it with 401 when no Access Manager round-trip happens.
//
// Nothing here is switchable at run time: there is no global flag, and every
// entry point takes a testing.TB. A nil testing.TB panics with a message naming
// the helper. An invalid principal (one PrincipalFromContext would report as
// absent) or a nil context fails the test through tb.Fatalf when the helper is
// called, on the test goroutine; the value returned after a Fatalf that did not
// stop the goroutine publishes nothing and refuses every request with 401.
// Handlers built by Fiber and HTTP never touch tb while serving, hold an
// immutable copy of the principal, and are safe for concurrent requests; an
// Issuer's key is read-only after NewIssuer, so Token is safe from parallel tests.
//
// lib-auth's own guard test fails if any non-test file in the module imports this
// package. Consumers can apply the same rule with depguard; see the README.
package authtest
