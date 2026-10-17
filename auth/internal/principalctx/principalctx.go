// Package principalctx holds the context key under which the authorization
// middleware publishes the caller Principal. It is internal so that only
// lib-auth itself can write that entry: the middleware, which derives the
// principal from a bearer token, and auth/authtest, which places one on a
// request for a consumer's tests. No code outside this module can import it.
package principalctx

// Key is the typed context key the Principal is stored under. A dedicated
// unexported-to-consumers type keeps the entry uncollidable with any key a
// service defines.
type Key struct{}
