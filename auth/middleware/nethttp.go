package middleware

import (
	"errors"
	"net/http"

	"github.com/LerianStudio/lib-auth/v5/auth/bearer"
)

// HTTPErrorHandler renders a refusal of AuthorizeHTTP. err is always a
// *RefusalError; recover it with errors.As to read the status, the message and,
// when the Access Manager sent one, its decoded refusal body. The handler owns
// the response: it must write a status, and it should preserve the one carried
// by the refusal.
type HTTPErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// WithHTTPErrorHandler installs the handler AuthorizeHTTP renders its refusals
// with, so a service keeps its own envelope (problem+json, say) the way a Fiber
// service does through its ErrorHandler. Without one, a refusal is written as
// plain text: the status and its message, as Fiber's default handler renders the
// same refusal on Authorize.
//
// Set it once, before serving: it is read on every refused request and is not
// safe to change while requests are in flight. It returns the receiver for fluent
// configuration after NewAuthClient; a nil receiver or nil handler is a no-op.
func (auth *AuthClient) WithHTTPErrorHandler(h HTTPErrorHandler) *AuthClient {
	if auth == nil || h == nil {
		return auth
	}

	auth.httpErrorHandler = h

	return auth
}

// AuthorizeHTTP is Authorize for a plain net/http server: a middleware that asks
// the Access Manager whether the bearer of the request may perform action on
// resource, and serves next only when it may.
//
// It runs the SAME decision flow as Authorize — AUTH_REQUIRED, the scope
// declaration, the disabled and principal-required postures, M2M inversion and
// product forwarding, the decision cache, retry, breaker and local verification —
// and publishes the same Principal and RequestScope on the request context, read
// back with PrincipalFromContext and ScopeFromContext. Two things differ, both
// deliberately:
//
//   - The bearer is extracted with the strict rules of package bearer: exactly
//     one Authorization header holding "Bearer <token>", the token at most
//     bearer.MaxTokenBytes and three non-empty base64url segments, no control
//     bytes. A missing credential is 401 "Missing Token", any other malformed
//     one 401 "Unauthorized"; neither reaches the Access Manager.
//   - A FromPath dimension reads r.PathValue, which only the Go 1.22+ ServeMux
//     populates. Under another router it resolves empty and the request is
//     refused with 403.
//
// The caller IP is derived from TRUSTED_PROXIES exactly as on the Fiber path,
// anchored on r.RemoteAddr.
//
// Refusals are rendered by the HTTPErrorHandler (see WithHTTPErrorHandler). A nil
// client passes every request through, as Authorize does; a nil next answers 500
// instead of panicking.
func (auth *AuthClient) AuthorizeHTTP(product, resource, action string, scopes ...ScopeDeclaration) func(http.Handler) http.Handler {
	auth.warnMissingTrustedProxies()

	route := newAuthorizeRoute(product, resource, action, scopes)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if next == nil {
				if auth != nil {
					logErrorf(r.Context(), auth.Logger, "AuthorizeHTTP was mounted with a nil next handler; answering 500")
				}

				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

				return
			}

			outcome := auth.decide(r.Context(), route, netHTTPRequest{r: r})
			if outcome.refusal != nil {
				auth.renderHTTPRefusal(w, r, outcome.refusal)

				return
			}

			if outcome.principal == nil {
				next.ServeHTTP(w, r)

				return
			}

			next.ServeHTTP(w, r.WithContext(outcome.publish(r.Context())))
		})
	}
}

// renderHTTPRefusal hands the refusal to the installed handler, or the default.
func (auth *AuthClient) renderHTTPRefusal(w http.ResponseWriter, r *http.Request, refusal *RefusalError) {
	handler := defaultHTTPErrorHandler
	if auth != nil && auth.httpErrorHandler != nil {
		handler = auth.httpErrorHandler
	}

	handler(w, r, refusal)
}

// defaultHTTPErrorHandler writes the refusal as plain text: its status and its
// message.
func defaultHTTPErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	var refusal *RefusalError
	if errors.As(err, &refusal) && refusal != nil {
		http.Error(w, refusal.Message, refusal.Status)

		return
	}

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

// netHTTPRequest reads a net/http request for the shared authorization flow.
type netHTTPRequest struct {
	r *http.Request
}

func (v netHTTPRequest) token() (string, error) {
	return bearer.FromRequest(v.r)
}

func (v netHTTPRequest) clientIP(auth *AuthClient) string {
	return auth.resolveClientIPHTTP(v.r)
}

func (v netHTTPRequest) dimension(d Dimension) string {
	return d.resolveHTTP(v.r)
}

// Both adapters satisfy the shared flow's view of a request.
var (
	_ requestView = fiberRequest{}
	_ requestView = netHTTPRequest{}
)
