package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

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
//     populates. Under another router it resolves empty, and a partner-bound
//     credential is refused with 403.
//   - A route that relies on its product's manifest scope (no RequireScope, see
//     SetManifestScope and SetManifestRouteScope) is the request method and the
//     path of r.Pattern, its "{name}" and "{name...}" segments read as ":name".
//     Under another router there is no pattern and the route derives no path
//     dimension, so a partner-bound credential is asked without them.
//   - A body-scoped route (FromBody, FromForm) reads at most
//     maxAuthorizeHTTPBodyBytes (4 MiB, Fiber's default BodyLimit) for a
//     partner-bound credential; a larger body is refused with 413. The bytes
//     read are put back on the request for next.
//
// Headers, the query and a urlencoded form are read exactly as Authorize reads
// them: every occurrence, each split on ',', a query key in another letter case
// refused. The query is read as r.URL.Query reads it.
//
// The caller IP is derived from TRUSTED_PROXIES exactly as on the Fiber path,
// anchored on r.RemoteAddr.
//
// Refusals are rendered by the HTTPErrorHandler (see WithHTTPErrorHandler). A nil
// client passes every request through, as Authorize does; a nil next answers 500
// instead of panicking.
func (auth *AuthClient) AuthorizeHTTP(product, resource, action string, scopes ...ScopeDeclaration) func(http.Handler) http.Handler {
	auth.warnMissingTrustedProxies()

	route := auth.newAuthorizeRoute(product, resource, action, scopes)

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

// pathParam reads r.PathValue, which only the Go 1.22+ ServeMux populates:
// under any other router a path dimension resolves empty and the request is
// refused, never sent unscoped.
func (v netHTTPRequest) pathParam(key string) string {
	return v.r.PathValue(key)
}

func (v netHTTPRequest) headerValues(name string) []string {
	var values []string

	for k, lines := range v.r.Header {
		if strings.EqualFold(k, name) {
			values = append(values, lines...)
		}
	}

	return values
}

// queryValues reads the query as r.URL.Query does, which is how a net/http
// handler reads it.
func (v netHTTPRequest) queryValues(key string) ([]string, bool) {
	if v.r.URL == nil {
		return nil, false
	}

	var values []string

	for name, occurrences := range v.r.URL.Query() {
		switch {
		case name == key:
			values = occurrences
		case strings.EqualFold(name, key):
			return nil, true
		}
	}

	return values, false
}

func (v netHTTPRequest) contentType() string {
	return v.r.Header.Get("Content-Type")
}

// route is the request method and the path of the ServeMux pattern that matched
// it, rewritten to the ':name' form the manifest scope is declared in. Only the
// Go 1.22+ ServeMux sets r.Pattern: under another router the path is "" and a
// route relying on the manifest scope derives no dimension.
func (v netHTTPRequest) route() (string, string) {
	return v.r.Method, serveMuxRoutePath(v.r.Pattern)
}

// maxAuthorizeHTTPBodyBytes caps the body AuthorizeHTTP reads for a body-scoped
// route: Fiber's default BodyLimit, so the two adapters accept the same bodies
// by default. net/http sets no limit of its own, and an unbounded read would
// let one request hold any amount of memory before it is authorized.
const maxAuthorizeHTTPBodyBytes = 4 << 20

// body reads the request body, at most maxAuthorizeHTTPBodyBytes, and puts the
// bytes back on the request so the handler reads exactly what the caller sent.
// A larger body is refused with 413, one that fails to read with 400.
func (v netHTTPRequest) body() ([]byte, *errBodyScope) {
	if v.r.Body == nil {
		return nil, nil
	}

	raw, err := io.ReadAll(io.LimitReader(v.r.Body, maxAuthorizeHTTPBodyBytes+1))
	if err != nil {
		return nil, &errBodyScope{message: http.StatusText(http.StatusBadRequest), status: http.StatusBadRequest}
	}

	if len(raw) > maxAuthorizeHTTPBodyBytes {
		return nil, &errBodyScope{message: http.StatusText(http.StatusRequestEntityTooLarge), status: http.StatusRequestEntityTooLarge}
	}

	v.r.Body = io.NopCloser(bytes.NewReader(raw))

	return raw, nil
}

// serveMuxRoutePath returns the path of a ServeMux pattern ("[METHOD ][HOST]/PATH")
// with every wildcard segment written as a ':name' parameter: "{id}" and
// "{rest...}" become ":id" and ":rest", and the end anchor "{$}" is dropped. An
// empty pattern is "".
func serveMuxRoutePath(pattern string) string {
	if sep := strings.IndexAny(pattern, " \t"); sep >= 0 {
		pattern = strings.TrimLeft(pattern[sep:], " \t")
	}

	slash := strings.Index(pattern, "/")
	if slash < 0 {
		return ""
	}

	segments := strings.Split(pattern[slash:], "/")

	for i, segment := range segments {
		if segment == "{$}" {
			segments[i] = ""

			continue
		}

		if name, ok := strings.CutPrefix(segment, "{"); ok {
			if name, ok = strings.CutSuffix(name, "}"); ok {
				segments[i] = ":" + strings.TrimSuffix(name, "...")
			}
		}
	}

	return strings.Join(segments, "/")
}

// Both adapters satisfy the shared flow's view of a request.
var (
	_ requestView = fiberRequest{}
	_ requestView = netHTTPRequest{}
)
