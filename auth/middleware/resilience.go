package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/LerianStudio/lib-observability/v2/tracing"
	"github.com/cenkalti/backoff/v5"
	"github.com/sony/gobreaker"
	"go.opentelemetry.io/otel/trace"
)

const (
	// defaultAuthTimeout bounds each authorization round-trip when AUTH_TIMEOUT is
	// unset/invalid. 30s matches the prior client-wide HTTP timeout, so the default
	// is behavior-neutral.
	defaultAuthTimeout = 30 * time.Second

	// defaultBreakerMaxFailures is the consecutive-failure count that trips the
	// breaker when AUTH_BREAKER_ENABLED is set.
	defaultBreakerMaxFailures uint32 = 5

	// defaultBreakerOpenTimeout is how long the breaker stays open before probing.
	defaultBreakerOpenTimeout = 30 * time.Second
)

// authzOutcome is the result of one authorization round-trip, decoupled from
// checkAuthorization's (bool, int, error) contract so the retry/breaker layer can
// distinguish an authoritative decision from a transient failure:
//   - authErr != nil  -> surface this error with statusCode (an authoritative coded
//     deny, or an internal parse/marshal failure) — exactly what the pre-resilience
//     code returned.
//   - authErr == nil  -> a clean decision: authorized at statusCode.
type authzOutcome struct {
	authorized bool
	statusCode int
	authErr    error
}

// requestTimeout is the per-request authorization deadline, falling back to the
// default when unset (e.g. a struct-literal client in tests).
func (auth *AuthClient) requestTimeout() time.Duration {
	if auth.timeout > 0 {
		return auth.timeout
	}

	return defaultAuthTimeout
}

// resolveAuthz performs the authorization call through the configured resilience
// layers and maps the result to checkAuthorization's contract. Every
// non-authoritative outcome — transient failure exhausted, breaker open, timeout —
// denies (fail closed): it returns (false, 403, nil), the same "not authorized"
// path a normal denial takes, never failing open. A clean decision is cached (when
// the cache is enabled) before being returned.
func (auth *AuthClient) resolveAuthz(ctx context.Context, span trace.Span, accessToken string, body []byte, key cacheKey) (bool, int, error) {
	outcome, err := auth.invokeAuthz(ctx, span, accessToken, body)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Authorization unavailable, denying (fail closed): %v", err)
		tracing.HandleSpanError(span, "Authorization unavailable, denying", err)

		return false, http.StatusForbidden, nil
	}

	if outcome.authErr != nil {
		return false, outcome.statusCode, outcome.authErr
	}

	if auth.cache != nil {
		auth.cache.set(key, outcome.authorized)
	}

	return outcome.authorized, outcome.statusCode, nil
}

// invokeAuthz runs the authorization call under the resilience layers. Composition
// is breaker( retry( doAuthorizeCall ) ): retry absorbs transient blips; the
// breaker counts a sustained failure only once per fully-failed retry sequence
// and, once open, short-circuits.
//
// When neither retry nor breaker is enabled it makes a single call and returns the
// outcome as-is (identical to the pre-resilience behavior — transient
// classification is irrelevant without a layer to act on it). Otherwise a non-nil
// returned error means "transient failure exhausted" or "breaker open"; the caller
// denies. A nil error means the outcome is authoritative.
func (auth *AuthClient) invokeAuthz(ctx context.Context, span trace.Span, accessToken string, body []byte) (authzOutcome, error) {
	call := func() (authzOutcome, error) {
		return auth.doAuthorizeCall(ctx, span, accessToken, body)
	}

	if auth.breaker == nil && auth.retryMax == 0 {
		outcome, _ := call()

		return outcome, nil
	}

	run := call
	if auth.retryMax > 0 {
		run = func() (authzOutcome, error) {
			return backoff.Retry(ctx, call,
				backoff.WithMaxTries(1+auth.retryMax),
				backoff.WithMaxElapsedTime(auth.requestTimeout()),
			)
		}
	}

	if auth.breaker == nil {
		return run()
	}

	res, err := auth.breaker.Execute(func() (any, error) {
		outcome, opErr := run()

		return outcome, opErr
	})

	outcome, _ := res.(authzOutcome)

	return outcome, err
}

// doAuthorizeCall performs one POST /v1/authorize and classifies the result. The
// authzOutcome mirrors the legacy (bool, int, error) semantics exactly; the second
// return is non-nil ONLY for a TRANSIENT failure — a network error, a context
// timeout, or a 5xx — which is what the retry and breaker layers act on.
// Authoritative decisions (2xx, 401, 403) return a nil transient error, so they
// are never retried and never trip the breaker.
func (auth *AuthClient) doAuthorizeCall(ctx context.Context, span trace.Span, accessToken string, body []byte) (authzOutcome, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/authorize", auth.Address), bytes.NewReader(body))
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to create request: %v", err)
		tracing.HandleSpanError(span, "Failed to create request", err)

		return authzOutcome{statusCode: http.StatusInternalServerError, authErr: fmt.Errorf("failed to create request: %w", err)}, nil
	}

	tracing.InjectHTTPContext(ctx, req.Header)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", accessToken)

	resp, err := sharedHTTPClient.Do(req)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to make request: %v", err)
		tracing.HandleSpanError(span, "Failed to make request", err)

		wrapped := fmt.Errorf("failed to make request: %w", err)

		return authzOutcome{statusCode: http.StatusInternalServerError, authErr: wrapped}, wrapped
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to read response body: %v", err)
		tracing.HandleSpanError(span, "Failed to read response body", err)

		wrapped := fmt.Errorf("failed to read response body: %w", err)

		return authzOutcome{statusCode: http.StatusInternalServerError, authErr: wrapped}, wrapped
	}

	outcome := auth.classifyResponse(ctx, span, resp.StatusCode, respBody)

	if resp.StatusCode >= http.StatusInternalServerError {
		// 5xx is transient for the resilience layer regardless of how it is surfaced.
		return outcome, fmt.Errorf("authz service returned status %d", resp.StatusCode)
	}

	return outcome, nil
}

// classifyResponse converts an authz HTTP response (status + body) into an
// authzOutcome, reproducing the pre-resilience decision logic exactly: a coded
// error body is an authoritative deny at its status; otherwise the AuthResponse
// decides; unparseable bodies are internal errors.
func (auth *AuthClient) classifyResponse(ctx context.Context, span trace.Span, statusCode int, body []byte) authzOutcome {
	respError, err := unmarshalErrorResponse(body)
	if err != nil {
		logErrorf(ctx, auth.Logger, "Failed to unmarshal auth error response: %v", err)
		tracing.HandleSpanError(span, "Failed to unmarshal auth error response", err)

		return authzOutcome{statusCode: http.StatusInternalServerError, authErr: fmt.Errorf("failed to unmarshal auth error response: %w", err)}
	}

	if respError.Code != "" && statusCode != http.StatusInternalServerError {
		logErrorf(ctx, auth.Logger, "Authorization request failed: %s", respError.Message)
		tracing.HandleSpanError(span, "Authorization request failed", respError)

		return authzOutcome{statusCode: statusCode, authErr: respError}
	}

	var response AuthResponse
	if err := json.Unmarshal(body, &response); err != nil {
		logErrorf(ctx, auth.Logger, "Failed to unmarshal response: %v", err)
		tracing.HandleSpanError(span, "Failed to unmarshal response", err)

		return authzOutcome{statusCode: http.StatusInternalServerError, authErr: fmt.Errorf("failed to unmarshal response: %w", err)}
	}

	return authzOutcome{authorized: response.Authorized, statusCode: statusCode}
}

// newAuthBreaker builds a circuit breaker that opens after maxFailures consecutive
// failures and stays open for openTimeout before probing with a single request.
func newAuthBreaker(maxFailures uint32, openTimeout time.Duration) *gobreaker.CircuitBreaker {
	return gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "lib-auth-authorize",
		MaxRequests: 1,
		Timeout:     openTimeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= maxFailures
		},
	})
}

// parseAuthTimeout reads AUTH_TIMEOUT (a Go duration, e.g. "5s"), falling back to
// the behavior-neutral default when unset or invalid.
func parseAuthTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("AUTH_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}

	return defaultAuthTimeout
}

// newDecisionCacheFromEnv builds the decision cache when AUTH_CACHE_TTL is a
// positive Go duration, and nil (disabled) otherwise. The cache trades a bounded
// revocation-propagation lag (up to the TTL) for load shedding and outage
// resilience — a documented security tradeoff, kept tight by a small TTL.
func newDecisionCacheFromEnv() *decisionCache {
	v := strings.TrimSpace(os.Getenv("AUTH_CACHE_TTL"))
	if v == "" {
		return nil
	}

	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return nil
	}

	return newDecisionCache(d)
}

// newBreakerFromEnv builds the circuit breaker when AUTH_BREAKER_ENABLED=="true",
// and nil (disabled) otherwise.
func newBreakerFromEnv() *gobreaker.CircuitBreaker {
	if os.Getenv("AUTH_BREAKER_ENABLED") != "true" {
		return nil
	}

	return newAuthBreaker(defaultBreakerMaxFailures, defaultBreakerOpenTimeout)
}

// parseRetryMax reads AUTH_RETRY_MAX (the maximum number of retries applied to
// transient failures), returning 0 (disabled) when unset or invalid.
func parseRetryMax() uint {
	v := strings.TrimSpace(os.Getenv("AUTH_RETRY_MAX"))
	if v == "" {
		return 0
	}

	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}

	return uint(n)
}
