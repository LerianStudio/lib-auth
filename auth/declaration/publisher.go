// Package declaration is the "D7 declaration publisher": a startup hook that lets a
// plugin publish its OWN permissions manifest to the access-manager (identity
// component) at boot, instead of permissions living centrally in init_data.json.
//
// It runs ONCE at initialization (and, optionally, periodically) OUTSIDE the
// request path — it is NOT per-request middleware. The plugin embeds its manifest
// (//go:embed permissions.yaml) and this package mints an M2M token via the
// existing middleware.AuthClient, then PUTs the wire JSON to
// {IdentityAddr}/v1/declarations/{slug}.
//
// Correctness lives on the SERVER: the PUT is idempotent by hash (the identity
// stores the manifest CanonicalHash on the M2M app and no-ops a matching PUT), so N
// pods pushing the same manifest is safe by construction. Everything here (cache,
// retry) is optimization/resilience, not a correctness requirement — which is why
// every degraded path (no cache, identity down) is fail-open by default.
//
// Extension point (D10, deferred): manifest signing is out of scope. A future
// cfg.Signer would compute an X-Declaration-Signature header over the wire JSON
// here, before the PUT; the transport is untrusted by design (authority is the M2M
// token + server-side BOLA), so signing is a BYOC/sovereign hardening, not a
// correctness requirement.
package declaration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	observability "github.com/LerianStudio/lib-observability/v2"
	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/LerianStudio/lib-observability/v2/runtime"
	"github.com/LerianStudio/lib-observability/v2/tracing"
	"github.com/cenkalti/backoff/v5"
	"go.opentelemetry.io/otel/attribute"
)

const (
	// defaultMaxTries bounds the retry budget of a single Publish pass (one-shot
	// mode). In periodic mode the next tick retries again, so the effective budget
	// is unbounded across ticks — matching the spec (§6).
	defaultMaxTries uint = 5

	// defaultRetryInitialInterval / defaultRetryMaxInterval bound the exponential
	// backoff (with jitter, via cenkalti/backoff/v5) between retries.
	defaultRetryInitialInterval = 1 * time.Second
	defaultRetryMaxInterval     = 30 * time.Second

	// defaultCacheTTL is the advisory TTL for the cached hash. The final source of
	// truth is the server-side `declaration-hash` Tag, so this is deliberately
	// generous — it only trims redundant re-PUTs on the periodic path.
	defaultCacheTTL = 24 * time.Hour

	// spanName / componentName label observability signals.
	spanName      = "declaration.publisher.publish"
	componentName = "declaration"
)

// TokenMinter mints an M2M access token via client_credentials. Both lib-auth v2
// and v3 *middleware.AuthClient satisfy it, so the publisher is not coupled to a
// specific lib-auth major.
type TokenMinter interface {
	GetApplicationToken(ctx context.Context, clientID, clientSecret string) (string, error)
}

// Cache is the pluggable dedup seam — the SAME interface the future lib-auth
// rate-limiter will consume. nil disables caching (the server no-ops by hash
// anyway). An L1 in-memory default and an injected L2 Redis impl are follow-ups; the
// pilot runs with Cache: nil.
type Cache interface {
	Get(ctx context.Context, key string) (string, bool)
	Set(ctx context.Context, key, val string, ttl time.Duration)
}

// Config configures a Publisher.
//
// D10 (deferred): a future Signer field + X-Declaration-Signature header would live
// here — see the package doc. Not implemented in the pilot.
type Config struct {
	// Slug is the service identifier. It MUST equal manifest.service and the M2M
	// app DisplayName (the server enforces this via BOLA). Required.
	Slug string
	// Manifest is the embedded manifest content (permissions.yaml OR .json). The
	// caller does the //go:embed (embed is relative to the caller's source). Required.
	Manifest []byte
	// IdentityAddr is the base URL of the identity component (target of the PUT).
	// Distinct from the auth address; WireFromEnv sources it from IDP_HOST (the
	// pre-#4232 PLUGIN_IDENTITY_HOST remains a deprecated alias for one release).
	// Required.
	IdentityAddr string
	// Auth is any TokenMinter — typically the plugin's existing *middleware.AuthClient
	// (v2 or v3). Its GetApplicationToken mints the M2M token (client_credentials);
	// the concrete AuthClient also carries the AUTH address. Required.
	Auth TokenMinter
	// ClientID / ClientSecret are the plugin's M2M credentials (from manual
	// provisioning). Required. ClientSecret is NEVER logged.
	ClientID     string
	ClientSecret string
	// Cache is the optional, pluggable dedup cache. nil => always PUT (pilot).
	Cache Cache
	// Interval, when > 0, re-publishes periodically to heal drift. 0 = startup-only
	// (pilot).
	Interval time.Duration
	// FailFast, when true, makes Start surface a failing initial publish as a fatal
	// error. Default false (fail-open): the plugin serves regardless of the
	// access-manager's availability.
	FailFast bool
	// Logger receives structured logs. Defaults to a no-op logger when nil.
	Logger log.Logger
}

// Publisher publishes the plugin's permissions manifest to the access-manager at
// startup. Construct it with New.
type Publisher struct {
	slug         string
	identityAddr string
	auth         TokenMinter
	clientID     string
	clientSecret string
	cache        Cache
	interval     time.Duration
	failFast     bool
	logger       log.Logger

	// manifest is parsed+validated eagerly at New; wire and hash are precomputed so
	// each Publish pass is a pure I/O operation.
	manifest *DeclarationManifest
	wire     []byte
	hash     string

	// retry knobs (exposed unexported for test overrides).
	maxTries             uint
	retryInitialInterval time.Duration
	retryMaxInterval     time.Duration
	cacheTTL             time.Duration

	httpClient *http.Client
}

// PublishError is a typed publish failure. Deterministic errors (401/403/422, or
// a misconfiguration) are NOT retried and NOT cached — they need human action.
// Transient errors (409/5xx/network) are retried with backoff; after the budget is
// exhausted the last transient error is returned (and the caller, if fail-open,
// reschedules).
type PublishError struct {
	// StatusCode is the identity HTTP status (0 for a network/pre-request failure).
	StatusCode int
	// Deterministic classifies the error: true => no retry; false => transient.
	Deterministic bool
	// Op is the failing operation, for context (e.g. "put declaration").
	Op string
	// Detail is a safe, non-secret detail (e.g. the server message). Never a token.
	Detail string
	// Err is the wrapped cause, if any.
	Err error
}

func (e *PublishError) Error() string {
	kind := "transient"
	if e.Deterministic {
		kind = "deterministic"
	}

	msg := fmt.Sprintf("declaration publish failed (%s, op=%s", kind, e.Op)
	if e.StatusCode != 0 {
		msg += fmt.Sprintf(", status=%d", e.StatusCode)
	}

	if e.Detail != "" {
		msg += fmt.Sprintf(", detail=%s", e.Detail)
	}

	msg += ")"

	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}

	return msg
}

func (e *PublishError) Unwrap() error { return e.Err }

// New builds a Publisher. It validates the config and parses+validates the embedded
// manifest eagerly, so a missing field or a broken manifest fails fast at boot
// instead of at the first PUT. The hash and wire JSON are precomputed.
func New(cfg Config) (*Publisher, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	manifest, err := parseManifest(cfg.Manifest)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("validate manifest: %w", err)
	}

	if manifest.Service != cfg.Slug {
		return nil, fmt.Errorf("slug %q must equal manifest.service %q (BOLA: DisplayName==slug==service)", cfg.Slug, manifest.Service)
	}

	wire, err := manifest.wireJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal wire manifest: %w", err)
	}

	hash, err := manifest.CanonicalHash()
	if err != nil {
		return nil, fmt.Errorf("compute canonical hash: %w", err)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.NewNop()
	}

	return &Publisher{
		slug:                 cfg.Slug,
		identityAddr:         cfg.IdentityAddr,
		auth:                 cfg.Auth,
		clientID:             cfg.ClientID,
		clientSecret:         cfg.ClientSecret,
		cache:                cfg.Cache,
		interval:             cfg.Interval,
		failFast:             cfg.FailFast,
		logger:               logger,
		manifest:             manifest,
		wire:                 wire,
		hash:                 hash,
		maxTries:             defaultMaxTries,
		retryInitialInterval: defaultRetryInitialInterval,
		retryMaxInterval:     defaultRetryMaxInterval,
		cacheTTL:             defaultCacheTTL,
		httpClient:           &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func validateConfig(cfg Config) error {
	switch {
	case cfg.Slug == "":
		return errors.New("config: Slug is required")
	case len(cfg.Manifest) == 0:
		return errors.New("config: Manifest is required")
	case cfg.IdentityAddr == "":
		return errors.New("config: IdentityAddr is required")
	case cfg.Auth == nil:
		return errors.New("config: Auth is required")
	case cfg.ClientID == "":
		return errors.New("config: ClientID is required")
	case cfg.ClientSecret == "":
		return errors.New("config: ClientSecret is required")
	}

	// IdentityAddr must be an absolute http(s) URL: parse cleanly, carry an http or
	// https scheme, and a non-empty host. A hostless or wrong-scheme value would
	// otherwise pass here and only fail later inside doPut as a *retryable* PUT
	// error, masking a boot-time misconfiguration.
	u, err := url.Parse(cfg.IdentityAddr)
	if err != nil {
		return fmt.Errorf("config: IdentityAddr is not a valid URL: %w", err)
	}

	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("config: IdentityAddr must be an absolute http(s) URL, got %q", cfg.IdentityAddr)
	}

	return nil
}

// cacheKey is the dedup key for the slug's hash.
func (p *Publisher) cacheKey() string {
	return "declaration:" + p.slug + ":hash"
}

// Publish executes ONE pass of the flow (§4): cache check → mint token → PUT →
// store hash. It is idempotent (the server no-ops a matching hash) and, on failure,
// returns a typed *PublishError; the caller decides whether that is fatal.
func (p *Publisher) Publish(ctx context.Context) error {
	_, tracer, reqID, _ := observability.NewTrackingFromContext(ctx)

	ctx, span := tracer.Start(ctx, spanName)
	defer span.End()

	span.SetAttributes(
		attribute.String("app.request.request_id", reqID),
		attribute.String("declaration.slug", p.slug),
		attribute.String("declaration.hash", p.hash),
	)

	if p.cache != nil {
		if cached, ok := p.cache.Get(ctx, p.cacheKey()); ok && cached == p.hash {
			p.logInfof(ctx, "declaration already published for slug=%s (hash match), skipping PUT", p.slug)

			return nil
		}
	}

	if err := p.mintAndPutWithRetry(ctx); err != nil {
		tracing.HandleSpanError(span, "publish declaration failed", err)

		return err
	}

	if p.cache != nil {
		p.cache.Set(ctx, p.cacheKey(), p.hash, p.cacheTTL)
	}

	p.logInfof(ctx, "declaration published for slug=%s (hash=%s)", p.slug, p.hash)

	return nil
}

// mintAndPutWithRetry runs mint→PUT as a SINGLE bounded backoff operation, minting a
// FRESH token per attempt so a transient auth outage at boot is retried alongside the
// PUT (not fatal for the whole one-shot pass). Classification is preserved: a
// transient mint error is a plain error (retried); an empty token (auth
// disabled/misconfigured) is backoff.Permanent (deterministic, not retried); doPut's
// own deterministic/transient classification is unchanged. Transient failures retry
// until the budget is exhausted, then surface the last error.
func (p *Publisher) mintAndPutWithRetry(ctx context.Context) error {
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = p.retryInitialInterval
	exp.MaxInterval = p.retryMaxInterval

	op := func() (struct{}, error) {
		token, err := p.auth.GetApplicationToken(ctx, p.clientID, p.clientSecret)
		if err != nil {
			pubErr := &PublishError{Deterministic: false, Op: "mint m2m token", Err: err}
			p.logWarnf(ctx, "failed to mint M2M token for slug=%s (transient, will retry): %v", p.slug, err)

			return struct{}{}, pubErr
		}

		if token == "" {
			p.logErrorf(ctx, "empty M2M token for slug=%s (auth disabled or misconfigured); not retrying", p.slug)

			pubErr := &PublishError{Deterministic: true, Op: "mint m2m token", Detail: "empty token (auth disabled or misconfigured)"}

			return struct{}{}, backoff.Permanent(pubErr)
		}

		return struct{}{}, p.doPut(ctx, token)
	}

	_, err := backoff.Retry(ctx, op,
		backoff.WithBackOff(exp),
		backoff.WithMaxTries(p.maxTries),
	)

	return err
}

// doPut performs one PUT and classifies the result per §8. A returned error is
// either wrapped in backoff.Permanent (deterministic → stop) or plain (transient →
// retry). nil means the declaration was accepted (200).
func (p *Publisher) doPut(ctx context.Context, token string) error {
	// Build the URL from a parsed base so a trailing slash on IdentityAddr does not
	// yield a "//v1" path. JoinPath is used only for the STATIC prefix; the slug is
	// appended as a single, fully percent-escaped path segment via RawPath so a
	// reserved char (e.g. '?') or a literal '/' cannot add a segment or alter the
	// request target. Note: passing url.PathEscape(slug) into JoinPath would
	// double-escape (JoinPath re-escapes the '%'), hence the explicit Path/RawPath.
	base, err := url.Parse(p.identityAddr)
	if err != nil {
		return backoff.Permanent(&PublishError{Deterministic: true, Op: "build request", Err: err})
	}

	base = base.JoinPath("v1", "declarations")

	// escapedPrefix is the escaped static prefix (e.g. "/v1/declarations"); compute it
	// BEFORE mutating Path. Path holds the decoded form; RawPath holds the escaped form
	// so URL.String() emits "<prefix>/<escaped-slug>" and round-trips unchanged.
	escapedPrefix := base.EscapedPath()
	base.Path += "/" + p.slug
	base.RawPath = escapedPrefix + "/" + url.PathEscape(p.slug)

	reqURL := base.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(p.wire))
	if err != nil {
		return backoff.Permanent(&PublishError{Deterministic: true, Op: "build request", Err: err})
	}

	tracing.InjectHTTPContext(ctx, req.Header)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.logWarnf(ctx, "declaration PUT network error for slug=%s (transient, will retry): %v", p.slug, err)

		return &PublishError{Deterministic: false, Op: "put declaration", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	detail := serverMessage(body)

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusUnprocessableEntity:
		pubErr := &PublishError{Deterministic: true, StatusCode: resp.StatusCode, Op: "put declaration", Detail: detail}
		p.logErrorf(ctx, "declaration PUT rejected for slug=%s: status=%d detail=%q (deterministic, not retrying)", p.slug, resp.StatusCode, detail)

		return backoff.Permanent(pubErr)
	default:
		pubErr := &PublishError{Deterministic: false, StatusCode: resp.StatusCode, Op: "put declaration", Detail: detail}
		p.logWarnf(ctx, "declaration PUT failed for slug=%s: status=%d detail=%q (transient, will retry)", p.slug, resp.StatusCode, detail)

		return pubErr
	}
}

// Start runs Publish in the background so it never blocks serving, and — when
// Interval > 0 — re-publishes on a ticker to heal drift. It returns a stop func for
// graceful shutdown.
//
// Fail-open (default): a failing initial Publish does NOT make Start return a fatal
// error; it is logged and (if periodic) retried on the next tick. With FailFast the
// initial Publish runs synchronously and its error surfaces from Start.
func (p *Publisher) Start(ctx context.Context) (func(), error) {
	runCtx, cancel := context.WithCancel(ctx)

	if p.failFast {
		if err := p.Publish(runCtx); err != nil {
			cancel()

			return func() {}, fmt.Errorf("initial declaration publish failed (fail-fast): %w", err)
		}
	}

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()
		defer runtime.RecoverAndLogWithContext(runCtx, p.logger, componentName, "publisher.loop")

		p.runLoop(runCtx)
	}()

	stop := func() {
		cancel()
		wg.Wait()
	}

	return stop, nil
}

// runLoop performs the initial publish (unless already done in fail-fast mode) then,
// if configured, re-publishes on the ticker until the context is cancelled.
func (p *Publisher) runLoop(ctx context.Context) {
	if !p.failFast {
		if err := p.Publish(ctx); err != nil {
			p.logWarnf(ctx, "initial declaration publish failed for slug=%s (fail-open, serving continues): %v", p.slug, err)
		}
	}

	if p.interval <= 0 {
		return
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.Publish(ctx); err != nil {
				p.logWarnf(ctx, "periodic declaration publish failed for slug=%s (will retry next tick): %v", p.slug, err)
			}
		}
	}
}

// serverMessage extracts a safe, human-readable detail from the identity error
// body (the server message is not secret). It tolerates a non-JSON body.
func serverMessage(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	var parsed struct {
		Message string `json:"message"`
		Title   string `json:"title"`
	}

	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Message != "" {
			return parsed.Message
		}

		if parsed.Title != "" {
			return parsed.Title
		}
	}

	const maxLen = 256
	if len(body) > maxLen {
		return string(body[:maxLen])
	}

	return string(body)
}

func (p *Publisher) logInfof(ctx context.Context, format string, args ...any) {
	p.logger.Log(ctx, log.LevelInfo, fmt.Sprintf(format, args...))
}

func (p *Publisher) logWarnf(ctx context.Context, format string, args ...any) {
	p.logger.Log(ctx, log.LevelWarn, fmt.Sprintf(format, args...))
}

func (p *Publisher) logErrorf(ctx context.Context, format string, args ...any) {
	p.logger.Log(ctx, log.LevelError, fmt.Sprintf(format, args...))
}
