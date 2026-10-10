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
// The manifest's optional scope section is the product's catalog of instance
// dimensions. It is published whenever the product's auth is on — with the rest
// of the manifest when the permission declaration is on, alone (Config.ScopeOnly)
// when it is off — and WireScope hands it to the middleware so Authorize derives
// each route's dimensions from the route path.
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
	"sync/atomic"
	"time"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
	observability "github.com/LerianStudio/lib-observability/v4"
	"github.com/LerianStudio/lib-observability/v4/runtime"
	"github.com/LerianStudio/lib-observability/v4/tracing"
	"github.com/cenkalti/backoff/v5"
	"go.opentelemetry.io/otel/attribute"
)

const (
	// defaultMaxTries bounds the retries of one Publish call and of each periodic
	// tick. Start's initial background publish has no budget: it retries transient
	// failures until the declaration is accepted or refused, or stop is called.
	defaultMaxTries uint = 5

	// defaultRetryInitialInterval / defaultRetryMaxInterval bound the exponential
	// backoff (with jitter, via cenkalti/backoff/v5) between retries.
	defaultRetryInitialInterval = 1 * time.Second
	defaultRetryMaxInterval     = 30 * time.Second

	// defaultTokenMaxAge bounds how long one minted token is reused across retries.
	defaultTokenMaxAge = 5 * time.Minute

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
	//
	// When it is a *middleware.AuthClient, New also wires the manifest's scope
	// section into it (see WireScope): the routes that client authorizes derive
	// their partner scope from this manifest, whatever the order the routes and
	// the publisher are built in. New also registers the scope process-wide under
	// manifest.service (see middleware.SetProductManifestScope), so routes that
	// authorize that product with another client, one with no catalog of its
	// own, derive it too.
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
	Logger obs.Logger
	// ScopeOnly publishes ONLY the manifest's scope section (with its service and
	// version), the partner opt-in and the permissions' levels, leaving the
	// permissions, roles and m2m sections out of the body so the access manager
	// keeps what it already holds for them.
	//
	// The scope catalog is published whenever the product's auth is enabled,
	// while the permission sections keep their own switch. A product whose
	// permission declaration is off therefore still builds a publisher when its
	// auth is on, with ScopeOnly set:
	//
	//	ScopeOnly: !declarationEnabled
	//
	// A manifest without a scope section and without the partner opt-in makes a
	// ScopeOnly publisher a no-op: it never calls the identity service.
	ScopeOnly bool
	// Status, when set, reports where the publication stands, for a readiness
	// check. Optional.
	Status *Status
}

// State is where a declaration publication stands.
type State int32

const (
	// StateIdle: nothing is being published (the zero value of a Status).
	StateIdle State = iota
	// StatePending: not accepted yet; transient failures are being retried.
	StatePending
	// StatePublished: the access manager accepted the declaration.
	StatePublished
	// StateFailed: refused for good (401/403/422/501, no token, or missing
	// configuration); it needs an operator.
	StateFailed
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StatePublished:
		return "published"
	case StateFailed:
		return "failed"
	default:
		return "idle"
	}
}

// Status holds the State of a publication; share one by pointer through
// Config.Status or WireInput.Status and read it from a readiness check.
type Status struct{ state atomic.Int32 }

// State reports where the publication stands.
func (s *Status) State() State { return State(s.state.Load()) }

func (s *Status) set(v State) {
	if s != nil {
		s.state.Store(int32(v))
	}
}

// record settles a publish result: accepted is published, a deterministic
// failure is failed, and a transient one leaves the state as it was.
func (s *Status) record(err error) {
	var pubErr *PublishError

	switch {
	case err == nil:
		s.set(StatePublished)
	case errors.As(err, &pubErr) && pubErr.Deterministic:
		s.set(StateFailed)
	}
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
	logger       obs.Logger

	// manifest is parsed+validated eagerly at New; wire and hash are precomputed so
	// each Publish pass is a pure I/O operation.
	manifest *DeclarationManifest
	wire     []byte
	hash     string
	// scopeOnly selects the scope-only body (see Config.ScopeOnly); nothing is
	// true when that body would carry no scope, and Publish is then a no-op.
	scopeOnly bool
	nothing   bool
	status    *Status

	// retry knobs (exposed unexported for test overrides).
	maxTries             uint
	retryInitialInterval time.Duration
	retryMaxInterval     time.Duration
	tokenMaxAge          time.Duration
	cacheTTL             time.Duration

	httpClient *http.Client
}

// PublishError is a typed publish failure. Deterministic errors (401/403/422/501,
// or a misconfiguration) are NOT retried and NOT cached — they need human action,
// but which action depends on the shape. 401/403/422 are a REJECTION of what was
// sent: look at the M2M credential or the manifest. 501 means this deployment does
// not serve declaration upserts at all (multi-tenant, where the tenant-manager
// materializes manifests instead) — nothing in the credential or the manifest can
// change that answer, so there is nothing to correct there; the action is to stop
// declaring on that deployment (IDP_DECLARATION_ENABLED=false in its chart).
// Transient errors (409/5xx/network) are retried with backoff; after the budget is
// exhausted the last transient error is returned (and the caller, if fail-open,
// reschedules).
type PublishError struct {
	// StatusCode is the HTTP status of the failing call, the PUT or the token mint
	// (Op says which); 0 for a network/pre-request failure.
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

	// The client that mints the publisher's token is, in a product, the client
	// its routes authorize with: the manifest's scope goes to it here, so the
	// routes derive their scope from the same bytes the product publishes,
	// without a wiring call of their own.
	if auth, ok := cfg.Auth.(*middleware.AuthClient); ok && auth != nil {
		if err := wireManifestScope(auth, manifest); err != nil {
			return nil, fmt.Errorf("wire manifest scope: %w", err)
		}
	}

	// A product may authorize its routes with a client other than the one it
	// hands the publisher. The scope is also registered process-wide under the
	// manifest's service, and every client with no catalog of its own for that
	// product uses it.
	if err := wireManifestScope(productScopes{}, manifest); err != nil {
		return nil, fmt.Errorf("register manifest scope: %w", err)
	}

	var published publication = manifest
	if cfg.ScopeOnly {
		published = manifest.scopeOnly()
	}

	wire, err := published.wireJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal wire manifest: %w", err)
	}

	hash, err := published.CanonicalHash()
	if err != nil {
		return nil, fmt.Errorf("compute canonical hash: %w", err)
	}

	logger := cfg.Logger
	if obs.IsNil(logger) {
		logger = obs.Nop()
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
		scopeOnly:            cfg.ScopeOnly,
		nothing:              cfg.ScopeOnly && !manifest.hasScopeCatalog(),
		status:               cfg.Status,
		maxTries:             defaultMaxTries,
		retryInitialInterval: defaultRetryInitialInterval,
		retryMaxInterval:     defaultRetryMaxInterval,
		tokenMaxAge:          defaultTokenMaxAge,
		cacheTTL:             defaultCacheTTL,
		httpClient:           &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// publication is a body the publisher sends: the full manifest, or its
// scope-only projection.
type publication interface {
	wireJSON() ([]byte, error)
	CanonicalHash() (string, error)
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
//
// The scope-only body is a different publication with its own hash, so it keys
// separately: sharing one entry would let either publication suppress the other.
func (p *Publisher) cacheKey() string {
	if p.scopeOnly {
		return "declaration:" + p.slug + ":scope:hash"
	}

	return "declaration:" + p.slug + ":hash"
}

// Publish executes ONE pass of the flow (§4): cache check → mint token → PUT →
// store hash. It is idempotent (the server no-ops a matching hash) and, on failure,
// returns a typed *PublishError; the caller decides whether that is fatal.
func (p *Publisher) Publish(ctx context.Context) error {
	return p.publish(ctx, p.maxTries)
}

// publish is Publish with its own retry budget; tries == 0 retries transient
// failures until the context ends.
func (p *Publisher) publish(ctx context.Context, tries uint) (err error) {
	if p.nothing {
		p.status.set(StateIdle)
		p.logInfof(ctx, "declaration manifest for slug=%s declares no scope and does not opt in to partners; nothing to publish", p.slug)

		return nil
	}

	defer func() { p.status.record(err) }()

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

	if err := p.mintAndPutWithRetry(ctx, tries); err != nil {
		tracing.HandleSpanError(span, "publish declaration failed", err)

		return err
	}

	if p.cache != nil {
		p.cache.Set(ctx, p.cacheKey(), p.hash, p.cacheTTL)
	}

	p.logInfof(ctx, "declaration published for slug=%s (hash=%s)", p.slug, p.hash)

	return nil
}

// mintAndPutWithRetry runs mint→PUT as ONE backoff operation. The token is reused
// across transient PUT failures and minted again after a mint failure, a 401 on a
// reused token, or once it is tokenMaxAge old. tries == 0 retries until ctx ends.
func (p *Publisher) mintAndPutWithRetry(ctx context.Context, tries uint) error {
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = p.retryInitialInterval
	exp.MaxInterval = p.retryMaxInterval

	var (
		token    string
		mintedAt time.Time
	)

	op := func() (struct{}, error) {
		reused := token != "" && time.Since(mintedAt) < p.tokenMaxAge
		if !reused {
			var err error
			if token, err = p.mint(ctx); err != nil {
				return struct{}{}, err
			}

			mintedAt = time.Now()
		}

		err := p.doPut(ctx, token, reused)

		var pubErr *PublishError
		if errors.As(err, &pubErr) && pubErr.StatusCode == http.StatusUnauthorized {
			token = ""
		}

		return struct{}{}, err
	}

	_, err := backoff.Retry(ctx, op,
		backoff.WithBackOff(exp),
		backoff.WithMaxTries(tries),
		backoff.WithMaxElapsedTime(0),
	)

	return err
}

// mint mints the publisher's M2M token. The token endpoint refusing the credential
// (a 4xx other than 429) and an empty token (auth off) are final; the rest retries.
func (p *Publisher) mint(ctx context.Context) (string, error) {
	token, err := p.auth.GetApplicationToken(ctx, p.clientID, p.clientSecret)

	var refusal middleware.TokenRefusal

	switch {
	case errors.As(err, &refusal) && refusal.StatusCode/100 == 4 && refusal.StatusCode != http.StatusTooManyRequests:
		detail := refusal.Response.Message
		p.logErrorf(ctx, "M2M token refused for slug=%s: status=%d detail=%q (check the M2M client id and secret; not retrying)", p.slug, refusal.StatusCode, detail)

		return "", backoff.Permanent(&PublishError{Deterministic: true, StatusCode: refusal.StatusCode, Op: "mint m2m token", Detail: detail})
	case err != nil:
		p.logWarnf(ctx, "failed to mint M2M token for slug=%s (transient, will retry): %v", p.slug, err)

		return "", &PublishError{Deterministic: false, Op: "mint m2m token", Err: err}
	case token == "":
		p.logErrorf(ctx, "empty M2M token for slug=%s (auth disabled or misconfigured); not retrying", p.slug)

		return "", backoff.Permanent(&PublishError{Deterministic: true, Op: "mint m2m token", Detail: "empty token (auth disabled or misconfigured)"})
	}

	return token, nil
}

// doPut performs one PUT and classifies the result per §8. A returned error is
// either wrapped in backoff.Permanent (deterministic → stop) or plain (transient →
// retry). nil means the declaration was accepted (200).
//
// Deterministic covers two distinct shapes, logged differently: a REJECTION of what
// was sent (401/403/422 — look at the credential or the manifest) and a deployment
// that does NOT SERVE the operation (501 — multi-tenant; nothing to correct in the
// credential or the manifest, but the operator should stop declaring on that
// deployment).
func (p *Publisher) doPut(ctx context.Context, token string, reused bool) error {
	reqURL, err := p.declarationURL()
	if err != nil {
		return backoff.Permanent(&PublishError{Deterministic: true, Op: "build request", Err: err})
	}

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
		if resp.StatusCode == http.StatusUnauthorized && reused {
			p.logWarnf(ctx, "declaration PUT refused the reused M2M token for slug=%s: status=401 detail=%q (minting a fresh one)", p.slug, detail)

			return &PublishError{Deterministic: false, StatusCode: resp.StatusCode, Op: "put declaration", Detail: detail}
		}

		pubErr := &PublishError{Deterministic: true, StatusCode: resp.StatusCode, Op: "put declaration", Detail: detail}
		p.logErrorf(ctx, "declaration PUT rejected for slug=%s: status=%d detail=%q (deterministic, not retrying)", p.slug, resp.StatusCode, detail)

		return backoff.Permanent(pubErr)
	case http.StatusNotImplemented:
		// 501 is deterministic like the three above, but for a different reason,
		// so it gets its own message. 401/403/422 mean "the server rejected what
		// you sent" — the operator should look at the M2M credential or the
		// manifest. 501 means "this deployment does not serve this operation at
		// all": the identity returns it in multi-tenant mode, where materializing
		// a manifest belongs to the tenant-manager (S3 catalog -> Caradhras, with
		// an explicit owner). Nothing about this plugin, its credential or its
		// manifest can change the answer, and MULTI_TENANT_ENABLED is a
		// deployment-mode flag that does not flip under a running pod — so this is
		// permanent for the deployment, never transient. Logged at WARN, not
		// ERROR: no component failed. It stays above INFO because declaring is
		// switched ON in a deployment that can never accept it, which the
		// operator should fix in the chart (IDP_DECLARATION_ENABLED=false).
		pubErr := &PublishError{Deterministic: true, StatusCode: resp.StatusCode, Op: "put declaration", Detail: detail}
		p.logWarnf(ctx, "declaration PUT not implemented by this identity deployment for slug=%s: status=%d detail=%q (deterministic, not retrying); in multi-tenant mode manifest materialization is owned by the tenant-manager, not by the plugin, so there is nothing to fix in this plugin's M2M credential or manifest; set IDP_DECLARATION_ENABLED=false on multi-tenant deployments to stop declaring", p.slug, resp.StatusCode, detail)

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
// Fail-open (default): the initial publish runs in the background, retrying transient
// failures until the declaration is accepted or refused or stop is called. With FailFast
// it runs synchronously, with the bounded budget, and its error surfaces from Start.
func (p *Publisher) Start(ctx context.Context) (func(), error) {
	p.status.set(StatePending)

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
		if err := p.publish(ctx, 0); err != nil && ctx.Err() == nil {
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

// declarationURL is {IdentityAddr}/v1/declarations/{slug}: a trailing slash on the base
// cannot yield "//v1", and the slug is one percent-escaped segment set via RawPath, so a
// '?' or '/' in it cannot alter the target (JoinPath would double-escape an escaped slug).
func (p *Publisher) declarationURL() (string, error) {
	base, err := url.Parse(p.identityAddr)
	if err != nil {
		return "", err
	}

	base = base.JoinPath("v1", "declarations")

	// escapedPrefix is the escaped static prefix (e.g. "/v1/declarations"); compute it
	// BEFORE mutating Path. Path holds the decoded form; RawPath holds the escaped form
	// so URL.String() emits "<prefix>/<escaped-slug>" and round-trips unchanged.
	escapedPrefix := base.EscapedPath()
	base.Path += "/" + p.slug
	base.RawPath = escapedPrefix + "/" + url.PathEscape(p.slug)

	return base.String(), nil
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
	p.logger.Log(ctx, obs.LevelInfo, fmt.Sprintf(format, args...))
}

func (p *Publisher) logWarnf(ctx context.Context, format string, args ...any) {
	p.logger.Log(ctx, obs.LevelWarn, fmt.Sprintf(format, args...))
}

func (p *Publisher) logErrorf(ctx context.Context, format string, args ...any) {
	p.logger.Log(ctx, obs.LevelError, fmt.Sprintf(format, args...))
}
