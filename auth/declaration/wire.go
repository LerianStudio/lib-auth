package declaration

// wire.go hoists the D7-declaration boilerplate that EVERY plugin used to
// hand-write at boot — read a handful of env vars, trim them, validate the
// required ones, build a *middleware.AuthClient token minter, assemble a
// declaration.Config, then New + Start the publisher — into a SINGLE lib-auth
// call: WireFromEnv.
//
// The whole point is the FIXED, un-prefixed env contract below. Because the
// contract is fixed (not per-plugin-prefixed), a plugin's boot code shrinks to
// one line that passes only the two values that are genuinely plugin-specific
// (its Slug and its embedded Manifest); everything operational (identity host,
// M2M creds, auth host) comes from the shared, deployment-owned environment.
//
// This file is ADDITIVE: it does not change publisher.go / manifest.go behavior.
// It only composes their existing public surface (New, Publisher.Start) plus the
// middleware.AuthClient token minter.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/LerianStudio/lib-auth/v5/auth/middleware"
	"github.com/LerianStudio/lib-auth/v5/auth/obs"
)

// Fixed env contract consumed by WireFromEnv. The four RI/D7-declaration vars
// now carry a PRODUCT-WIDE "IDP_" prefix (identity provider) per the platform
// env-naming standard (#4232). This is NOT the per-plugin prefix an earlier
// revision of this file forbade: "IDP_" is shared across EVERY plugin, so the
// shared-contract property — the whole reason WireFromEnv can absorb the boot
// boilerplate — is fully preserved. A plugin's boot code still passes only its
// Slug and Manifest; every operational value comes from these fixed names.
//
// Backward compatibility: each of the four vars accepts its OLD, un-prefixed
// name as a DEPRECATED ALIAS, honored for ONE release. When only the alias is
// set, WireFromEnv resolves its value and logs a single WARN naming both the
// deprecated and canonical names (never the value). Canonical always wins over
// the alias. Remove the aliases (and this note) after the alias-window release.
//
// The auth-minter vars (PLUGIN_AUTH_ENABLED / PLUGIN_AUTH_HOST) are OUT of
// scope for #4232 and intentionally keep their existing names.
const (
	// envDeclarationEnabled is the master switch. Any value other than "true"
	// leaves the plugin boot exactly as it was before D7 existed: WireFromEnv
	// reads/validates NOTHING else and returns a no-op stop.
	envDeclarationEnabled = "IDP_DECLARATION_ENABLED"
	// envIdentityHost is the identity base URL — the PUT target (Config.IdentityAddr).
	envIdentityHost = "IDP_HOST"
	// envM2MClientID / envM2MClientSecret are the plugin's M2M credentials. The
	// secret's VALUE is never logged.
	envM2MClientID     = "IDP_M2M_CLIENT_ID"
	envM2MClientSecret = "IDP_M2M_CLIENT_SECRET" // #nosec G101 -- env var NAME, not a credential value

	// Deprecated aliases — the legacy pre-#4232 names (e.g. PLUGIN_IDENTITY_HOST
	// for IDP_HOST; the M2M_* pair and DECLARATION_ENABLED were un-prefixed). Honored for ONE
	// release with a WARN on use; delete after the alias-window release ships.
	envDeclarationEnabledDeprecated = "DECLARATION_ENABLED"
	envIdentityHostDeprecated       = "PLUGIN_IDENTITY_HOST"
	envM2MClientIDDeprecated        = "M2M_CLIENT_ID"
	envM2MClientSecretDeprecated    = "M2M_CLIENT_SECRET" // #nosec G101 -- env var NAME, not a credential value

	// envAuthEnabled / envAuthHost configure the token minter (the AUTH host,
	// distinct from the identity host). Both are REQUIRED when declaration is
	// enabled: the identity endpoint is M2M-guarded, so without a mintable token
	// the PUT can never be accepted. Leaving them optional turned a permanent
	// misconfiguration into a silent one — the publisher fail-opens on the minting
	// failure, so the pod goes green and simply never declares. Requiring them
	// here converts that into a boot error naming the missing variable.
	envAuthEnabled = "PLUGIN_AUTH_ENABLED"
	envAuthHost    = "PLUGIN_AUTH_HOST"

	// envAuthHostDeprecated is the OTHER spelling of the auth host already in
	// production. Roughly half the platform's deployments set PLUGIN_AUTH_ADDRESS
	// and the other half PLUGIN_AUTH_HOST, both carrying the same value (the auth
	// component's base URL); some set both. Honored as an alias so requiring the
	// auth host above does not fail-close every deployment in the ADDRESS camp.
	// Convergence on a single name is tracked separately; until it lands, the
	// canonical name wins and using the alias logs a WARN.
	envAuthHostDeprecated = "PLUGIN_AUTH_ADDRESS"
)

// lookupWithDeprecatedAlias resolves an env var during the #4232 rename window.
// It returns the TRIMMED canonical value when non-empty; otherwise, when the
// TRIMMED deprecated alias is non-empty, it logs a SINGLE warn naming both vars
// (never the value) and returns the alias value; otherwise it returns "".
//
// It is kept local to this package deliberately: the deprecation warning is a
// one-release migration aid specific to the RI/D7-declaration contract, not a
// general-purpose utility worth widening lib-commons' surface for.
func lookupWithDeprecatedAlias(canonical, deprecated string, logger obs.Logger) string {
	if v := strings.TrimSpace(os.Getenv(canonical)); v != "" {
		return v
	}

	if v := strings.TrimSpace(os.Getenv(deprecated)); v != "" {
		if !obs.IsNil(logger) {
			logger.Log(context.Background(), obs.LevelWarn,
				fmt.Sprintf("env %s is deprecated; use %s", deprecated, canonical))
		}

		return v
	}

	return ""
}

// newAuthClient builds the token minter WireFromEnv owns when the service
// injects none. A variable so tests can prove an injected client is the only one.
var newAuthClient = middleware.NewAuthClient

// WireInput carries the ONLY per-plugin values; everything else comes from the
// fixed env contract above.
type WireInput struct {
	// Slug is the plugin slug. It MUST equal manifest.service and the M2M app
	// DisplayName (New enforces slug == manifest.service via BOLA). Required.
	Slug string
	// Manifest is the plugin's embedded permissions manifest — the plugin does
	// the //go:embed (embed is relative to the caller's source). Required.
	Manifest []byte
	// Logger receives structured logs. Optional; nil => a no-op logger.
	Logger obs.Logger
	// AuthClient is the client the service already authorizes its routes with.
	// Optional. When set, WireFromEnv mints the publisher's token with it and
	// wires the manifest's scope into it, and reads neither PLUGIN_AUTH_HOST (nor
	// its alias PLUGIN_AUTH_ADDRESS) nor PLUGIN_AUTH_ENABLED: the client's own
	// Address and Enabled stand in for them, so the service keeps a single
	// AuthClient and its own env names for it. With the declaration on, a client
	// that is disabled or has no Address fails the boot by name, as the env pair
	// does. When nil, WireFromEnv builds its own client from the env, as before.
	AuthClient *middleware.AuthClient
	// Status, when set, reports where the publication stands, for a readiness
	// check: idle when nothing is published. Optional.
	Status *Status
}

// injectedAuthError reports why an injected client cannot mint the publisher's
// token, or nil when it can.
func injectedAuthError(c *middleware.AuthClient) error {
	switch {
	case strings.TrimSpace(c.Address) == "":
		return fmt.Errorf("WireInput.AuthClient.Address is required when %s=true: the identity declaration endpoint is M2M-guarded and no token can be minted without it",
			envDeclarationEnabled)
	case !c.Enabled:
		return fmt.Errorf("WireInput.AuthClient.Enabled must be true when %s=true: the identity declaration endpoint is M2M-guarded and the minter yields an empty token while auth is off",
			envDeclarationEnabled)
	}

	return nil
}

// wireScopeOnly publishes the manifest's scope section and partner opt-in alone,
// for a deployment whose permission declaration is off. It runs only when
// PLUGIN_AUTH_ENABLED is true and the manifest declares a scope or opts in to
// partners; otherwise it reads and validates nothing else, which keeps the
// declaration-off boot exactly as it was for every manifest with neither.
//
// It never fails the boot. The scope is a catalog the identity provider uses to
// validate partner writes; a deployment that cannot publish it keeps serving,
// and the reason is logged at ERROR naming the missing variable.
func wireScopeOnly(ctx context.Context, in WireInput) (func(), error) {
	noop := func() {}

	authOn := os.Getenv(envAuthEnabled) == "true"
	if in.AuthClient != nil {
		authOn = in.AuthClient.Enabled
	}

	if !authOn {
		return noop, nil
	}

	logError := func(format string, args ...any) {
		in.Status.set(StateFailed)

		if !obs.IsNil(in.Logger) {
			in.Logger.Log(ctx, obs.LevelError, fmt.Sprintf(format, args...))
		}
	}

	// With the permission declaration off, an unparseable manifest never failed
	// the boot; it still does not, but a scope it may carry cannot be published.
	manifest, err := parseManifest(in.Manifest)
	if err != nil {
		logError("scope catalog for slug=%s not published: %v", in.Slug, err)

		return noop, nil
	}

	if !manifest.hasScopeCatalog() {
		return noop, nil
	}

	identityHost := lookupWithDeprecatedAlias(envIdentityHost, envIdentityHostDeprecated, in.Logger)
	clientID := lookupWithDeprecatedAlias(envM2MClientID, envM2MClientIDDeprecated, in.Logger)
	clientSecret := lookupWithDeprecatedAlias(envM2MClientSecret, envM2MClientSecretDeprecated, in.Logger)
	// An injected client's Address stands in for the env auth host, which is
	// then not read.
	var authHost, authHostName, authSwitch string
	if in.AuthClient != nil {
		authHost, authHostName, authSwitch = strings.TrimSpace(in.AuthClient.Address), "WireInput.AuthClient.Address", "WireInput.AuthClient.Enabled"
	} else {
		authHost = lookupWithDeprecatedAlias(envAuthHost, envAuthHostDeprecated, in.Logger)
		authHostName, authSwitch = envAuthHost+" (or its alias "+envAuthHostDeprecated+")", envAuthEnabled
	}

	missing := ""

	switch {
	case identityHost == "":
		missing = envIdentityHost
	case clientID == "":
		missing = envM2MClientID
	case clientSecret == "":
		missing = envM2MClientSecret
	case authHost == "":
		missing = authHostName
	}

	if missing != "" {
		logError("scope catalog for slug=%s not published: %s is required when %s=true; partner scopes for this product cannot be validated until it is",
			in.Slug, missing, authSwitch)

		return noop, nil
	}

	auth := in.AuthClient
	if auth == nil {
		auth = newAuthClient(authHost, true, in.Logger)
	}

	pub, err := New(Config{
		Slug:         in.Slug,
		Manifest:     in.Manifest,
		IdentityAddr: identityHost,
		Auth:         auth,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Logger:       in.Logger,
		ScopeOnly:    true,
		Status:       in.Status,
	})
	if err != nil {
		logError("scope catalog for slug=%s not published: %v", in.Slug, err)

		return noop, nil
	}

	stop, err := pub.Start(ctx)
	if err != nil {
		logError("scope catalog for slug=%s not published: %v", in.Slug, err)

		return noop, nil
	}

	return stop, nil
}

// authClientFromEnv builds the token minter from the env auth pair, the one
// WireFromEnv owns when the service injects none. Both are required: the
// identity declaration endpoint is M2M-guarded, and a blank host or auth off
// yields an empty token. The order of the checks, after the identity config,
// keeps the error a deployment sees the same as before the client was injectable.
func authClientFromEnv(logger obs.Logger) (*middleware.AuthClient, error) {
	authHost := lookupWithDeprecatedAlias(envAuthHost, envAuthHostDeprecated, logger)

	switch {
	case authHost == "":
		return nil, fmt.Errorf("%s (or its alias %s) is required when %s=true: the identity declaration endpoint is M2M-guarded and no token can be minted without it",
			envAuthHost, envAuthHostDeprecated, envDeclarationEnabled)
	case os.Getenv(envAuthEnabled) != "true":
		return nil, fmt.Errorf("%s must be true when %s=true: the identity declaration endpoint is M2M-guarded and the minter yields an empty token while auth is off",
			envAuthEnabled, envDeclarationEnabled)
	}

	// NewAuthClient resolves a nil logger to its own default, so the caller's
	// logger goes straight through.
	return newAuthClient(authHost, true, logger), nil
}

// WireFromEnv builds and starts the D7 declaration publisher from the FIXED,
// un-prefixed env contract, absorbing the config/trim/validation/auth-client/
// lifecycle boilerplate that each plugin used to hand-write. It returns a stop
// func for graceful shutdown.
//
// Contract (the IDP_* names below are the CANONICAL ones — see the const block:
// each also accepts its legacy (pre-#4232) name as a DEPRECATED alias for one
// release, and canonical always wins. New deployments must set the IDP_* names):
//   - IDP_DECLARATION_ENABLED != "true"  => the permission sections are not
//     published. When PLUGIN_AUTH_ENABLED=true AND the manifest declares a scope
//     or partners: true, the scope section and the opt-in alone are published
//     (see wireScopeOnly; it never fails the boot). Otherwise it is a no-op:
//     returns a non-nil func(){} and a nil error WITHOUT reading or validating
//     any other env, so a manifest with neither keeps the plugin boot unchanged
//     when the flag is off.
//   - enabled => IDP_HOST, IDP_M2M_CLIENT_ID, IDP_M2M_CLIENT_SECRET, the auth
//     host (PLUGIN_AUTH_HOST, or its alias PLUGIN_AUTH_ADDRESS) and
//     PLUGIN_AUTH_ENABLED=true are required; each yields a clear, named error
//     when blank or off. The auth pair is required because the identity
//     declaration endpoint is M2M-guarded: without a mintable token the publish
//     can never succeed, and since the publish fail-opens, omitting them used to
//     produce a green pod that silently never declared. Deeper URL validation is
//     delegated to New.
//   - WireInput.AuthClient set => the service's own client mints the token and
//     receives the manifest's scope; PLUGIN_AUTH_HOST, PLUGIN_AUTH_ADDRESS and
//     PLUGIN_AUTH_ENABLED are not read, and no second client is built. Its
//     Address and Enabled take their place in the checks above (a blank Address
//     or Enabled=false is a named boot error when the declaration is on), and its
//     Enabled decides whether the scope alone is published when it is off.
//
// Fail-open by design: on the happy path Start never blocks on identity
// reachability (a failing initial publish is logged in the background, not
// fatal); WireInput.Status reports where it stands. On EVERY error path a NON-NIL
// no-op stop is returned so a caller's `defer stop()` can never nil-panic.
func WireFromEnv(ctx context.Context, in WireInput) (func(), error) {
	// noop is the always-safe stop returned on the disabled path and on every
	// error path, so a deferred stop() is never nil.
	noop := func() {}

	// The flag honors its deprecated alias for the #4232 rename window
	// (canonical IDP_DECLARATION_ENABLED wins). Off, the permission sections are
	// not published — but the scope catalog still is whenever auth is on.
	if lookupWithDeprecatedAlias(envDeclarationEnabled, envDeclarationEnabledDeprecated, in.Logger) != "true" {
		return wireScopeOnly(ctx, in)
	}

	// Resolve every value through the canonical-wins / deprecated-alias helper
	// (which also trims — absorbing the old normalizeDeclarationConfig). Only the
	// four RI/D7 vars carry the IDP_ prefix + alias; the auth-minter vars do not.
	identityHost := lookupWithDeprecatedAlias(envIdentityHost, envIdentityHostDeprecated, in.Logger)
	clientID := lookupWithDeprecatedAlias(envM2MClientID, envM2MClientIDDeprecated, in.Logger)
	clientSecret := lookupWithDeprecatedAlias(envM2MClientSecret, envM2MClientSecretDeprecated, in.Logger)

	switch {
	case identityHost == "":
		return noop, fmt.Errorf("%s is required when %s=true", envIdentityHost, envDeclarationEnabled)
	case clientID == "":
		return noop, fmt.Errorf("%s is required when %s=true", envM2MClientID, envDeclarationEnabled)
	case clientSecret == "":
		return noop, fmt.Errorf("%s is required when %s=true", envM2MClientSecret, envDeclarationEnabled)
	}

	// An injected client is the service's own: its Address and Enabled replace
	// the env auth pair, which is then not read at all.
	auth := in.AuthClient
	if auth != nil {
		if err := injectedAuthError(auth); err != nil {
			return noop, err
		}
	} else {
		var err error
		if auth, err = authClientFromEnv(in.Logger); err != nil {
			return noop, err
		}
	}

	// Assemble the Config. Cache/Interval/FailFast are hardcoded to the
	// pilot-safe values (no extra env knobs now): no dedup cache, startup-only,
	// fail-open.
	cfg := Config{
		Slug:         in.Slug,
		Manifest:     in.Manifest,
		IdentityAddr: identityHost,
		Auth:         auth,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Cache:        nil,
		Interval:     0,
		FailFast:     false,
		Logger:       in.Logger,
		Status:       in.Status,
	}

	pub, err := New(cfg)
	if err != nil {
		return noop, fmt.Errorf("build declaration publisher: %w", err)
	}

	stop, err := pub.Start(ctx)
	if err != nil {
		return noop, err
	}

	return stop, nil
}

// catalogDimensionSources and routeDimensionSources map a scope dimension's
// `from` to the source the middleware reads it from, for the catalog and for
// scope.routes. Validate accepts exactly these keys; a new source is one entry
// here and one in the middleware.
var (
	catalogDimensionSources = map[string]middleware.Source{
		scopeFromPath:   middleware.FromPath,
		scopeFromQuery:  middleware.FromQuery,
		scopeFromHeader: middleware.FromHeader,
	}
	routeDimensionSources = map[string]middleware.Source{
		scopeFromBody:   middleware.FromBody,
		scopeFromForm:   middleware.FromForm,
		scopeFromQuery:  middleware.FromQuery,
		scopeFromHeader: middleware.FromHeader,
	}
)

// routeDimensions builds the middleware dimensions one scope.routes entry
// declares.
func routeDimensions(r DeclarationScopeRoute) []middleware.Dimension {
	dims := make([]middleware.Dimension, 0, len(r.Dimensions))

	for _, d := range r.Dimensions {
		dim := middleware.Dim(d.Name, routeDimensionSources[d.From]).At(d.Field)
		if d.Optional {
			dim = dim.Optional()
		}

		dims = append(dims, dim)
	}

	return dims
}

// WireScope wires the manifest's scope section into the authorization client, so
// auth.Authorize derives each route's scope dimensions from the route path, the
// query and headers (see middleware.AuthClient.SetManifestScope). It parses and
// validates the manifest — the same embedded bytes the product publishes — and
// registers its scope under manifest.service, which must be the product name the
// routes pass to Authorize.
//
// New does this for the client it is given as Config.Auth, and registers the
// scope process-wide for every client with no catalog of its own for the
// product, so a product that builds a publisher needs no call of its own.
// WireScope is for a client whose routes must follow a manifest no publisher
// is built from. It may be called before or after the
// routes are registered: each route works out its scope on its first request.
//
//	auth := middleware.NewAuthClient(authHost, authEnabled, logger)
//	if err := declaration.WireScope(auth, embeddedManifest); err != nil {
//		return err
//	}
//	app.Get("/v1/organizations/:organization_id/ledgers/:ledger_id",
//		auth.Authorize("midaz", "ledgers", "get"), handler)
//
// The routes of scope.routes read the dimensions they declare from their JSON
// request body, a urlencoded form body, the query or headers (see
// middleware.AuthClient.SetManifestRouteScope); a route that cannot be honoured
// fails here, at boot.
//
// A manifest without a scope section leaves the service with no catalog.
func WireScope(auth *middleware.AuthClient, manifest []byte) error {
	if auth == nil {
		return errors.New("wire scope: auth client is required")
	}

	m, err := parseManifest(manifest)
	if err != nil {
		return fmt.Errorf("wire scope: %w", err)
	}

	if err := m.Validate(); err != nil {
		return fmt.Errorf("wire scope: %w", err)
	}

	if err := wireManifestScope(auth, m); err != nil {
		return fmt.Errorf("wire scope: %w", err)
	}

	return nil
}

// scopeTarget is where a manifest's scope section is wired: one authorization
// client, or the process-wide registry every client without a catalog of its
// own falls back to.
type scopeTarget interface {
	SetManifestScope(product string, dims ...middleware.Dimension) error
	SetManifestRouteScope(product, method, path string, dims ...middleware.Dimension) error
}

// productScopes is the process-wide registry as a scopeTarget.
type productScopes struct{}

func (productScopes) SetManifestScope(product string, dims ...middleware.Dimension) error {
	return middleware.SetProductManifestScope(product, dims...)
}

func (productScopes) SetManifestRouteScope(product, method, path string, dims ...middleware.Dimension) error {
	return middleware.SetProductManifestRouteScope(product, method, path, dims...)
}

// wireManifestScope registers a validated manifest's scope section under its
// service: the catalog, then the dimensions of every scope.routes entry. A
// manifest without a scope section removes the service's catalog, leaving the
// target as if none had been wired.
func wireManifestScope(auth scopeTarget, m *DeclarationManifest) error {
	if err := auth.SetManifestScope(m.Service, catalogDimensions(m.Scope)...); err != nil {
		return err
	}

	if m.Scope == nil {
		return nil
	}

	for _, r := range m.Scope.Routes {
		if err := auth.SetManifestRouteScope(m.Service, r.Method, r.Path, routeDimensions(r)...); err != nil {
			return err
		}
	}

	return nil
}

// catalogDimensions builds the middleware dimensions of the scope catalog, in
// catalog order; none for a manifest without a scope section.
func catalogDimensions(scope *DeclarationScope) []middleware.Dimension {
	if scope == nil {
		return nil
	}

	dims := make([]middleware.Dimension, 0, len(scope.Dimensions))
	for _, d := range scope.Dimensions {
		dims = append(dims, middleware.Dim(d.Name, catalogDimensionSources[d.From]).At(d.Param))
	}

	return dims
}
