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
	"fmt"
	"os"
	"strings"

	"github.com/LerianStudio/lib-auth/v3/auth/middleware"
	"github.com/LerianStudio/lib-observability/v2/log"
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

	// Deprecated aliases — the pre-#4232 un-prefixed names. Honored for ONE
	// release with a WARN on use; delete after the alias-window release ships.
	envDeclarationEnabledDeprecated = "DECLARATION_ENABLED"
	envIdentityHostDeprecated       = "PLUGIN_IDENTITY_HOST"
	envM2MClientIDDeprecated        = "M2M_CLIENT_ID"
	envM2MClientSecretDeprecated    = "M2M_CLIENT_SECRET" // #nosec G101 -- env var NAME, not a credential value

	// envAuthEnabled / envAuthHost configure the token minter (the AUTH host,
	// distinct from the identity host). Passed through faithfully to
	// middleware.NewAuthClient; the publisher fail-opens if a token cannot be
	// minted, so auth need NOT be enabled for WireFromEnv to succeed. These are
	// OUT of scope for #4232 and keep their names.
	envAuthEnabled = "PLUGIN_AUTH_ENABLED"
	envAuthHost    = "PLUGIN_AUTH_HOST"
)

// lookupWithDeprecatedAlias resolves an env var during the #4232 rename window.
// It returns the TRIMMED canonical value when non-empty; otherwise, when the
// TRIMMED deprecated alias is non-empty, it logs a SINGLE warn naming both vars
// (never the value) and returns the alias value; otherwise it returns "".
//
// It is kept local to this package deliberately: the deprecation warning is a
// one-release migration aid specific to the RI/D7-declaration contract, not a
// general-purpose utility worth widening lib-commons' surface for.
func lookupWithDeprecatedAlias(canonical, deprecated string, logger log.Logger) string {
	if v := strings.TrimSpace(os.Getenv(canonical)); v != "" {
		return v
	}

	if v := strings.TrimSpace(os.Getenv(deprecated)); v != "" {
		if logger != nil {
			logger.Log(context.Background(), log.LevelWarn,
				fmt.Sprintf("env %s is deprecated; use %s", deprecated, canonical))
		}

		return v
	}

	return ""
}

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
	Logger log.Logger
}

// WireFromEnv builds and starts the D7 declaration publisher from the FIXED,
// un-prefixed env contract, absorbing the config/trim/validation/auth-client/
// lifecycle boilerplate that each plugin used to hand-write. It returns a stop
// func for graceful shutdown.
//
// Contract (the IDP_* names below are the CANONICAL ones — see the const block:
// each also accepts its old un-prefixed name as a DEPRECATED alias for one
// release, and canonical always wins. New deployments must set the IDP_* names):
//   - IDP_DECLARATION_ENABLED != "true"  => no-op: returns a non-nil func(){} and
//     a nil error WITHOUT reading or validating any other env (default-off keeps
//     the plugin boot unchanged when the flag is off).
//   - enabled => IDP_HOST, IDP_M2M_CLIENT_ID and IDP_M2M_CLIENT_SECRET are
//     required (each yields a clear, named error when blank). Deeper URL
//     validation is delegated to New.
//
// Fail-open by design: on the happy path Start never blocks on identity
// reachability (a failing initial publish is logged in the background, not
// fatal). On EVERY error path a NON-NIL no-op stop is returned so a caller's
// `defer stop()` can never nil-panic.
func WireFromEnv(ctx context.Context, in WireInput) (func(), error) {
	// noop is the always-safe stop returned on the disabled path and on every
	// error path, so a deferred stop() is never nil.
	noop := func() {}

	// Default-off: when the flag is not exactly "true", validate nothing and
	// leave the plugin boot untouched. The flag honors its deprecated alias for
	// the #4232 rename window (canonical IDP_DECLARATION_ENABLED wins).
	if lookupWithDeprecatedAlias(envDeclarationEnabled, envDeclarationEnabledDeprecated, in.Logger) != "true" {
		return noop, nil
	}

	// Resolve every value through the canonical-wins / deprecated-alias helper
	// (which also trims — absorbing the old normalizeDeclarationConfig). Only the
	// four RI/D7 vars carry the IDP_ prefix + alias; the auth-minter vars do not.
	identityHost := lookupWithDeprecatedAlias(envIdentityHost, envIdentityHostDeprecated, in.Logger)
	clientID := lookupWithDeprecatedAlias(envM2MClientID, envM2MClientIDDeprecated, in.Logger)
	clientSecret := lookupWithDeprecatedAlias(envM2MClientSecret, envM2MClientSecretDeprecated, in.Logger)
	authHost := strings.TrimSpace(os.Getenv(envAuthHost))
	authEnabled := os.Getenv(envAuthEnabled) == "true"

	// Validate the required fields (absorbs the old validateDeclarationConfig).
	// The secret's VALUE is never included in any error.
	switch {
	case identityHost == "":
		return noop, fmt.Errorf("%s is required when %s=true", envIdentityHost, envDeclarationEnabled)
	case clientID == "":
		return noop, fmt.Errorf("%s is required when %s=true", envM2MClientID, envDeclarationEnabled)
	case clientSecret == "":
		return noop, fmt.Errorf("%s is required when %s=true", envM2MClientSecret, envDeclarationEnabled)
	}

	// Build the token minter. NewAuthClient takes *log.Logger: pass a pointer to
	// the caller's logger when present, else nil (it falls back to its own
	// logger). Auth is passed through faithfully — the publisher fail-opens if a
	// token can't be minted, matching current plugin behavior.
	var loggerPtr *log.Logger
	if in.Logger != nil {
		loggerPtr = &in.Logger
	}

	auth := middleware.NewAuthClient(authHost, authEnabled, loggerPtr)

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
