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

// Fixed env contract consumed by WireFromEnv. These names are DELIBERATELY
// un-prefixed and shared across every plugin — that shared contract is the
// feature. Do NOT reintroduce a per-plugin prefix here.
const (
	// envDeclarationEnabled is the master switch. Any value other than "true"
	// leaves the plugin boot exactly as it was before D7 existed: WireFromEnv
	// reads/validates NOTHING else and returns a no-op stop.
	envDeclarationEnabled = "DECLARATION_ENABLED"
	// envIdentityHost is the identity base URL — the PUT target (Config.IdentityAddr).
	envIdentityHost = "PLUGIN_IDENTITY_HOST"
	// envM2MClientID / envM2MClientSecret are the plugin's M2M credentials. The
	// secret's VALUE is never logged.
	envM2MClientID     = "M2M_CLIENT_ID"
	envM2MClientSecret = "M2M_CLIENT_SECRET" // #nosec G101 -- env var NAME, not a credential value
	// envAuthEnabled / envAuthHost configure the token minter (the AUTH host,
	// distinct from the identity host). Passed through faithfully to
	// middleware.NewAuthClient; the publisher fail-opens if a token cannot be
	// minted, so auth need NOT be enabled for WireFromEnv to succeed.
	envAuthEnabled = "PLUGIN_AUTH_ENABLED"
	envAuthHost    = "PLUGIN_AUTH_HOST"
)

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
// Contract:
//   - DECLARATION_ENABLED != "true"  => no-op: returns a non-nil func(){} and a
//     nil error WITHOUT reading or validating any other env (default-off keeps
//     the plugin boot unchanged when the flag is off).
//   - enabled => PLUGIN_IDENTITY_HOST, M2M_CLIENT_ID and M2M_CLIENT_SECRET are
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
	// leave the plugin boot untouched.
	if os.Getenv(envDeclarationEnabled) != "true" {
		return noop, nil
	}

	// Trim every string env value (absorbs the old normalizeDeclarationConfig).
	identityHost := strings.TrimSpace(os.Getenv(envIdentityHost))
	clientID := strings.TrimSpace(os.Getenv(envM2MClientID))
	clientSecret := strings.TrimSpace(os.Getenv(envM2MClientSecret))
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
