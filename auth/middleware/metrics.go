package middleware

import (
	"context"
	"fmt"

	observability "github.com/LerianStudio/lib-observability/v2"
	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/LerianStudio/lib-observability/v2/metrics"
)

// JWKS key-source metric definitions (card 1.1.8). Names/units follow the
// lib-observability/v2 metrics.Metric convention (mirroring metrics.MetricAccountsCreated
// et al.): a unit of "1" for dimensionless counters and "s" for the age gauge.
var (
	// metricJWKSRefreshTotal counts upstream JWKS fetch outcomes, labelled result=ok|fail.
	metricJWKSRefreshTotal = metrics.Metric{
		Name:        "jwks_refresh_total",
		Unit:        "1",
		Description: "Number of upstream JWKS fetch outcomes by result (ok|fail).",
	}

	// metricJWKSCacheAgeSeconds gauges the age of the currently-served JWKS keys.
	metricJWKSCacheAgeSeconds = metrics.Metric{
		Name:        "jwks_cache_age_seconds",
		Unit:        "s",
		Description: "Age in seconds of the currently-served JWKS keys (since the last successful live fetch).",
	}

	// metricJWKSVerifyFailTotal counts token verification failures on the dynamic
	// JWKS key-source path (a real signature/key-staleness or claim-shape verify
	// failure — NOT token-type/sub, which are enforced downstream of verifySignature).
	metricJWKSVerifyFailTotal = metrics.Metric{
		Name:        "jwks_verify_fail_total",
		Unit:        "1",
		Description: "Number of token verification failures on the dynamic JWKS key-source path.",
	}

	// metricJWKSUnknownKIDTotal counts tokens presenting a kid absent from the current
	// cached JWKS key set (the future signal for a new-kid rotation). It is metric-only
	// and never influences the verification decision.
	metricJWKSUnknownKIDTotal = metrics.Metric{
		Name:        "jwks_unknown_kid_total",
		Unit:        "1",
		Description: "Number of tokens presenting a kid absent from the current cached JWKS key set.",
	}
)

// incrJWKSCounter increments a JWKS key-source counter by one. It is best-effort
// and non-blocking: the metrics factory is resolved from ctx via the module's
// NewTrackingFromContext convention (never nil — it falls back to a no-op factory
// backed by the global meter provider), so no meter injection or constructor change
// is needed. A failure to create/record the instrument is logged at WARN and never
// affects the verification decision.
func incrJWKSCounter(ctx context.Context, m metrics.Metric, labels map[string]string) {
	logger, _, _, factory := observability.NewTrackingFromContext(ctx)

	counter, err := factory.Counter(m)
	if err != nil {
		logger.Log(ctx, log.LevelWarn, fmt.Sprintf("failed to create metric %q: %v", m.Name, err))

		return
	}

	if len(labels) > 0 {
		counter = counter.WithLabels(labels)
	}

	if err := counter.AddOne(ctx); err != nil {
		logger.Log(ctx, log.LevelWarn, fmt.Sprintf("failed to record metric %q: %v", m.Name, err))
	}
}

// setJWKSGauge records the current value of a JWKS key-source gauge. Best-effort and
// non-blocking, using the same factory-from-ctx convention as incrJWKSCounter.
func setJWKSGauge(ctx context.Context, m metrics.Metric, value int64) {
	logger, _, _, factory := observability.NewTrackingFromContext(ctx)

	gauge, err := factory.Gauge(m)
	if err != nil {
		logger.Log(ctx, log.LevelWarn, fmt.Sprintf("failed to create metric %q: %v", m.Name, err))

		return
	}

	if err := gauge.Set(ctx, value); err != nil {
		logger.Log(ctx, log.LevelWarn, fmt.Sprintf("failed to record metric %q: %v", m.Name, err))
	}
}
