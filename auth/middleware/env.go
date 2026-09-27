package middleware

// The AUTH_* variables NewAuthClient reads at construction. Every read goes
// through these names, and EnvNames publishes exactly this set.
const (
	m2mProductForwardEnv     = "AUTH_M2M_PRODUCT_FORWARD_ENABLED"
	m2mInversionEnv          = "AUTH_M2M_INVERSION_ENABLED"
	requiredEnv              = "AUTH_REQUIRED"
	principalWhenDisabledEnv = "AUTH_PRINCIPAL_REQUIRED_WHEN_DISABLED"
	timeoutEnv               = "AUTH_TIMEOUT"
	cacheTTLEnv              = "AUTH_CACHE_TTL"
	breakerEnabledEnv        = "AUTH_BREAKER_ENABLED"
	retryMaxEnv              = "AUTH_RETRY_MAX"
	jwtVerifyCertEnv         = "AUTH_JWT_VERIFY_CERT"
	jwtVerifyCertPathEnv     = "AUTH_JWT_VERIFY_CERT_PATH"
	jwtIssuerEnv             = "AUTH_JWT_ISSUER"
)

// EnvNames returns every AUTH_* environment variable NewAuthClient reads, as a
// fresh slice per call, so a consumer can clean or audit the client's
// configuration surface without copying it.
func EnvNames() []string {
	return []string{
		m2mProductForwardEnv,
		m2mInversionEnv,
		requiredEnv,
		principalWhenDisabledEnv,
		timeoutEnv,
		cacheTTLEnv,
		breakerEnabledEnv,
		retryMaxEnv,
		jwtVerifyCertEnv,
		jwtVerifyCertPathEnv,
		jwtIssuerEnv,
	}
}
