package middleware

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnvNames_EveryNameConfiguresTheClient proves EnvNames lists only variables
// NewAuthClient acts on: each name, set alone, changes the client a blank
// environment builds.
func TestEnvNames_EveryNameConfiguresTheClient(t *testing.T) {
	_, pubPEM := newTestRSAKeyPEM(t)
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(certPath, []byte(pubPEM), 0o600))

	values := map[string]string{
		m2mProductForwardEnv:     "true",
		m2mInversionEnv:          "true",
		requiredEnv:              "true",
		principalWhenDisabledEnv: "true",
		timeoutEnv:               "5s",
		cacheTTLEnv:              "1m",
		breakerEnabledEnv:        "true",
		retryMaxEnv:              "2",
		jwtVerifyCertEnv:         pubPEM,
		jwtVerifyCertPathEnv:     certPath,
		jwtIssuerEnv:             "http://issuer:8000",
	}

	for _, name := range EnvNames() {
		t.Setenv(name, "")
	}

	logger := &testLogger{}
	blank := NewAuthClient("", false, logger)

	for _, name := range EnvNames() {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, values[name])

			assert.False(t, reflect.DeepEqual(blank, NewAuthClient("", false, logger)),
				"%s=%q left the client unchanged, so NewAuthClient does not read it", name, values[name])
		})
	}
}
