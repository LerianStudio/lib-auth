package endpoint

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testComponent = "authorization client"

func TestRequireHTTPS_AcceptsHTTPS(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://am.example",
		"HTTPS://am.example",
		"https://am.example:8443/base",
		"https://user:secret@am.example",
		"https://127.0.0.1:8443",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			assert.NoError(t, RequireHTTPS(testComponent, raw))
		})
	}
}

func TestRequireHTTPS_RefusesEverythingElse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw    string
		reason string
		scheme string
	}{
		{raw: "http://am.example", reason: ReasonPlaintextHTTP, scheme: "http"},
		{raw: "HTTP://am.example", reason: ReasonPlaintextHTTP, scheme: "http"},
		{raw: "Http://127.0.0.1", reason: ReasonPlaintextHTTP, scheme: "http"},
		{raw: "http://localhost:4000", reason: ReasonPlaintextHTTP, scheme: "http"},
		{raw: "am.example", reason: ReasonMissingScheme},
		{raw: "//am.example", reason: ReasonMissingScheme},
		{raw: "", reason: ReasonMissingScheme},
		{raw: "am.example:8443", reason: ReasonUnsupportedScheme, scheme: "am.example"},
		{raw: "ftp://am", reason: ReasonUnsupportedScheme, scheme: "ftp"},
		{raw: "ws://am", reason: ReasonUnsupportedScheme, scheme: "ws"},
		{raw: "wss://am", reason: ReasonUnsupportedScheme, scheme: "wss"},
		{raw: "grpc://am", reason: ReasonUnsupportedScheme, scheme: "grpc"},
		{raw: "unix:///sock", reason: ReasonUnsupportedScheme, scheme: "unix"},
		{raw: "https:///v1", reason: ReasonMissingHost, scheme: "https"},
		{raw: "https:am.example", reason: ReasonMissingHost, scheme: "https"},
		{raw: "https://:443", reason: ReasonMissingHost, scheme: "https"},
		{raw: " https://am", reason: ReasonUnparseable},
		{raw: "https://am ", reason: ReasonUnparseable},
		{raw: "%zz", reason: ReasonUnparseable},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()

			err := RequireHTTPS(testComponent, tc.raw)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInsecure)

			var insecure *InsecureError
			require.True(t, errors.As(err, &insecure), "want *InsecureError, got %T", err)
			assert.Equal(t, testComponent, insecure.Component)
			assert.Equal(t, tc.reason, insecure.Reason)
			assert.Equal(t, tc.scheme, insecure.Scheme)

			msg := err.Error()
			assert.Contains(t, msg, testComponent)
			assert.Contains(t, msg, tc.reason)
			assert.Contains(t, msg, "development posture")
		})
	}
}

func TestRequireHTTPS_NeverEchoesUserinfoSecret(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"http://user:secret@am.example",
		"ftp://user:secret@am.example",
		"//user:secret@am.example",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			err := RequireHTTPS(testComponent, raw)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "secret")

			var insecure *InsecureError
			require.True(t, errors.As(err, &insecure))
			assert.NotContains(t, insecure.Address, "secret")
		})
	}
}

func TestRequireHTTPS_UnparseableAddressIsNotEchoed(t *testing.T) {
	t.Parallel()

	err := RequireHTTPS(testComponent, "http://user:secret@am.example/%zz")

	var insecure *InsecureError
	require.True(t, errors.As(err, &insecure))
	assert.Equal(t, ReasonUnparseable, insecure.Reason)
	assert.Empty(t, insecure.Address)
	assert.NotContains(t, err.Error(), "secret")
}

func TestInsecureError_IsOnlyErrInsecure(t *testing.T) {
	t.Parallel()

	err := RequireHTTPS(testComponent, "http://am.example")

	assert.ErrorIs(t, err, ErrInsecure)
	assert.NotErrorIs(t, err, errors.New("lib-auth: access manager address must be https"))
}

func TestInsecureError_NilReceiver(t *testing.T) {
	t.Parallel()

	var e *InsecureError

	assert.NotPanics(t, func() {
		assert.True(t, strings.Contains(e.Error(), "https"))
		assert.True(t, e.Is(ErrInsecure))
	})
}
