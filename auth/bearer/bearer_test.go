package bearer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validToken is three non-empty base64url segments: the shape of a signed JWT.
const validToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJl"

// tokenOfLength builds a well-formed three-segment token of exactly n bytes.
func tokenOfLength(t *testing.T, n int) string {
	t.Helper()

	const head, sig = "aaaa", "bbbb"

	body := n - len(head) - len(sig) - 2
	require.Positive(t, body)
	require.NotEqual(t, 1, body%4, "a raw base64url segment cannot be 1 mod 4 long")

	return head + "." + strings.Repeat("A", body) + "." + sig
}

func TestParse_Accepts(t *testing.T) {
	t.Parallel()

	atCap := tokenOfLength(t, MaxTokenBytes)

	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"canonical scheme", "Bearer " + validToken, validToken},
		{"lower-case scheme", "bearer " + validToken, validToken},
		{"upper-case scheme", "BEARER " + validToken, validToken},
		{"repeated spaces after the scheme", "Bearer    " + validToken, validToken},
		{"surrounding spaces", "  Bearer " + validToken + "  ", validToken},
		{"token of exactly the cap", "Bearer " + atCap, atCap},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tc.header)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParse_Refuses(t *testing.T) {
	t.Parallel()

	overCap := tokenOfLength(t, MaxTokenBytes+1)

	cases := []struct {
		name   string
		header string
		want   error
	}{
		{"empty header", "", ErrMissing},
		{"blank header", "   ", ErrMissing},
		{"scheme alone", "Bearer", ErrMalformed},
		{"scheme and trailing spaces", "Bearer   ", ErrMalformed},
		{"bare token without scheme", validToken, ErrMalformed},
		{"basic scheme", "Basic " + validToken, ErrMalformed},
		{"scheme glued to token", "Bearer" + validToken, ErrMalformed},
		{"two tokens", "Bearer " + validToken + " " + validToken, ErrMalformed},
		{"token one byte over the cap", "Bearer " + overCap, ErrMalformed},
		{"huge header", "Bearer " + strings.Repeat("A", 1<<20), ErrMalformed},
		{"carriage return", "Bearer " + validToken + "\r", ErrMalformed},
		{"line feed inside the token", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIi\nOiJ1In0.c2lnbmF0dXJl", ErrMalformed},
		{"CRLF injection", "Bearer " + validToken + "\r\nX-Evil: 1", ErrMalformed},
		{"tab as separator", "Bearer\t" + validToken, ErrMalformed},
		{"NUL byte", "Bearer " + validToken + "\x00", ErrMalformed},
		{"DEL byte", "Bearer " + validToken + "\x7f", ErrMalformed},
		{"non-ASCII byte", "Bearer eyJhbGciOiJIUzI1NiJ9.é.c2lnbmF0dXJl", ErrMalformed},
		{"two segments", "Bearer aaaa.bbbb", ErrMalformed},
		{"four segments", "Bearer aaaa.bbbb.cccc.dddd", ErrMalformed},
		{"empty header segment", "Bearer .bbbb.cccc", ErrMalformed},
		{"empty payload segment", "Bearer aaaa..cccc", ErrMalformed},
		{"empty signature segment (unsigned token)", "Bearer aaaa.bbbb.", ErrMalformed},
		{"padded segment", "Bearer aaaa.bbb=.cccc", ErrMalformed},
		{"standard alphabet plus", "Bearer aaaa.bb+b.cccc", ErrMalformed},
		{"standard alphabet slash", "Bearer aaaa.bb/b.cccc", ErrMalformed},
		{"impossible segment length", "Bearer aaaa.b.cccc", ErrMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tc.header)
			require.ErrorIs(t, err, tc.want)
			assert.Empty(t, got, "a refused header must never yield a token")
		})
	}
}

func TestFromRequest(t *testing.T) {
	t.Parallel()

	t.Run("nil request is missing", func(t *testing.T) {
		t.Parallel()

		got, err := FromRequest(nil)
		require.ErrorIs(t, err, ErrMissing)
		assert.Empty(t, got)
	})

	t.Run("no authorization header is missing", func(t *testing.T) {
		t.Parallel()

		got, err := FromRequest(httptest.NewRequest(http.MethodGet, "/", nil))
		require.ErrorIs(t, err, ErrMissing)
		assert.Empty(t, got)
	})

	t.Run("blank authorization header is missing", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", " ")

		got, err := FromRequest(r)
		require.ErrorIs(t, err, ErrMissing)
		assert.Empty(t, got)
	})

	t.Run("single well-formed header yields the token", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+validToken)

		got, err := FromRequest(r)
		require.NoError(t, err)
		assert.Equal(t, validToken, got)
	})

	t.Run("two authorization lines are malformed", func(t *testing.T) {
		t.Parallel()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", "Bearer "+validToken)
		r.Header.Add("Authorization", "Bearer "+validToken)

		got, err := FromRequest(r)
		require.ErrorIs(t, err, ErrMalformed)
		assert.Empty(t, got)
	})

	t.Run("refusals are distinct sentinels", func(t *testing.T) {
		t.Parallel()

		assert.False(t, errors.Is(ErrMissing, ErrMalformed))
	})
}
