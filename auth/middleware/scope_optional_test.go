package middleware

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Optional body dimensions
// ---------------------------------------------------------------------------

// optionalClient reads organizationId from the body, required, and ledgerId
// from field, optional.
func optionalClient(t *testing.T, srv *decidingAuthServer, field string) *AuthClient {
	t.Helper()

	return bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At(field).Optional())
}

// An optional field the body does not name is left out of the question; the
// question still carries every other dimension.
func TestAuthorize_OptionalBody_AbsentOrNullIsLeftOut(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"absent": `{"organizationId":"org-1"}`,
		"null":   `{"organizationId":"org-1","ledgerId":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := optionalClient(t, srv, "ledgerId")

			probe := &handlerProbe{}
			app := fiber.New()
			app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

			got := doPost(t, app, directPath, partnerToken("acme/p1"), body)

			assert.Equal(t, http.StatusOK, got.status)
			assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
			assert.Equal(t, int64(1), probe.calls.Load())
		})
	}
}

// Positive control: an optional field the body names is asked about like any
// other, and its value is still the authorization service's to refuse.
func TestAuthorize_OptionalBody_PresentIsAsked(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t, "led-out")
	auth := optionalClient(t, srv, "ledgerId")

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, directPath, partnerToken("acme/p1"), `{"organizationId":"org-1","ledgerId":"led-1"}`)
	assert.Equal(t, http.StatusOK, got.status)

	got = doPost(t, app, directPath, partnerToken("acme/p1"), `{"organizationId":"org-1","ledgerId":"led-out"}`)
	assert.Equal(t, http.StatusForbidden, got.status)

	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1", "ledgerId": "led-out"},
	}, srv.attributeCalls())
}

// Optional means the field may be absent, not that it may be wrong: a value
// that is there but is not a non-empty string is refused, naming the field.
func TestAuthorize_OptionalBody_PresentButInvalidIsABadRequest(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"empty_string": `{"organizationId":"org-1","ledgerId":""}`,
		"number":       `{"organizationId":"org-1","ledgerId":7}`,
		"object":       `{"organizationId":"org-1","ledgerId":{"id":"led-1"}}`,
		"array":        `{"organizationId":"org-1","ledgerId":["led-1"]}`,
		"bool":         `{"organizationId":"org-1","ledgerId":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := optionalClient(t, srv, "ledgerId")

			probe := &handlerProbe{}
			app := fiber.New()
			app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), probe.handle)

			got := doPost(t, app, directPath, partnerToken("acme/p1"), body)

			assert.Equal(t, http.StatusBadRequest, got.status)
			assert.Contains(t, got.body, `"ledgerId"`, "the refusal names the field")
			assert.Equal(t, int64(0), srv.hits.Load())
			assert.Equal(t, int64(0), probe.calls.Load())
		})
	}
}

// A required field keeps refusing what an optional one lets through: the
// difference is the declaration, not the body.
func TestAuthorize_OptionalBody_RequiredStillRefusesAbsence(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId"),
		Dim("ledgerId", FromBody).At("ledgerId"))

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	for _, body := range []string{`{"organizationId":"org-1"}`, `{"organizationId":"org-1","ledgerId":null}`} {
		got := doPost(t, app, directPath, partnerToken("acme/p1"), body)

		assert.Equal(t, http.StatusBadRequest, got.status, body)
		assert.Contains(t, got.body, `"ledgerId"`, body)
	}

	assert.Equal(t, int64(0), srv.hits.Load())
}

// Inside an array each element is its own question: an element without the
// optional field asks without it, its neighbours ask with theirs.
func TestAuthorize_OptionalBody_PerArrayElement(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := optionalClient(t, srv, "items[].ledgerId")

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, directPath, partnerToken("acme/p1"),
		`{"organizationId":"org-1","items":[{"ledgerId":"led-1"},{},{"ledgerId":null}]}`)

	assert.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, []map[string]string{
		{"organizationId": "org-1", "ledgerId": "led-1"},
		{"organizationId": "org-1"},
	}, srv.attributeCalls())
}

// The array an optional field sits in may itself be absent or null: the body
// names no value for it. An empty or non-array value is still malformed.
func TestAuthorize_OptionalBody_AbsentArray(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"absent": `{"organizationId":"org-1"}`,
		"null":   `{"organizationId":"org-1","items":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := optionalClient(t, srv, "items[].ledgerId")

			app := fiber.New()
			app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

			got := doPost(t, app, directPath, partnerToken("acme/p1"), body)

			assert.Equal(t, http.StatusOK, got.status)
			assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
		})
	}

	for name, body := range map[string]string{
		"empty":     `{"organizationId":"org-1","items":[]}`,
		"not_array": `{"organizationId":"org-1","items":{"ledgerId":"led-1"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newDecidingAuthServer(t)
			auth := optionalClient(t, srv, "items[].ledgerId")

			app := fiber.New()
			app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

			got := doPost(t, app, directPath, partnerToken("acme/p1"), body)

			assert.Equal(t, http.StatusBadRequest, got.status)
			assert.Contains(t, got.body, `"items"`)
			assert.Equal(t, int64(0), srv.hits.Load())
		})
	}
}

// An array a REQUIRED field also sits in cannot be absent, even when an
// optional one shares it.
func TestAuthorize_OptionalBody_ArrayOfARequiredFieldStaysRequired(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("items[].organizationId"),
		Dim("ledgerId", FromBody).At("items[].ledgerId").Optional())

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, directPath, partnerToken("acme/p1"), `{}`)
	assert.Equal(t, http.StatusBadRequest, got.status)
	assert.Contains(t, got.body, `"items"`)

	got = doPost(t, app, directPath, partnerToken("acme/p1"), `{"items":[{"organizationId":"org-1"}]}`)
	assert.Equal(t, http.StatusOK, got.status, "positive control")
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
}

// A partner request that ends up naming no dimension at all is a partner
// request the route cannot scope: refused before the call, as a route that
// declares nothing is. A body that names one is asked about.
func TestAuthorize_OptionalBody_NothingNamedIsUnscopeable(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("organizationId", FromBody).At("organizationId").Optional())

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	for _, body := range []string{`{}`, ``, `{"organizationId":null}`} {
		got := doPost(t, app, directPath, partnerToken("acme/p1"), body)
		assert.Equal(t, http.StatusForbidden, got.status, body)
	}

	assert.Equal(t, int64(0), srv.hits.Load(), "refused before any call")

	got := doPost(t, app, directPath, partnerToken("acme/p1"), `{"organizationId":"org-1"}`)
	assert.Equal(t, http.StatusOK, got.status, "positive control")
	assert.Equal(t, []map[string]string{{"organizationId": "org-1"}}, srv.attributeCalls())
}

// One element naming nothing among elements that do is refused the same way:
// it is a question with no dimension, and every question must be scopeable.
func TestAuthorize_OptionalBody_ElementNamingNothingIsUnscopeable(t *testing.T) {
	t.Parallel()

	srv := newDecidingAuthServer(t)
	auth := bodyScopedClient(t, srv.URL, http.MethodPost, directPath,
		Dim("ledgerId", FromBody).At("items[].ledgerId").Optional())

	app := fiber.New()
	app.Post(directPath, auth.Authorize("midaz", "transactions", "post"), ok)

	got := doPost(t, app, directPath, partnerToken("acme/p1"), `{"items":[{"ledgerId":"led-1"},{}]}`)
	assert.Equal(t, http.StatusForbidden, got.status)

	got = doPost(t, app, directPath, partnerToken("acme/p1"), `{"items":[{"ledgerId":"led-1"},{"ledgerId":"led-2"}]}`)
	assert.Equal(t, http.StatusOK, got.status, "positive control")
}

func TestDimension_Optional(t *testing.T) {
	t.Parallel()

	base := Dim("ledgerId", FromBody).At("ledgerId")
	opt := base.Optional()

	assert.False(t, base.IsOptional(), "Optional never mutates the receiver")
	assert.True(t, opt.IsOptional())
	assert.Equal(t, base.Key(), opt.Key())
	assert.True(t, opt.At("other").IsOptional(), "re-keying keeps optional")
}
