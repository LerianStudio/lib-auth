package middleware

import (
	"errors"
	"net/http"

	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/gofiber/fiber/v3"
)

// Denial reasons the authorization service publishes. Only the two that mean
// "this credential is finished" change the status this layer returns.
const (
	reasonSuspended = "suspended"
	reasonExpired   = "expired"
)

// denialStatus maps a denial reason to the status the caller is answered with.
// Unknown and absent reasons keep the 403 every denial returned before reasons
// existed, so a reason this version does not know never widens or narrows access.
func denialStatus(reason string) int {
	switch reason {
	case reasonSuspended, reasonExpired:
		return http.StatusUnauthorized
	default:
		return http.StatusForbidden
	}
}

// partnerDenial is the refusal a credential-finished reason is answered with:
// the 401 denialStatus picks, carrying a code and message that name the partner
// as the cause. The codes are the ones the authorization service answers a token
// request for the same partner with, so a client handles both alike. The token
// itself is valid — it works again once the partner is honoured — and a refusal
// that reads as a bad token sends its holder to debug the wrong thing. ok is
// false for every other reason.
func partnerDenial(reason string) (response commons.Response, ok bool) {
	switch reason {
	case reasonSuspended:
		return commons.Response{
			Code:    "AUT-1009",
			Title:   "Partner Suspended",
			Message: "the partner of this credential is suspended",
		}, true
	case reasonExpired:
		return commons.Response{
			Code:    "AUT-1010",
			Title:   "Partner Outside Its Validity Period",
			Message: "the partner of this credential is outside its validity period",
		}, true
	default:
		return commons.Response{}, false
	}
}

// refusalFor is the error a resolution refuses the request with, or nil when it
// allows it.
func (auth *AuthClient) refusalFor(c fiber.Ctx, resolution authzResolution) error {
	// checkResult, not legacyResult: an Access Manager that never produced an
	// answer must be refused as 503, not rendered as a 403 the caller reads as
	// "you are Forbidden" or a 500 that names the wrong subsystem. Fail-closed
	// is unchanged — the request is still refused — only the word is corrected,
	// which is what puts the outage in the rail's 5xx alarms.
	authorized, statusCode, err := resolution.checkResult()
	if err != nil {
		var commonsErr commons.Response
		if errors.As(err, &commonsErr) {
			return auth.authorizeCommonsRefusal(c, statusCode, commonsErr)
		}

		return auth.authorizeRefusal(c, statusCode, http.StatusText(statusCode))
	}

	if !authorized {
		// The denial reason, not the transport status, picks the word: a
		// credential the authorization service called finished is answered 401
		// so its holder re-issues it, while every other denial stays the 403 it
		// has always been.
		status := denialStatus(resolution.reason)

		if response, ok := partnerDenial(resolution.reason); ok {
			return auth.authorizeCommonsRefusal(c, status, response)
		}

		if response, ok := actorDenial(resolution.reason); ok {
			return auth.authorizeCommonsRefusal(c, status, response)
		}

		return auth.authorizeRefusal(c, status, http.StatusText(status))
	}

	return nil
}

func (auth *AuthClient) authorizeRefusal(_ fiber.Ctx, status int, message string) error {
	return fiber.NewError(status, message)
}

func (auth *AuthClient) authorizeCommonsRefusal(_ fiber.Ctx, status int, response commons.Response) error {
	return accessManagerRefusal{
		fiberErr: fiber.NewError(status, refusalMessage(response, status)),
		response: response,
	}
}

type accessManagerRefusal struct {
	fiberErr *fiber.Error
	response commons.Response
}

func (e accessManagerRefusal) Error() string { return e.fiberErr.Error() }

func (e accessManagerRefusal) Unwrap() []error { return []error{e.fiberErr, e.response} }

// TokenRefusal is the error GetApplicationToken returns when the token request
// is answered with a non-2xx status. It unwraps to the Response the service sent.
type TokenRefusal struct {
	StatusCode int
	Response   commons.Response
}

func (e TokenRefusal) Error() string { return e.Response.Error() }

func (e TokenRefusal) Unwrap() error { return e.Response }

// refusalMessage is the text a decoded Access Manager error renders as: its
// business message, else its title, else the status text. A body carrying only a
// code has an empty Message, and falling through to the status text keeps such a
// refusal from rendering an empty response.
func refusalMessage(response commons.Response, statusCode int) string {
	if response.Message != "" {
		return response.Message
	}

	if response.Title != "" {
		return response.Title
	}

	return http.StatusText(statusCode)
}

// accessManagerRefusalFrom builds the error a non-2xx Access Manager answer
// surfaces as. The STATUS is what makes the answer a refusal; the body only
// supplies the reason, so a body that is empty, carries no domain code, or is not
// JSON at all costs the caller the reason text and never the refusal itself. The
// message is always non-empty, so a caller that logs the error never logs a blank
// line.
func accessManagerRefusalFrom(statusCode int, body []byte) commons.Response {
	response, err := unmarshalErrorResponse(body)
	if err != nil {
		response = commons.Response{}
	}

	response.Message = refusalMessage(response, statusCode)

	return response
}
