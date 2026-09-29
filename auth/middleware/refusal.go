package middleware

import (
	"net/http"

	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/gofiber/fiber/v3"
)

// RefusalError is why an authorization middleware refused a request: the status
// to answer with and the message to render. AuthorizeHTTP hands it to the
// HTTPErrorHandler; the Fiber Authorize returns the same refusal as a
// *fiber.Error, with the same status and message.
type RefusalError struct {
	// Status is the HTTP status the caller must be answered with: 401, 403, 503,
	// or the status the Access Manager itself refused with.
	Status int
	// Message is the text to render: the status text, "Missing Token", or the
	// reason the Access Manager wrote.
	Message string
	// Response is the Access Manager's decoded refusal body when it sent one, else
	// nil. It is also reachable with errors.As into a commons.Response.
	Response *commons.Response
}

// Error returns the message, as a *fiber.Error does. A nil receiver is safe.
func (e *RefusalError) Error() string {
	if e == nil {
		return ""
	}

	return e.Message
}

// Unwrap returns the Access Manager's refusal, so errors.As into a
// commons.Response recovers it exactly as it does on the Fiber path. It is nil
// when the refusal was decided locally. A nil receiver is safe.
func (e *RefusalError) Unwrap() error {
	if e == nil || e.Response == nil {
		return nil
	}

	return *e.Response
}

// newRefusal is a locally decided refusal.
func newRefusal(status int, message string) *RefusalError {
	return &RefusalError{Status: status, Message: message}
}

// statusRefusal is a locally decided refusal rendered as the status text.
func statusRefusal(status int) *RefusalError {
	return newRefusal(status, http.StatusText(status))
}

// accessManagerRefusalAt is the Access Manager's own refusal, kept at the status it
// answered and rendered as the reason it wrote.
func accessManagerRefusalAt(status int, response commons.Response) *RefusalError {
	return &RefusalError{Status: status, Message: refusalMessage(response, status), Response: &response}
}

// fiberError is the refusal as the Fiber adapter returns it: a *fiber.Error for
// the application's ErrorHandler, which also unwraps to the Access Manager's
// commons.Response when there is one.
func (e *RefusalError) fiberError() error {
	fe := fiber.NewError(e.Status, e.Message)
	if e.Response == nil {
		return fe
	}

	return accessManagerRefusal{fiberErr: fe, response: *e.Response}
}

type accessManagerRefusal struct {
	fiberErr *fiber.Error
	response commons.Response
}

func (e accessManagerRefusal) Error() string { return e.fiberErr.Error() }

func (e accessManagerRefusal) Unwrap() []error { return []error{e.fiberErr, e.response} }

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
