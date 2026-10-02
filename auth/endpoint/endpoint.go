// Package endpoint holds the one rule this library applies when a consumer asks
// that every outbound call to the Access Manager or the identity provider travel
// over TLS: the address must be an absolute https URL with a host.
//
// It imports the standard library only. It never reads the environment and never
// decides a posture: whether https is required is the consumer's call, made in
// code (see middleware.WithRequireHTTPS, middleware.JWKSConfig.RequireHTTPS,
// declaration.Config.RequireHTTPS and declaration.WireInput.RequireHTTPS). A
// consumer that runs a development posture simply leaves the requirement off.
package endpoint

import (
	"errors"
	"fmt"
	"net/url"
)

// ErrInsecure is the sentinel every refusal matches with errors.Is, whatever the
// component and the reason.
var ErrInsecure = errors.New("lib-auth: access manager address must be https")

// Reasons an address is refused. They are the values of InsecureError.Reason.
const (
	// ReasonPlaintextHTTP is an http address, in any letter case.
	ReasonPlaintextHTTP = "plaintext http"
	// ReasonMissingScheme is an address with no scheme at all ("am.example",
	// "//am.example", "").
	ReasonMissingScheme = "missing scheme"
	// ReasonUnsupportedScheme is any scheme other than http or https ("ws",
	// "grpc", "unix"); "am.example:8443" lands here too, because it parses as
	// scheme "am.example".
	ReasonUnsupportedScheme = "unsupported scheme"
	// ReasonMissingHost is an https address with nothing to dial ("https:///v1").
	ReasonMissingHost = "missing host"
	// ReasonUnparseable is an address url.Parse refuses.
	ReasonUnparseable = "unparseable"
)

// InsecureError reports an address refused because https is required. It
// matches ErrInsecure with errors.Is.
type InsecureError struct {
	// Component names the part of the library that refused the address:
	// "authorization client", "declaration publisher" or "jwks key source".
	Component string
	// Address is the refused address with any userinfo password masked
	// (url.URL.Redacted). It is empty when the address did not parse, because an
	// unparseable string cannot be redacted and is never echoed.
	Address string
	// Scheme is the parsed, lowercased scheme; empty when there is none.
	Scheme string
	// Reason is one of the Reason* constants.
	Reason string
}

// Error names the component, the redacted address and the reason, and says how
// the requirement is meant to be lifted. A nil receiver yields ErrInsecure's text.
func (e *InsecureError) Error() string {
	if e == nil {
		return ErrInsecure.Error()
	}

	address := e.Address
	if address == "" {
		address = "(not shown)"
	}

	detail := e.Reason
	if e.Reason == ReasonUnsupportedScheme && e.Scheme != "" {
		detail = fmt.Sprintf("%s %q", e.Reason, e.Scheme)
	}

	return fmt.Sprintf("%s: %s address %q refused (%s); use an https address, or set the https requirement off only in a development posture",
		ErrInsecure.Error(), e.Component, address, detail)
}

// Is reports whether target is ErrInsecure, so errors.Is(err, ErrInsecure)
// holds for every refusal however it was wrapped.
func (e *InsecureError) Is(target error) bool {
	return target == ErrInsecure
}

// RequireHTTPS returns nil when raw parses as a URL whose scheme is https (in any
// letter case) and whose host is not empty; otherwise it returns an
// *InsecureError naming component.
//
// raw is validated exactly as it will be dialled: it is not trimmed, so an
// address carrying stray whitespace is refused here instead of being cleaned up
// into something the caller never configured.
func RequireHTTPS(component, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return &InsecureError{Component: component, Reason: ReasonUnparseable}
	}

	refuse := func(reason string) error {
		return &InsecureError{Component: component, Address: u.Redacted(), Scheme: u.Scheme, Reason: reason}
	}

	switch u.Scheme {
	case "https":
		if u.Hostname() == "" {
			return refuse(ReasonMissingHost)
		}

		return nil
	case "http":
		return refuse(ReasonPlaintextHTTP)
	case "":
		return refuse(ReasonMissingScheme)
	default:
		return refuse(ReasonUnsupportedScheme)
	}
}
