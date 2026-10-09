package middleware

import (
	"strings"

	"github.com/LerianStudio/lib-commons/v7/commons"
	"github.com/LerianStudio/lib-commons/v7/commons/net/http/actor"
	"github.com/gofiber/fiber/v3"
)

// A partner's request to one product may make that product call another Lerian
// product to serve it. The partner's own bearer travels along as the "actor":
// the receiving product's authorization asks the access manager to decide the
// partner's rules for that product too, on top of the calling service's own.
//
// This file holds the three places lib-auth takes part: publishing the actor of
// an authorized request (inbound), forwarding a relayed actor to the access
// manager (decision), and naming a denial the actor caused.

// actorReasonPrefix starts every denial reason the access manager publishes for
// the actor rather than for the caller.
const actorReasonPrefix = "actor_"

// Denial reasons the access manager publishes for the actor.
const (
	reasonActorTenant    = "actor_tenant"
	reasonActorSuspended = "actor_suspended"
	reasonActorExpired   = "actor_expired"
	reasonActorInvalid   = "actor_invalid"
)

// publishActor stores the actor of an authorized request on its context, so
// the service's outbound clients relay it (see actor.NewTransport). A
// partner-bound credential is its own actor: its raw bearer. An application
// caller relaying a partner passes on the actor it relayed, which the access
// manager has just decided along with the caller, so the next hop can relay it
// again. A user, or an application relaying no one, leaves nothing there.
func publishActor(c fiber.Ctx, caller authzCaller, accessToken, relayed string) {
	token := accessToken

	switch {
	case caller.partner != "":
	case caller.relays(relayed):
		token = relayed
	default:
		return
	}

	c.SetContext(actor.ContextWithToken(c.Context(), token))
}

// relayedActor is the actor the request carries in actor.HeaderName, verbatim,
// or "" when it carries none (the HTTP layer already strips a value's
// surrounding whitespace, so a blank header reads as none).
func relayedActor(c fiber.Ctx) string {
	return c.Get(actor.HeaderName)
}

// forwardsActor reports whether a relayed actor is part of the caller's
// question. Only a plain application (M2M) credential speaks on a partner's
// behalf: a partner is decided as itself and a user is never a relay, so for
// them the header is ignored and the question is the one they always made.
func (c authzCaller) forwardsActor() bool {
	return c.principal.Type == application && c.partner == ""
}

// relays reports whether the request is asked for the relayed actor too.
func (c authzCaller) relays(relayed string) bool {
	return relayed != "" && c.forwardsActor()
}

// asksAsPartner reports whether the question carries what a partner's does —
// the product and the instances the request names — because a partner is
// decided on it: the caller itself, or the actor it relays. Without them the
// access manager cannot tell which of the actor's rules apply, and a partner
// asked about no product is not checked at all (opt-in).
func (c authzCaller) asksAsPartner(relayed string) bool {
	return c.partner != "" || c.relays(relayed)
}

// actorDenial is the refusal a denial the actor caused is answered with: the
// 403 every denial is, carrying a code that names the partner the request was
// made for as the cause, so the calling service can tell its partner why
// instead of reading a refusal of its own credential. Permission and scope are
// not told apart, as for a direct partner call; a reason this version does not
// know is answered as a permission denial. ok is false for a reason that is
// not the actor's.
func actorDenial(reason string) (response commons.Response, ok bool) {
	if !strings.HasPrefix(reason, actorReasonPrefix) {
		return commons.Response{}, false
	}

	switch reason {
	case reasonActorTenant:
		return commons.Response{
			Code:    "AUT-1016",
			Title:   "Partner Of Another Tenant",
			Message: "the partner this request was made on behalf of belongs to another tenant",
		}, true
	case reasonActorSuspended:
		return commons.Response{
			Code:    "AUT-1017",
			Title:   "Partner Suspended",
			Message: "the partner this request was made on behalf of is suspended",
		}, true
	case reasonActorExpired, reasonActorInvalid:
		return commons.Response{
			Code:    "AUT-1018",
			Title:   "Partner Credential No Longer Valid",
			Message: "the partner this request was made on behalf of is outside its validity period or its credential is no longer valid",
		}, true
	default:
		return commons.Response{
			Code:    "AUT-1019",
			Title:   "Partner Not Allowed",
			Message: "the partner this request was made on behalf of is not allowed to perform it",
		}, true
	}
}
