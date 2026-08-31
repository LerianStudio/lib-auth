package middleware

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/LerianStudio/lib-auth/v3/auth/obs"
	"github.com/gofiber/fiber/v3"
)

// Minimum trusted-proxy prefix lengths. Trusting a maximally-permissive range
// (0.0.0.0/0, ::/0) makes EVERY hop a trusted proxy, so the walk below discards
// the whole chain and no caller IP is ever attributable — IP policy can then
// never be applied to a real caller again. That can only be a misconfiguration,
// so such a range is dropped at construction (loudly) instead of silently
// disabling IP policy. The
// thresholds allow realistic proxy subnets (a /8 corp range, a /48 IPv6 site)
// while rejecting the catch-all end of the spectrum. Mirrors
// plugin-access-manager's pkg/nettrust.
const (
	// minIPv4PrefixBits rejects IPv4 prefixes broader than /8 (i.e. /0-/7).
	minIPv4PrefixBits = 8
	// minIPv6PrefixBits rejects IPv6 prefixes broader than /48 (i.e. /0-/47).
	minIPv6PrefixBits = 48
	// v4MappedPrefixBits is the length of the IPv4-mapped IPv6 block,
	// ::ffff:0:0/96. A prefix written on a mapped address denotes an IPv4 range
	// only if it is at least this long, i.e. only if the whole prefix lies inside
	// that block; the bits past it are the IPv4 prefix length.
	v4MappedPrefixBits = 96
)

// exampleIPv4Entry is the entry diagnostics point at when they have no address
// of the operator's own to build a correction from. It is a constant rather
// than a literal repeated per message so there is one thing for a test to run
// through acceptTrustedProxy — a hardcoded example is exactly the kind of
// suggestion that goes stale silently when a floor moves.
const exampleIPv4Entry = "10.0.0.0/8"

// trustedProxiesEnv is the platform-wide variable naming the proxy CIDRs whose
// forwarded hop may be believed. The SAME name is already read by
// plugin-access-manager and flowker and already provisioned in gitops, so a
// service adopting this library inherits the operator's existing value. Do not
// rename it, and do not confuse it with TRUSTED_PROXY_CIDRS (tracer's audit
// trail — an unrelated variable).
const trustedProxiesEnv = "TRUSTED_PROXIES"

// forwardedHeader is the hop-by-hop chain this library reads. It is fixed here
// rather than taken from the consuming service's Fiber ProxyHeader, for the same
// reason the chain is tokenised here: what this library attributes must not move
// with the embedding service's configuration.
const forwardedHeader = fiber.HeaderXForwardedFor

// loadTrustedProxies reads the trusted-proxy CIDR allowlist from the
// environment at construction. An unset or empty value yields NO trusted
// proxies, which makes every resolved client IP empty — see resolveClientIP for
// why that is deliberate and must not be "fixed" into a socket-peer fallback.
//
// It NEVER fails the boot: there is no Fatal, no panic and no error return
// anywhere on this path. Absent, empty or entirely-unusable configuration
// leaves the service running and forwarding no address, which the authorization
// service handles under its own policy rather than erroring. What this function
// does instead is make that degradation observable — ONE log line, at
// construction, naming both the cause and the consequence, so an operator learns
// it from the boot log rather than from a surprise verdict in production. It is
// not logged per request: the value is read once here and cached on the client.
func loadTrustedProxies(logger obs.Logger) []netip.Prefix {
	raw := os.Getenv(trustedProxiesEnv)

	prefixes := parseTrustedProxies(raw, logger)
	if len(prefixes) > 0 {
		return prefixes
	}

	// Same consequence either way; the cause differs, and the cause is what
	// tells the operator whether to add the variable or fix its value.
	cause := trustedProxiesEnv + " is not set"
	if strings.TrimSpace(raw) != "" {
		cause = trustedProxiesEnv + " has no usable CIDR (every entry was dropped, see the errors above)"
	}

	logErrorf(context.Background(), logger,
		"%s; client IP will not be forwarded and the per-tenant IP allowlist has nothing to match the caller against", cause)

	return nil
}

// parseTrustedProxies parses a comma-separated CIDR list into prefixes. It is
// deliberately non-fatal: NewAuthClient has no error return (the whole library
// is constructed from env at boot), so an unusable entry is logged at ERROR and
// DROPPED while the valid entries stand. Dropping is the fail-closed direction
// here — a smaller trusted set can only shorten the walk, never widen who is
// believed.
//
// A bare address ("10.0.0.1") is rejected, not silently widened to a host
// prefix: an operator who meant a range must say so. Entries are stored masked
// so an unmasked prefix ("10.1.2.3/8") matches the same set as its canonical
// form, and stored in the same address form the hop walk compares against — see
// rebaseMappedPrefix for why a range written in IPv4-mapped IPv6 form is
// rewritten rather than kept as written.
func parseTrustedProxies(raw string, logger obs.Logger) []netip.Prefix {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	tokens := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(tokens))

	for _, token := range tokens {
		entry := strings.TrimSpace(token)
		if entry == "" {
			continue
		}

		prefix, ok := acceptTrustedProxy(entry)
		if !ok {
			logRejectedEntry(logger, entry)

			continue
		}

		prefixes = append(prefixes, prefix)
	}

	if len(prefixes) == 0 {
		return nil
	}

	return prefixes
}

// acceptTrustedProxy is THE acceptance path: everything an entry must survive to
// become a trusted prefix — parsing, IPv4-mapped rebasing and the breadth floor
// — and nothing else. It returns the prefix in the exact form the list stores.
//
// It is a separate function from the loop above for one reason: a diagnostic
// that suggests a correction has to put that suggestion through the SAME
// checks the operator's retyped entry would face, and it cannot do so by
// calling parseTrustedProxies (which logs, and whose logging is what would need
// checking). Everything acceptance-related lives here, so "what the parser
// accepts" and "what a suggestion is checked against" cannot drift apart —
// there is only one of them.
//
// It logs nothing and explains nothing. That silence is what makes it safe to
// call from inside a diagnostic: validating a suggestion can never itself
// produce a suggestion needing validation.
func acceptTrustedProxy(entry string) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(entry))
	if err != nil {
		return netip.Prefix{}, false
	}

	prefix, ok := rebaseMappedPrefix(prefix)
	if !ok {
		return netip.Prefix{}, false
	}

	if prefix.Bits() < minPrefixBits(prefix.Addr()) {
		return netip.Prefix{}, false
	}

	return prefix.Masked(), true
}

// logRejectedEntry emits the one ERROR line for an entry acceptTrustedProxy
// refused, naming the rule that refused it. It re-walks the same checks in the
// same order purely to explain them — the decision was already made — which is
// the same shape describeParseFailure uses against netip's own parser.
//
// The final branch names the breadth floor, so it asserts the floor is what
// actually fired rather than assuming it. If acceptTrustedProxy ever grows a
// fourth rule, an entry refused by that rule degrades to a vague line instead
// of being told, confidently, to fix a width that was never the problem.
func logRejectedEntry(logger obs.Logger, entry string) {
	ctx := context.Background()

	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		logErrorf(ctx, logger,
			"invalid %s entry %q, dropped (%s): %v", trustedProxiesEnv, entry, describeParseFailure(entry), err)

		return
	}

	rebased, ok := rebaseMappedPrefix(prefix)
	if !ok {
		logErrorf(ctx, logger,
			"invalid %s entry %q, dropped (an IPv4-mapped address only denotes an IPv4 range from /%d onwards; write the range in IPv4 form, e.g. %s)",
			trustedProxiesEnv, entry, v4MappedPrefixBits, exampleIPv4Entry)

		return
	}

	if minBits := minPrefixBits(rebased.Addr()); rebased.Bits() < minBits {
		logErrorf(ctx, logger,
			"%s entry %q is too broad (it covers %s, and a trusted-proxy range must be at least /%d), dropped: trusting it would discard every hop and leave no attributable caller IP",
			trustedProxiesEnv, entry, rebased.Masked(), minBits)

		return
	}

	logErrorf(ctx, logger, "invalid %s entry %q, dropped", trustedProxiesEnv, entry)
}

// describeParseFailure names the rule that rejected entry, phrased as the fix it
// implies. netip.ParsePrefix reports five distinct failures behind one opaque
// error type, and one of them ("no '/'") covers two entries an operator has to
// fix in opposite ways: 10.0.0.1 is an address missing its length, while
// not-an-ip is not an address at all. A single message for all of them tells the
// operator to add a mask to an entry that already carries one, or to a token
// that could never carry one.
//
// It re-walks the parser's own decisions in the parser's own order, so the
// branch reached here is the branch that fired there. The final fallback is
// therefore unreachable in practice and kept only so a future parser change
// degrades to a vague message rather than a wrong one; the parser's error is
// appended to the log line either way.
func describeParseFailure(entry string) string {
	slash := strings.LastIndexByte(entry, '/')
	if slash < 0 {
		addr, err := netip.ParseAddr(entry)

		switch {
		case err != nil:
			return "it is not an IP address at all; write an address and a prefix length, e.g. " + exampleIPv4Entry
		case addr.Zone() != "":
			return describeBareZone(addr)
		default:
			return "a bare address is not a range; " +
				suggestEntry("add a prefix length, e.g. %s", addr, addr.BitLen())
		}
	}

	addr, err := netip.ParseAddr(entry[:slash])
	if err != nil {
		return fmt.Sprintf("the address before the '/' (%q) is not an IP address", entry[:slash])
	}

	if addr.Zone() != "" {
		return describeZonedPrefix(addr, entry[slash+1:])
	}

	bits := entry[slash+1:]

	length, readable := readPrefixLength(bits)

	switch {
	case !readable:
		return fmt.Sprintf("the prefix length after the '/' (%q) is not a plain number of bits", bits)
	case length > addr.BitLen():
		return fmt.Sprintf("a prefix length of /%d is out of range for an IPv%d address (the maximum is /%d)",
			length, addrFamily(addr), addr.BitLen())
	}

	return "it is not a CIDR range"
}

// readPrefixLength returns the bit count written after the '/', and whether the
// parser can read it at all: it accepts only a plain decimal count — no sign, no
// leading zero, no empty string. Anything else never reaches its range check, so
// it must not be reported as a range problem. Whether a readable count FITS the
// address is a separate question, left to the caller, because the two failures
// send an operator in different directions.
//
// It is shared with the zoned-address path, which has to answer the same
// question about the same text to decide whether the length is worth preserving
// in the correction it prints. Two copies of this rule would let the message and
// the parser disagree about what a length is.
func readPrefixLength(bits string) (int, bool) {
	length, err := strconv.Atoi(bits)
	if err != nil || bits == "" || (len(bits) > 1 && (bits[0] < '1' || bits[0] > '9')) {
		return 0, false
	}

	return length, true
}

// suggestEntry is the ONE place a diagnostic turns an address and a prefix
// length into an entry it tells the operator to write. offer is the clause the
// entry is rendered into and must carry exactly one %s.
//
// It emits the entry only if acceptTrustedProxy accepts it — the same path the
// retyped entry would take in parseTrustedProxies, so a suggestion is checked
// against the rules that will actually judge it rather than against the one
// rule the message happens to be about. Every previous round of this defect had
// the same shape: a message fixed the rule in front of it and printed a value
// the NEXT rule drops, sending the operator from one rejection to another.
//
// When the entry is refused, refuseSuggestion replaces the whole offer: naming
// a value the library will not take is worse than naming none, and the caller's
// lead-in prose ("keeping the length you gave") would be a lie about a length
// that cannot be kept.
//
// Nothing on this path logs, and nothing on it re-enters the diagnostics, so a
// suggestion can never need a suggestion of its own.
func suggestEntry(offer string, addr netip.Addr, bits int) string {
	entry := fmt.Sprintf("%s/%d", addr, bits)
	if _, ok := acceptTrustedProxy(entry); ok {
		return fmt.Sprintf(offer, entry)
	}

	return refuseSuggestion(addr, bits)
}

// refuseSuggestion explains why the entry the operator's own address and length
// would form is not one the library takes, and names one that is.
//
// It says which rule refuses it, in the rule's own terms — the breadth floor
// that applies AFTER any IPv4-mapped rebasing, because that is the floor that
// governs the entry even when the length written is an IPv6 one (a mapped /100
// is an IPv4 /4). It deliberately does NOT print the refused entry: the whole
// point of the check above is that this value must not reach the operator as
// something to type.
//
// The example is built from the operator's own address masked to that floor,
// so it is the closest accepted range to what they asked for rather than a
// literal from somewhere else. It is put through acceptTrustedProxy too — it
// cannot fail by construction, and checking anyway is what keeps "no diagnostic
// prints a refused entry" true without depending on that reasoning staying
// true.
func refuseSuggestion(addr netip.Addr, bits int) string {
	base := addr.Unmap().WithZone("")
	floor := minPrefixBits(base)

	reason := fmt.Sprintf("a length of /%d is below the minimum for a trusted-proxy range (/%d)", bits, floor)

	switch {
	case addr.Is4In6() && bits < v4MappedPrefixBits:
		reason = fmt.Sprintf("a length of /%d denotes no IPv4 range at all (on an IPv4-mapped address a prefix only denotes one from /%d onwards)",
			bits, v4MappedPrefixBits)
	case addr.Is4In6():
		reason = fmt.Sprintf("a length of /%d denotes an IPv4 /%d, which is below the minimum for a trusted-proxy range (/%d)",
			bits, bits-v4MappedPrefixBits, floor)
	}

	example := netip.PrefixFrom(base, floor).Masked()
	if _, ok := acceptTrustedProxy(example.String()); !ok {
		return reason + "; write the range on the unzoned address with an accepted length"
	}

	return fmt.Sprintf("%s; write the range on the unzoned address with an accepted length (%s)", reason, example)
}

// describeBareZone reports a zone on an entry that carried no prefix length at
// all (fe80::1%eth0), which a prefix may never carry: a zone names one host's
// link, so it cannot describe a range of proxies.
//
// The correction it prints has to PARSE, and then survive every other rule. Two
// things it could plausibly print do not: the unzoned address alone lands on
// "no '/'", and a length the library refuses lands on the breadth floor. So the
// entry goes through suggestEntry, which supplies the address's own bit count —
// what a single address means as a range, and the only length that can be
// supplied here without inventing a wider one than was asked for.
func describeBareZone(addr netip.Addr) string {
	unzoned := addr.WithZone("")

	return fmt.Sprintf("an IPv6 zone (%q) cannot appear in a range; %s", addr.Zone(),
		suggestEntry("write the range on the unzoned address, with a prefix length (%s)", unzoned, unzoned.BitLen()))
}

// describeZonedPrefix reports a zone sitting in the address half of a prefix the
// operator did write a length for (fe80::1%eth0/64), and PRESERVES that length in
// the correction. They said how wide they wanted the range; answering with the
// address's own bit count would silently narrow it to one host, and answering
// with anything else would invent a width.
//
// A length is only preserved if the parser could use it. The zone is rejected
// BEFORE the length is ever read — netip reports the zone for fe80::1%eth0/999
// just as it does for /64 — so an unusable length reaches here unexamined, and
// echoing it back would print a correction that fails to parse, which is the
// defect this whole path exists to avoid. When that happens the line says the
// length is unusable too, and falls back to the address's own bit count so the
// suggestion still parses.
//
// "Usable" here means readable and in range for the family; whether the length
// is one the library will TAKE is a wider question, and not one this function
// answers. A readable, in-range /0 is preserved and handed to suggestEntry,
// which refuses it against the breadth floor and says so. Keeping that
// judgement in one place is the point: this function knows about zones.
func describeZonedPrefix(addr netip.Addr, bits string) string {
	unzoned := addr.WithZone("")

	length, readable := readPrefixLength(bits)
	if !readable || length > unzoned.BitLen() {
		return fmt.Sprintf("an IPv6 zone (%q) cannot appear in a range, and the prefix length after the '/' (%q) is not usable either; %s",
			addr.Zone(), bits,
			suggestEntry("write the range on the unzoned address (%s)", unzoned, unzoned.BitLen()))
	}

	return fmt.Sprintf("an IPv6 zone (%q) cannot appear in a range; %s", addr.Zone(),
		suggestEntry("write the range on the unzoned address, keeping the length you gave (%s)", unzoned, length))
}

// addrFamily returns 4 or 6 for use in operator-facing prose. An IPv4-mapped
// address reports 6 on purpose: 128 bits are what its prefix length is measured
// against, so saying otherwise would contradict the maximum quoted beside it.
func addrFamily(addr netip.Addr) int {
	if addr.Is4() {
		return 4
	}

	return 6
}

// rebaseMappedPrefix rewrites a trusted-proxy prefix written in IPv4-mapped
// IPv6 form (::ffff:10.0.0.0/104) into the plain IPv4 prefix it denotes
// (10.0.0.0/8), and reports whether the entry is usable at all.
//
// The list has to be held in the same address form the walk compares against.
// firstUntrustedHop unmaps every hop, and no IPv6 prefix can contain an
// unmapped IPv4 address, so an entry left in the mapped form would parse, pass
// every check, be stored — and match nothing. That is worse than a rejected
// entry: the proxy is then never recognised as one, the walk stops at it, and
// the proxy's own address is handed on as the caller. The library normalises
// hops, so it normalises the list the same way.
//
// netip has no single call for this. Addr().Unmap() yields the IPv4 address but
// Bits() still counts the 96 bits of the mapping, so the length is rebased
// explicitly, and only for a prefix that lies entirely inside the mapped block.
// Below that boundary the prefix spans addresses outside the mapping and
// denotes no IPv4 range at all (::ffff:10.0.0.0/95 masks to ::fffe:0:0/95);
// there is nothing to rebase it to, so it is reported unusable and the caller
// drops it rather than storing something inert.
//
// Rebasing happens BEFORE the minimum-length check on purpose, so the floor is
// applied to the IPv4 length that actually governs matching and rebasing can
// never widen what the list trusts: /104 becomes /8 and is accepted, /100
// becomes /4 and is rejected exactly as a plainly-written 10.0.0.0/4 would be.
func rebaseMappedPrefix(p netip.Prefix) (netip.Prefix, bool) {
	if !p.Addr().Is4In6() {
		return p, true
	}

	if p.Bits() < v4MappedPrefixBits {
		return netip.Prefix{}, false
	}

	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-v4MappedPrefixBits), true
}

// minPrefixBits returns the narrowest prefix length accepted for addr's family.
// It is asked about the REBASED address, so a range written in IPv4-mapped form
// is measured against the IPv4 floor that governs it — and refuseSuggestion asks
// the same function, so the floor a diagnostic names is the floor that refused
// the entry rather than a second copy of the rule.
func minPrefixBits(addr netip.Addr) int {
	if addr.Is4() {
		return minIPv4PrefixBits
	}

	return minIPv6PrefixBits
}

// resolveClientIP derives the caller IP that IP-based policy is applied to,
// WITHOUT depending on the consuming service's Fiber configuration.
//
// It cannot depend on it: the service builds the fiber.App, and Fiber only
// walks the forwarded chain right-to-left when TrustProxy, TrustProxyConfig,
// ProxyHeader AND EnableIPValidation are all set. Miss the last one and c.IP()
// returns the raw header — a value the caller supplies about itself. So this
// library derives the IP from its own TRUSTED_PROXIES list instead, over a chain
// it reads and splits itself (see forwardedHops).
//
// With no trusted proxies configured it returns "" and NO IP is forwarded. That
// is a deliberate product decision, not an oversight: falling back to the socket
// peer would forward the ingress address, and a tenant that happens to have the
// ingress CIDR in its allow list would get a FALSE ALLOW for every caller on
// earth. An empty value can never match an allow list by accident.
//
// What it CANNOT do is decide the request, and it must not be read as harmless.
// Omitting the field hands the decision to the authorization service, whose
// policy for an addressless request is conditional: as of 2026-08-23, a tenant
// with an active allowlist DENIES unless that service recognises the caller as
// one of the platform's own. An empty result is therefore a real outcome, not a
// no-op — see the README's client-IP section, and that service's own
// IP-allowlist operations documentation, which is the authority. This comment is
// a copy with a date on it precisely because the rule lives elsewhere and has
// already moved twice.
func (auth *AuthClient) resolveClientIP(c fiber.Ctx) string {
	if len(auth.trustedProxies) == 0 {
		return ""
	}

	// The socket peer is ground truth (nothing the caller writes can change it)
	// and therefore anchors the walk as the rightmost hop; the forwarded header
	// is only believed to the extent trusted proxies wrote it. Without a peer
	// there is no anchor, so nothing in the header can be trusted.
	reqCtx := c.RequestCtx()
	if reqCtx == nil {
		return ""
	}

	peer := reqCtx.RemoteIP()
	if peer == nil {
		return ""
	}

	forwarded := forwardedHops(c)

	hops := make([]string, 0, len(forwarded)+1)
	hops = append(hops, forwarded...)
	hops = append(hops, peer.String())

	return firstUntrustedHop(hops, auth.trustedProxies)
}

// forwardedHops reads the forwarded chain off the request and splits it here,
// deliberately in place of c.IPs().
//
// c.IPs() reads the same header, but filters it through the embedding service's
// app config first: with EnableIPValidation set, Fiber DROPS every token it does
// not recognise as an address before this library ever sees the chain. Dropping
// a token splices the chain — the hops on either side of the hole become
// adjacent — so the guard in firstUntrustedHop, whose whole job is to stop at a
// hop that cannot be shown to be a proxy, never fires, and the walk carries on
// left past the point where it had to stop. The same request would then attribute
// a different caller depending only on a flag set by whoever embeds the library.
// So the derivation reads the bytes.
//
// Every comma-separated position is one hop, surrounding whitespace trimmed,
// EMPTY POSITIONS KEPT. An empty position is a hop this library cannot vouch for,
// and the guard is entitled to treat it like any other unreadable one; skipping
// it would splice the chain in exactly the way described above. Keeping it costs
// nothing where it cannot matter: the walk only ever reaches an empty position
// when every hop to its right is a trusted proxy, i.e. when that position is
// where the caller would have been named.
//
// All X-Forwarded-For lines are read and concatenated in order, not just the
// first. Repeated field lines are equivalent to one comma-joined value
// (RFC 9110 §5.2), and a proxy appending its own line rather than extending the
// existing one is ordinary behaviour. Reading only the first — what a single
// header peek returns — would drop the rightmost, most trustworthy hops and let
// the walk stop somewhere further left, crediting caller-supplied text in place
// of a hop that a trusted proxy actually wrote.
func forwardedHops(c fiber.Ctx) []string {
	values := c.Request().Header.PeekAll(forwardedHeader)
	if len(values) == 0 {
		return nil
	}

	hops := make([]string, 0, len(values))

	for _, value := range values {
		for _, token := range strings.Split(string(value), ",") {
			hops = append(hops, strings.TrimSpace(token))
		}
	}

	return hops
}

// firstUntrustedHop walks hops from right (closest to us, most trustworthy) to
// left (furthest away, least trustworthy), discarding hops that are trusted
// proxies, and returns the first hop that is not one — the caller. It returns ""
// when every hop is a trusted proxy (fully-internal traffic: no caller IP is
// attributable) and when no proxy is trusted at all.
//
// A hop that does not parse as a bare IP stops the walk with "": it cannot be
// shown to be a trusted proxy, so nothing further left may be credited, and the
// unparseable token itself must never be handed on as an "IP". Addresses are
// unmapped and de-zoned first, so an IPv4-mapped IPv6 hop (::ffff:10.0.0.1,
// what a dual-stack listener reports) still matches an IPv4 CIDR and is
// normalised to the form an allow list stores.
func firstUntrustedHop(hops []string, trusted []netip.Prefix) string {
	if len(trusted) == 0 {
		return ""
	}

	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ""
		}

		addr = addr.Unmap().WithZone("")

		if isTrustedProxy(addr, trusted) {
			continue
		}

		return addr.String()
	}

	return ""
}

// isTrustedProxy reports whether addr falls inside any trusted CIDR.
func isTrustedProxy(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
