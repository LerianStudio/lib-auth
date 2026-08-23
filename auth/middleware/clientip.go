package middleware

import (
	"context"
	"net/netip"
	"os"
	"strings"

	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/gofiber/fiber/v3"
)

// Minimum trusted-proxy prefix lengths. Trusting a maximally-permissive range
// (0.0.0.0/0, ::/0) makes EVERY hop a trusted proxy, so the walk below discards
// the whole chain and no caller IP is ever attributable — every IP-policy
// request then denies. That can only be a misconfiguration, so such a range is
// dropped at construction (loudly) instead of silently disabling IP policy. The
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

// trustedProxiesEnv is the platform-wide variable naming the proxy CIDRs whose
// forwarded hop may be believed. The SAME name is already read by
// plugin-access-manager and flowker and already provisioned in gitops, so a
// service adopting this library inherits the operator's existing value. Do not
// rename it, and do not confuse it with TRUSTED_PROXY_CIDRS (tracer's audit
// trail — an unrelated variable).
const trustedProxiesEnv = "TRUSTED_PROXIES"

// loadTrustedProxies reads the trusted-proxy CIDR allowlist from the
// environment at construction. An unset or empty value yields NO trusted
// proxies, which makes every resolved client IP empty — see resolveClientIP for
// why that is deliberate and must not be "fixed" into a socket-peer fallback.
//
// It NEVER fails the boot: there is no Fatal, no panic and no error return
// anywhere on this path. Absent, empty or entirely-unusable configuration
// leaves the service running with IP policy inert, which the access manager
// already absorbs. What it does instead is make that degradation observable —
// ONE log line, at construction, naming both the cause and the consequence, so
// an operator learns it from the boot log rather than from a 403. It is not
// logged per request: the value is read once here and cached on the client.
func loadTrustedProxies(logger log.Logger) []netip.Prefix {
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
		"%s; client IP will not be forwarded and the per-tenant IP allowlist will not enforce", cause)

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
func parseTrustedProxies(raw string, logger log.Logger) []netip.Prefix {
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

		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			logErrorf(context.Background(), logger,
				"invalid %s entry %q, dropped (a bare address is not a CIDR): %v", trustedProxiesEnv, entry, err)

			continue
		}

		prefix, ok := rebaseMappedPrefix(prefix)
		if !ok {
			logErrorf(context.Background(), logger,
				"invalid %s entry %q, dropped (an IPv4-mapped address only denotes an IPv4 range from /%d onwards; write the range in IPv4 form, e.g. 10.0.0.0/8)",
				trustedProxiesEnv, entry, v4MappedPrefixBits)

			continue
		}

		if minBits := minPrefixBits(prefix); prefix.Bits() < minBits {
			logErrorf(context.Background(), logger,
				"%s entry %q is too broad (it covers %s, and a trusted-proxy range must be at least /%d), dropped: trusting it would discard every hop and leave no attributable caller IP",
				trustedProxiesEnv, entry, prefix.Masked(), minBits)

			continue
		}

		prefixes = append(prefixes, prefix.Masked())
	}

	if len(prefixes) == 0 {
		return nil
	}

	return prefixes
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

// minPrefixBits returns the narrowest prefix length accepted for the address
// family of p. It is applied to the rebased prefix, so a range written in
// IPv4-mapped form is measured against the IPv4 floor that governs it.
func minPrefixBits(p netip.Prefix) int {
	if p.Addr().Is4() {
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
// library derives the IP from its own TRUSTED_PROXIES list instead.
//
// With no trusted proxies configured it returns "" and NO IP is forwarded. That
// is a deliberate product decision, not an oversight: falling back to the socket
// peer would forward the ingress address, and a tenant that happens to have the
// ingress CIDR in its allow list would get a FALSE ALLOW for every caller on
// earth. An empty value never matches by accident — the auth service treats an
// absent clientIp as deny-missing-ip.
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

	forwarded := c.IPs()

	hops := make([]string, 0, len(forwarded)+1)
	hops = append(hops, forwarded...)
	hops = append(hops, peer.String())

	return firstUntrustedHop(hops, auth.trustedProxies)
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
