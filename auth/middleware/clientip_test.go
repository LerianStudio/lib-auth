package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LerianStudio/lib-observability/v2/log"
	"github.com/gofiber/fiber/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPeerCIDR is the in-memory Fiber test connection's peer address (0.0.0.0)
// as a host CIDR. Listing it as a trusted proxy is what lets a test drive a
// known client IP through the forwarded header deterministically — the same
// role the ingress subnet plays in production.
const testPeerCIDR = "0.0.0.0/32"

// mustPrefixes builds a trusted-proxy list the way production builds it — by
// running the CIDRs through parseTrustedProxies — so no test can be green
// against a list held in a form the parser would never actually store. It fails
// if any entry is dropped, which keeps a fixture typo loud.
func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()

	prefixes := parseTrustedProxies(strings.Join(cidrs, ","), &testLogger{})
	require.Len(t, prefixes, len(cidrs), "every fixture CIDR must survive parsing: %v", cidrs)

	return prefixes
}

// prefixStrings renders prefixes for comparison in table assertions.
func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}

	return out
}

// ---------------------------------------------------------------------------
// parseTrustedProxies (unit)
// ---------------------------------------------------------------------------

// TestParseTrustedProxies pins the TRUSTED_PROXIES parsing contract: a
// comma-separated CIDR list, where a malformed entry is DROPPED (logged, never
// fatal — NewAuthClient has no error return) and a bare address is REJECTED
// rather than silently widened to a /32 or /128. Overly broad ranges are also
// rejected: trusting them makes every hop trusted, which resolves to an empty
// client IP and leaves IP policy with nothing to match any caller against — a
// config that can only be a mistake.
func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty", raw: "", want: nil},
		{name: "whitespace_only", raw: "   \t ", want: nil},
		{name: "single_cidr", raw: "10.0.0.0/8", want: []string{"10.0.0.0/8"}},
		{
			name: "multiple_with_spaces_and_empty_tokens",
			raw:  " 10.0.0.0/8 , ,192.168.0.0/16 ",
			want: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		{
			name: "malformed_entry_is_dropped_valid_kept",
			raw:  "not-an-ip,10.0.0.0/8,10.0.0.0/99",
			want: []string{"10.0.0.0/8"},
		},
		{
			name: "bare_address_is_rejected",
			raw:  "10.0.0.1,192.168.0.0/16",
			want: []string{"192.168.0.0/16"},
		},
		{
			name: "unmasked_prefix_is_normalised",
			raw:  "10.1.2.3/8",
			want: []string{"10.0.0.0/8"},
		},
		{name: "ipv4_catch_all_is_rejected", raw: "0.0.0.0/0", want: nil},
		{name: "ipv4_too_broad_is_rejected", raw: "10.0.0.0/7", want: nil},
		{name: "ipv6_catch_all_is_rejected", raw: "::/0", want: nil},
		{name: "ipv6_too_broad_is_rejected", raw: "2001:db8::/47", want: nil},
		{name: "ipv6_cidr_is_accepted", raw: "2001:db8::/48", want: []string{"2001:db8::/48"}},
		{name: "single_host_cidr_is_accepted", raw: "203.0.113.7/32", want: []string{"203.0.113.7/32"}},
		{
			// An IPv4 range written in IPv4-mapped IPv6 form is rebased to the plain
			// IPv4 prefix it denotes, so it is stored in the form the hop walk
			// compares against instead of a form that can never match.
			name: "v4_mapped_range_is_rebased_to_ipv4",
			raw:  "::ffff:10.0.0.0/104",
			want: []string{"10.0.0.0/8"},
		},
		{
			name: "v4_mapped_range_is_rebased_and_masked",
			raw:  "::ffff:10.1.2.3/104",
			want: []string{"10.0.0.0/8"},
		},
		{
			name: "v4_mapped_host_is_rebased_to_a_32",
			raw:  "::ffff:203.0.113.7/128",
			want: []string{"203.0.113.7/32"},
		},
		{
			// The rebased length is what the floor is applied to, so rebasing can
			// never smuggle a range past a check the IPv4 form would have failed.
			// /104 is exactly the /8 floor and is kept; /103 is a /7 and is not.
			name: "v4_mapped_range_at_the_ipv4_floor_is_accepted",
			raw:  "::ffff:10.0.0.0/104,::ffff:10.0.0.0/103",
			want: []string{"10.0.0.0/8"},
		},
		{
			name: "v4_mapped_range_broader_than_the_ipv4_floor_is_rejected",
			raw:  "::ffff:10.0.0.0/100",
			want: nil,
		},
		{
			// ::ffff:0:0/96 is every IPv4 address there is — the catch-all 0.0.0.0/0
			// wearing a different hat.
			name: "v4_mapped_catch_all_is_rejected",
			raw:  "::ffff:0:0/96",
			want: nil,
		},
		{
			// Below /96 the prefix runs past the start of the mapped block, so it
			// denotes no IPv4 range at all and cannot be rebased. Kept as written it
			// would be stored and match nothing, so it is dropped instead.
			name: "v4_mapped_address_with_a_prefix_shorter_than_the_mapping_is_rejected",
			raw:  "::ffff:10.0.0.0/95",
			want: nil,
		},
		{
			name: "v4_mapped_address_with_an_ipv6_sized_prefix_is_rejected",
			raw:  "::ffff:10.0.0.0/48",
			want: nil,
		},
		{
			// A genuine IPv6 range is untouched by any of the above.
			name: "ipv6_range_near_the_mapped_block_is_kept_as_ipv6",
			raw:  "::fffe:0:0/96",
			want: []string{"::fffe:0:0/96"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := parseTrustedProxies(tt.raw, &testLogger{})
			assert.Equal(t, tt.want, prefixStringsOrNil(got))
		})
	}
}

// prefixStringsOrNil keeps the table's `want: nil` cases comparable.
func prefixStringsOrNil(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}

	return prefixStrings(prefixes)
}

// TestParseTrustedProxies_DroppedEntriesNameTheirReason pins WHICH rule dropped
// an entry, not merely that it was dropped. The rules point an operator in
// different directions: "too broad" says the range covers too much, a v4-mapped
// address carrying a prefix shorter than the mapping denotes no IPv4 range at
// all and has to be rewritten, and an entry the parser rejects is wrong in one
// of several ways that share nothing but the outcome. Reporting one rule's
// wording for another rule's entry sends the operator to fix what is not broken
// — to add a mask to 10.0.0.0/99, which already has one.
//
// Every case therefore asserts on wording only its own cause produces, and the
// wording asserted is this library's, never a substring the parser's own error
// would supply: collapsing these messages into one shared string has to turn the
// whole table red, or it is checking that a message exists rather than that it
// is the right one.
//
// It is also what keeps the /96 boundary honest. Rebasing a shorter prefix
// underflows into an invalid prefix, which the length check then discards on its
// own — the entry disappears either way and only the message shows that the
// arithmetic ran on something it does not apply to.
//
// Where a case names a correction (wantCorrection), the correction is fed back
// through parseTrustedProxies itself and must come out as a trusted prefix. A
// message that names a fix the parser then rejects sends the operator from one
// rejection to the next, which is no better than saying nothing; asserting the
// wording alone cannot catch that, because the wording is exactly what looks
// right. Round-tripping it closes the class rather than the instance.
func TestParseTrustedProxies_DroppedEntriesNameTheirReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		notWant string
		// wantCorrection is the entry the message tells the operator to write.
		// It is asserted verbatim, then parsed back.
		wantCorrection string
	}{
		{
			name:    "prefix_shorter_than_the_mapping_is_not_reported_as_too_broad",
			raw:     "::ffff:10.0.0.0/95",
			want:    "only denotes an IPv4 range from /96 onwards",
			notWant: "too broad",
		},
		{
			// The too-broad line names the range in the form that governs matching,
			// so an operator reading it sees the /4 they actually asked for.
			name: "rebased_range_is_reported_in_its_ipv4_form",
			raw:  "::ffff:10.0.0.0/100",
			want: "too broad (it covers 0.0.0.0/4, and a trusted-proxy range must be at least /8)",
		},
		{
			// The one entry the missing-length wording is actually about. The
			// suggestion is the operator's own address with the length that makes it
			// a range, so the fix can be copied out of the log.
			name: "bare_ipv4_address_is_told_to_add_a_length",
			raw:  "10.0.0.1",
			want: "a bare address is not a range; add a prefix length, e.g. 10.0.0.1/32",
		},
		{
			// Same rule, other family: the suggested length has to follow the
			// address, not a hardcoded /32.
			name:    "bare_ipv6_address_is_told_to_add_a_128",
			raw:     "2001:db8::1",
			want:    "add a prefix length, e.g. 2001:db8::1/128",
			notWant: "/32",
		},
		{
			// Shares the parser's "no '/'" with the bare address above and nothing
			// else: there is no mask to add to a token that is not an address.
			name:    "token_that_is_not_an_address_is_not_told_to_add_a_length",
			raw:     "not-an-ip",
			want:    "it is not an IP address at all",
			notWant: "add a prefix length",
		},
		{
			// A length IS present, so the entry cannot be missing one; what is wrong
			// is the half in front of the slash, and the line quotes that half.
			name:    "unparseable_address_half_is_named_as_the_address",
			raw:     "not-an-ip/24",
			want:    `the address before the '/' ("not-an-ip") is not an IP address`,
			notWant: "add a prefix length",
		},
		{
			name:    "out_of_range_octet_is_named_as_the_address",
			raw:     "10.0.0.300/24",
			want:    `the address before the '/' ("10.0.0.300") is not an IP address`,
			notWant: "add a prefix length",
		},
		{
			// The finding this test was extended for: an operator who wrote /99 was
			// told to add a mask that is already there.
			name:    "prefix_length_past_the_family_maximum_names_the_maximum",
			raw:     "10.0.0.0/99",
			want:    "a prefix length of /99 is out of range for an IPv4 address (the maximum is /32)",
			notWant: "add a prefix length",
		},
		{
			name:    "ipv6_prefix_length_past_the_family_maximum_names_the_ipv6_maximum",
			raw:     "2001:db8::/129",
			want:    "out of range for an IPv6 address (the maximum is /128)",
			notWant: "/32",
		},
		{
			// The parser never range-checks a length it cannot read, so this must not
			// be reported as a range problem either.
			name:    "unreadable_prefix_length_is_not_reported_as_a_range_problem",
			raw:     "10.0.0.0/eight",
			want:    `the prefix length after the '/' ("eight") is not a plain number of bits`,
			notWant: "out of range",
		},
		{
			// A leading zero is rejected by the parser even though the digits read as
			// a length a human would accept, so the line has to say the length is
			// unreadable rather than out of range.
			name:    "leading_zero_prefix_length_is_reported_as_unreadable",
			raw:     "10.0.0.0/08",
			want:    `("08") is not a plain number of bits`,
			notWant: "out of range",
		},
		{
			// A zone names one host's link. Nothing about it is a length problem.
			// The operator said how wide they wanted the range, so the correction
			// keeps that width: suggesting the address's own /128 instead would
			// quietly hand them a narrower range than the one they asked for.
			name:           "zone_in_a_written_prefix_keeps_the_operator_s_length",
			raw:            "fe80::1%eth0/64",
			want:           `an IPv6 zone ("eth0") cannot appear in a range; write the range on the unzoned address, keeping the length you gave (fe80::1/64)`,
			notWant:        "/128",
			wantCorrection: "fe80::1/64",
		},
		{
			// No length was written, so there is none to keep and one has to be
			// supplied. Naming the bare unzoned address is what the message used to
			// do, and it does not parse — the operator typed fe80::1 and got "no
			// '/'". A single address IS its own /128 range, which is the only length
			// that can be supplied here without widening what was asked for.
			name:           "bare_zoned_address_is_given_a_length_that_parses",
			raw:            "fe80::1%eth0",
			want:           `an IPv6 zone ("eth0") cannot appear in a range; write the range on the unzoned address, with a prefix length (fe80::1/128)`,
			notWant:        "keeping the length you gave",
			wantCorrection: "fe80::1/128",
		},
		{
			// netip rejects the zone BEFORE it reads the length, so a zoned entry
			// arrives here with its length unexamined. Echoing /999 back would print
			// a correction that fails to parse, so the line says the length is
			// unusable too and falls back to a length that works.
			name:           "zone_with_an_out_of_range_length_does_not_echo_that_length",
			raw:            "fe80::1%eth0/999",
			want:           `an IPv6 zone ("eth0") cannot appear in a range, and the prefix length after the '/' ("999") is not usable either; write the range on the unzoned address (fe80::1/128)`,
			notWant:        "fe80::1/999",
			wantCorrection: "fe80::1/128",
		},
		{
			// Same fallback for a length that is not a number at all. It must not
			// borrow the unreadable-length wording used when no zone is involved:
			// that line is about an entry whose only problem is the length.
			name:           "zone_with_an_unreadable_length_does_not_echo_that_length",
			raw:            "fe80::1%eth0/eight",
			want:           `and the prefix length after the '/' ("eight") is not usable either; write the range on the unzoned address (fe80::1/128)`,
			notWant:        "is not a plain number of bits",
			wantCorrection: "fe80::1/128",
		},
		{
			// The only zoned address that is not plain IPv6: a v4-mapped one. Its
			// length is still measured in 128 bits, so the correction is built from
			// the address's own BitLen rather than a constant, and it survives the
			// rebasing the parser then applies to it (/104 becomes the IPv4 /8).
			// A plain IPv4 address can never carry a zone — netip stops at the '.'
			// before it ever sees the '%' — so this is the whole of the v4 story.
			// Keeping the operator's length is only right while the parser would
			// take it. /0 is readable and in range for the family, so the zone path
			// used to preserve it and print fe80::1/0 — an entry the breadth floor
			// then drops for a reason the line never mentioned. The line now names
			// the floor that refuses it and offers the nearest range that passes.
			name:           "zone_with_a_length_below_the_breadth_floor_is_not_offered_back",
			raw:            "fe80::1%eth0/0",
			want:           `an IPv6 zone ("eth0") cannot appear in a range; a length of /0 is below the minimum for a trusted-proxy range (/48); write the range on the unzoned address with an accepted length (fe80::/48)`,
			notWant:        "fe80::1/0",
			wantCorrection: "fe80::/48",
		},
		{
			// Same defect on a mapped address, where the floor that refuses the
			// length is NOT the one the length is written in: /100 is an IPv6
			// length, but after rebasing it is an IPv4 /4 and the IPv4 floor is what
			// drops it. The line has to name /8, not /48, or it sends the operator
			// to widen a length that was already too wide.
			name:           "v4_mapped_zone_below_the_ipv4_floor_names_the_ipv4_floor",
			raw:            "::ffff:10.0.0.1%eth0/100",
			want:           `an IPv6 zone ("eth0") cannot appear in a range; a length of /100 denotes an IPv4 /4, which is below the minimum for a trusted-proxy range (/8); write the range on the unzoned address with an accepted length (10.0.0.0/8)`,
			notWant:        "::ffff:10.0.0.1/100",
			wantCorrection: "10.0.0.0/8",
		},
		{
			// A mapped address whose length reaches past the mapped block denotes no
			// IPv4 range at all, so "too broad" would be the wrong rule to name.
			name:           "v4_mapped_zone_shorter_than_the_mapping_names_the_mapping",
			raw:            "::ffff:10.0.0.1%eth0/95",
			want:           `a length of /95 denotes no IPv4 range at all (on an IPv4-mapped address a prefix only denotes one from /96 onwards); write the range on the unzoned address with an accepted length (10.0.0.0/8)`,
			notWant:        "below the minimum",
			wantCorrection: "10.0.0.0/8",
		},
		{
			name:           "v4_mapped_zone_keeps_its_128_bit_length",
			raw:            "::ffff:1.2.3.4%eth0/104",
			want:           `an IPv6 zone ("eth0") cannot appear in a range; write the range on the unzoned address, keeping the length you gave (::ffff:1.2.3.4/104)`,
			notWant:        "/128",
			wantCorrection: "::ffff:1.2.3.4/104",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := &recordingLogger{}
			require.Empty(t, parseTrustedProxies(tt.raw, logger))

			logger.mu.Lock()
			defer logger.mu.Unlock()

			require.Len(t, logger.messages, 1, "one dropped entry, one line")
			assert.Equal(t, log.LevelError, logger.levels[0])
			assert.Contains(t, logger.messages[0], tt.want)

			if tt.notWant != "" {
				assert.NotContains(t, logger.messages[0], tt.notWant)
			}

			if tt.wantCorrection == "" {
				return
			}

			assert.Contains(t, logger.messages[0], "("+tt.wantCorrection+")",
				"the message must name the correction verbatim, parenthesised, so it can be copied out of the log")

			// The correction goes back through the SAME entry point the rejected
			// entry went through, and must survive all of it — parsing, rebasing
			// and the breadth floor — with no second complaint. Checking only that
			// it parses would still let the line hand the operator a range the next
			// rule drops.
			retry := &recordingLogger{}
			assert.Len(t, parseTrustedProxies(tt.wantCorrection, retry), 1,
				"the suggested correction must be accepted as written")

			retry.mu.Lock()
			defer retry.mu.Unlock()
			assert.Empty(t, retry.messages, "the suggested correction must not itself be complained about")
		})
	}
}

// entryShapedToken matches text shaped like an address followed by a prefix
// length — the shape of something an operator can paste into TRUSTED_PROXIES.
// It requires at least one address character IMMEDIATELY before the '/', so the
// bare widths diagnostics quote ("at least /48", "the maximum is /32", "from
// /96 onwards") are not mistaken for entries.
var entryShapedToken = regexp.MustCompile(`[0-9A-Fa-f:.]+/[0-9]+`)

// echoesTheEntry reports whether token is a diagnostic quoting the operator's
// own entry back at them rather than telling them to write something. Three
// forms count as an echo: any part of the entry as written (which covers the
// %q of the entry and netip's error, which embeds it), the range the entry
// denotes, and the range it denotes after IPv4-mapped rebasing — the too-broad
// line names that one so the operator sees the width they actually asked for.
//
// Everything else printed in entry shape is the library telling the operator
// what to write, and has to be something the library will take.
func echoesTheEntry(entry, token string) bool {
	if strings.Contains(entry, token) {
		return true
	}

	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return false
	}

	if token == prefix.Masked().String() {
		return true
	}

	rebased, ok := rebaseMappedPrefix(prefix)

	return ok && token == rebased.Masked().String()
}

// TestSuggestEntry_NeverOffersWhatTheParserRefuses pins the property at the
// choke point itself, independently of any input that reaches it: for EVERY
// address and EVERY length suggestEntry can be handed, the text it returns
// either names an entry acceptTrustedProxy accepts, or names no entry at all.
//
// This is the structural half of the guarantee. A table of malformed inputs can
// only prove the rows somebody thought to write — which is exactly how a
// suggested /0 and a suggested mapped /100 got through three rounds of fixes.
// Enumerating the whole (address, length) domain removes the need to have
// thought of them.
func TestSuggestEntry_NeverOffersWhatTheParserRefuses(t *testing.T) {
	t.Parallel()

	addresses := []string{
		"10.0.0.1", "0.0.0.0", "255.255.255.255", "203.0.113.7",
		"fe80::1", "::", "::1", "2001:db8::", "2001:db8::1",
		"::ffff:10.0.0.1", "::ffff:0.0.0.0", "::ffff:255.255.255.255",
	}

	offered := 0

	for _, address := range addresses {
		addr := netip.MustParseAddr(address)

		for bits := 0; bits <= addr.BitLen(); bits++ {
			message := suggestEntry("write this instead (%s)", addr, bits)

			for _, token := range entryShapedToken.FindAllString(message, -1) {
				offered++

				_, ok := acceptTrustedProxy(token)
				assert.True(t, ok,
					"suggestEntry(%s, /%d) offers %q, which the parser refuses: %s", address, bits, token, message)
			}
		}
	}

	// Every one of the 1164 (address, length) pairs above names some entry —
	// either the one asked for, or the accepted range refuseSuggestion falls
	// back to — so a change that silently stopped suggesting anything cannot
	// pass this test by leaving nothing to check. A floor rather than an
	// equality: adding an address to the list must not turn the test red.
	assert.GreaterOrEqual(t, offered, 1164,
		"every (address, length) pair must still name an entry to write; suggesting nothing is not a fix")
}

// TestParseTrustedProxies_NoDiagnosticSuggestsARejectedEntry is the guarantee
// the choke point cannot give on its own: it reads the EMITTED TEXT, so it
// holds for a diagnostic that never calls suggestEntry — one that hardcodes an
// example, or formats its own correction. A future message that tells the
// operator to write something the parser refuses turns this red regardless of
// how it was built, as long as some input in the corpus reaches it.
//
// The corpus is generated rather than listed — every address form crossed with
// every zone form crossed with every prefix-length form — because a listed
// corpus can only contain inputs somebody already knew were interesting, which
// is the failure mode this test exists to end.
//
// It also pins the other direction: an entry the parser ACCEPTS must produce no
// diagnostic at all. A message about an entry that was kept is as misleading as
// a correction that is refused.
func TestParseTrustedProxies_NoDiagnosticSuggestsARejectedEntry(t *testing.T) {
	t.Parallel()

	offered := map[string]bool{}

	for _, entry := range trustedProxyEntryCorpus() {
		logger := &recordingLogger{}
		accepted := parseTrustedProxies(entry, logger)

		logger.mu.Lock()
		messages := append([]string(nil), logger.messages...)
		logger.mu.Unlock()

		if len(accepted) > 0 {
			assert.Empty(t, messages, "entry %q was accepted, so nothing should be complained about", entry)

			continue
		}

		for _, message := range messages {
			for _, token := range entryShapedToken.FindAllString(message, -1) {
				if echoesTheEntry(entry, token) {
					continue
				}

				offered[token] = true

				_, ok := acceptTrustedProxy(token)
				assert.True(t, ok,
					"the diagnostic for %q tells the operator to write %q, which the parser then refuses:\n%s",
					entry, token, message)
			}
		}
	}

	// Naming the suggestions the corpus must have reached, rather than counting
	// them: a count can be satisfied by one branch firing repeatedly, and every
	// round of this defect was one branch nobody had exercised. Each entry below
	// is produced by a different diagnostic, so losing any of them means the
	// scan above went quiet about a path instead of passing on it.
	for _, reached := range []string{
		exampleIPv4Entry,      // the address-less example (unparseable token, unrebasable mapping)
		"10.0.0.1/32",         // bare IPv4 address told to add a length
		"2001:db8::1/128",     // same rule, IPv6, length taken from the address
		"fe80::1/128",         // bare zoned address given a length that parses
		"fe80::1/64",          // zoned prefix whose length is kept
		"fe80::/48",           // zoned prefix whose length is refused and replaced
		"::ffff:10.0.0.1/104", // mapped zoned prefix whose length is kept
	} {
		assert.True(t, offered[reached],
			"the corpus never reached the diagnostic that suggests %q, so the scan above proves nothing about it", reached)
	}
}

// trustedProxyEntryCorpus crosses address forms with zone forms with
// prefix-length forms. Every combination is fed through parseTrustedProxies:
// most are rejected, a few are accepted, and the point is that no row was
// chosen for being interesting.
func trustedProxyEntryCorpus() []string {
	addresses := []string{
		"10.0.0.1", "10.0.0.0", "10.1.2.3", "0.0.0.0", "203.0.113.7", "255.255.255.255",
		"fe80::1", "2001:db8::", "2001:db8::1", "::", "::1",
		"::ffff:10.0.0.1", "::ffff:10.0.0.0", "::ffff:0.0.0.0", "::ffff:203.0.113.7",
		"::fffe:0:0", "not-an-ip", "10.0.0.300", "1.2.3.4:80", "10.0.0", "",
	}
	zones := []string{"", "%eth0", "%1", "%"}
	lengths := []string{
		"", "/0", "/1", "/4", "/7", "/8", "/9", "/24", "/32", "/33", "/47", "/48",
		"/64", "/95", "/96", "/100", "/103", "/104", "/128", "/129", "/999",
		"/-1", "/08", "/eight", "/", "/ 8",
	}

	corpus := make([]string, 0, len(addresses)*len(zones)*len(lengths))

	for _, address := range addresses {
		for _, zone := range zones {
			for _, length := range lengths {
				corpus = append(corpus, address+zone+length)
			}
		}
	}

	return corpus
}

// TestExampleIPv4Entry_IsAccepted pins the one suggestion that is a literal
// rather than something derived from the operator's own entry. Nothing computes
// it, so nothing else would notice if a floor moved past it.
func TestExampleIPv4Entry_IsAccepted(t *testing.T) {
	t.Parallel()

	_, ok := acceptTrustedProxy(exampleIPv4Entry)
	assert.True(t, ok, "the example diagnostics point at must be an entry the parser takes")
}

// TestLoadTrustedProxies_UnsetYieldsNoTrust pins the product decision (Roberto,
// 2026-08-22): with TRUSTED_PROXIES unset there is NO trusted-proxy list, so the
// client IP resolves to empty and no address is forwarded. It must NOT fall back
// to the socket peer: the peer is the ingress address, and an operator who
// happens to have registered the ingress CIDR in a tenant allow list would get a
// FALSE ALLOW. Empty never matches an allow list by accident.
func TestLoadTrustedProxies_UnsetYieldsNoTrust(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")

	assert.Empty(t, loadTrustedProxies(&testLogger{}),
		"TRUSTED_PROXIES unset must yield no trusted proxies (client IP empty, nothing forwarded), never a socket-peer fallback")
}

// TestLoadTrustedProxies_ReadsEnv proves the platform-wide variable name is the
// one read (TRUSTED_PROXIES — the same name plugin-access-manager and flowker
// already consume and gitops already provisions).
func TestLoadTrustedProxies_ReadsEnv(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.0.0/16")

	assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"},
		prefixStrings(loadTrustedProxies(&testLogger{})))
}

// recordingLogger captures emitted messages so a test can assert on what an
// operator would actually see in the boot log.
type recordingLogger struct {
	mu       sync.Mutex
	messages []string
	levels   []log.Level
}

func (l *recordingLogger) Log(_ context.Context, level log.Level, msg string, _ ...log.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.messages = append(l.messages, msg)
	l.levels = append(l.levels, level)
}

func (l *recordingLogger) With(_ ...log.Field) log.Logger { return l }
func (l *recordingLogger) WithGroup(_ string) log.Logger  { return l }
func (l *recordingLogger) Enabled(_ log.Level) bool       { return true }
func (l *recordingLogger) Sync(_ context.Context) error   { return nil }

// degradedLines returns the messages announcing that no client IP will be
// forwarded. The phrase is the consequence half of the line, which is the part
// an operator greps for.
func (l *recordingLogger) degradedLines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	var found []string

	for _, msg := range l.messages {
		if strings.Contains(msg, "IP allowlist has nothing to match") {
			found = append(found, msg)
		}
	}

	return found
}

// TestLoadTrustedProxies_DegradationIsObservable pins the boot-time contract for
// missing or unusable configuration: the service comes up (this path has no
// Fatal, no panic, no error return — a misconfigured deployment must not fail to
// boot), but the operator gets EXACTLY ONE log line naming both the cause and
// the consequence. Silence here is the failure mode: IP policy stops enforcing
// and the only other signal is a 403 in production.
func TestLoadTrustedProxies_DegradationIsObservable(t *testing.T) {
	t.Run("unset_logs_cause_and_consequence_once", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "")

		logger := &recordingLogger{}
		require.Empty(t, loadTrustedProxies(logger))

		lines := logger.degradedLines()
		require.Len(t, lines, 1, "the degradation must be announced exactly once, at construction")
		assert.Contains(t, lines[0], "TRUSTED_PROXIES is not set", "the line must name the cause")
		assert.Contains(t, lines[0], "client IP will not be forwarded", "the line must name the consequence")
		assert.Equal(t, log.LevelError, logger.levels[len(logger.levels)-1],
			"a silently-disabled security control is logged at the level this library already uses for degraded config")
	})

	t.Run("all_entries_unusable_logs_a_distinct_cause_once", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "not-an-ip,10.0.0.1")

		logger := &recordingLogger{}
		require.Empty(t, loadTrustedProxies(logger))

		lines := logger.degradedLines()
		require.Len(t, lines, 1, "the degradation must be announced exactly once, however many entries were dropped")
		assert.Contains(t, lines[0], "no usable CIDR",
			"a value that was set but unusable must be distinguishable from one that was never set")
	})

	t.Run("v4_mapped_entry_that_cannot_be_trusted_is_announced_not_stored", func(t *testing.T) {
		// The failure this guards against is silence: an entry that looks valid,
		// is stored, and matches nothing leaves the proxy unrecognised and its own
		// address forwarded as the caller. Whatever cannot be rebased into a
		// usable IPv4 range is dropped loudly instead.
		t.Setenv("TRUSTED_PROXIES", "::ffff:10.0.0.0/100,::ffff:10.0.0.0/95")

		logger := &recordingLogger{}
		require.Empty(t, loadTrustedProxies(logger),
			"neither entry can be trusted as written, so nothing may be stored")

		lines := logger.degradedLines()
		require.Len(t, lines, 1, "the degradation must be announced exactly once")
		assert.Contains(t, lines[0], "no usable CIDR")
	})

	t.Run("valid_config_is_silent", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")

		logger := &recordingLogger{}
		require.Len(t, loadTrustedProxies(logger), 1)

		assert.Empty(t, logger.degradedLines(), "a working configuration must not warn")
	})
}

// ---------------------------------------------------------------------------
// firstUntrustedHop (unit)
// ---------------------------------------------------------------------------

// TestFirstUntrustedHop covers the derivation itself: walk the hop list (the
// forwarded header, then the real socket peer) from RIGHT to LEFT, discard hops
// inside the trusted CIDRs, and return the first untrusted one.
func TestFirstUntrustedHop(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hops    []string
		trusted []string
		want    string
	}{
		{
			// The whole point of the hotfix: with no trusted-proxy list nothing is
			// derivable, so the caller gets no IP at all.
			name:    "no_trusted_proxies_yields_empty",
			hops:    []string{"203.0.113.7", "10.0.0.1"},
			trusted: nil,
			want:    "",
		},
		{
			// The spoof: the peer is NOT a trusted proxy, so the request did not
			// arrive through our ingress and its forwarded header is worthless. The
			// attacker-chosen value must NOT win; the socket peer does.
			name:    "untrusted_peer_beats_spoofed_header",
			hops:    []string{"1.2.3.4", "198.51.100.9"},
			trusted: []string{"10.0.0.0/8"},
			want:    "198.51.100.9",
		},
		{
			name:    "trusted_peer_yields_last_forwarded_hop",
			hops:    []string{"203.0.113.7", "10.0.0.1"},
			trusted: []string{"10.0.0.0/8"},
			want:    "203.0.113.7",
		},
		{
			name:    "multiple_trusted_hops_are_skipped_right_to_left",
			hops:    []string{"1.2.3.4", "203.0.113.7", "10.0.0.5", "10.0.0.1"},
			trusted: []string{"10.0.0.0/8"},
			want:    "203.0.113.7",
		},
		{
			name:    "all_hops_trusted_yields_empty",
			hops:    []string{"10.0.0.9", "10.0.0.5", "10.0.0.1"},
			trusted: []string{"10.0.0.0/8"},
			want:    "",
		},
		{
			// An unparseable hop cannot be shown to be a trusted proxy, so nothing
			// to its left may be credited: stop and yield empty (fail closed)
			// instead of returning a bogus "IP" or reaching further into
			// attacker-controlled territory.
			name:    "unparseable_hop_stops_the_walk",
			hops:    []string{"203.0.113.7", "unknown", "10.0.0.1"},
			trusted: []string{"10.0.0.0/8"},
			want:    "",
		},
		{
			name:    "hop_with_port_is_not_accepted",
			hops:    []string{"203.0.113.7:44321", "10.0.0.1"},
			trusted: []string{"10.0.0.0/8"},
			want:    "",
		},
		{
			// A v4-mapped v6 peer must still match an IPv4 trusted CIDR, otherwise
			// an operator's 10.0.0.0/8 silently stops matching behind a
			// dual-stack listener and the derivation returns the proxy itself.
			name:    "v4_mapped_v6_hop_matches_ipv4_cidr",
			hops:    []string{"203.0.113.7", "::ffff:10.0.0.1"},
			trusted: []string{"10.0.0.0/8"},
			want:    "203.0.113.7",
		},
		{
			// ...and the returned value is normalised to its IPv4 form, so the
			// auth service compares the same string the allow list stores.
			name:    "v4_mapped_v6_client_is_normalised",
			hops:    []string{"::ffff:203.0.113.7", "10.0.0.1"},
			trusted: []string{"10.0.0.0/8"},
			want:    "203.0.113.7",
		},
		{
			name:    "ipv6_hop_matches_ipv6_cidr",
			hops:    []string{"2001:db8:1::9", "2001:db8::1"},
			trusted: []string{"2001:db8::/48"},
			want:    "2001:db8:1::9",
		},
		{
			// netip.Prefix.Contains rejects any zoned address outright, so a
			// link-local proxy hop would never match its own CIDR unless the zone is
			// stripped first.
			name:    "zoned_ipv6_hop_is_de_zoned_before_matching",
			hops:    []string{"203.0.113.7", "2001:db8::1%eth0"},
			trusted: []string{"2001:db8::/48"},
			want:    "203.0.113.7",
		},
		{
			// A zone on an IPv4 literal is not a valid address; it stops the walk
			// like any other unparseable hop rather than being silently repaired.
			name:    "zoned_ipv4_hop_stops_the_walk",
			hops:    []string{"203.0.113.7", "10.0.0.1%eth0"},
			trusted: []string{"10.0.0.0/8"},
			want:    "",
		},
		{
			name:    "surrounding_whitespace_is_tolerated",
			hops:    []string{" 203.0.113.7 ", " 10.0.0.1 "},
			trusted: []string{"10.0.0.0/8"},
			want:    "203.0.113.7",
		},
		{
			name:    "empty_hop_list_yields_empty",
			hops:    nil,
			trusted: []string{"10.0.0.0/8"},
			want:    "",
		},
		{
			// An IPv4 range written in v4-mapped-v6 form is rebased to the plain
			// IPv4 prefix it denotes when the list is parsed, so it matches exactly
			// what 10.0.0.0/8 matches. Held in the mapped form it would match
			// nothing — hops are unmapped before comparison and no IPv6 prefix
			// contains an IPv4 address — and the unrecognised proxy would itself be
			// returned as the caller, which is the wrong answer rather than no
			// answer. This case is the guard against that regression.
			name:    "v4_range_written_in_v6_mapped_form_matches_v4_hops",
			hops:    []string{"203.0.113.7", "10.0.0.1"},
			trusted: []string{"::ffff:10.0.0.0/104"},
			want:    "203.0.113.7",
		},
		{
			// The same list, with only the proxy in the chain: every hop is trusted,
			// so no caller is attributable. Proves the rebased entry really matches
			// the proxy rather than the walk merely stopping one hop earlier.
			name:    "v4_range_in_v6_mapped_form_trusts_the_proxy_itself",
			hops:    []string{"10.0.0.1"},
			trusted: []string{"::ffff:10.0.0.0/104"},
			want:    "",
		},
		{
			// A single host written in mapped form rebases to a /32 and matches only
			// itself: the hop beside it is still the caller.
			name:    "v4_host_written_in_v6_mapped_form_matches_only_that_host",
			hops:    []string{"203.0.113.7", "10.0.0.1"},
			trusted: []string{"::ffff:10.0.0.1/128"},
			want:    "203.0.113.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var trusted []netip.Prefix
			if len(tt.trusted) > 0 {
				trusted = mustPrefixes(t, tt.trusted...)
			}

			assert.Equal(t, tt.want, firstUntrustedHop(tt.hops, trusted))
		})
	}
}

// ---------------------------------------------------------------------------
// Authorize - client IP derived by lib-auth, not by Fiber
// ---------------------------------------------------------------------------

// misconfiguredProxyApp builds a Fiber app with the PARTIAL trusted-proxy
// config that is the actual hole: TrustProxy + Proxies + ProxyHeader are set,
// EnableIPValidation is FORGOTTEN. Fiber v3 only walks the chain right-to-left
// when all four are present; with validation off, extractIPFromHeader returns
// the RAW X-Forwarded-For header verbatim (req.go:636), attacker-controlled and
// unparsed. Every test below runs on this app on purpose: lib-auth must reach
// the right answer regardless of what the consuming service configured.
func misconfiguredProxyApp(auth *AuthClient) *fiber.App {
	return clientIPApp(auth, misconfiguredProxyConfig())
}

// misconfiguredProxyConfig returns that partial config as a fresh value, so a
// test can vary ONE field of it and hold everything else still.
func misconfiguredProxyConfig() fiber.Config {
	return fiber.Config{
		TrustProxy:       true,
		TrustProxyConfig: fiber.TrustProxyConfig{Proxies: []string{"0.0.0.0"}},
		ProxyHeader:      fiber.HeaderXForwardedFor,
	}
}

// clientIPApp mounts Authorize on an app built from cfg.
func clientIPApp(auth *AuthClient, cfg fiber.Config) *fiber.App {
	app := fiber.New(cfg)
	app.Get("/x", auth.Authorize("midaz", "resource", "get"), func(c fiber.Ctx) error {
		return c.SendString("reached handler")
	})

	return app
}

// clientIPThrough drives one request carrying xffValues (one X-Forwarded-For
// header line each) through an app built from cfg, and returns the body the
// authorize call carried. Everything except cfg is fixed, so a difference
// between two calls can only come from the app configuration.
func clientIPThrough(t *testing.T, cfg fiber.Config, trusted []netip.Prefix, xffValues ...string) map[string]string {
	t.Helper()

	var capturedBody map[string]string

	server := bodyCapturingAuthServer(t, &capturedBody)

	auth := &AuthClient{
		Address:        server.URL,
		Enabled:        true,
		Logger:         &testLogger{},
		trustedProxies: trusted,
	}

	resp := getThroughApp(t, clientIPApp(auth, cfg), xffValues...)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return capturedBody
}

// bodyCapturingAuthServer records the authorize request body and always allows.
func bodyCapturingAuthServer(t *testing.T, captured *map[string]string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(captured); err != nil {
			t.Errorf("mock server: failed to decode request body: %v", err)
		}

		writeAuthorized(w, true)
	}))

	t.Cleanup(server.Close)

	return server
}

func clientIPTestToken() string {
	return createTestJWT(jwt.MapClaims{
		"type":  "normal-user",
		"owner": "acme-org",
		"sub":   "user123",
	})
}

func getWithForwardedFor(t *testing.T, app *fiber.App, xff string) *http.Response {
	t.Helper()

	if xff == "" {
		return getThroughApp(t, app)
	}

	return getThroughApp(t, app, xff)
}

// getThroughApp issues the request with ONE X-Forwarded-For header line per
// value, which is how a chain split across several lines reaches the server.
func getThroughApp(t *testing.T, app *fiber.App, xffValues ...string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+clientIPTestToken())

	for _, value := range xffValues {
		req.Header.Add(fiber.HeaderXForwardedFor, value)
	}

	resp, err := app.Test(req)
	require.NoError(t, err)

	return resp
}

// TestAuthorize_ClientIP_SpoofedHeaderIsIgnoredWhenPeerUntrusted is the pentest
// case (Taura, 2026-08-19). The socket peer (the in-memory test connection,
// 0.0.0.0) is NOT in the trusted-proxy list, so the forwarded header cannot be
// believed: the attacker's chosen value must not reach the auth service. Under
// the pre-fix code (clientIP := c.IP()) this app hands the raw header straight
// through and the assertion fails.
func TestAuthorize_ClientIP_SpoofedHeaderIsIgnoredWhenPeerUntrusted(t *testing.T) {
	t.Parallel()

	var capturedBody map[string]string

	server := bodyCapturingAuthServer(t, &capturedBody)

	auth := &AuthClient{
		Address:        server.URL,
		Enabled:        true,
		Logger:         &testLogger{},
		trustedProxies: mustPrefixes(t, "10.0.0.0/8"),
	}

	resp := getWithForwardedFor(t, misconfiguredProxyApp(auth), "203.0.113.7")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.NotEqual(t, "203.0.113.7", capturedBody["clientIp"],
		"a forwarded header from an UNTRUSTED peer must never become the client IP")
	assert.Equal(t, "0.0.0.0", capturedBody["clientIp"],
		"the real socket peer is the only trustworthy hop here")
}

// TestAuthorize_ClientIP_WalksChainRightToLeft proves lib-auth parses the chain
// itself. With the peer and the last hop trusted, the client is the first
// untrusted hop from the right — not the whole raw header, which is what the
// misconfigured Fiber app would return.
func TestAuthorize_ClientIP_WalksChainRightToLeft(t *testing.T) {
	t.Parallel()

	var capturedBody map[string]string

	server := bodyCapturingAuthServer(t, &capturedBody)

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		// The test peer stands in for the outermost proxy; 10.0.0.0/8 for the
		// ingress subnet behind it.
		trustedProxies: mustPrefixes(t, testPeerCIDR, "10.0.0.0/8"),
	}

	resp := getWithForwardedFor(t, misconfiguredProxyApp(auth), "203.0.113.7, 10.1.2.3")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Equal(t, "203.0.113.7", capturedBody["clientIp"],
		"the first untrusted hop from the right is the client")
}

// TestAuthorize_ClientIP_AllHopsTrustedOmitsField covers fully-internal traffic:
// every hop is a trusted proxy, no caller IP is attributable, and the optional
// clientIp field is omitted so the wire body stays byte-identical to the
// pre-IP behaviour for every deployed access-manager.
func TestAuthorize_ClientIP_AllHopsTrustedOmitsField(t *testing.T) {
	t.Parallel()

	var capturedBody map[string]string

	server := bodyCapturingAuthServer(t, &capturedBody)

	auth := &AuthClient{
		Address:        server.URL,
		Enabled:        true,
		Logger:         &testLogger{},
		trustedProxies: mustPrefixes(t, testPeerCIDR, "10.0.0.0/8"),
	}

	resp := getWithForwardedFor(t, misconfiguredProxyApp(auth), "10.1.2.3")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	_, has := capturedBody["clientIp"]
	assert.False(t, has, "clientIp must be omitted when every hop is a trusted proxy")
}

// TestAuthorize_ClientIP_MalformedForwardedTokenOmitsField drives a malformed
// X-Forwarded-For token through Fiber's REAL c.IPs() at the Authorize level. The
// unit table feeds firstUntrustedHop a hop list directly and so assumes garbage
// can reach the derivation; this proves Fiber actually hands it over (with
// EnableIPValidation off, extractIPsFromHeader appends every comma-separated
// token unvalidated) and that the parse guard in clientip.go is load-bearing
// rather than dead code.
//
// Chain: 203.0.113.7, garbage, 10.1.2.3 + the 0.0.0.0 peer. Walking right to
// left the peer and 10.1.2.3 are trusted, then "garbage" cannot be shown to be a
// trusted proxy — so the walk stops and no caller IP is attributed, rather than
// crediting the 203.0.113.7 sitting behind it.
func TestAuthorize_ClientIP_MalformedForwardedTokenOmitsField(t *testing.T) {
	t.Parallel()

	var capturedBody map[string]string

	server := bodyCapturingAuthServer(t, &capturedBody)

	auth := &AuthClient{
		Address:        server.URL,
		Enabled:        true,
		Logger:         &testLogger{},
		trustedProxies: mustPrefixes(t, testPeerCIDR, "10.0.0.0/8"),
	}

	resp := getWithForwardedFor(t, misconfiguredProxyApp(auth), "203.0.113.7, garbage, 10.1.2.3")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.NotContains(t, capturedBody, "clientIp",
		"an unparseable hop must stop the walk: no caller IP is attributable, so the field is omitted")
	assert.NotEqual(t, "203.0.113.7", capturedBody["clientIp"],
		"the hop behind the unparseable one must never be credited as the caller")
}

// TestAuthorize_ClientIP_OmittedWhenTrustedProxiesUnset pins the unset->empty
// product decision at the wire level: no TRUSTED_PROXIES, no clientIp field —
// even though a forwarded header is present and Fiber would happily return it.
// What the authorization service then does with a request carrying no address is
// its own policy, and not something this library asserts.
func TestAuthorize_ClientIP_OmittedWhenTrustedProxiesUnset(t *testing.T) {
	t.Parallel()

	var capturedBody map[string]string

	server := bodyCapturingAuthServer(t, &capturedBody)

	auth := &AuthClient{Address: server.URL, Enabled: true, Logger: &testLogger{}}

	resp := getWithForwardedFor(t, misconfiguredProxyApp(auth), "203.0.113.7")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	_, has := capturedBody["clientIp"]
	assert.False(t, has, "with no trusted-proxy list configured no client IP may be forwarded")
}

// TestAuthorize_ClientIP_EmptyKeysCacheAsEmpty guards the decision cache against
// the change in what clientIP holds. With no trusted proxies every request
// derives "" — so two requests carrying DIFFERENT forwarded headers collapse to
// the SAME cache key (clientIP: "") and the second is served from cache. That is
// the pre-existing gRPC/no-IP behaviour, unchanged. (It is safe precisely
// because the decisions being shared are all made with no IP at all.)
func TestAuthorize_ClientIP_EmptyKeysCacheAsEmpty(t *testing.T) {
	t.Parallel()

	server, hits := countingAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _ int64) {
		writeAuthorized(w, true)
	})

	auth := &AuthClient{
		Address: server.URL,
		Enabled: true,
		Logger:  &testLogger{},
		cache:   newDecisionCache(time.Minute),
	}
	app := misconfiguredProxyApp(auth)

	assert.Equal(t, http.StatusOK, getWithForwardedFor(t, app, "203.0.113.7").StatusCode)
	assert.Equal(t, http.StatusOK, getWithForwardedFor(t, app, "198.51.100.9").StatusCode)

	assert.Equal(t, int64(1), hits.Load(),
		"both requests derive an empty client IP, so they share the cache key and the authz service is queried once")
}

// TestAuthorize_ClientIP_IndependentOfEnableIPValidation is the assertion the
// whole derivation exists for: the SAME chain, the same trusted list and the
// same peer must attribute the same caller no matter how the embedding service
// configured Fiber.
//
// The chain carries an unreadable hop between two readable ones. Reading it
// through c.IPs() with EnableIPValidation set makes Fiber drop that hop before
// lib-auth sees the chain, which closes the hole in it and lets the walk reach
// the leftmost value — text the caller wrote about itself. With the flag unset
// the same request stops at the hole and attributes nobody. One flag in the
// consuming service, two different answers.
func TestAuthorize_ClientIP_IndependentOfEnableIPValidation(t *testing.T) {
	t.Parallel()

	const chain = "203.0.113.7, garbage, 10.1.2.3"

	trusted := mustPrefixes(t, testPeerCIDR, "10.0.0.0/8")

	validationOff := misconfiguredProxyConfig()

	validationOn := misconfiguredProxyConfig()
	validationOn.EnableIPValidation = true

	bodies := map[string]map[string]string{
		"EnableIPValidation unset": clientIPThrough(t, validationOff, trusted, chain),
		"EnableIPValidation set":   clientIPThrough(t, validationOn, trusted, chain),
	}

	assert.Equal(t, bodies["EnableIPValidation unset"]["clientIp"], bodies["EnableIPValidation set"]["clientIp"],
		"the attributed caller must not move with the embedding service's Fiber configuration")

	for name, body := range bodies {
		assert.NotContains(t, body, "clientIp",
			"%s: an unreadable hop must stop the walk, so no caller is attributable", name)
		assert.NotEqual(t, "203.0.113.7", body["clientIp"],
			"%s: the hop behind the unreadable one must never be credited as the caller", name)
	}
}

// TestAuthorize_ClientIP_IndependentOfProxyHeader holds the same line for the
// other setting that decides which header Fiber would read. lib-auth names the
// header itself, so a service that never set ProxyHeader — and whose c.IP()
// therefore returns the socket peer — still gets the same caller attributed.
func TestAuthorize_ClientIP_IndependentOfProxyHeader(t *testing.T) {
	t.Parallel()

	const chain = "203.0.113.7, 10.1.2.3"

	trusted := mustPrefixes(t, testPeerCIDR, "10.0.0.0/8")

	headerSet := misconfiguredProxyConfig()

	headerUnset := misconfiguredProxyConfig()
	headerUnset.ProxyHeader = ""

	withHeader := clientIPThrough(t, headerSet, trusted, chain)
	withoutHeader := clientIPThrough(t, headerUnset, trusted, chain)

	assert.Equal(t, withHeader["clientIp"], withoutHeader["clientIp"],
		"the attributed caller must not move with ProxyHeader")
	assert.Equal(t, "203.0.113.7", withHeader["clientIp"],
		"the first untrusted hop from the right is the client, either way")
}

// TestAuthorize_ClientIP_ChainSplitAcrossHeaderLines pins how a chain delivered
// as several X-Forwarded-For lines is read. Repeated field lines mean one
// comma-joined value in order, so the LAST value on the LAST line is the hop
// nearest to us and anchors the walk. Reading only the first line would throw
// away the trustworthy right-hand end of the chain and stop the walk further
// left, on text the caller supplied.
func TestAuthorize_ClientIP_ChainSplitAcrossHeaderLines(t *testing.T) {
	t.Parallel()

	trusted := mustPrefixes(t, testPeerCIDR, "10.0.0.0/8")

	t.Run("a later line continues the chain to the right", func(t *testing.T) {
		t.Parallel()

		body := clientIPThrough(t, misconfiguredProxyConfig(), trusted, "203.0.113.7", "198.51.100.9")

		assert.Equal(t, "198.51.100.9", body["clientIp"],
			"the rightmost hop across all lines is the nearest one, so it is the caller here")
		assert.NotEqual(t, "203.0.113.7", body["clientIp"],
			"reading only the first line would credit the hop the caller wrote about itself")
	})

	t.Run("an unreadable hop on a later line still stops the walk", func(t *testing.T) {
		t.Parallel()

		body := clientIPThrough(t, misconfiguredProxyConfig(), trusted, "203.0.113.7", "garbage")

		assert.NotContains(t, body, "clientIp",
			"a hop that cannot be shown to be a proxy stops the walk wherever it was written")
	})
}

// TestAuthorize_ClientIP_EmptyForwardedPositionStopsTheWalk pins the tokenising
// decision: an empty comma position is kept as a hop rather than skipped. It is
// a position this library cannot vouch for, and the walk only ever reaches one
// when everything to its right is a trusted proxy — that is, when it stands
// exactly where the caller would have been named.
func TestAuthorize_ClientIP_EmptyForwardedPositionStopsTheWalk(t *testing.T) {
	t.Parallel()

	trusted := mustPrefixes(t, testPeerCIDR, "10.0.0.0/8")

	body := clientIPThrough(t, misconfiguredProxyConfig(), trusted, "203.0.113.7, 10.1.2.3,")

	assert.NotContains(t, body, "clientIp",
		"an empty position is an unreadable hop: it stops the walk instead of being closed over")
	assert.NotEqual(t, "203.0.113.7", body["clientIp"],
		"skipping the empty position would splice the chain and credit the caller's own text")
}
