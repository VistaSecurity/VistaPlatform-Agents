// Package attrlist keeps evidence the identity layer refused as IDENTIFIERS but
// must not lose: a bounded, most-recent-first list of strings under one key of
// `assets.attributes`.
//
// Three lists use it (#2081):
//
//	synthetic_names            UUID-form, IP-encoded and none-N names (D1)
//	ipv6_temporary_addresses   rotating RFC 8981-shaped IPv6 addresses (D2)
//	link_local_addresses       fe80::/10 addresses with no segment to scope to (D2)
//	virtual_interface_addresses  a host's own addresses on its virtual
//	                           interfaces (bridges, veths, tunnels), as its
//	                           agent reported them (#2374 WP7)
//
// Each is evidence that EXPLAINS an asset — what else it answered to — and
// none of it identifies anything, which is why it is an attribute and not an
// identifier: a value that rotates daily attached as an identifier is a key
// nobody will ever look up again.
//
// This package only folds the lists ([Merge]); storing them is the platform's
// job, not the agent's.
package attrlist

import (
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform-agents/shared/identity/derive"
)

// The attribute keys, and the cap on the two address lists. (The name list's
// cap is hostnamequality.MaxSyntheticNames.)
const (
	KeySyntheticNames = "synthetic_names"
	KeyIPv6Temporary  = "ipv6_temporary_addresses"
	KeyLinkLocal      = "link_local_addresses"
	// KeyVirtualInterfaceAddresses holds the addresses a host reported on its
	// VIRTUAL interfaces. They are real and they are the host's, but they are
	// not where it lives: a container bridge's 172.17.0.1 is on every Docker
	// host, so as an identifier it would merge them all.
	KeyVirtualInterfaceAddresses = "virtual_interface_addresses"
	MaxAddressEvidence           = 10
)

// AddressAttribute is #2081 D2's rule for one address, in the one place both
// intakes read it: the attribute key an address is recorded under INSTEAD of
// becoming an ip_address identifier, or "" when it stays an identifier.
//
//   - a temporary-shaped IPv6 address ([derive.RoleTemporary]) →
//     [KeyIPv6Temporary];
//   - a link-local address → an identifier only when segmentScoped (the
//     observation resolved to a real segment the caller scopes it to — a
//     link-local address is unique only on its own link), otherwise
//     [KeyLinkLocal];
//   - everything else — IPv4, EUI-64, a hand-assigned IPv6 address — "".
func AddressAttribute(addr netip.Addr, segmentScoped bool) string {
	switch derive.IPv6Role(addr) {
	case derive.RoleTemporary:
		return KeyIPv6Temporary
	case derive.RoleLinkLocal:
		if segmentScoped {
			return ""
		}
		return KeyLinkLocal
	default:
		return ""
	}
}

// Merge folds incoming into existing: each value normalised (trimmed, lower
// case, one trailing dot dropped), deduplicated, incoming first in its own
// order and then existing, capped at max. incoming is the newer evidence, so a
// value seen again moves to the front and the oldest fall off the end.
//
// A max below one keeps nothing.
func Merge(incoming, existing []string, max int) []string {
	if max < 1 {
		return []string{}
	}
	out := make([]string, 0, min(max, len(incoming)+len(existing)))
	seen := map[string]bool{}
	for _, list := range [][]string{incoming, existing} {
		for _, v := range list {
			n := normalize(v)
			if n == "" || seen[n] {
				continue
			}
			if len(out) == max {
				return out
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func normalize(v string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
}
