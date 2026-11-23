package planrun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vistasecurity/vistaplatform-agents/shared/discovery"
	"github.com/vistasecurity/vistaplatform-agents/shared/probeconsent"
)

// ErrForbiddenAddress wraps every refusal of the sensor's own rules.
var ErrForbiddenAddress = errors.New("address refused by the sensor's own rules")

// refuseReserved refuses what no scan has any business touching, whoever
// asked: not an address, unspecified, loopback (the sensor's own host),
// link-local (cloud metadata lives there), multicast and limited broadcast.
// Every rule in this file starts here, so the reserved set cannot drift
// between the managed and the standalone sensor.
func refuseReserved(a netip.Addr) error {
	switch {
	case !a.IsValid():
		return fmt.Errorf("%w: not an address", ErrForbiddenAddress)
	case a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%w: %s is a reserved address", ErrForbiddenAddress, a)
	}
	return nil
}

// NamedTargetsRule is the rule of a standalone scan (crypto-sensor scan),
// which has no platform and no owned-network scope behind it: the operator's
// named targets are the whole scope. It refuses the same reserved addresses
// SensorRule refuses, even when a target names them, and then allows only an
// address inside one of prefixes (the targets as prefixes: an address as a
// /32 or /128, a range as the prefixes that cover it exactly, a hostname as
// the addresses it was resolved to). Nothing outside them is touched,
// liveness included.
func NamedTargetsRule(prefixes []netip.Prefix) func(netip.Addr) error {
	named := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			// Addresses are unmapped before the check; so is the prefix.
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		named = append(named, p.Masked())
	}
	return func(a netip.Addr) error {
		a = a.Unmap()
		if err := refuseReserved(a); err != nil {
			return err
		}
		for _, p := range named {
			if p.Contains(a) {
				return nil
			}
		}
		return fmt.Errorf("%w: %s is not inside any target named on the command line", ErrForbiddenAddress, a)
	}
}

// SensorRule is the standalone sensor's own judgement of an address a planned
// scan may touch, over the owned-network scope the platform delivers on every
// heartbeat (probeconsent; the scope the TLS enricher already decides by).
// The platform authorized every address before dispatch; this is the sensor
// refusing to be the tool that scans what its own view of the tenant says it
// must not, whatever a command says:
//
//   - never the reserved ranges a scan has no business in: unspecified,
//     loopback (the sensor's own host), link-local (cloud metadata lives
//     there), multicast, limited broadcast;
//   - never inside a prefix the tenant excluded (a sensitive or
//     probes-disabled segment, an automatic-scan exclusion) — an exclusion
//     beats everything;
//   - only an address the scope says is the tenant's: private space, or a
//     prefix the tenant declared. A dispatched scan never carries anything
//     else (external targets run from the platform only), so a refusal here
//     means the sensor's view and the command disagree, and the sensor's view
//     wins.
//
// scope is read on every call, so an exclusion delivered mid-scan stops the
// hosts not yet started.
func SensorRule(scope func() probeconsent.Scope) func(netip.Addr) error {
	return func(a netip.Addr) error {
		a = a.Unmap()
		if err := refuseReserved(a); err != nil {
			return err
		}
		if !scope().Owns(a.String(), 0) {
			return fmt.Errorf("%w: %s is excluded from probing, or is not inside the networks this tenant owns as this sensor last heard them", ErrForbiddenAddress, a)
		}
		return nil
	}
}

// SensorEndpointRule is SensorRule for a certificate verification (#2746):
// the same reserved ranges and exclusions, but ownership is judged on the
// ENDPOINT — address AND port — so a location a person declared and asked to
// have verified (registered in the delivered scope as an endpoint, exactly like
// an elevated connection) authorizes that one port and nothing else on the
// host. An owned address (private space, a declared prefix) authorizes every
// port of it, as SensorRule does.
func SensorEndpointRule(scope func() probeconsent.Scope) func(netip.AddrPort) error {
	return func(ap netip.AddrPort) error {
		a := ap.Addr().Unmap()
		if err := refuseReserved(a); err != nil {
			return err
		}
		if ap.Port() == 0 {
			return fmt.Errorf("%w: no port", ErrForbiddenAddress)
		}
		if !scope().Owns(a.String(), int(ap.Port())) {
			return fmt.Errorf("%w: %s is excluded from probing, or is neither inside the networks this tenant owns nor a location it asked to have verified, as this sensor last heard them", ErrForbiddenAddress, netip.AddrPortFrom(a, ap.Port()))
		}
		return nil
	}
}

// endpointDialer refuses, before any packet, a dial to an endpoint allow
// refuses.
type endpointDialer struct {
	inner discovery.Dialer
	allow func(netip.AddrPort) error
}

// GuardedEndpointDialer wraps d so that every connection is to an endpoint
// allow accepts: the backstop for a verification, as GuardedDialer is for a
// scan.
func GuardedEndpointDialer(d discovery.Dialer, allow func(netip.AddrPort) error) discovery.Dialer {
	return &endpointDialer{inner: d, allow: allow}
}

func (g *endpointDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a literal address", ErrForbiddenAddress, address)
	}
	if err := g.allow(ap); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	return g.inner.DialContext(ctx, network, address)
}

// guardedDialer refuses, before any packet, a dial to an address allow
// refuses.
type guardedDialer struct {
	inner discovery.Dialer
	allow func(netip.Addr) error
}

// GuardedDialer wraps d so that every connection the engine opens — liveness,
// port scan, identification, UDP — is to an address allow accepts. The run
// also asks allow before each host; this is the backstop for a rule that
// changed while a host was in flight, and for any path that might dial
// something the run did not hand it.
func GuardedDialer(d discovery.Dialer, allow func(netip.Addr) error) discovery.Dialer {
	return &guardedDialer{inner: d, allow: allow}
}

func (g *guardedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a literal address", ErrForbiddenAddress, address)
	}
	if err := g.allow(ap.Addr()); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	return g.inner.DialContext(ctx, network, address)
}
