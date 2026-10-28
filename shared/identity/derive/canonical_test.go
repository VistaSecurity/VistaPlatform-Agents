package derive_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/identityvectors"
	"github.com/vistasecurity/vistaplatform-agents/shared/identity/derive"
)

// Whatever this package emits is stored as a mac_address identifier, so it must
// already be the exact form the platform normalises to. If the two ever
// disagree a derived MAC would never compare equal to the native one it is
// meant to corroborate.
//
// The platform's rule reaches this test as data: every accepted mac_address
// vector in fixtures/identity/identifier-vectors.json, whatever its spelling,
// maps to one canonical form, and that form is the one a derived MAC must
// already have.
func TestOutputIsCanonicalIdentityForm(t *testing.T) {
	v := identityvectors.Load(t)
	canonical := map[string]bool{}
	for _, a := range v.Accepted {
		if a.Kind == "mac_address" {
			canonical[a.Canonical] = true
			if a.Canonical != strings.ToLower(a.Canonical) || len(a.Canonical) != 17 {
				t.Fatalf("vector %q -> %q: not the lower-case aa:bb:cc:dd:ee:ff form this test assumes", a.Value, a.Canonical)
			}
		}
	}
	if len(canonical) == 0 {
		t.Fatal("no mac_address vectors; this test would prove nothing")
	}

	fromIPv6, ok := derive.MACFromEUI64(netip.MustParseAddr("fd00::A2B2:C3FF:FED4:E5F6"))
	if !ok {
		t.Fatal("expected a MAC from the EUI-64 address")
	}
	// The vectors include A0:B2:C3:D4:E5:F6, the MAC behind this address: the
	// derived value must be exactly the platform's canonical form of it.
	if !canonical[fromIPv6] {
		t.Fatalf("derived %q from EUI-64, which is not the platform's canonical form of that MAC", fromIPv6)
	}

	// 00:00:0c is a long-standing Cisco prefix in the embedded IEEE registry.
	fromSerial, ok := derive.MACFromSerialRegistered("00000C1A2B3C")
	if !ok {
		t.Fatal("expected a MAC from the serial")
	}
	for _, mac := range []string{fromIPv6, fromSerial} {
		if mac != strings.ToLower(mac) || strings.Count(mac, ":") != 5 || len(mac) != 17 {
			t.Fatalf("derived MAC %q is not in the platform's canonical form", mac)
		}
	}
	if fromSerial != "00:00:0c:1a:2b:3c" {
		t.Fatalf("MACFromSerialRegistered(00000C1A2B3C) = %q", fromSerial)
	}
}
