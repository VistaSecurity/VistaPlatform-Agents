package hostobs

import "net/netip"

// LLDP (IEEE 802.1AB). The LLDPDU is a stream of TLVs; each TLV header is two
// bytes holding a 7-bit type and a 9-bit length.
const (
	lldpTLVEnd        = 0
	lldpTLVChassisID  = 1
	lldpTLVPortID     = 2
	lldpTLVTTL        = 3
	lldpTLVPortDesc   = 4
	lldpTLVSysName    = 5
	lldpTLVSysDesc    = 6
	lldpTLVSysCaps    = 7
	lldpTLVMgmtAddr   = 8
	lldpTLVOrgSpec    = 127
	lldpMaxTLVs       = 64
	lldpChassisSubMAC = 4
	lldpChassisSubNet = 5
	lldpPortSubMAC    = 3
	lldpPortSubIfName = 5
)

// LLDP-MED (ANSI/TIA-1057) inventory TLVs. They ride in the organisationally
// specific TLV (type 127) under the TIA OUI, and subtype 10 is the one field
// in all of LLDP that states a hardware model as a field rather than as prose.
// VoIP phones, the main LLDP-MED speakers, populate it.
var lldpMEDOUI = [3]byte{0x00, 0x12, 0xbb}

const (
	lldpMEDSubtypeManufacturer = 9
	lldpMEDSubtypeModel        = 10
)

// lldpCapabilityNames indexes IEEE 802.1AB Table 8-4 by bit position. These
// are the strongest passive class signal on a wired segment: "bridge+router"
// is a layer-3 switch, "telephone" is a VoIP phone, "station only" is an
// endpoint.
var lldpCapabilityNames = []string{
	"other", "repeater", "bridge", "wlan_access_point",
	"router", "telephone", "docsis_cable_device", "station_only",
	"c_vlan_component", "s_vlan_component", "two_port_mac_relay",
}

// LLDPCapabilityNames is the vocabulary this decoder emits, as a copy. Exported
// for the same reason as [CDPCapabilityNames]: the `lldp_capability` rules are
// written in these words, and a rule naming anything else fires for no device
// ever and reports nothing while doing it.
func LLDPCapabilityNames() []string {
	return append([]string(nil), lldpCapabilityNames...)
}

// DecodeLLDP extracts the advertising device's identity.
//
// The subject is the ADVERTISER: its chassis ID (usually a MAC), its system
// name, the addresses it says its management plane is on, and — when the frame
// carries the LLDP-MED inventory TLV — its model.
//
// NO adjacency is recorded. A captured advertisement proves the advertiser
// exists; it does not prove the advertiser is attached to the host running the
// sensor, which is normally fed by a mirror or SPAN port. See the note above
// [HostObservation].
//
// The system description is truncated to [MaxDescriptionLen] and passed
// through the PEM scrubber. A full IOS or JunOS description block runs to
// several kilobytes of banner, and a device's description field is a free-text
// box an operator can paste anything into.
func DecodeLLDP(f Frame) (*HostObservation, error) {
	b := f.Payload
	if len(b) < 2 {
		return nil, ErrMalformed
	}

	obs := f.newObservation(SourceLLDP)

	sawChassis := false
	chassisFromText := false
	off := 0
	for n := 0; n < lldpMaxTLVs; n++ {
		if off+2 > len(b) {
			// Running off the end without an End TLV is common in captures
			// truncated by a snaplen; what was parsed still stands.
			break
		}
		hdr, _ := be16(b, off)
		ttype := int(hdr >> 9)
		tlen := int(hdr & 0x01ff)
		off += 2
		if ttype == lldpTLVEnd {
			break
		}
		if off+tlen > len(b) {
			// A TLV whose value runs past the end of the buffer. Stop and keep
			// what parsed, rather than discarding the frame.
			//
			// This is the snaplen case, and it is common: the mandatory TLVs
			// come FIRST (chassis ID, port ID, TTL), and the one that overruns
			// is almost always the optional system description at the end. A
			// capture cut at 256 bytes would otherwise lose the switch's
			// identity entirely because its banner was too long — throwing away
			// a measurement we have because of one we do not.
			//
			// A truncated frame and a lying length field are indistinguishable
			// here, so this also tolerates the second. That is the right trade:
			// the TLVs already parsed were self-consistent.
			break
		}
		val := b[off : off+tlen]
		off += tlen

		switch ttype {
		case lldpTLVChassisID:
			if len(val) < 2 {
				continue
			}
			sawChassis = true
			sub, id := val[0], val[1:]
			switch sub {
			case lldpChassisSubMAC:
				if mac := MACFromBytes(id); mac != "" {
					obs.MAC = mac
				}
			case lldpChassisSubNet:
				// addrfamily(1) + address
				if len(id) >= 2 {
					if a, ok := lldpAddrFromIANA(id[0], id[1:]); ok {
						obs.addAddr(a)
					}
				}
			default:
				// Interface alias, port component, interface name, locally
				// assigned — an opaque string chosen by the operator. Kept as
				// evidence; it is not a name the platform can resolve.
				s := boundIdentifier(string(id))
				if s == "" {
					continue
				}
				obs.setAttr("lldp_chassis_id", s)
				// Unless the string IS a MAC address. Some gateways advertise
				// their base (chassis) MAC as text under a non-MAC subtype,
				// usually "locally assigned". Taking the Ethernet source below
				// instead would key the device on the MAC of whichever port
				// sent the frame, while ARP from the same device keys it on
				// the base MAC: one device, two records. The sending port stays
				// in AttrLLDPSourceMAC, below, and in lldp_port_id when the port
				// ID is its MAC.
				if mac := lldpMACFromText(s); mac != "" {
					obs.MAC = mac
					chassisFromText = true
				}
			}

		case lldpTLVPortID:
			// The advertiser's OWN port — "GigabitEthernet1/0/24" on the switch
			// that sent the frame. An attribute, not a fact: it says nothing
			// about what is plugged into it, and the port the sensor received
			// the copy on is not necessarily the port named here.
			if len(val) < 2 {
				continue
			}
			sub, id := val[0], val[1:]
			port := ""
			if sub == lldpPortSubMAC {
				port = MACFromBytes(id)
			} else {
				port = boundIdentifier(string(id))
			}
			if port != "" {
				obs.setAttr("lldp_port_id", port)
			}

		case lldpTLVPortDesc:
			if s := boundIdentifier(string(val)); s != "" {
				obs.setAttr("lldp_port_description", s)
			}

		case lldpTLVSysName:
			obs.addName(string(val))

		case lldpTLVSysDesc:
			if s := boundText(string(val)); s != "" {
				obs.setAttr("lldp_system_description", s)
			}

		case lldpTLVSysCaps:
			// available(2) enabled(2). Only the ENABLED set is recorded: what
			// a device is capable of is a product-datasheet fact, what it has
			// turned on is a fact about this deployment.
			if len(val) < 4 {
				continue
			}
			enabled, _ := be16(val, 2)
			if caps := decodeCapabilityBits(uint32(enabled), lldpCapabilityNames); len(caps) > 0 {
				obs.setAttr("lldp_capabilities", caps)
			}

		case lldpTLVMgmtAddr:
			// addrlen(1) covers subtype(1)+address; then ifsubtype(1)
			// ifnumber(4) oidlen(1) oid.
			if len(val) < 2 {
				continue
			}
			alen := int(val[0])
			if alen < 2 || 1+alen > len(val) {
				continue
			}
			if a, ok := lldpAddrFromIANA(val[1], val[2:1+alen]); ok {
				obs.addAddr(a)
			}

		case lldpTLVOrgSpec:
			// oui(3) subtype(1) then the value. Only the LLDP-MED inventory
			// model and manufacturer are read; every other organisationally
			// specific TLV — 802.1 VLAN, 802.3 power, and whatever a vendor
			// invented — is stepped over structurally, the same positive
			// allowlist the DHCP option reader uses.
			if len(val) < 4 {
				continue
			}
			if val[0] != lldpMEDOUI[0] || val[1] != lldpMEDOUI[1] || val[2] != lldpMEDOUI[2] {
				continue
			}
			switch val[3] {
			case lldpMEDSubtypeModel:
				if m := boundIdentifier(string(val[4:])); m != "" {
					obs.Model = m
				}
			case lldpMEDSubtypeManufacturer:
				// Kept as evidence only. hw.vendor stays OUI-derived (the
				// platform resolves it from the MAC at ingestion): a
				// MED manufacturer string is whatever the firmware author
				// typed, and two sources for one fact is how a device ends
				// up filed under two vendors.
				if m := boundIdentifier(string(val[4:])); m != "" {
					obs.setAttr("lldp_med_manufacturer", m)
				}
			}
		}
	}

	if !sawChassis {
		// A TLV stream with no chassis ID is not an LLDPDU — the standard
		// makes the first three TLVs mandatory and in order.
		return nil, ErrNotApplicable
	}

	// Fall back to the Ethernet source when the chassis ID was not a MAC, in
	// either the MAC subtype or a MAC written as text: the frame still came
	// from the advertiser's port.
	if obs.MAC == "" {
		obs.MAC = NormalizeMAC(f.SrcMAC)
	} else if chassisFromText {
		// The text displaced the source as the subject's MAC, and the source is
		// still the advertiser's own: the port its ARP and DHCP frames on this
		// segment carry. A multi-port device's frames can only meet on one
		// record if both addresses reach the platform. Under the MAC subtype
		// this decoder never read the source, and it still does not.
		if src := NormalizeMAC(f.SrcMAC); src != "" && src != obs.MAC {
			obs.setAttr(AttrLLDPSourceMAC, src)
		}
	}

	obs.Finalize()
	if !obs.Identifies() {
		return nil, ErrNotApplicable
	}
	return obs, nil
}

// AttrLLDPSourceMAC is the attribute holding an LLDP frame's Ethernet source
// MAC when the chassis ID, written as text, took the subject's MAC field. It is
// the advertiser's own sending port, never a neighbour's address.
const AttrLLDPSourceMAC = "lldp_source_mac"

// lldpMACFromText returns s as a normalised MAC address when it is written in
// one of the three common MAC spellings — six two-digit groups separated by
// ':' or by '-' (one separator throughout), or three four-digit groups
// separated by '.' — and "" otherwise.
//
// The shape is checked here rather than left to [NormalizeMAC], which skips
// separators wherever they fall: an operator-chosen chassis string is free
// text, and only a value that is unmistakably a MAC may become the identity
// the device is keyed on. Twelve bare hex digits are refused for the same
// reason: they are as likely a serial number as an address.
func lldpMACFromText(s string) string {
	isHex := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	}
	var group int
	var sep byte
	switch len(s) {
	case 17: // aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff
		group, sep = 2, s[2]
		if sep != ':' && sep != '-' {
			return ""
		}
	case 14: // aabb.ccdd.eeff
		group, sep = 4, '.'
	default:
		return ""
	}
	for i := 0; i < len(s); i++ {
		if (i+1)%(group+1) == 0 {
			if s[i] != sep {
				return ""
			}
			continue
		}
		if !isHex(s[i]) {
			return ""
		}
	}
	return NormalizeMAC(s)
}

// lldpAddrFromIANA converts an IANA address-family-numbered address (1 = IPv4,
// 2 = IPv6) to a netip.Addr.
func lldpAddrFromIANA(family byte, raw []byte) (netip.Addr, bool) {
	switch family {
	case 1:
		if len(raw) < 4 {
			return netip.Addr{}, false
		}
		return addrFromBytes(raw[:4])
	case 2:
		if len(raw) < 16 {
			return netip.Addr{}, false
		}
		return addrFromBytes(raw[:16])
	}
	return netip.Addr{}, false
}

// decodeCapabilityBits turns a bitmask into the names of the set bits, bounded
// by MaxCapabilities. Bits the standard has not assigned are dropped rather
// than rendered as a position: a reserved bit set by a buggy implementation is
// not a capability, and inventing "bit_17" as a device attribute would put
// noise into the classifier's feature set.
func decodeCapabilityBits(mask uint32, names []string) []string {
	out := make([]string, 0, MaxCapabilities)
	for i := 0; i < 32 && len(out) < MaxCapabilities; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		if i < len(names) {
			out = append(out, names[i])
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
