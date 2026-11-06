// Package ifselect decides which capture devices the sensor opens: it resolves
// the names an operator configures to capture devices, and picks devices when
// none is configured.
//
// It is pure (no libpcap, no system calls) so it is tested on every OS with
// lists of devices and adapters as input. The callers gather those lists:
// internal/sensor/capture asks libpcap (Npcap on Windows) for the capture
// devices and the OS for its network adapters.
//
// Why both lists: on Windows the names differ. Npcap names a device
// `\Device\NPF_{GUID}` and describes it with the adapter's description
// ("Intel(R) Ethernet Connection I219-V"), while Windows, and the sensor's own
// interface report (net.Interfaces), call the same adapter by its friendly
// name ("Ethernet 2"). The adapter's GUID joins the two. On Linux and macOS the
// device name is the interface name, and there is no adapter list.
package ifselect

import (
	"fmt"
	"net"
	"strings"
)

// Device is a capture device as libpcap (or Npcap on Windows) names it.
type Device struct {
	Name        string
	Description string
	Addresses   []net.IP
	// Loopback and Up come from libpcap's device flags.
	Loopback bool
	Up       bool
}

// Adapter is a network adapter as the operating system names it. Only
// Windows supplies adapters (GetAdaptersAddresses); elsewhere the list is
// empty and the device names are the interface names.
type Adapter struct {
	// GUID is the adapter's name in GetAdaptersAddresses, "{...}" with the
	// braces. Npcap's device for it is `\Device\NPF_` + GUID.
	GUID string
	// FriendlyName is what Windows shows and net.Interfaces reports ("Ethernet 2").
	FriendlyName string
	// Description is the driver's description ("Intel(R) Ethernet Connection").
	Description string
	Up          bool
	// Loopback and Tunnel adapters are never chosen automatically.
	Loopback  bool
	Tunnel    bool
	Addresses []net.IP
}

// Resolution maps one configured name to the capture device it means.
type Resolution struct {
	Configured string
	Device     string
}

// Label names a device for a person: its device name and, where they are
// known, the adapter's friendly name and description, which are also names
// Resolve accepts.
func Label(dev Device, adapters []Adapter) string {
	var parts []string
	if a, ok := adapterForDevice(dev.Name, adapters); ok {
		if a.FriendlyName != "" {
			parts = append(parts, fmt.Sprintf("%q", a.FriendlyName))
		}
		if a.Description != "" {
			parts = append(parts, a.Description)
		}
	} else if dev.Description != "" {
		parts = append(parts, dev.Description)
	}
	if len(parts) == 0 {
		return dev.Name
	}
	return fmt.Sprintf("%s (%s)", dev.Name, strings.Join(parts, ", "))
}

// Labels is Label for every device, in order.
func Labels(devs []Device, adapters []Adapter) []string {
	out := make([]string, 0, len(devs))
	for _, d := range devs {
		out = append(out, Label(d, adapters))
	}
	return out
}

// Resolve maps a configured interface name to a capture device name. For one
// adapter it accepts, in this order:
//
//  1. the capture device name itself (`\Device\NPF_{GUID}`, `eth0`), exactly
//     and then ignoring case. An exact name wins across every device before
//     anything else is tried: on Linux most devices have no description, and a
//     fuzzy match must never shadow an exact one further down the list;
//  2. the adapter's friendly name ("Ethernet 2", what the sensor reports as
//     its available interfaces), its GUID with or without braces, or its
//     description, ignoring case;
//  3. the capture device's description, ignoring case;
//  4. as before this package existed, a part of a device description
//     ("Realtek"), but only when exactly one device matches: an ambiguous
//     fragment is an error rather than the first device that happens to match.
func Resolve(want string, devs []Device, adapters []Adapter) (string, error) {
	name := strings.TrimSpace(want)
	if name == "" {
		return "", fmt.Errorf("an empty interface name matches no capture device")
	}
	for _, d := range devs {
		if d.Name == name {
			return d.Name, nil
		}
	}
	for _, d := range devs {
		if strings.EqualFold(d.Name, name) {
			return d.Name, nil
		}
	}

	bare := strings.Trim(name, "{}")
	for _, a := range adapters {
		guid := strings.Trim(a.GUID, "{}")
		byName := strings.EqualFold(a.FriendlyName, name)
		byGUID := guid != "" && strings.EqualFold(guid, bare)
		if !byName && !byGUID {
			continue
		}
		if dev, ok := deviceForAdapter(a, devs); ok {
			return dev, nil
		}
		return "", fmt.Errorf("interface %q is the adapter %s, which has no capture device: Npcap does not capture on it (it may be disabled, or Npcap was installed before the adapter was added). Capture devices: %v",
			want, a.GUID, Labels(devs, adapters))
	}
	if dev, ok := uniqueMatch(devs, func(d Device) bool {
		a, ok := adapterForDevice(d.Name, adapters)
		return ok && a.Description != "" && strings.EqualFold(a.Description, name)
	}); ok {
		return dev, nil
	}
	if dev, ok := uniqueMatch(devs, func(d Device) bool {
		return d.Description != "" && strings.EqualFold(d.Description, name)
	}); ok {
		return dev, nil
	}

	lower := strings.ToLower(name)
	var fragment []string
	for _, d := range devs {
		desc := strings.ToLower(d.Description)
		if desc == "" {
			continue
		}
		if strings.Contains(desc, lower) || strings.Contains(lower, desc) {
			fragment = append(fragment, d.Name)
		}
	}
	switch len(fragment) {
	case 1:
		return fragment[0], nil
	case 0:
		return "", fmt.Errorf("interface %q matches no capture device. Name one by its device name, adapter name or description: %v",
			want, Labels(devs, adapters))
	default:
		return "", fmt.Errorf("interface %q matches %d capture devices %v; name one exactly: %v",
			want, len(fragment), fragment, Labels(devs, adapters))
	}
}

// Unresolved is a configured name that matches no capture device.
type Unresolved struct {
	Configured string
	Err        error
}

// ResolveAll resolves every configured name. Names that resolve come back in
// configured order, without a device twice; each name that does not resolve
// comes back with its error, so a caller can capture on the rest.
func ResolveAll(configured []string, devs []Device, adapters []Adapter) ([]Resolution, []Unresolved) {
	var out []Resolution
	var failed []Unresolved
	seen := map[string]bool{}
	for _, want := range configured {
		dev, err := Resolve(want, devs, adapters)
		if err != nil {
			failed = append(failed, Unresolved{Configured: want, Err: err})
			continue
		}
		if seen[dev] {
			continue
		}
		seen[dev] = true
		out = append(out, Resolution{Configured: want, Device: dev})
	}
	return out, failed
}

// AutoSelect picks the capture devices to open when the operator named none:
// every adapter (or, without an adapter list, every device) that is up, is
// not a loopback or tunnel, is not one of Windows' "WAN Miniport" pseudo
// devices, and has a usable address (not loopback, link-local or
// unspecified). The order is the adapters' (or devices') order.
//
// With adapters, a device is chosen only through its adapter: the adapter list
// is the authority on which adapters are up, since Npcap's device flags are not
// relied on to say so.
func AutoSelect(devs []Device, adapters []Adapter) []Resolution {
	var out []Resolution
	if len(adapters) > 0 {
		for _, a := range adapters {
			if !a.Up || a.Loopback || a.Tunnel || isPseudo(a.Description) || isPseudo(a.FriendlyName) || !hasUsableAddress(a.Addresses) {
				continue
			}
			dev, ok := deviceForAdapter(a, devs)
			if !ok {
				continue
			}
			name := a.FriendlyName
			if name == "" {
				name = dev
			}
			out = append(out, Resolution{Configured: name, Device: dev})
		}
		return out
	}
	for _, d := range devs {
		if !d.Up || d.Loopback || isPseudo(d.Description) || isPseudo(d.Name) || !hasUsableAddress(d.Addresses) {
			continue
		}
		out = append(out, Resolution{Configured: d.Name, Device: d.Name})
	}
	return out
}

// isPseudo reports names of devices that carry no capturable traffic of
// their own: Windows' WAN Miniport adapters and Npcap's loopback adapter.
func isPseudo(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "wan miniport") || strings.Contains(n, "loopback")
}

func hasUsableAddress(ips []net.IP) bool {
	for _, ip := range ips {
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		return true
	}
	return false
}

// deviceForAdapter finds the Npcap device of an adapter: the device whose
// name ends in the adapter's GUID (`\Device\NPF_{GUID}`).
func deviceForAdapter(a Adapter, devs []Device) (string, bool) {
	guid := strings.ToLower(strings.Trim(a.GUID, "{}"))
	if guid == "" {
		return "", false
	}
	for _, d := range devs {
		if deviceGUID(d.Name) == guid {
			return d.Name, true
		}
	}
	return "", false
}

func adapterForDevice(device string, adapters []Adapter) (Adapter, bool) {
	guid := deviceGUID(device)
	if guid == "" {
		return Adapter{}, false
	}
	for _, a := range adapters {
		if strings.ToLower(strings.Trim(a.GUID, "{}")) == guid {
			return a, true
		}
	}
	return Adapter{}, false
}

// deviceGUID is the lower-case GUID in `\Device\NPF_{GUID}`, or "".
func deviceGUID(device string) string {
	open := strings.LastIndex(device, "{")
	if open < 0 || !strings.HasSuffix(device, "}") {
		return ""
	}
	return strings.ToLower(device[open+1 : len(device)-1])
}

func uniqueMatch(devs []Device, match func(Device) bool) (string, bool) {
	found := ""
	for _, d := range devs {
		if !match(d) {
			continue
		}
		if found != "" {
			return "", false
		}
		found = d.Name
	}
	return found, found != ""
}
