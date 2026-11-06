package ifselect

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func ips(s ...string) []net.IP {
	out := make([]net.IP, 0, len(s))
	for _, v := range s {
		out = append(out, net.ParseIP(v))
	}
	return out
}

// A Windows 11 host as Npcap 1.10 and GetAdaptersAddresses describe it: one
// wired adapter up, Wi-Fi up without an address, Hyper-V's switch, the WAN
// Miniport pseudo devices and Npcap's loopback adapter.
const (
	guidEth  = "{6B29FC40-CA47-1067-B31D-00DD010662DA}"
	guidWiFi = "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}"
	guidVEth = "{11111111-2222-3333-4444-555555555555}"
	guidWAN  = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
	guidTun  = "{99999999-8888-7777-6666-555555555555}"
)

var winDevices = []Device{
	{Name: `\Device\NPF_` + guidWAN, Description: "WAN Miniport (Network Monitor)"},
	{Name: `\Device\NPF_` + guidWiFi, Description: "Intel(R) Wi-Fi 6 AX201 160MHz", Addresses: ips("fe80::1")},
	{Name: `\Device\NPF_` + guidEth, Description: "Intel(R) Ethernet Connection (7) I219-V", Addresses: ips("fe80::2", "10.0.0.10")},
	{Name: `\Device\NPF_` + guidVEth, Description: "Hyper-V Virtual Ethernet Adapter", Addresses: ips("172.20.0.1")},
	{Name: `\Device\NPF_` + guidTun, Description: "Microsoft Teredo Tunneling Adapter", Addresses: ips("2001::1")},
	{Name: `\Device\NPF_Loopback`, Description: "Adapter for loopback traffic capture", Loopback: true, Up: true, Addresses: ips("127.0.0.1")},
}

var winAdapters = []Adapter{
	// GetAdaptersAddresses returns GUIDs in upper case; Npcap device names
	// may differ in case, which must not matter.
	{GUID: strings.ToLower(guidEth), FriendlyName: "Ethernet 2", Description: "Intel(R) Ethernet Connection (7) I219-V", Up: true, Addresses: ips("fe80::2", "10.0.0.10")},
	{GUID: guidWiFi, FriendlyName: "Wi-Fi", Description: "Intel(R) Wi-Fi 6 AX201 160MHz", Up: true, Addresses: ips("fe80::1", "169.254.10.10")},
	{GUID: guidVEth, FriendlyName: "vEthernet (Default Switch)", Description: "Hyper-V Virtual Ethernet Adapter", Up: true, Addresses: ips("172.20.0.1")},
	{GUID: guidWAN, FriendlyName: "Local Area Connection* 1", Description: "WAN Miniport (Network Monitor)", Up: true, Addresses: ips("10.99.0.1")},
	{GUID: guidTun, FriendlyName: "Teredo Tunneling Pseudo-Interface", Description: "Microsoft Teredo Tunneling Adapter", Up: true, Tunnel: true, Addresses: ips("2001::1")},
	{GUID: "{00000000-0000-0000-0000-000000000001}", FriendlyName: "Loopback Pseudo-Interface 1", Description: "Software Loopback Interface 1", Up: true, Loopback: true, Addresses: ips("127.0.0.1")},
	{GUID: "{DEADBEEF-0000-0000-0000-000000000000}", FriendlyName: "Ethernet 3", Description: "USB GbE", Up: false, Addresses: ips("10.1.1.1")},
}

var linuxDevices = []Device{
	{Name: "any", Description: "Pseudo-device that captures on all interfaces", Up: true},
	{Name: "lo", Loopback: true, Up: true, Addresses: ips("127.0.0.1")},
	{Name: "eth0", Up: true, Addresses: ips("10.0.0.5")},
	{Name: "eth1", Up: true},
	{Name: "wlan0", Up: false, Addresses: ips("10.0.1.5")},
}

func TestResolve(t *testing.T) {
	eth := `\Device\NPF_` + guidEth
	tests := []struct {
		name     string
		want     string
		devs     []Device
		adapters []Adapter
		device   string
		errHas   []string
	}{
		// What the issue saw: the name the sensor reports is refused.
		{"friendly name the sensor reports", "Ethernet 2", winDevices, winAdapters, eth, nil},
		{"friendly name ignores case", "ethernet 2", winDevices, winAdapters, eth, nil},
		{"device name", eth, winDevices, winAdapters, eth, nil},
		{"device name ignores case", strings.ToLower(eth), winDevices, winAdapters, eth, nil},
		{"adapter GUID with braces", guidEth, winDevices, winAdapters, eth, nil},
		{"adapter GUID without braces", strings.Trim(guidEth, "{}"), winDevices, winAdapters, eth, nil},
		{"adapter description", "Intel(R) Ethernet Connection (7) I219-V", winDevices, winAdapters, eth, nil},
		{"device description without adapters", "intel(r) ethernet connection (7) i219-v", winDevices, nil, eth, nil},
		{"unique description fragment", "Realtek", []Device{{Name: `\Device\NPF_{A}`, Description: "Intel(R) Ethernet"}, {Name: `\Device\NPF_{B}`, Description: "Realtek PCIe GbE"}}, nil, `\Device\NPF_{B}`, nil},
		{"ambiguous fragment is refused", "Intel", winDevices, winAdapters, "", []string{"matches 2 capture devices", "name one exactly"}},
		{"friendly name without a capture device", "Ethernet 3", winDevices, winAdapters, "", []string{"has no capture device", "Npcap"}},
		{"unknown name lists every accepted name", "Ethernet 9", winDevices, winAdapters, "", []string{"matches no capture device", `"Ethernet 2"`, eth, "Intel(R) Ethernet Connection (7) I219-V"}},
		{"empty name", "  ", winDevices, winAdapters, "", []string{"empty"}},
		// Linux: device name is the interface name; descriptions are mostly empty.
		{"linux exact name not shadowed by a description-less device", "eth1", linuxDevices, nil, "eth1", nil},
		{"linux exact name beats an earlier description match", "eth0", append([]Device{{Name: "br0", Description: "eth0 bridge"}}, linuxDevices...), nil, "eth0", nil},
		{"linux unknown name", "wlan9", linuxDevices, nil, "", []string{"matches no capture device", "eth0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.want, tc.devs, tc.adapters)
			if tc.errHas != nil {
				if err == nil {
					t.Fatalf("Resolve(%q) = %q, want an error", tc.want, got)
				}
				for _, s := range tc.errHas {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q does not contain %q", err, s)
					}
				}
				return
			}
			if err != nil || got != tc.device {
				t.Fatalf("Resolve(%q) = %q, %v; want %q", tc.want, got, err, tc.device)
			}
		})
	}
}

func TestAutoSelect(t *testing.T) {
	tests := []struct {
		name     string
		devs     []Device
		adapters []Adapter
		want     []Resolution
	}{
		{
			// Only the wired adapter and Hyper-V's switch are up with a
			// routable address. Wi-Fi has only link-local addresses; WAN
			// Miniport, Teredo, loopback and the down USB adapter are out.
			"windows host", winDevices, winAdapters,
			[]Resolution{
				{Configured: "Ethernet 2", Device: `\Device\NPF_` + guidEth},
				{Configured: "vEthernet (Default Switch)", Device: `\Device\NPF_` + guidVEth},
			},
		},
		{
			// Npcap reports no Up flag; with adapters, the adapters decide.
			"windows ignores device flags", winDevices, winAdapters[:1],
			[]Resolution{{Configured: "Ethernet 2", Device: `\Device\NPF_` + guidEth}},
		},
		{"windows adapter without a capture device is skipped", winDevices[:1], winAdapters, nil},
		{"windows with nothing usable", winDevices, winAdapters[3:], nil},
		{
			"no adapter list falls back to device flags", linuxDevices, nil,
			[]Resolution{{Configured: "eth0", Device: "eth0"}},
		},
		{"nothing at all", nil, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AutoSelect(tc.devs, tc.adapters)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("AutoSelect = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestResolveAll(t *testing.T) {
	eth := `\Device\NPF_` + guidEth
	got, failed := ResolveAll([]string{"Ethernet 2", eth, "nope", "Wi-Fi"}, winDevices, winAdapters)
	want := []Resolution{
		{Configured: "Ethernet 2", Device: eth},
		{Configured: "Wi-Fi", Device: `\Device\NPF_` + guidWiFi},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved = %+v, want %+v (one device once, in configured order)", got, want)
	}
	if len(failed) != 1 || failed[0].Configured != "nope" || !strings.Contains(failed[0].Err.Error(), `"nope"`) {
		t.Fatalf("failed = %v, want one error naming \"nope\"", failed)
	}
}

func TestLabel(t *testing.T) {
	got := Label(winDevices[2], winAdapters)
	want := `\Device\NPF_` + guidEth + ` ("Ethernet 2", Intel(R) Ethernet Connection (7) I219-V)`
	if got != want {
		t.Fatalf("Label = %q, want %q", got, want)
	}
	if got := Label(Device{Name: "eth0"}, nil); got != "eth0" {
		t.Fatalf("Label = %q, want eth0", got)
	}
}
