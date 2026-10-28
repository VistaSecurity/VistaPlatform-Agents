package capture

import (
	"net"

	"github.com/gopacket/gopacket/pcap"
)

// Device is a capture device as libpcap (or Npcap on Windows) names it. Those
// names differ from net.Interfaces names on Windows, which is why callers
// outside this package ask here instead of importing the libpcap binding.
type Device struct {
	Name        string
	Description string
	Addresses   []net.IP
}

// ListDevices returns the capture devices libpcap reports, with their
// non-nil addresses in the order libpcap gives them.
func ListDevices() ([]Device, error) {
	found, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	devices := make([]Device, 0, len(found))
	for _, d := range found {
		dev := Device{Name: d.Name, Description: d.Description}
		for _, a := range d.Addresses {
			if a.IP != nil {
				dev.Addresses = append(dev.Addresses, a.IP)
			}
		}
		devices = append(devices, dev)
	}
	return devices, nil
}

// DeviceAddresses maps each capture device that has an address to its
// addresses as strings. It satisfies discovery.CaptureDeviceAddresses.
func DeviceAddresses() (map[string][]string, error) {
	devices, err := ListDevices()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, d := range devices {
		for _, ip := range d.Addresses {
			out[d.Name] = append(out[d.Name], ip.String())
		}
	}
	return out, nil
}
