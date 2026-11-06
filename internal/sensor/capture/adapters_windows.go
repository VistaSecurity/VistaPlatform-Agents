//go:build windows

package capture

import (
	"errors"
	"net"
	"unsafe"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/capture/ifselect"
	"golang.org/x/sys/windows"
)

// hostAdapters lists the host's network adapters with GetAdaptersAddresses:
// the GUID that joins an adapter to its Npcap device (`\Device\NPF_{GUID}`),
// its friendly name ("Ethernet 2", what net.Interfaces and the sensor's
// interface report call it), its description, whether it is up, and its
// unicast addresses. Everything that decides anything is in package ifselect;
// this only copies the system's answer.
func hostAdapters() ([]ifselect.Adapter, error) {
	size := uint32(15000)
	var buf []byte
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size <= uint32(len(buf)) {
			return nil, err
		}
		if attempt == 3 {
			return nil, err
		}
	}
	var out []ifselect.Adapter
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		a := ifselect.Adapter{
			GUID:         windows.BytePtrToString(aa.AdapterName),
			FriendlyName: windows.UTF16PtrToString(aa.FriendlyName),
			Description:  windows.UTF16PtrToString(aa.Description),
			Up:           aa.OperStatus == windows.IfOperStatusUp,
			Loopback:     aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK,
			Tunnel:       aa.IfType == windows.IF_TYPE_TUNNEL,
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := ua.Address.IP(); ip != nil {
				a.Addresses = append(a.Addresses, append(net.IP(nil), ip...))
			}
		}
		out = append(out, a)
	}
	return out, nil
}
