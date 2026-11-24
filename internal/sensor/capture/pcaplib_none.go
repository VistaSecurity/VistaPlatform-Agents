//go:build nocapture

package capture

// A build without a packet capture library (tag nocapture): the sensor as it
// ships in a container image, where it runs scan jobs and never captures. It
// needs no CGO and no libpcap, so the image holds one static executable.
// Everything that would open a device or a capture file answers
// ErrNotBuilt; nothing here can read a packet.

import (
	"errors"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Built reports whether this build can capture packets and read capture
// files.
const Built = false

// ErrNotBuilt is the answer to every attempt to capture in this build.
var ErrNotBuilt = errors.New("this build of the sensor has no packet capture: it runs scans only (use a host installation of the sensor to capture)")

type pcapHandle struct{}

func (*pcapHandle) Close()                    {}
func (*pcapHandle) SetBPFFilter(string) error { return ErrNotBuilt }
func (*pcapHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (*pcapHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, ErrNotBuilt
}

type pcapInterfaceAddress struct{ IP net.IP }

type pcapInterface struct {
	Name        string
	Description string
	Flags       uint32
	Addresses   []pcapInterfaceAddress
}

const pcapBlockForever = time.Duration(-1)

func pcapOpenLive(string, int32, bool, time.Duration) (*pcapHandle, error) { return nil, ErrNotBuilt }
func pcapOpenOffline(string) (*pcapHandle, error)                          { return nil, ErrNotBuilt }
func pcapFindAllDevs() ([]pcapInterface, error)                            { return nil, ErrNotBuilt }
