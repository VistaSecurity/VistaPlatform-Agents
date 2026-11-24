//go:build !nocapture

package capture

// The packet capture library (libpcap, or Npcap on Windows), named once so
// that a build without it (pcaplib_none.go, tag nocapture) is a matter of two
// files and not of every file that opens a device.

import "github.com/gopacket/gopacket/pcap"

// Built reports whether this build can capture packets and read capture
// files. It is false only in a build with the nocapture tag.
const Built = true

type (
	pcapHandle    = pcap.Handle
	pcapInterface = pcap.Interface
)

const pcapBlockForever = pcap.BlockForever

var (
	pcapOpenLive    = pcap.OpenLive
	pcapOpenOffline = pcap.OpenOffline
	pcapFindAllDevs = pcap.FindAllDevs
)
