package capture

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
)

// Stop used to close pc.workers and then pc.discoveries straight away, while
// the workers were still analysing the packets left in the queue. A worker
// that then emitted a discovery sent on a closed channel and the sensor
// panicked at shutdown; one that did not get that far lost its packet. Stop
// must let the workers finish the queue before it closes anything they write
// to, so every queued packet is decoded and nothing panics.
func TestStopDrainsTheWorkerQueueBeforeClosingDiscoveries(t *testing.T) {
	const packets = 200
	pkts := make([]gopacket.Packet, packets)
	for i := range pkts {
		// A distinct destination each, so the UDP dedup keeps all of them.
		pkts[i] = wireGuardTo(t, net.IPv4(198, 51, 100, byte(i+1)))
	}

	for round := 0; round < 25; round++ {
		cfg := &config.Config{SensorID: "s"}
		cfg.Capture.EnableWireGuard = true
		cfg.Capture.DedupTTLMinutes = 1
		pc := NewPacketCapture(cfg)
		if cap(pc.workers) < packets || cap(pc.discoveries) < packets {
			t.Fatalf("buffers too small for the test: workers %d, discoveries %d", cap(pc.workers), cap(pc.discoveries))
		}
		for _, p := range pkts {
			pc.workers <- capturedPacket{pkt: p, iface: "eth0"}
		}
		pc.startWorkers(4)
		pc.Stop()

		got := 0
		for range pc.GetDiscoveries() {
			got++
		}
		if got != packets {
			t.Fatalf("round %d: %d discoveries after Stop, want %d (Stop closed the channel before the workers drained their queue)", round, got, packets)
		}
		pc.Stop() // a second Stop is a no-op, not a double close
	}
}

// wireGuardTo is a WireGuard handshake initiation to dst on UDP 51820.
func wireGuardTo(t *testing.T, dst net.IP) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IPv4(192, 0, 2, 10), DstIP: dst}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 51820}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, udp, gopacket.Payload(wgHandshakeInitiation())); err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Now()
	return p
}
