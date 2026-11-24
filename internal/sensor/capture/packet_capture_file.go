package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
)

// fileFlushEvery is how many packets RunFile reads between evictions of the
// flows that went idle in packet time, so a long file does not hold every
// connection it ever saw open until the end.
const fileFlushEvery = 1024

// RunFile decodes a capture file (pcap or pcapng, whatever libpcap opens)
// through the same filter and decoders as live capture, then runs Stop: every
// reassembly buffer is flushed and the discoveries channel is closed. The
// caller drains GetDiscoveries concurrently, as it does for live capture; the
// channel is closed whatever RunFile returns.
//
// Unlike live capture nothing is dropped for speed. Packets are decoded in file
// order on the calling goroutine, and reading waits while the discoveries
// channel or the host-observation queue is half full, so the same file decodes
// to the same observations every run. Idle flows are evicted by packet time,
// never by the wall clock, for the same reason. Use NewFileCapture, whose
// discoveries channel holds the flush at the end of the file.
//
// Reading a file needs no capture privileges and sends nothing. Cancelling ctx
// stops reading; what was read is still flushed.
func (pc *PacketCapture) RunFile(ctx context.Context, path string) error {
	defer pc.Stop()
	handle, err := pcapOpenOffline(path)
	if err != nil {
		return fmt.Errorf("cannot open capture file %s: %w", path, err)
	}
	// Stop closes it with the live handles.
	pc.handles = append(pc.handles, handle)
	if err := handle.SetBPFFilter(buildBPFFilter(pc.config)); err != nil {
		return fmt.Errorf("cannot apply the capture filter to %s: %w", path, err)
	}
	pc.startDecoders()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	iface := filepath.Base(path)
	var latest time.Time
	var n int64
	for {
		if !pc.waitForHeadroom(ctx) {
			return nil
		}
		packet, err := source.NextPacket()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading %s stopped after %d packets: %w", path, n, err)
		}
		n++
		atomic.AddInt64(&pc.packetCount, 1)
		if ts := packet.Metadata().Timestamp; ts.After(latest) {
			latest = ts
		}
		pc.analyzePacket(packet, iface)
		if n%fileFlushEvery == 0 && !latest.IsZero() {
			pc.flushAssemblersOlderThan(latest.Add(-assemblerMaxIdle))
		}
	}
}

// waitForHeadroom blocks until the discoveries channel and the
// host-observation queue are at most half full, so the decoders' non-blocking
// hand-offs never find them full. It reports false when ctx ends first.
func (pc *PacketCapture) waitForHeadroom(ctx context.Context) bool {
	for {
		full := len(pc.discoveries) > cap(pc.discoveries)/2
		if pc.hostObs != nil && len(pc.hostObs.frames) > cap(pc.hostObs.frames)/2 {
			full = true
		}
		if !full {
			return ctx.Err() == nil
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
		}
	}
}
