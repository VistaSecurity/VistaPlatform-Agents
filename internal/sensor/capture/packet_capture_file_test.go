package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/models"
)

// writeTLSCapture writes a pcap holding n complete TLS 1.2 handshakes (SYN,
// SYN-ACK, ClientHello, the server flight with a certificate, FIN), each to
// its own server so the endpoint dedup reports every one.
func writeTLSCapture(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tls.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	var flight []byte
	flight = append(flight, handshakeRecord(0x02, buildServerHello(0x0303, 0xC02F, 0))...)
	flight = append(flight, handshakeRecord(0x0B, certificateMsg(testCertDER(t, "example.com")))...)
	flight = append(flight, handshakeRecord(0x0E, nil)...)
	serverFlight := tlsRecord(0x16, flight)
	clientFlight := clientHelloRecord()

	ts := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	write := func(p gopacket.Packet) {
		ts = ts.Add(time.Millisecond)
		ci := gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(p.Data()), Length: len(p.Data())}
		if err := w.WritePacket(ci, p.Data()); err != nil {
			t.Fatal(err)
		}
	}
	const clientISN, serverISN = uint32(1000), uint32(9000)
	for i := 0; i < n; i++ {
		server := fmt.Sprintf("10.1.%d.%d", i/250, i%250+1)
		write(tcpSegment(t, bidiClientIP, server, bidiClientPort, 443, clientISN, 0, true, nil))
		write(tcpSegment(t, server, bidiClientIP, 443, bidiClientPort, serverISN, clientISN+1, true, nil))
		write(tcpSegment(t, bidiClientIP, server, bidiClientPort, 443, clientISN+1, serverISN+1, false, clientFlight))
		write(tcpSegment(t, server, bidiClientIP, 443, bidiClientPort, serverISN+1, clientISN+1+uint32(len(clientFlight)), false, serverFlight))
	}
	return path
}

func fileCaptureConfig() *config.Config {
	cfg := &config.Config{SensorID: "test-sensor"}
	cfg.Capture.DedupTTLMinutes = 1
	return cfg
}

// runFile reads path and returns every discovery and RunFile's error. The
// collector stops only when the channel closes, so a RunFile that forgot to
// close it hangs the test rather than passing.
func runFile(t *testing.T, path string) ([]*models.CryptoDiscovery, error) {
	t.Helper()
	pc := NewFileCapture(fileCaptureConfig())
	done := make(chan []*models.CryptoDiscovery)
	go func() {
		var out []*models.CryptoDiscovery
		for d := range pc.GetDiscoveries() {
			out = append(out, d)
		}
		done <- out
	}()
	err := pc.RunFile(context.Background(), path)
	select {
	case out := <-done:
		return out, err
	case <-time.After(30 * time.Second):
		t.Fatal("the discoveries channel was not closed after RunFile")
		return nil, nil
	}
}

func TestRunFileDecodesATLSHandshake(t *testing.T) {
	got, err := runFile(t, writeTLSCapture(t, 1))
	if err != nil {
		t.Fatalf("RunFile: %v", err)
	}
	var tls []*models.CryptoDiscovery
	for _, d := range got {
		if d.Protocol == "TLS" {
			tls = append(tls, d)
		}
	}
	if len(tls) != 1 {
		t.Fatalf("got %d TLS discoveries, want 1", len(tls))
	}
	d := tls[0]
	if d.Version != "TLS 1.2" || d.CipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || d.Port != 443 {
		t.Errorf("discovery = %s %s port %d", d.Version, d.CipherSuite, d.Port)
	}
	if certs, _ := d.RawMetadata["certificates"].([]interface{}); len(certs) != 1 {
		t.Errorf("certificates = %v, want the one-cert chain", d.RawMetadata["certificates"])
	}
}

// Thousands of connections in one file: every one is reported, more than the
// live channel (1000) could hold, which is what a dropping pump or a
// too-small channel would lose.
func TestRunFileDropsNothing(t *testing.T) {
	const n = 2500
	got, err := runFile(t, writeTLSCapture(t, n))
	if err != nil {
		t.Fatalf("RunFile: %v", err)
	}
	servers := map[string]bool{}
	for _, d := range got {
		if d.Protocol == "TLS" && d.Version == "TLS 1.2" {
			servers[d.DestIP] = true
		}
	}
	if len(servers) != n {
		t.Fatalf("reported %d of %d servers", len(servers), n)
	}
}

func TestRunFileUnopenableFileClosesTheChannel(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "not-a-capture.pcap")
	if err := os.WriteFile(bad, []byte("this is not a capture file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runFile(t, bad); err == nil {
		t.Fatal("RunFile accepted a file that is not a capture")
	}
	if _, err := runFile(t, filepath.Join(t.TempDir(), "missing.pcap")); err == nil {
		t.Fatal("RunFile accepted a missing file")
	}
}

// Live capture keeps the channel depth it has always had; only a file reader
// gets the deep one.
func TestDiscoveryBufferDepths(t *testing.T) {
	if got := cap(NewPacketCapture(fileCaptureConfig()).discoveries); got != 1000 {
		t.Errorf("live discoveries channel holds %d, want 1000", got)
	}
	if got := cap(NewFileCapture(fileCaptureConfig()).discoveries); got != fileDiscoveryBuffer {
		t.Errorf("file discoveries channel holds %d, want %d", got, fileDiscoveryBuffer)
	}
}
