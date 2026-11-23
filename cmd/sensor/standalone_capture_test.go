package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/models"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/outputschema"
)

// testServerCert is a self-signed ECDSA certificate for svc.example.test.
func testServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "svc.example.test"}, DNSNames: []string{"svc.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// flightRecorder keeps every write of one side of a connection, in order.
type flightRecorder struct {
	net.Conn
	mu      *sync.Mutex
	fromCli bool
	chunks  *[]chunk
}

type chunk struct {
	fromClient bool
	data       []byte
}

func (r *flightRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	*r.chunks = append(*r.chunks, chunk{fromClient: r.fromCli, data: append([]byte(nil), b...)})
	r.mu.Unlock()
	return r.Conn.Write(b)
}

// realTLS12Handshake runs a real crypto/tls handshake (TLS 1.2, so the
// certificate travels in clear) over an in-memory pipe and returns the bytes
// each side wrote, in order.
func realTLS12Handshake(t *testing.T) []chunk {
	t.Helper()
	cliConn, srvConn := net.Pipe()
	var mu sync.Mutex
	var chunks []chunk
	srv := tls.Server(&flightRecorder{Conn: srvConn, mu: &mu, chunks: &chunks},
		&tls.Config{Certificates: []tls.Certificate{testServerCert(t)}, MaxVersion: tls.VersionTLS12})
	cli := tls.Client(&flightRecorder{Conn: cliConn, mu: &mu, fromCli: true, chunks: &chunks},
		&tls.Config{ServerName: "svc.example.test", InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}) //nolint:gosec // a test handshake against its own certificate
	errs := make(chan error, 1)
	go func() { errs <- srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	// Close the pipe, not the TLS connections: a close_notify would block on
	// a pipe nobody reads, and it is not part of the handshake.
	_ = cliConn.Close()
	_ = srvConn.Close()
	return chunks
}

// writeHandshakePcap writes one TCP connection per server address carrying
// the recorded handshake, from a client in a private test range.
func writeHandshakePcap(t *testing.T, servers ...string) string {
	t.Helper()
	chunks := realTLS12Handshake(t)
	path := filepath.Join(t.TempDir(), "handshake.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	const client, clientPort = "10.0.0.10", 50000
	for _, server := range servers {
		cliSeq, srvSeq := uint32(1000), uint32(5000)
		emit := func(fromClient, syn, fin bool, payload []byte) {
			src, dst, sport, dport, seq, ack := client, server, clientPort, 443, cliSeq, srvSeq
			if !fromClient {
				src, dst, sport, dport, seq, ack = server, client, 443, clientPort, srvSeq, cliSeq
			}
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
			tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), Seq: seq, Ack: ack, SYN: syn, FIN: fin,
				ACK: !(syn && fromClient), PSH: len(payload) > 0, Window: 65535}
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
				t.Fatal(err)
			}
			ts = ts.Add(time.Millisecond)
			if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()); err != nil {
				t.Fatal(err)
			}
			n := uint32(len(payload))
			if syn || fin {
				n++
			}
			if fromClient {
				cliSeq += n
			} else {
				srvSeq += n
			}
		}
		emit(true, true, false, nil)
		emit(false, true, false, nil)
		for _, c := range chunks {
			for data := c.data; len(data) > 0; {
				n := min(len(data), 1400)
				emit(c.fromClient, false, false, data[:n])
				data = data[n:]
			}
		}
		emit(true, false, true, nil)
		emit(false, false, true, nil)
	}
	return path
}

// runCmd runs a standalone command and returns its exit status, standard
// output and standard error.
func runCmd(t *testing.T, env standaloneEnv, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env.stdout, env.stderr = &stdout, &stderr
	if env.ctx == nil {
		env.ctx = context.Background()
	}
	code := runStandalone(env, args)
	return code, stdout.String(), stderr.String()
}

type record struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

func records(t *testing.T, jsonl []byte) []record {
	t.Helper()
	outputschema.ValidateJSONL(t, jsonl)
	var out []record
	for _, line := range bytes.Split(bytes.TrimSpace(jsonl), []byte("\n")) {
		var r record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

type passiveData struct {
	DestIP      string         `json:"dest_ip"`
	Port        int            `json:"port"`
	Protocol    string         `json:"protocol"`
	Version     string         `json:"version"`
	CipherSuite string         `json:"cipher_suite"`
	RawMetadata map[string]any `json:"raw_metadata"`
}

func TestStandaloneCaptureReadsAPcap(t *testing.T) {
	pcap := writeHandshakePcap(t, "10.0.0.20")
	out := filepath.Join(t.TempDir(), "out.jsonl")
	code, _, stderr := runCmd(t, standaloneEnv{}, "capture", "--pcap", pcap, "--out", out)
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	recs := records(t, data)
	if recs[0].Kind != "run" || recs[len(recs)-1].Kind != "summary" {
		t.Fatalf("first/last kinds = %s/%s", recs[0].Kind, recs[len(recs)-1].Kind)
	}
	var found bool
	for _, r := range recs {
		if r.Kind != "passive_observation" {
			continue
		}
		var d passiveData
		if err := json.Unmarshal(r.Data, &d); err != nil {
			t.Fatal(err)
		}
		if d.Protocol == "TLS" && d.DestIP == "10.0.0.20" && d.Port == 443 {
			found = true
			if d.Version != "TLS 1.2" || !strings.HasPrefix(d.CipherSuite, "TLS_ECDHE_ECDSA_") {
				t.Errorf("version %q cipher %q", d.Version, d.CipherSuite)
			}
		}
	}
	if !found {
		t.Fatalf("no TLS passive_observation for 10.0.0.20:443 in:\n%s", data)
	}
	if !strings.Contains(stderr, "capture file "+pcap+": ") || !strings.Contains(stderr, "packets") {
		t.Errorf("summary does not say what was read:\n%s", stderr)
	}
}

func TestStandaloneCaptureCSVHasTheEndpoint(t *testing.T) {
	pcap := writeHandshakePcap(t, "10.0.0.20")
	code, stdout, stderr := runCmd(t, standaloneEnv{}, "capture", "--pcap", pcap, "--format", "csv", "--quiet")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	rows, err := csv.NewReader(strings.NewReader(stdout)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	var found bool
	for _, r := range rows[1:] {
		if r[col["address"]] == "10.0.0.20" && r[col["port"]] == "443" && r[col["protocol"]] == "TLS" {
			found = true
			for name, want := range map[string]string{
				"kind": "passive_observation", "host": "svc.example.test", "transport": "tcp",
				"protocol_version": "TLS 1.2", "certificate_subject": "CN=svc.example.test",
				"certificate_key_algorithm": "ECDSA",
			} {
				if got := r[col[name]]; got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			if r[col["cipher_suite"]] == "" || r[col["certificate_fingerprint_sha256"]] == "" || r[col["certificate_not_after"]] == "" {
				t.Errorf("endpoint row is missing the cipher or certificate: %v", r)
			}
		}
	}
	if !found {
		t.Fatalf("no endpoint row for 10.0.0.20:443:\n%s", stdout)
	}
	if stderr != "" {
		t.Errorf("--quiet still wrote to stderr: %q", stderr)
	}
}

// observationKeys is a run's passive observations without ids, timestamps
// and session ids, sorted, so two runs over one file compare equal exactly
// when they observed the same things.
func observationKeys(t *testing.T, jsonl []byte) []string {
	t.Helper()
	var keys []string
	for _, r := range records(t, jsonl) {
		if r.Kind != "passive_observation" {
			continue
		}
		var d passiveData
		if err := json.Unmarshal(r.Data, &d); err != nil {
			t.Fatal(err)
		}
		fp := ""
		if leaf := leafCertificate(d.RawMetadata["certificates"]); leaf != nil {
			fp = metaString(leaf, "fingerprint_sha256")
		}
		keys = append(keys, fmt.Sprintf("%s|%d|%s|%s|%s|%v|%s", d.DestIP, d.Port, d.Protocol, d.Version, d.CipherSuite, d.RawMetadata["sni"], fp))
	}
	sort.Strings(keys)
	return keys
}

func TestStandaloneCaptureIsRepeatable(t *testing.T) {
	var servers []string
	for i := 1; i <= 40; i++ {
		servers = append(servers, fmt.Sprintf("10.0.1.%d", i))
	}
	pcap := writeHandshakePcap(t, servers...)
	var runs [2][]string
	for i := range runs {
		code, stdout, stderr := runCmd(t, standaloneEnv{}, "capture", "--pcap", pcap, "--quiet")
		if code != 0 {
			t.Fatalf("run %d: exit %d; stderr:\n%s", i, code, stderr)
		}
		runs[i] = observationKeys(t, []byte(stdout))
	}
	if len(runs[0]) < len(servers) {
		t.Fatalf("first run has %d observations for %d connections", len(runs[0]), len(servers))
	}
	if strings.Join(runs[0], "\n") != strings.Join(runs[1], "\n") {
		t.Fatalf("two runs over one file differ:\n%v\n---\n%v", runs[0], runs[1])
	}
}

func TestStandaloneCaptureRefusesBadFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"capture"}, "--pcap FILE, or --interface IF --duration D"},
		{[]string{"capture", "--pcap", "x.pcap", "--interface", "eth0", "--duration", "1s"}, "cannot be used together"},
		{[]string{"capture", "--interface", "eth0"}, "--interface needs --duration"},
		{[]string{"capture", "--pcap", "x.pcap", "--duration", "1s"}, "--duration applies to --interface only"},
		{[]string{"capture", "--pcap", "x.pcap", "--format", "xml"}, "unknown output format"},
		{[]string{"capture", "--nonsense"}, "flag provided but not defined"},
	} {
		code, stdout, stderr := runCmd(t, standaloneEnv{}, tc.args...)
		if code != 1 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d, stderr %q; want 1 and %q", tc.args, code, stderr, tc.want)
		}
		if stdout != "" {
			t.Errorf("%v: refused before any work, yet wrote output %q", tc.args, stdout)
		}
	}
}

func TestStandaloneCaptureUnopenableFileIsAnErrorRecord(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pcap")
	if err := os.WriteFile(bad, []byte("not a capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runCmd(t, standaloneEnv{}, "capture", "--pcap", bad, "--quiet")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	var sawError bool
	for _, r := range records(t, []byte(stdout)) {
		if r.Kind == "error" && strings.Contains(string(r.Data), "cannot open capture file") {
			sawError = true
		}
	}
	if !sawError {
		t.Fatalf("no error record:\n%s", stdout)
	}
}

func TestStandaloneHelpListsEveryFlagAndSaysNoPlatform(t *testing.T) {
	for cmd, flags := range map[string][]string{
		"capture": {"-pcap", "-interface", "-duration", "-out", "-format", "-quiet"},
	} {
		code, _, stderr := runCmd(t, standaloneEnv{}, cmd, "--help")
		if code != 0 {
			t.Errorf("%s --help: exit %d", cmd, code)
		}
		for _, f := range flags {
			if !strings.Contains(stderr, f) {
				t.Errorf("%s --help does not list %s", cmd, f)
			}
		}
		if !strings.Contains(stderr, "contacts no Vista Platform") {
			t.Errorf("%s --help does not say it contacts no platform", cmd)
		}
	}
}

func TestStandaloneCommandDispatch(t *testing.T) {
	for args, want := range map[string]bool{
		"capture": true, "": false, "-version": false, "-config x": false, "collect": false,
	} {
		if got := standaloneCommand(strings.Fields(args)); got != want {
			t.Errorf("standaloneCommand(%q) = %v, want %v", args, got, want)
		}
	}
}

func TestEndpointsOfHostObservationHasNone(t *testing.T) {
	for _, d := range []*models.CryptoDiscovery{
		nil,
		{DestIP: "10.0.0.9", DiscoveryType: "host_observation", Protocol: "ARP"},
		{DestIP: "10.0.0.9", Protocol: "LLDP"},
	} {
		if got := endpointsOf(d); got != nil {
			t.Errorf("endpointsOf(%+v) = %v, want no endpoint", d, got)
		}
	}
	got := endpointsOf(&models.CryptoDiscovery{DestIP: "10.0.0.9", Port: 500, Protocol: "IKE", DiscoveryMethod: "passive"})
	if len(got) != 1 || got[0].Transport != "udp" || got[0].Port != 500 {
		t.Errorf("IKE endpoint = %+v", got)
	}
}
