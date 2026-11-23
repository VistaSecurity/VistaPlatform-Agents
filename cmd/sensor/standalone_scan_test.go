package main

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// scanNet is a scan's only network in these tests: every dial is recorded; an
// address registered with a port connects to a loopback listener, any other
// port of a registered host is refused like a real RST, and every other
// address gives no answer. Nothing leaves loopback.
type scanNet struct {
	t      *testing.T
	mu     sync.Mutex
	dials  []netip.AddrPort
	hosts  map[netip.Addr]map[uint16]string
	forbid bool // fail the test on any dial
}

func newScanNet(t *testing.T) *scanNet {
	return &scanNet{t: t, hosts: map[netip.Addr]map[uint16]string{}}
}

func (n *scanNet) host(addr string, ports map[uint16]string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ports == nil {
		ports = map[uint16]string{}
	}
	n.hosts[netip.MustParseAddr(addr)] = ports
}

func (n *scanNet) dialed() []netip.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []netip.Addr
	for _, ap := range n.dials {
		out = append(out, ap.Addr())
	}
	return out
}

type scanTimeout struct{}

func (scanTimeout) Error() string   { return "i/o timeout" }
func (scanTimeout) Timeout() bool   { return true }
func (scanTimeout) Temporary() bool { return true }

func (n *scanNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, errors.New("scanNet: not a literal address: " + address)
	}
	n.mu.Lock()
	n.dials = append(n.dials, ap)
	ports, up := n.hosts[ap.Addr().Unmap()]
	forbid := n.forbid
	n.mu.Unlock()
	if forbid {
		n.t.Errorf("dialled %s %s although the run should have sent nothing", network, address)
		return nil, errors.New("forbidden")
	}
	if !up || network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: scanTimeout{}}
	}
	real, ok := ports[ap.Port()]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", real)
}

// serveTestTLS listens on loopback with the svc.example.test certificate.
func serveTestTLS(t *testing.T) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{testServerCert(t)}})
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = c.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	return ln.Addr().String()
}

func scanEnv(n *scanNet, lookup map[string][]string) standaloneEnv {
	return standaloneEnv{
		dialer: n,
		lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			addrs, ok := lookup[host]
			if !ok {
				return nil, errors.New("no such host")
			}
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		},
	}
}

type scanHost struct {
	Target  string `json:"target"`
	Address string `json:"address"`
	TCP     []struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Result   *struct {
			TLSVersions  []string `json:"tls_versions"`
			Certificates []struct {
				SubjectDN string `json:"subject_dn"`
			} `json:"certificates"`
		} `json:"result"`
	} `json:"tcp"`
}

func TestStandaloneScanEndToEnd(t *testing.T) {
	n := newScanNet(t)
	n.host("10.0.0.5", map[uint16]string{443: serveTestTLS(t)})
	out := filepath.Join(t.TempDir(), "scan.jsonl")
	code, _, stderr := runCmd(t, scanEnv(n, nil), "scan", "--target", "10.0.0.5", "--depth", "quick", "--pace", "fast", "--out", out)
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var host *scanHost
	for _, r := range records(t, data) {
		if r.Kind == "scan_host" {
			host = &scanHost{}
			if err := json.Unmarshal(r.Data, host); err != nil {
				t.Fatal(err)
			}
		}
	}
	if host == nil || host.Address != "10.0.0.5" || host.Target != "10.0.0.5" {
		t.Fatalf("scan_host = %+v in:\n%s", host, data)
	}
	var tlsSeen bool
	for _, o := range host.TCP {
		if o.Port == 443 && o.Protocol == "TLS" && o.Result != nil && len(o.Result.Certificates) > 0 &&
			o.Result.Certificates[0].SubjectDN == "CN=svc.example.test" {
			tlsSeen = true
		}
	}
	if !tlsSeen {
		t.Fatalf("no identified TLS observation on 443:\n%s", data)
	}
	for _, a := range n.dialed() {
		if a != netip.MustParseAddr("10.0.0.5") {
			t.Errorf("dialled %s, which no target names", a)
		}
	}
	if !strings.Contains(stderr, "1 address in 1 target, depth quick, pace fast") {
		t.Errorf("summary scope missing:\n%s", stderr)
	}
}

func TestStandaloneScanCSVRow(t *testing.T) {
	n := newScanNet(t)
	n.host("10.0.0.5", map[uint16]string{443: serveTestTLS(t)})
	code, stdout, stderr := runCmd(t, scanEnv(n, map[string][]string{"svc.example.test": {"10.0.0.5"}}),
		"scan", "--target", "svc.example.test", "--depth", "quick", "--pace", "fast", "--format", "csv", "--quiet")
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
		if r[col["port"]] == "443" {
			found = true
			for name, want := range map[string]string{
				"kind": "scan_host", "host": "svc.example.test", "address": "10.0.0.5", "transport": "tcp",
				"protocol": "TLS", "certificate_subject": "CN=svc.example.test", "source": "scan",
			} {
				if got := r[col[name]]; got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			if r[col["protocol_version"]] == "" || r[col["cipher_suite"]] == "" {
				t.Errorf("row lacks the negotiated version or cipher: %v", r)
			}
		}
	}
	if !found {
		t.Fatalf("no 443 row:\n%s", stdout)
	}
}

func TestStandaloneScanResolvesOnceAndPins(t *testing.T) {
	n := newScanNet(t)
	n.host("10.0.0.7", nil)
	var lookups int
	env := scanEnv(n, nil)
	env.lookup = func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("10.0.0.7"), netip.MustParseAddr("fd00::7")}, nil
	}
	code, stdout, stderr := runCmd(t, env, "scan", "--target", "app.example.test", "--depth", "quick", "--pace", "fast", "--quiet")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	if lookups != 1 {
		t.Errorf("resolved %d times, want once", lookups)
	}
	recs := records(t, []byte(stdout))
	var run struct {
		Resolved map[string][]string `json:"resolved"`
	}
	if err := json.Unmarshal(recs[0].Data, &run); err != nil {
		t.Fatal(err)
	}
	if got := run.Resolved["app.example.test"]; len(got) != 1 || got[0] != "10.0.0.7" {
		t.Errorf("run.resolved = %v, want the pinned IPv4 address", run.Resolved)
	}
	for _, a := range n.dialed() {
		if a != netip.MustParseAddr("10.0.0.7") {
			t.Errorf("dialled %s, not the pinned address", a)
		}
	}
}

// A range is swept (liveness first) and nothing outside it is dialled.
func TestStandaloneScanRangeStaysInside(t *testing.T) {
	n := newScanNet(t)
	n.host("10.0.0.5", map[uint16]string{443: serveTestTLS(t)})
	code, _, stderr := runCmd(t, scanEnv(n, nil), "scan", "--target", "10.0.0.4-10.0.0.6", "--depth", "quick", "--pace", "fast", "--quiet")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	in := map[netip.Addr]bool{}
	for _, a := range []string{"10.0.0.4", "10.0.0.5", "10.0.0.6"} {
		in[netip.MustParseAddr(a)] = true
	}
	dialled := n.dialed()
	if len(dialled) == 0 {
		t.Fatal("nothing was dialled")
	}
	for _, a := range dialled {
		if !in[a] {
			t.Errorf("dialled %s outside 10.0.0.4-10.0.0.6", a)
		}
	}
}

func TestStandaloneScanPublicNeedsTheFlag(t *testing.T) {
	for _, target := range []string{"192.0.2.10", "198.51.100.0/30", "2001:db8::1", "pub.example.test"} {
		n := newScanNet(t)
		n.forbid = true
		env := scanEnv(n, map[string][]string{"pub.example.test": {"203.0.113.80"}})
		code, stdout, stderr := runCmd(t, env, "scan", "--target", target)
		if code != 1 || !strings.Contains(stderr, "--allow-public") || !strings.Contains(stderr, "authorised") {
			t.Errorf("%s: exit %d, stderr %q; want a usage error naming --allow-public", target, code, stderr)
		}
		if stdout != "" {
			t.Errorf("%s: wrote output before refusing: %q", target, stdout)
		}
	}

	n := newScanNet(t)
	code, stdout, stderr := runCmd(t, scanEnv(n, nil), "scan", "--target", "192.0.2.10", "--allow-public", "--depth", "thorough", "--pace", "fast", "--quiet")
	if code != 0 {
		t.Fatalf("with --allow-public: exit %d; stderr:\n%s", code, stderr)
	}
	if len(n.dialed()) == 0 {
		t.Fatal("with --allow-public nothing was dialled")
	}
	for _, a := range n.dialed() {
		if a != netip.MustParseAddr("192.0.2.10") {
			t.Errorf("dialled %s", a)
		}
	}
	// Public space is scanned at standard depth at most, and the run says so.
	if !strings.Contains(stdout, "scanned at standard, not thorough") {
		t.Errorf("the depth cap is not in the run record:\n%s", stdout[:min(len(stdout), 2000)])
	}
}

func TestStandaloneScanRefusesReservedEvenWhenNamed(t *testing.T) {
	for _, target := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.251", "255.255.255.255", "::1", "fe80::1"} {
		n := newScanNet(t)
		n.forbid = true
		code, stdout, stderr := runCmd(t, scanEnv(n, nil), "scan", "--target", target, "--depth", "quick", "--quiet")
		if code != 1 {
			t.Errorf("%s: exit %d, want 1; stderr %q", target, code, stderr)
		}
		var refused bool
		for _, r := range records(t, []byte(stdout)) {
			if r.Kind == "error" && strings.Contains(string(r.Data), "reserved address") {
				refused = true
			}
			if r.Kind == "scan_host" {
				t.Errorf("%s: a reserved address was scanned", target)
			}
		}
		if !refused {
			t.Errorf("%s: no reserved-address error record:\n%s", target, stdout)
		}
	}
}

func TestStandaloneScanRefusesBadTargetsBeforeAnything(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"scan"}, "name what to scan"},
		{[]string{"scan", "--target", "10.0.0.0/33"}, "not a CIDR range"},
		{[]string{"scan", "--target", "10.0.0.9-10.0.0.1"}, "ends before it starts"},
		{[]string{"scan", "--target", "not a host"}, "is not an address"},
		{[]string{"scan", "--target", "10.0.0.0/8"}, "too large"},
		{[]string{"scan", "--target", "10.0.0.1", "--depth", "custom"}, "--depth"},
		{[]string{"scan", "--target", "10.0.0.1", "--pace", "ludicrous"}, "pace"},
		{[]string{"scan", "--targets-file", "/nonexistent/targets.txt"}, "targets file"},
	} {
		n := newScanNet(t)
		n.forbid = true
		code, stdout, stderr := runCmd(t, scanEnv(n, nil), tc.args...)
		if code != 1 || !strings.Contains(stderr, tc.want) || stdout != "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want 1 and %q", tc.args, code, stdout, stderr, tc.want)
		}
	}
}

func TestStandaloneScanTargetsFileAndUnresolvedName(t *testing.T) {
	n := newScanNet(t)
	n.host("10.0.0.5", nil)
	file := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(file, []byte("# lab\n10.0.0.5   # the box\n\nmissing.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCmd(t, scanEnv(n, nil), "scan", "--targets-file", file, "--depth", "quick", "--pace", "fast", "--quiet")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (one name did not resolve); stderr:\n%s", code, stderr)
	}
	var hosts, errs int
	for _, r := range records(t, []byte(stdout)) {
		switch r.Kind {
		case "scan_host":
			hosts++
		case "error":
			if strings.Contains(string(r.Data), "missing.example.test") {
				errs++
			}
		}
	}
	if hosts != 1 || errs != 1 {
		t.Errorf("scan_host %d, resolve errors %d; want 1 and 1:\n%s", hosts, errs, stdout)
	}
}

func TestParseTargetsList(t *testing.T) {
	got, err := parseTargetsList(strings.NewReader("a.example.test\n  # only a comment\n10.0.0.1#x\n\n 10.0.0.0/30 \n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "a.example.test,10.0.0.1,10.0.0.0/30" {
		t.Errorf("got %v", got)
	}
}

func TestRangePrefixesCoverExactly(t *testing.T) {
	for _, tc := range []struct{ start, end, want string }{
		{"10.0.0.0", "10.0.0.255", "10.0.0.0/24"},
		{"10.0.0.4", "10.0.0.6", "10.0.0.4/31,10.0.0.6/32"},
		{"10.0.0.250", "10.0.1.2", "10.0.0.250/31,10.0.0.252/30,10.0.1.0/31,10.0.1.2/32"},
		{"10.0.0.7", "10.0.0.7", "10.0.0.7/32"},
		{"255.255.255.254", "255.255.255.255", "255.255.255.254/31"},
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
	} {
		var got []string
		for _, p := range rangePrefixes(netip.MustParseAddr(tc.start), netip.MustParseAddr(tc.end)) {
			got = append(got, p.String())
		}
		if strings.Join(got, ",") != tc.want {
			t.Errorf("%s-%s = %v, want %s", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestTargetIsPublic(t *testing.T) {
	for in, want := range map[string]bool{
		"10.1.2.3": false, "172.31.0.0/16": false, "192.168.1.1-192.168.1.9": false, "100.64.0.1": false, "fd12::1": false,
		"127.0.0.1": false, "169.254.169.254": false, // reserved: refused by the rule, not "public"
		"192.0.2.1": true, "172.32.0.1": true, "10.0.0.0/7": true, "2001:db8::/64": true, "192.168.255.250-192.169.0.1": true,
	} {
		tgt, err := parseScanTarget(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := targetIsPublic(tgt); got != want {
			t.Errorf("targetIsPublic(%s) = %v, want %v", in, got, want)
		}
	}
}
