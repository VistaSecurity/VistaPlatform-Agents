package hostinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/facts"
)

func TestConnections_ExcludeAcceptedInboundAndIgnoreEphemeralLocalPort(t *testing.T) {
	listeners := []Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 443}}
	in := []Connection{
		// Accepted inbound client: an established socket on a proven listener.
		{Proto: "tcp", LocalAddress: "192.0.2.10", LocalPort: 443, RemoteAddress: "198.51.100.8", RemotePort: 53122, Process: "server"},
		// Same outbound peer observed with two different ephemeral ports. It is
		// one durable connection identity, not two rows per collection.
		{Proto: "tcp", LocalAddress: "192.0.2.10", LocalPort: 49152, RemoteAddress: "203.0.113.20", RemotePort: 443, Process: "browser", PID: 10},
		{Proto: "tcp", LocalAddress: "192.0.2.10", LocalPort: 61234, RemoteAddress: "203.0.113.20", RemotePort: 443, Process: "browser", PID: 11},
	}

	got := coalesceConnections(excludeAcceptedConnections(in, listeners), 256)
	if len(got) != 1 {
		t.Fatalf("connections = %+v, want one outbound peer", got)
	}
	if got[0].RemoteAddress != "203.0.113.20" || got[0].RemotePort != 443 {
		t.Fatalf("wrong peer survived: %+v", got[0])
	}
	projected := projectConnections(got)
	if _, ok := projected[0]["local_port"]; ok {
		t.Error("local ephemeral port reached the durable fact projection")
	}
	if _, ok := projected[0]["pid"]; ok {
		t.Error("process id reached the durable fact projection")
	}
}

func TestConnections_FailClosedWhenListenerSnapshotFailed(t *testing.T) {
	rep := &Report{Sections: map[string]string{SectionListeners: SectionFailed}}
	runner := newFakeLocal()
	collectLinuxConnections(context.Background(), runner, rep, Options{CollectConnections: true})
	if len(rep.Connections) != 0 || rep.SectionState(SectionConnections) != SectionFailed {
		t.Fatalf("connections=%+v section=%q; want no projection from an incomplete listener snapshot", rep.Connections, rep.SectionState(SectionConnections))
	}
	if runner.ran(linuxCmdConnections) {
		t.Error("connection command ran even though direction could not be resolved")
	}
}

func TestDarwinConnections_EmptyCompleteSnapshotAndPartialFailure(t *testing.T) {
	// Root, netstat unavailable: lsof's "no matches" is a measured empty.
	rep := &Report{Sections: map[string]string{SectionListeners: SectionOK}}
	runner := newFakeLocal()
	runner.cmdExit(darwinCmdLsofConnections, 1, "")
	runner.cmdExit(darwinCmdLsofUDP, 1, "")
	collectDarwinConnections(context.Background(), runner, rep, Options{CollectConnections: true}, darwinSockets{root: true})
	if !rep.SectionOK(SectionConnections) || rep.Connections == nil {
		t.Fatalf("valid empty lsof snapshot = state %q, value %#v; want measured empty", rep.SectionState(SectionConnections), rep.Connections)
	}

	rep = &Report{Sections: map[string]string{SectionListeners: SectionOK}}
	runner = newFakeLocal()
	runner.cmdExit(darwinCmdLsofConnections, 1, "")
	runner.cmdExit(darwinCmdLsofUDP, 1, "permission denied")
	collectDarwinConnections(context.Background(), runner, rep, Options{CollectConnections: true}, darwinSockets{root: true})
	if rep.SectionState(SectionConnections) != SectionFailed || len(rep.Connections) != 0 {
		t.Fatalf("partial lsof snapshot = state %q, value %#v; want failed with no projection", rep.SectionState(SectionConnections), rep.Connections)
	}

	// Not root, netstat unavailable: lsof could only see this account, so its
	// empty answer must not become "this host has no connections".
	rep = &Report{Sections: map[string]string{SectionListeners: SectionOK}}
	runner = newFakeLocal()
	runner.cmdExit(darwinCmdLsofConnections, 1, "")
	runner.cmdExit(darwinCmdLsofUDP, 1, "")
	collectDarwinConnections(context.Background(), runner, rep, Options{CollectConnections: true}, darwinSockets{})
	if rep.SectionState(SectionConnections) != SectionFailed {
		t.Fatalf("non-root lsof snapshot = state %q; want failed", rep.SectionState(SectionConnections))
	}
}

func TestConnections_RejectNonRoutablePeersAndApplyStableCap(t *testing.T) {
	in := []Connection{
		{Proto: "tcp", LocalAddress: "127.0.0.1", RemoteAddress: "203.0.113.2", RemotePort: 443},
		{Proto: "tcp", LocalAddress: "192.0.2.2", RemoteAddress: "127.0.0.1", RemotePort: 443},
		{Proto: "tcp", LocalAddress: "::ffff:192.0.2.2", RemoteAddress: "::ffff:127.0.0.1", RemotePort: 443},
		{Proto: "udp", LocalAddress: "192.0.2.2", RemoteAddress: "169.254.1.2", RemotePort: 53},
		{Proto: "tcp", LocalAddress: "192.0.2.2", RemoteAddress: "203.0.113.3", RemotePort: 443},
		{Proto: "tcp", LocalAddress: "192.0.2.2", RemoteAddress: "203.0.113.1", RemotePort: 443},
	}
	got := coalesceConnections(in, 1)
	if len(got) != 1 || got[0].RemoteAddress != "203.0.113.1" {
		t.Fatalf("bounded connections = %+v, want deterministic first routable peer", got)
	}
}

func TestBoundUDPSockets_ApplyStableCap(t *testing.T) {
	in := make([]BoundUDPSocket, 0, defaultMaxBoundUDP+10)
	for i := 0; i < defaultMaxBoundUDP+10; i++ {
		in = append(in, BoundUDPSocket{Address: "0.0.0.0", Port: 1000 + i, Process: fmt.Sprintf("p%d", i)})
	}
	got := coalesceBoundUDP(in)
	if len(got) != defaultMaxBoundUDP {
		t.Fatalf("bound UDP sockets = %d, want cap %d", len(got), defaultMaxBoundUDP)
	}
}

func TestBoundUDPSockets_PreserveUnknownRoleWithoutListenerClaim(t *testing.T) {
	listeners, bound := ParseSSBindings([]byte("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:49664 0.0.0.0:*\n"))
	if len(listeners) != 1 || listeners[0].Port != 49664 {
		t.Fatalf("TCP listener lost: %+v", listeners)
	}
	if len(bound) != 1 || bound[0].Port != 53 {
		t.Fatalf("UDP binding evidence lost: %+v", bound)
	}
	projected := projectBoundUDPSockets(bound)
	if projected[0]["role"] != "unknown" {
		t.Fatalf("UDP role = %v, want explicit unknown", projected[0]["role"])
	}
}

// A /proc/net port field is a uint16. A wider value is a malformed row and is
// refused, not truncated into some other port.
func TestParseProcHexAddr_PortIsSixteenBits(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantAddr string
		wantPort int
		wantOK   bool
	}{
		{"0100007F:01BB", "127.0.0.1", 443, true},
		{"0100007F:FFFF", "127.0.0.1", 65535, true},
		{"0100007F:10000", "", 0, false},
		{"0100007F:FFFFFFFF", "", 0, false},
	} {
		addr, port, ok := parseProcHexAddr(tc.in)
		if addr != tc.wantAddr || port != tc.wantPort || ok != tc.wantOK {
			t.Errorf("parseProcHexAddr(%q) = (%q, %d, %v), want (%q, %d, %v)",
				tc.in, addr, port, ok, tc.wantAddr, tc.wantPort, tc.wantOK)
		}
	}
}

// darwinSocketRunner answers the host-side commands an unprivileged service
// account's collection would make, with lsof seeing none of this account's
// sockets: exit 1 and no output, which is how macOS answers a caller that owns
// nothing.
func darwinSocketRunner(t *testing.T) *fakeRunner {
	t.Helper()
	f := newFakeLocal()
	f.cmd(darwinCmdNetstatTCP, fixture(t, "darwin", "netstat-tcp.txt"))
	f.cmd(darwinCmdNetstatUDP, fixture(t, "darwin", "netstat-udp.txt"))
	f.cmdExit(darwinCmdLsof, 1, "")
	f.cmdExit(darwinCmdLsofUDP, 1, "")
	f.cmdExit(darwinCmdLsofConnections, 1, "")
	f.cmd(darwinCmdID, "501\n")
	return f
}

// Mutation: read lsof first again → no listeners and section ok, red.
func TestDarwinListeners_AnUnprivilegedAccountSeesTheWholeHost(t *testing.T) {
	rep := &Report{}
	sockets := collectDarwinListeners(context.Background(), darwinSocketRunner(t), rep)
	if !rep.SectionOK(SectionListeners) || len(rep.Listeners) != 7 {
		t.Fatalf("listeners: state %q, %+v", rep.SectionState(SectionListeners), rep.Listeners)
	}
	if !rep.SectionOK(SectionBoundUDP) || len(rep.BoundUDPSockets) != 4 {
		t.Fatalf("bound UDP: state %q, %+v", rep.SectionState(SectionBoundUDP), rep.BoundUDPSockets)
	}
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %+v", rep.Errors)
	}
	collectDarwinConnections(context.Background(), newFakeLocal(), rep, Options{CollectConnections: true}, sockets)
	if !rep.SectionOK(SectionConnections) {
		t.Fatalf("connections: state %q, errors %+v", rep.SectionState(SectionConnections), rep.Errors)
	}
	// The socket from 198.51.100.50 arrived at the listener on 22, so it is not
	// an outbound connection; the link-local peer is not routable; the agent's
	// own call out and the UDP peer remain.
	if len(rep.Connections) != 2 {
		t.Errorf("connections: %+v", rep.Connections)
	}
}

// The defect this guards: netstat unavailable, not root, lsof sees nothing.
// That used to be `ok` with no listeners, on a host with listeners.
//
// Mutation: mark SectionOK in markLsofFallback regardless of root → red.
func TestDarwinListeners_NothingReadableIsNeverOK(t *testing.T) {
	f := darwinSocketRunner(t)
	f.cmdExit(darwinCmdNetstatTCP, 1, "")
	f.cmdExit(darwinCmdNetstatUDP, 1, "")
	rep := &Report{}
	collectDarwinListeners(context.Background(), f, rep)
	for _, section := range []string{SectionListeners, SectionBoundUDP} {
		if got := rep.SectionState(section); got != SectionPartial {
			t.Errorf("%s = %q, want %q", section, got, SectionPartial)
		}
	}
	if rep.SectionOK(SectionListeners) {
		t.Error("SectionOK reported true for a partial section")
	}
	if len(rep.Errors) != 2 || !strings.Contains(rep.Errors[0].Message, "non-root") {
		t.Errorf("a partial section must say why: %+v", rep.Errors)
	}
}

// What lsof could see is kept: every row is true, and only the absence of the
// rest means nothing.
func TestDarwinListeners_LsofFallbackKeepsWhatItSaw(t *testing.T) {
	f := darwinSocketRunner(t)
	f.cmdExit(darwinCmdNetstatTCP, 1, "")
	f.cmd(darwinCmdLsof, fixture(t, "darwin", "lsof.txt"))
	rep := &Report{}
	collectDarwinListeners(context.Background(), f, rep)
	if rep.SectionState(SectionListeners) != SectionPartial || len(rep.Listeners) != 4 {
		t.Fatalf("state %q, %+v", rep.SectionState(SectionListeners), rep.Listeners)
	}
	// UDP's netstat answered, so that section stays complete.
	if !rep.SectionOK(SectionBoundUDP) {
		t.Errorf("bound UDP: %q", rep.SectionState(SectionBoundUDP))
	}
}

// Root's lsof sees every process, so its answer is complete, and the fallback
// is still recorded.
func TestDarwinListeners_RootLsofIsComplete(t *testing.T) {
	f := darwinSocketRunner(t)
	f.cmdExit(darwinCmdNetstatTCP, 1, "")
	f.cmd(darwinCmdLsof, fixture(t, "darwin", "lsof.txt"))
	f.cmd(darwinCmdID, "0\n")
	rep := &Report{}
	collectDarwinListeners(context.Background(), f, rep)
	if !rep.SectionOK(SectionListeners) || len(rep.Listeners) != 4 || len(rep.Errors) != 1 {
		t.Fatalf("state %q, %+v, errors %+v", rep.SectionState(SectionListeners), rep.Listeners, rep.Errors)
	}
}

func TestDarwinListeners_NoAnswerFromEitherToolFails(t *testing.T) {
	f := darwinSocketRunner(t)
	f.cmdExit(darwinCmdNetstatTCP, 1, "")
	f.cmdExit(darwinCmdLsof, 1, "lsof: WARNING: something")
	rep := &Report{}
	collectDarwinListeners(context.Background(), f, rep)
	if rep.SectionState(SectionListeners) != SectionFailed || len(rep.Listeners) != 0 {
		t.Fatalf("state %q, %+v", rep.SectionState(SectionListeners), rep.Listeners)
	}
}

// A row netstat printed and the parser could not read may be a socket, so the
// section is partial, and partial licenses nothing: no fact, no connections.
//
// Mutation: mark SectionOK in markNetstatSection regardless → red.
func TestDarwinListeners_AnUnreadableRowIsPartial(t *testing.T) {
	f := darwinSocketRunner(t)
	f.cmd(darwinCmdNetstatTCP, fixture(t, "darwin", "netstat-tcp.txt")+
		"tcp6       0      0  2001:db8:ffff:.8443 *.* LISTEN 0 0 131072 131072 nginx:1203 00100\n")
	rep := &Report{}
	sockets := collectDarwinListeners(context.Background(), f, rep)
	if rep.SectionState(SectionListeners) != SectionPartial || len(rep.Listeners) != 7 {
		t.Fatalf("state %q, %+v", rep.SectionState(SectionListeners), rep.Listeners)
	}
	collectDarwinConnections(context.Background(), newFakeLocal(), rep, Options{CollectConnections: true}, sockets)
	if rep.SectionState(SectionConnections) != SectionFailed {
		t.Errorf("connections on a partial listener table: %q", rep.SectionState(SectionConnections))
	}
}

// Both keys reach the wire. They are omitempty, so an absent key means no rows,
// and on a Mac that was the visible symptom of lsof seeing none.
func TestCollectDarwin_SendsListenersAndBoundUDPThroughTheReport(t *testing.T) {
	f := darwinSocketRunner(t)
	rep := &Report{}
	collectDarwinListeners(context.Background(), f, rep)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"listeners":[`, `"bound_udp_sockets":[`, `"listeners":"ok"`, `"bound_udp_sockets":"ok"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("report JSON lacks %s: %s", key, b)
		}
	}
}

// The whole collector, on the platform path: the socket sections and the
// connection step are wired to netstat's snapshot.
//
// Mutation: drop the collectDarwinListeners call from collectDarwin → red.
func TestCollect_DarwinReadsSocketsFromNetstat(t *testing.T) {
	rep, err := Collect(context.Background(), darwinSocketRunner(t), Options{
		Mode: ModeLocal, Platform: PlatformDarwin, Now: fixedNow, CollectConnections: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.SectionOK(SectionListeners) || len(rep.Listeners) != 7 ||
		!rep.SectionOK(SectionBoundUDP) || !rep.SectionOK(SectionConnections) {
		t.Fatalf("sections %v, %d listeners", rep.Sections, len(rep.Listeners))
	}
}

// A partial list reaches the platform as endpoints, which are true, and never
// as the complete-list fact, and the section value travels with it: the
// platform retires sockets only on a section that says ok.
//
// Mutation: emit the listening-sockets fact on any section state → red.
func TestToObservations_PartialListenersAreNotACompleteList(t *testing.T) {
	rep := &Report{Listeners: []Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"}}}
	rep.partial(SectionListeners, fmt.Errorf("only this account's sockets"))
	result, err := ToObservations(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Facts {
		if f.Key == facts.KeySvcListeningSockets {
			t.Errorf("a partial list was emitted as the complete fact: %+v", f)
		}
	}
	if len(result.Assets) != 1 || result.Assets[0].Port != 22 {
		t.Errorf("the socket that was seen must still be reported: %+v", result.Assets)
	}
	meta, _ := result.DeviceInfo["host_inventory"].(map[string]any)
	sections, _ := meta["sections"].(map[string]any)
	if sections[SectionListeners] != SectionPartial {
		t.Errorf("sections = %v", sections)
	}
}
