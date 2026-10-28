package managedprotocol

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHeaderRoundTripAndParse(t *testing.T) {
	p := Protocol{Version: 1, Capabilities: []string{"scan_plan_v1", "identity_dns_v1", "scan_plan_v1"}}
	v := FormatHeader(p)
	if v != "1; capabilities=identity_dns_v1,scan_plan_v1" {
		t.Fatalf("FormatHeader = %q", v)
	}
	got, ok, err := ParseHeader(v)
	if !ok || err != nil || got.Version != 1 || !reflect.DeepEqual(got.Capabilities, []string{"identity_dns_v1", "scan_plan_v1"}) {
		t.Fatalf("ParseHeader(%q) = %+v %v %v", v, got, ok, err)
	}
	for in, want := range map[string]int{"1": 1, " 2 ": 2, "1; future=x; capabilities=a": 1} {
		got, ok, err := ParseHeader(in)
		if !ok || err != nil || got.Version != want {
			t.Errorf("ParseHeader(%q) = %+v %v %v, want version %d", in, got, ok, err, want)
		}
	}
	if _, ok, _ := ParseHeader(""); ok {
		t.Error("an empty header parsed as present")
	}
	for _, bad := range []string{"one", "0", "-1", "; capabilities=a"} {
		if _, ok, err := ParseHeader(bad); !ok || err == nil {
			t.Errorf("ParseHeader(%q) accepted a value that names no version", bad)
		}
	}
}

func TestNewRequestNamesTheProtocol(t *testing.T) {
	req, err := NewRequest(http.MethodPost, "https://platform.example.test/x", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get(Header) != "1" || req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", req.Header)
	}
	req, _ = NewRequest(http.MethodGet, "https://platform.example.test/x", nil)
	if req.Header.Get(Header) != "1" || req.Header.Get("Content-Type") != "" {
		t.Fatalf("bodiless request headers = %v", req.Header)
	}
}

func TestNegotiate(t *testing.T) {
	own := []string{"identity_dns_v1", "scan_plan_v1", "verify_certificate_v1"}
	caps, err := Negotiate(&Protocol{Version: 1, Capabilities: []string{"scan_plan_v1", "device_discovery", "future_v9"}}, 200, own)
	if err != nil || !reflect.DeepEqual(caps, []string{"scan_plan_v1"}) {
		t.Fatalf("Negotiate = %v %v, want the intersection [scan_plan_v1]", caps, err)
	}
	var inc *IncompatibleError
	if _, err := Negotiate(nil, 200, own); !errors.As(err, &inc) || inc.PlatformVersion != 0 {
		t.Fatalf("no protocol = %v, want IncompatibleError naming none", err)
	}
	if _, err := Negotiate(&Protocol{Version: 2}, 200, own); !errors.As(err, &inc) || inc.PlatformVersion != 2 {
		t.Fatalf("version 2 = %v, want IncompatibleError naming 2", err)
	}
	h := http.Header{}
	if _, err := NegotiateHeader(h, 204, own); !IsIncompatible(err) {
		t.Fatalf("204 without the header = %v", err)
	}
	h.Set(Header, "1; capabilities=verify_certificate_v1")
	if caps, err := NegotiateHeader(h, 204, own); err != nil || !reflect.DeepEqual(caps, []string{"verify_certificate_v1"}) {
		t.Fatalf("204 with the header = %v %v", caps, err)
	}
}

func TestCheckHeaderIfPresent(t *testing.T) {
	h := http.Header{}
	if err := CheckHeaderIfPresent(h, 200); err != nil {
		t.Fatalf("absent header = %v", err)
	}
	h.Set(Header, "1")
	if err := CheckHeaderIfPresent(h, 200); err != nil {
		t.Fatalf("version 1 = %v", err)
	}
	for _, v := range []string{"2", "garbage"} {
		h.Set(Header, v)
		if err := CheckHeaderIfPresent(h, 200); !IsIncompatible(err) {
			t.Fatalf("header %q = %v, want a refusal", v, err)
		}
	}
}

// The one line D-P2 specifies, and the 426 that carries the platform's own
// explanation.
func TestTheRefusalLine(t *testing.T) {
	cases := map[string]*IncompatibleError{
		"platform speaks no managed protocol version; this agent supports 1; nothing will be collected until the agent or the platform is changed": {},
		"platform speaks managed protocol 2; this agent supports 1; nothing will be collected until the agent or the platform is changed":          {PlatformVersion: 2},
	}
	for want, e := range cases {
		if e.Error() != want {
			t.Errorf("Error() = %q, want %q", e.Error(), want)
		}
	}
	err := FromStatus(http.StatusUpgradeRequired, http.Header{}, []byte(`{"code":"agent_protocol_unsupported","agent_protocol":1,"supported":[2],"message":"install the listed agent"}`))
	var inc *IncompatibleError
	if !errors.As(err, &inc) || !reflect.DeepEqual(inc.Supported, []int{2}) || !strings.Contains(err.Error(), "managed protocol 2") || !strings.Contains(err.Error(), "install the listed agent") {
		t.Fatalf("426 = %v", err)
	}
	if FromStatus(http.StatusBadRequest, http.Header{}, nil) != nil {
		t.Fatal("a 400 is not a protocol refusal")
	}
}

func TestGateTransitionsAndLogsOnce(t *testing.T) {
	g := NewGate([]string{"scan_plan_v1"})
	var mu sync.Mutex
	var lines []string
	g.SetLogger(func(f string, a ...any) { mu.Lock(); lines = append(lines, fmt.Sprintf(f, a...)); mu.Unlock() })

	if !errors.Is(g.Ready(), ErrNotNegotiated) || g.Has("scan_plan_v1") {
		t.Fatal("a new gate is open")
	}
	g.Compatible([]string{"scan_plan_v1"})
	if g.Ready() != nil || !g.Has("scan_plan_v1") || g.Problem() != "" {
		t.Fatal("the gate did not open")
	}
	for i := 0; i < 3; i++ {
		if err := g.Observe(&IncompatibleError{PlatformVersion: 2}); !IsIncompatible(err) {
			t.Fatalf("Observe returned %v", err)
		}
	}
	if !IsIncompatible(g.Ready()) || g.Has("scan_plan_v1") || g.Problem() == "" {
		t.Fatal("the gate did not close")
	}
	if n := len(lines); n != 1 {
		t.Fatalf("logged %d lines over three identical refusals, want 1: %v", n, lines)
	}
	if g.Observe(errors.New("network down")) == nil || !IsIncompatible(g.Ready()) {
		t.Fatal("an ordinary error changed the gate")
	}
	g.Compatible(nil)
	if g.Ready() != nil || len(lines) != 2 {
		t.Fatalf("reopening: ready=%v lines=%v", g.Ready(), lines)
	}
}

func TestGateWaitReady(t *testing.T) {
	g := NewGate(nil)
	start := time.Now()
	if !errors.Is(g.WaitReady(50*time.Millisecond), ErrNotNegotiated) || time.Since(start) < 40*time.Millisecond {
		t.Fatal("WaitReady did not wait for its bound")
	}
	go func() { time.Sleep(20 * time.Millisecond); g.Compatible(nil) }()
	if err := g.WaitReady(5 * time.Second); err != nil {
		t.Fatalf("WaitReady = %v after the gate opened", err)
	}
	_ = g.Observe(&IncompatibleError{})
	start = time.Now()
	if !IsIncompatible(g.WaitReady(time.Second)) || time.Since(start) > 500*time.Millisecond {
		t.Fatal("WaitReady waited on a gate known to be closed")
	}
}
