package api

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/fakeplatform"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostcrypto"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

func hcjLocalReport() *hostcrypto.Report {
	return &hostcrypto.Report{
		Collected: time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC), Mode: hostinventory.ModeLocal, Platform: "linux",
		Sections: map[string]string{hostcrypto.SectionPlatform: hostcrypto.SectionOK},
		Certificates: []hostcrypto.Certificate{{Location: hostcrypto.Location{Path: "/etc/ssl/a.pem", FoundBy: hostcrypto.FoundByKnownLocation},
			FingerprintSHA256: "00"}},
	}
}

// A local collection reaches the platform's host-crypto intake, over mTLS,
// as a submission the fake holds to host-crypto.submission (which holds the
// report to defs/host-crypto-report.json).
func TestSubmitHostCrypto_AgainstTheFakePlatform(t *testing.T) {
	p := fakeplatform.New(t)
	cfg, c := enrolledAgent(t, p)
	if err := c.SubmitHostCrypto(hcjLocalReport()); err != nil {
		t.Fatalf("SubmitHostCrypto: %v", err)
	}
	reqs := p.Requests("host-crypto.submission")
	if len(reqs) != 1 {
		t.Fatalf("%d submissions reached the intake", len(reqs))
	}
	if reqs[0].PeerCN != cfg.AgentID || reqs[0].Body["agent_id"] != cfg.AgentID || reqs[0].Body["mode"] != "local" {
		t.Fatalf("submission %+v", reqs[0])
	}
	report, _ := json.Marshal(reqs[0].Body["report"])
	var r hostcrypto.Report
	if err := json.Unmarshal(report, &r); err != nil || len(r.Certificates) != 1 {
		t.Fatalf("report did not arrive whole: %v %s", err, report)
	}
}

// A platform that did not offer host_crypto_v1 is sent nothing, and the
// caller is told why.
func TestSubmitHostCrypto_NotNegotiatedSendsNothing(t *testing.T) {
	p := fakeplatform.New(t)
	p.SetCapabilities("device_discovery")
	_, c := enrolledAgent(t, p)
	if err := c.SubmitHostCrypto(hcjLocalReport()); !errors.Is(err, ErrHostCryptoNotNegotiated) {
		t.Fatalf("err = %v, want ErrHostCryptoNotNegotiated", err)
	}
	if n := len(p.Requests("host-crypto.submission")); n != 0 {
		t.Fatalf("%d submissions sent to a platform that has nowhere to put them", n)
	}
}

// Only a local collection is posted on its own; a remote one is a job's.
func TestSubmitHostCrypto_RefusesARemoteReport(t *testing.T) {
	p := fakeplatform.New(t)
	_, c := enrolledAgent(t, p)
	r := hcjLocalReport()
	r.Mode = hostinventory.ModeRemote
	if err := c.SubmitHostCrypto(r); err == nil {
		t.Fatal("a remote report was posted to the local intake")
	}
}

// The capability is offered at enrollment and named on every poll.
func TestAgentCapabilities_IncludeHostCrypto(t *testing.T) {
	found := false
	for _, c := range AgentCapabilities() {
		found = found || c == hostcrypto.CapabilityHostCrypto
	}
	if !found {
		t.Fatalf("AgentCapabilities() = %v", AgentCapabilities())
	}
	p := fakeplatform.New(t)
	_, _ = enrolledAgent(t, p)
	reg := p.Requests("registration.request")
	if len(reg) != 1 {
		t.Fatal("no registration")
	}
	proto, _ := reg[0].Body["protocol"].(map[string]any)
	caps, _ := proto["capabilities"].([]any)
	offered := false
	for _, c := range caps {
		offered = offered || c == hostcrypto.CapabilityHostCrypto
	}
	if !offered {
		t.Fatalf("registration offered %v", caps)
	}
}
