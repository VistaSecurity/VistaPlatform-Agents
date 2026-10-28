package api

// Managed protocol 1, the device agent's real client against the fake control
// plane (internal/testsupport/fakeplatform): every flow and every refusal. The
// fake validates everything the agent sends against schemas/managed/v1 and
// answers 426 to a request that does not name the protocol.

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/models"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/fakeplatform"
	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

func newAgentClient(t *testing.T, p *fakeplatform.Platform) (*config.Config, *OutboundClient) {
	t.Helper()
	cfg := &config.Config{PlatformURL: p.URL(), RegistrationKey: "REG-0123456789abcdef0123456789abcdef",
		DataPath: t.TempDir(), PollInterval: 30 * time.Second, HeartbeatInterval: time.Minute}
	cfg.Security.ServerCACert = p.CAPEM() // the anchor trust bootstrap pins
	return cfg, NewOutboundClient(cfg)
}

func enrolledAgent(t *testing.T, p *fakeplatform.Platform) (*config.Config, *OutboundClient) {
	t.Helper()
	cfg, c := newAgentClient(t, p)
	if err := c.Register("test"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return cfg, c
}

func agentJob(typ string) map[string]any {
	return map[string]any{"id": uuid.NewString(), "type": typ, "device_type": "fortinet",
		"parameters": map[string]any{"management_url": "https://198.51.100.20"}, "created_at": time.Now().UTC().Format(time.RFC3339)}
}

// Enrollment with a CSR, the heartbeat, an empty poll (204 with the protocol
// in its header), a job with sealed credentials, its result, then rotation —
// over mTLS with the certificate the platform issued, every call named
// protocol 1.
func TestProtocol1_DeviceAgentFlowAgainstTheFakePlatform(t *testing.T) {
	p := fakeplatform.New(t)
	cfg, c := enrolledAgent(t, p)
	if !c.Gate().Has(di.CapabilityDeviceDiscovery) {
		t.Fatalf("negotiated %v, want device_discovery", c.Gate().Capabilities())
	}
	if cfg.AgentSecretState().Secret == "" || cfg.AgentSecretState().Secret != p.AgentSecret(cfg.AgentID) {
		t.Fatal("the agent does not hold the secret the platform issued")
	}

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	job, err := c.GetNextJob()
	if err != nil || job != nil {
		t.Fatalf("empty poll = %+v, %v; want no job and no error", job, err)
	}

	p.QueueAgentJob(agentJob("device_interrogation"), map[string]any{"username": "readonly", "password": "device-password"})
	job, err = c.GetNextJob()
	if err != nil || job == nil {
		t.Fatalf("GetNextJob = %+v, %v", job, err)
	}
	if job.Protocol == nil || job.Protocol.Version != managedprotocol.Version {
		t.Fatalf("job protocol = %+v", job.Protocol)
	}
	if err := c.SubmitResult(&models.JobResult{JobID: job.ID, Success: false, Error: "test", CompletedAt: time.Now()}); err != nil {
		t.Fatalf("SubmitResult: %v", err)
	}

	for _, r := range p.Requests("") {
		if r.Message != "registration.request" && r.PeerCN != cfg.AgentID {
			t.Errorf("%s %s presented client certificate %q, want %q", r.Method, r.Path, r.PeerCN, cfg.AgentID)
		}
		if r.Header.Get(managedprotocol.Header) != "1" {
			t.Errorf("%s %s: %s = %q", r.Method, r.Path, managedprotocol.Header, r.Header.Get(managedprotocol.Header))
		}
	}
	if caps := p.Requests("")[2].Header.Get(di.AgentCapabilitiesHeader); caps != "device_discovery" {
		t.Errorf("job poll %s = %q", di.AgentCapabilitiesHeader, caps)
	}

	// Rotation replaces the certificate and the secret; the client switches
	// to the new certificate itself.
	old := cfg.AgentSecretState().Secret
	if err := c.RotateCertificate(); err != nil {
		t.Fatalf("RotateCertificate: %v", err)
	}
	if st := cfg.AgentSecretState(); st.Secret == old || st.Previous != old || st.Secret != p.AgentSecret(cfg.AgentID) {
		t.Fatalf("secret after rotation = %+v", st)
	}
	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("heartbeat over the rotated certificate: %v", err)
	}
}

// An answer without the protocol (an older platform), with version 2, or a
// 426 closes the gate: no job is returned, nothing is submitted, no config is
// applied. The next protocol-1 answer opens it again.
func TestProtocol1_DeviceAgentRefusesAPlatformThatDoesNotSpeakIt(t *testing.T) {
	for _, m := range []struct {
		name string
		mis  fakeplatform.Misbehaviour
	}{
		{"no protocol", fakeplatform.NoProtocol},
		{"version 2", fakeplatform.Version2},
		{"426", fakeplatform.Upgrade426},
	} {
		t.Run(m.name, func(t *testing.T) {
			p := fakeplatform.New(t)
			_, c := enrolledAgent(t, p)
			applier := &fakeApplier{}
			c.SetConfigApplier(applier)

			p.SetMisbehaviour(m.mis)
			p.QueueAgentJob(agentJob("device_interrogation"), map[string]any{"password": "device-password"})
			job, err := c.GetNextJob()
			if job != nil || !managedprotocol.IsIncompatible(err) {
				t.Fatalf("GetNextJob = %+v, %v; want no job and the refusal", job, err)
			}
			if err := c.SendHeartbeat(); !managedprotocol.IsIncompatible(err) {
				t.Fatalf("SendHeartbeat = %v, want the refusal", err)
			}
			if applier.applyCalls != 0 {
				t.Fatal("a configuration from a platform this agent does not speak was applied")
			}
			before := len(p.Requests(""))
			if err := c.SubmitResult(&models.JobResult{JobID: uuid.New(), Success: true, CompletedAt: time.Now()}); !managedprotocol.IsIncompatible(err) {
				t.Fatalf("SubmitResult = %v, want the refusal", err)
			}
			if n := len(p.Requests("")); n != before {
				t.Fatal("a result reached the platform while the gate was closed")
			}

			p.SetMisbehaviour(fakeplatform.Behave)
			if err := c.SendHeartbeat(); err != nil {
				t.Fatalf("heartbeat once the platform speaks protocol 1 again: %v", err)
			}
		})
	}
}

// The poll's 204 must name the protocol in its header; one that does not is a
// refusal too.
func TestProtocol1_DeviceAgentEmptyPollWithoutTheHeaderIsRefused(t *testing.T) {
	p := fakeplatform.New(t)
	_, c := enrolledAgent(t, p)
	p.SetMisbehaviour(fakeplatform.NoProtocol)
	if job, err := c.GetNextJob(); job != nil || !managedprotocol.IsIncompatible(err) {
		t.Fatalf("GetNextJob = %+v, %v; want the refusal", job, err)
	}
}

// Enrollment against a platform that does not speak protocol 1, or that
// breaks it, applies nothing and exits 78 (cmd/device-agent exitcode.go).
func TestProtocol1_DeviceAgentEnrollmentRefusals(t *testing.T) {
	for _, m := range []struct {
		name      string
		mis       fakeplatform.Misbehaviour
		violation bool
	}{
		{"no protocol", fakeplatform.NoProtocol, false},
		{"version 2", fakeplatform.Version2, false},
		{"426", fakeplatform.Upgrade426, false},
		{"server-generated key", fakeplatform.ServerGeneratedKey, true},
		{"no agent secret", fakeplatform.NoAgentSecret, true},
	} {
		t.Run(m.name, func(t *testing.T) {
			p := fakeplatform.New(t)
			p.SetMisbehaviour(m.mis)
			cfg, c := newAgentClient(t, p)
			err := c.Register("test")
			if m.violation && !managedprotocol.IsViolation(err) || !m.violation && !managedprotocol.IsIncompatible(err) {
				t.Fatalf("Register = %v, want a %s refusal", err, m.name)
			}
			var rejected *RegistrationRejectedError
			if errors.As(err, &rejected) {
				t.Fatal("a protocol refusal was reported as a rejected registration key")
			}
			if cfg.AgentID != "" || cfg.Security.ClientCert != "" || cfg.Security.ClientKey != "" || cfg.AgentSecretState().Secret != "" {
				t.Fatalf("the refused answer was applied: agent %q", cfg.AgentID)
			}
		})
	}
}

// A rotation answer carrying a private key is refused and nothing from it is
// applied.
func TestProtocol1_DeviceAgentRotationWithAServerKeyIsRefused(t *testing.T) {
	p := fakeplatform.New(t)
	cfg, c := enrolledAgent(t, p)
	cert, secret := cfg.Security.ClientCert, cfg.AgentSecretState().Secret
	p.SetMisbehaviour(fakeplatform.ServerGeneratedKey)
	if err := c.RotateCertificate(); !managedprotocol.IsViolation(err) {
		t.Fatalf("RotateCertificate = %v, want a protocol violation", err)
	}
	if cfg.Security.ClientCert != cert || cfg.AgentSecretState().Secret != secret {
		t.Fatal("the refused rotation answer was applied")
	}
}
