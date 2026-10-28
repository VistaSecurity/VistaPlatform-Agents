package api

// Managed protocol 1, the sensor's real clients against the fake control plane
// (internal/testsupport/fakeplatform): every flow and every refusal. The fake
// validates everything the sensor sends against schemas/managed/v1 and answers
// 426 to a request that does not name the protocol, so a client that drifts
// from the schemas, or stops sending the header, fails here.

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/models"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/fakeplatform"
	"github.com/vistasecurity/vistaplatform-agents/shared/discovery"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch/planrun"
)

const fakeJobID = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42"

// sensorClients are the sensor's two clients, wired as main wires them.
type sensorClients struct {
	cfg *config.Config
	smc *SensorManagerClient
	oc  *OutboundClient
}

func newSensorClients(p *fakeplatform.Platform) *sensorClients {
	cfg := &config.Config{
		ControlPlaneURL:   p.URL(),
		RegistrationKey:   "REG-0123456789abcdef0123456789abcdef",
		Name:              "sensor-under-test",
		Platform:          "linux",
		Version:           "test",
		ReportingInterval: 30 * time.Second,
	}
	cfg.Security.ServerCACert = p.CAPEM() // the anchor trust bootstrap pins
	oc := NewOutboundClient(cfg)
	smc := NewSensorManagerClient(cfg)
	smc.UseGate(oc.Gate())
	return &sensorClients{cfg: cfg, smc: smc, oc: oc}
}

// enroll registers and switches the outbound client to mTLS, as main.register does.
func (c *sensorClients) enroll(t *testing.T) {
	t.Helper()
	if _, err := c.smc.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	c.oc.ActivateMTLS()
}

func (c *sensorClients) health() *models.SensorHealth {
	return &models.SensorHealth{SensorID: c.cfg.SensorID, Status: "active", Version: "test",
		Capabilities: SensorCapabilities(), Timestamp: time.Now(), LastHeartbeat: time.Now()}
}

func fakeDiscovery(sensorID string) *models.CryptoDiscovery {
	now := time.Now()
	return &models.CryptoDiscovery{
		ID: "d-1", SensorID: sensorID, Timestamp: now, SourceIP: "192.0.2.10", DestIP: "203.0.113.5", Port: 443,
		Protocol: "TLS", CipherSuite: "TLS_AES_128_GCM_SHA256", DiscoveryMethod: "passive", Confidence: 0.9, CreatedAt: now,
		RawMetadata: map[string]interface{}{
			"protocol_version": "TLS 1.3",
			"certificates": []interface{}{map[string]interface{}{
				"subject_dn": "CN=app.example.test", "issuer_dn": "CN=Example Test CA", "chain_order": 0,
				"fingerprint_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
			}},
		},
	}
}

func planCommand() map[string]any {
	return map[string]any{
		"id": "cmd-plan", "type": sensordispatch.CommandType, "priority": 5, "requires_ack": true, "created_at": time.Now().UTC().Format(time.RFC3339),
		"payload": map[string]any{"job_id": fakeJobID, "plan": map[string]any{
			"version": 1, "attempt": 1, "pace": "normal",
			"targets": []any{map[string]any{"target": "192.0.2.2", "target_id": "11111111-2222-4333-8444-555555555555", "tcp_ports": "443"}},
		}},
	}
}

// Enrollment with a CSR, then every call of a planned job, then rotation —
// all over mTLS with the certificate the platform issued, all named protocol 1.
func TestProtocol1_SensorFlowAgainstTheFakePlatform(t *testing.T) {
	p := fakeplatform.New(t)
	c := newSensorClients(p)

	c.enroll(t)
	if err := c.oc.Gate().Ready(); err != nil {
		t.Fatalf("after enrollment the gate is %v, want open", err)
	}
	if !c.oc.Gate().Has(sensordispatch.VerifyCertificateCapability) {
		t.Fatalf("negotiated %v, want the intersection to include %s", c.oc.Gate().Capabilities(), sensordispatch.VerifyCertificateCapability)
	}
	reg := p.Requests("registration.request")
	if len(reg) != 1 || reg[0].Body["csr"] == "" || reg[0].Body["agent_kind"] != managedprotocol.AgentKindSensor {
		t.Fatalf("registration request = %+v", reg)
	}

	p.QueueSensorCommand(planCommand())
	cmds, err := c.oc.Heartbeat(c.health())
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if len(cmds.Commands) != 1 || cmds.Commands[0].ID != "cmd-plan" {
		t.Fatalf("commands = %+v, want the queued plan", cmds.Commands)
	}
	if err := c.oc.SubmitDiscoveries([]*models.CryptoDiscovery{fakeDiscovery(c.cfg.SensorID)}); err != nil {
		t.Fatalf("SubmitDiscoveries: %v", err)
	}
	// A unit report with a host in it, so the fake holds the UnitResult the
	// sensor marshals (not only the empty ping) to unit-batch.schema.json.
	unit := sensordispatch.UnitResult{
		TargetID: "11111111-2222-4333-8444-555555555555", Address: "192.0.2.2", Attempt: 1,
		Host: sensordispatch.UnitHost{Liveness: "alive", LivenessEvidence: "tcp_open", PortsRequested: 1, Open: []int{443}, OpenCount: 1},
		TCP: []discovery.Observation{{Addr: netip.MustParseAddr("192.0.2.2"), Port: 443, Transport: "tcp", State: "open",
			Protocol: "TLS", Identified: true}},
		DeadlineSeconds: 60,
	}
	if _, err := c.oc.ReportDiscoveryJobUnits(fakeJobID, sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{unit}}); err != nil {
		t.Fatalf("unit report: %v", err)
	}
	if _, err := c.oc.ReportDiscoveryJobUnits(fakeJobID, sensordispatch.UnitBatch{}); err != nil {
		t.Fatalf("unit ping: %v", err)
	}
	if err := c.oc.CompleteDiscoveryJob(fakeJobID, sensordispatch.Completion{Status: "completed", TotalTargets: 1, SuccessfulTargets: 1}); err != nil {
		t.Fatalf("CompleteDiscoveryJob: %v", err)
	}
	if err := c.oc.AcknowledgeCommand("cmd-plan", &models.CommandResponse{ID: uuid.New(), CommandID: "cmd-plan", SensorID: c.cfg.SensorID,
		Status: "success", Message: "done", Timestamp: time.Now()}); err != nil {
		t.Fatalf("AcknowledgeCommand: %v", err)
	}

	// Every call after enrollment presented the issued certificate.
	for _, r := range p.Requests("") {
		if r.Message != "registration.request" && r.PeerCN != c.cfg.SensorID {
			t.Errorf("%s %s presented client certificate %q, want %q", r.Method, r.Path, r.PeerCN, c.cfg.SensorID)
		}
		if r.Header.Get(managedprotocol.Header) != "1" {
			t.Errorf("%s %s: %s = %q", r.Method, r.Path, managedprotocol.Header, r.Header.Get(managedprotocol.Header))
		}
	}

	// Rotation: a fresh key, a new certificate and secret; the platform revokes
	// the old certificate, so a client still holding it gets 401 until it
	// switches.
	oldSecret := c.cfg.AgentSecretState().Secret
	if err := c.smc.RotateCertificate(); err != nil {
		t.Fatalf("RotateCertificate: %v", err)
	}
	if st := c.cfg.AgentSecretState(); st.Secret == oldSecret || st.Previous != oldSecret {
		t.Fatalf("agent secret after rotation = %+v, want a new one with the old as previous", st)
	}
	if _, err := c.oc.Heartbeat(c.health()); err == nil {
		t.Fatal("a heartbeat over the revoked certificate was accepted")
	}
	c.oc.ActivateMTLS()
	if _, err := c.oc.Heartbeat(c.health()); err != nil {
		t.Fatalf("heartbeat over the rotated certificate: %v", err)
	}
}

// An answer without the protocol (an older platform) or with version 2 closes
// the gate: the heartbeat's commands are not returned, nothing is submitted,
// a running plan stops. The next protocol-1 answer opens it again.
func TestProtocol1_SensorRefusesAPlatformThatDoesNotSpeakIt(t *testing.T) {
	for _, m := range []struct {
		name string
		mis  fakeplatform.Misbehaviour
		want int
	}{
		{"no protocol", fakeplatform.NoProtocol, 0},
		{"version 2", fakeplatform.Version2, 2},
		{"426", fakeplatform.Upgrade426, 2},
	} {
		t.Run(m.name, func(t *testing.T) {
			p := fakeplatform.New(t)
			c := newSensorClients(p)
			c.enroll(t)

			p.SetMisbehaviour(m.mis)
			p.QueueSensorCommand(planCommand())
			cmds, err := c.oc.Heartbeat(c.health())
			var inc *managedprotocol.IncompatibleError
			if !errors.As(err, &inc) || cmds != nil {
				t.Fatalf("Heartbeat = %+v, %v; want no commands and an IncompatibleError", cmds, err)
			}
			if inc.PlatformVersion != m.want {
				t.Errorf("refusal names platform version %d, want %d: %v", inc.PlatformVersion, m.want, inc)
			}
			if c.oc.Gate().Ready() == nil || c.oc.Gate().Problem() == "" {
				t.Fatal("the gate stayed open after the refusal")
			}

			before := len(p.Requests(""))
			if err := c.oc.SubmitDiscoveries([]*models.CryptoDiscovery{fakeDiscovery(c.cfg.SensorID)}); !managedprotocol.IsIncompatible(err) {
				t.Fatalf("SubmitDiscoveries = %v, want the refusal", err)
			}
			if _, err := c.oc.ReportDiscoveryJobUnits(fakeJobID, sensordispatch.UnitBatch{}); !errors.Is(err, planrun.ErrJobStopped) {
				t.Fatalf("unit report = %v, want the run stopped", err)
			}
			if err := c.oc.CompleteDiscoveryJob(fakeJobID, sensordispatch.Completion{Status: "failed"}); !managedprotocol.IsIncompatible(err) {
				t.Fatalf("CompleteDiscoveryJob = %v, want the refusal", err)
			}
			if err := c.oc.AcknowledgeCommand("cmd-plan", &models.CommandResponse{ID: uuid.New(), CommandID: "cmd-plan",
				SensorID: c.cfg.SensorID, Status: "error", Message: "stopped", Timestamp: time.Now()}); !managedprotocol.IsIncompatible(err) {
				t.Fatalf("AcknowledgeCommand = %v, want the refusal", err)
			}
			if n := len(p.Requests("")); n != before {
				t.Fatalf("%d calls reached the platform while the gate was closed", n-before)
			}

			p.SetMisbehaviour(fakeplatform.Behave)
			if _, err := c.oc.Heartbeat(c.health()); err != nil {
				t.Fatalf("heartbeat once the platform speaks protocol 1 again: %v", err)
			}
			if err := c.oc.SubmitDiscoveries([]*models.CryptoDiscovery{fakeDiscovery(c.cfg.SensorID)}); err != nil {
				t.Fatalf("submission after recovery: %v", err)
			}
		})
	}
}

// Enrollment against a platform that does not speak protocol 1, or that
// breaks it, applies nothing: no id, no certificate, no key kept.
func TestProtocol1_SensorEnrollmentRefusals(t *testing.T) {
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
			c := newSensorClients(p)
			_, err := c.smc.Register()
			if m.violation && !managedprotocol.IsViolation(err) || !m.violation && !managedprotocol.IsIncompatible(err) {
				t.Fatalf("Register = %v, want a %s refusal", err, m.name)
			}
			var rejected *RegistrationRejectedError
			if errors.As(err, &rejected) {
				t.Fatal("a protocol refusal was reported as a rejected registration key")
			}
			if c.cfg.SensorID != "" || c.cfg.Security.ClientCert != "" || c.cfg.Security.ClientKey != "" || c.cfg.AgentSecretState().Secret != "" {
				t.Fatalf("the refused answer was applied: %+v", c.cfg.Security)
			}
		})
	}
}

// A rotation answer carrying a private key the platform generated is refused
// and nothing in it is applied: not the certificate, not the secret.
func TestProtocol1_SensorRotationWithAServerKeyIsRefused(t *testing.T) {
	p := fakeplatform.New(t)
	c := newSensorClients(p)
	c.enroll(t)
	cert, key, secret := c.cfg.Security.ClientCert, c.cfg.Security.ClientKey, c.cfg.AgentSecretState().Secret
	p.SetMisbehaviour(fakeplatform.ServerGeneratedKey)
	if err := c.smc.RotateCertificate(); !managedprotocol.IsViolation(err) {
		t.Fatalf("RotateCertificate = %v, want a protocol violation", err)
	}
	if c.cfg.Security.ClientCert != cert || c.cfg.Security.ClientKey != key || c.cfg.AgentSecretState().Secret != secret {
		t.Fatal("the refused rotation answer was applied")
	}
}

// A heartbeat answer carries every pending command, and a plan of 1,000
// targets with their port lists runs past 1 MiB: the answer is read whole, not
// truncated into a decode error on every heartbeat.
func TestProtocol1_SensorReadsALargeHeartbeatAnswer(t *testing.T) {
	p := fakeplatform.New(t)
	c := newSensorClients(p)
	c.enroll(t)
	cmd := planCommand()
	cmd["payload"].(map[string]any)["options"] = map[string]any{"note": strings.Repeat("x", 3<<20)}
	p.QueueSensorCommand(cmd)
	cmds, err := c.oc.Heartbeat(c.health())
	if err != nil {
		t.Fatalf("Heartbeat with a 3 MiB answer: %v", err)
	}
	if len(cmds.Commands) != 1 {
		t.Fatalf("commands = %d, want the queued plan", len(cmds.Commands))
	}
}

// The unit report's own answers still map: a 409 stop code stops the run.
func TestProtocol1_SensorUnitReportStop(t *testing.T) {
	p := fakeplatform.New(t)
	c := newSensorClients(p)
	c.enroll(t)
	if _, err := c.oc.Heartbeat(c.health()); err != nil {
		t.Fatal(err)
	}
	p.AnswerNextUnitReport(http.StatusConflict, map[string]any{"job_status": "cancelled", "code": sensordispatch.UnitsCodeJobCancelled, "accepted": 0, "duplicate": 0, "stale": 0, "unknown": 0})
	if _, err := c.oc.ReportDiscoveryJobUnits(fakeJobID, sensordispatch.UnitBatch{}); !errors.Is(err, planrun.ErrJobStopped) {
		t.Fatalf("409 stop = %v, want ErrJobStopped", err)
	}
}
