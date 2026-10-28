package main

// Managed protocol 1 at the sensor's own command handling, driven by the
// fake control plane (internal/testsupport/fakeplatform): what the sensor
// does with what a heartbeat answer hands it. The clients' flows are in
// internal/sensor/api/managed_protocol_test.go.

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/models"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/fakeplatform"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch"
)

// enrolledSensor is a sensor enrolled with p through its real clients, its job
// queue left without a worker so what was queued can be inspected.
func enrolledSensor(t *testing.T, p *fakeplatform.Platform) *Sensor {
	t.Helper()
	cfg := &config.Config{ControlPlaneURL: p.URL(), RegistrationKey: "REG-0123456789abcdef0123456789abcdef",
		Name: "sensor-under-test", Platform: "linux", ReportingInterval: 30 * time.Second}
	cfg.Security.ServerCACert = p.CAPEM()
	s := &Sensor{config: cfg, apiClient: api.NewOutboundClient(cfg), sensorManager: api.NewSensorManagerClient(cfg), startTime: time.Now()}
	s.sensorManager.UseGate(s.apiClient.Gate())
	if _, err := s.sensorManager.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	s.apiClient.ActivateMTLS()
	s.jobQueue = make(chan models.Command, discoveryJobQueueDepth)
	return s
}

func legacyJobCommand() map[string]any {
	return map[string]any{"id": "cmd-legacy", "type": sensordispatch.CommandType, "priority": 5, "requires_ack": true,
		"payload": map[string]any{"job_id": dispatchTestJobID, "targets": []any{"192.0.2.10"}, "protocols": []any{"TLS"}, "ports": []any{443}}}
}

func plannedJobCommand(id string, verify bool) map[string]any {
	plan := map[string]any{"version": 1, "attempt": 1, "pace": "normal",
		"targets": []any{map[string]any{"target": "192.0.2.2", "target_id": "11111111-2222-4333-8444-555555555555", "tcp_ports": "443"}}}
	if verify {
		plan["verify_certificate"] = map[string]any{"certificate_id": "c-1", "port": 443}
	}
	return map[string]any{"id": id, "type": sensordispatch.CommandType, "priority": 5, "requires_ack": true,
		"payload": map[string]any{"job_id": dispatchTestJobID, "plan": plan}}
}

func ackCode(t *testing.T, p *fakeplatform.Platform, commandID string) (string, bool) {
	t.Helper()
	for _, r := range p.Requests("command-ack") {
		if r.Body["command_id"] == commandID {
			data, _ := r.Body["response_data"].(map[string]any)
			code, _ := data["code"].(string)
			return code, true
		}
	}
	return "", false
}

// D-P5 and D-P2: a legacy protocols × ports job and an unknown command type
// from the platform are acknowledged as refused with unsupported_command and
// run nothing; a planned job is queued.
func TestProtocol1_SensorRefusesWorkItDoesNotRun(t *testing.T) {
	p := fakeplatform.New(t)
	s := enrolledSensor(t, p)

	p.QueueOutOfProtocolCommand(legacyJobCommand())
	p.QueueSensorCommand(map[string]any{"id": "cmd-unknown", "type": "rewrite_firmware", "payload": map[string]any{}})
	p.QueueSensorCommand(plannedJobCommand("cmd-plan", false))
	s.sendHeartbeat()

	for _, id := range []string{"cmd-legacy", "cmd-unknown"} {
		if code, acked := ackCode(t, p, id); !acked || code != managedprotocol.CodeUnsupportedCommand {
			t.Errorf("%s: acked=%v code=%q, want an unsupported_command refusal", id, acked, code)
		}
	}
	if len(s.jobQueue) != 1 {
		t.Fatalf("queue holds %d jobs, want only the planned one", len(s.jobQueue))
	}
	if queued := <-s.jobQueue; queued.ID != "cmd-plan" {
		t.Fatalf("queued %s, want cmd-plan", queued.ID)
	}
}

// Work whose capability the platform did not negotiate is refused the same
// way: here a certificate verification without verify_certificate_v1, and a
// scoped DNS lookup without identity_dns_v1.
func TestProtocol1_SensorRefusesWorkWhoseCapabilityWasNotNegotiated(t *testing.T) {
	p := fakeplatform.New(t)
	p.SetCapabilities(sensordispatch.ScanPlanCapability)
	s := enrolledSensor(t, p)

	p.QueueSensorCommand(plannedJobCommand("cmd-verify", true))
	p.QueueSensorCommand(map[string]any{"id": "cmd-dns", "type": sensordispatch.IdentityDNSCommand, "payload": map[string]any{},
		"expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
	s.sendHeartbeat()

	for _, id := range []string{"cmd-verify", "cmd-dns"} {
		if code, acked := ackCode(t, p, id); !acked || code != managedprotocol.CodeUnsupportedCommand {
			t.Errorf("%s: acked=%v code=%q, want an unsupported_command refusal", id, acked, code)
		}
	}
	if len(s.jobQueue) != 0 {
		t.Fatal("a verification the platform did not negotiate was queued")
	}
}

// D-P2: a heartbeat answer without the protocol, or naming version 2, runs
// nothing: no command is queued or acknowledged, and the next heartbeat says
// why (protocol_error).
func TestProtocol1_SensorRunsNothingFromAnAnswerWithoutTheProtocol(t *testing.T) {
	for _, m := range []fakeplatform.Misbehaviour{fakeplatform.NoProtocol, fakeplatform.Version2} {
		p := fakeplatform.New(t)
		s := enrolledSensor(t, p)
		p.SetMisbehaviour(m)
		p.QueueSensorCommand(plannedJobCommand("cmd-plan", false))
		p.QueueSensorCommand(map[string]any{"id": "cmd-unknown", "type": "rewrite_firmware", "payload": map[string]any{}})
		s.sendHeartbeat()

		if n := len(p.Requests("command-ack")); n != 0 {
			t.Fatalf("misbehaviour %d: %d command(s) acknowledged from an answer this sensor does not speak", m, n)
		}
		if len(s.jobQueue) != 0 {
			t.Fatalf("misbehaviour %d: a job was queued from an answer this sensor does not speak", m)
		}
		if atomic.LoadInt64(&s.errorsCount) == 0 {
			t.Errorf("misbehaviour %d: the refusal was not counted as an error", m)
		}

		p.SetMisbehaviour(fakeplatform.Behave)
		s.sendHeartbeat()
		beats := p.Requests("heartbeat.sensor.request")
		if got, _ := beats[len(beats)-1].Body["protocol_error"].(string); got == "" {
			t.Errorf("misbehaviour %d: the next heartbeat did not report the refusal", m)
		}
	}
}

// D-P2: enrollment against a platform that does not speak protocol 1 (no
// protocol, version 2, a 426) or that breaks it stops the sensor with exit 78,
// which the installers' units do not restart.
func TestProtocol1_SensorEnrollmentRefusalExits78(t *testing.T) {
	for _, m := range []fakeplatform.Misbehaviour{fakeplatform.NoProtocol, fakeplatform.Version2, fakeplatform.Upgrade426,
		fakeplatform.ServerGeneratedKey, fakeplatform.NoAgentSecret} {
		p := fakeplatform.New(t)
		p.SetMisbehaviour(m)

		var exited []int
		orig := exitProcess
		exitProcess = func(code int) { exited = append(exited, code) }

		cfg := &config.Config{ControlPlaneURL: p.URL(), RegistrationKey: "REG-0123456789abcdef0123456789abcdef", Name: "s"}
		cfg.Security.ServerCACert = p.CAPEM()
		cfg.Storage.DataPath = t.TempDir() // nothing may be written, but never beside the test
		configPath := filepath.Join(cfg.Storage.DataPath, "sensor-config.yaml")
		if err := os.WriteFile(configPath, []byte("sensorId: \"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := &Sensor{config: cfg, configPath: configPath, apiClient: api.NewOutboundClient(cfg), sensorManager: api.NewSensorManagerClient(cfg)}
		s.sensorManager.UseGate(s.apiClient.Gate())
		s.resolveRegistrationAtStartup(false, make(chan struct{}))
		exitProcess = orig

		if len(exited) != 1 || exited[0] != exitNeedsOperator {
			t.Fatalf("misbehaviour %d: exit calls = %v, want exactly [%d]", m, exited, exitNeedsOperator)
		}
		if cfg.SensorID != "" || cfg.Security.ClientCert != "" {
			t.Fatalf("misbehaviour %d: the refused enrollment was applied", m)
		}
	}
}
