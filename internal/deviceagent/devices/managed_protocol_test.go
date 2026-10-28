package devices

// Managed protocol 1 at the device agent's executor, driven end to end by the
// fake control plane: the real client polls, the real executor runs (or
// refuses) the job, the real client submits the result the fake checks
// against schemas/managed/v1.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/fakeplatform"
	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// pollAndRun is one turn of the agent's job loop: poll, run, report.
func pollAndRun(t *testing.T, c *api.OutboundClient, exec *JobExecutor) {
	t.Helper()
	job, err := c.GetNextJob()
	if err != nil || job == nil {
		t.Fatalf("GetNextJob = %+v, %v", job, err)
	}
	if err := exec.Execute(context.Background(), job); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

func lastResult(t *testing.T, p *fakeplatform.Platform) map[string]any {
	t.Helper()
	rs := p.Requests("job-result.device-agent")
	if len(rs) == 0 {
		t.Fatal("no result reached the platform")
	}
	return rs[len(rs)-1].Body
}

func enrolledExecutor(t *testing.T, p *fakeplatform.Platform) (*api.OutboundClient, *JobExecutor) {
	t.Helper()
	cfg := &config.Config{PlatformURL: p.URL(), RegistrationKey: "REG-0123456789abcdef0123456789abcdef", DataPath: t.TempDir()}
	cfg.Security.ServerCACert = p.CAPEM()
	c := api.NewOutboundClient(cfg)
	if err := c.Register("test"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	exec := NewJobExecutor(c, cfg)
	exec.submitter = c // no retry delays in a test; the gate stops a bad submit anyway
	return c, exec
}

func fakeJob(typ string) map[string]any {
	return map[string]any{"id": uuid.NewString(), "type": typ, "device_type": "no-such-type",
		"parameters": map[string]any{"device_type": "no-such-type"}, "created_at": time.Now().UTC().Format(time.RFC3339)}
}

// D-P7: credentials sealed under the agent secret the platform issued open;
// the job proceeds past the decrypt.
func TestProtocol1_SealedCredentialsOpen(t *testing.T) {
	p := fakeplatform.New(t)
	c, exec := enrolledExecutor(t, p)
	p.QueueAgentJob(fakeJob("device_interrogation"), map[string]any{"username": "u", "password": "device-password"})
	pollAndRun(t, c, exec)
	res := lastResult(t, p)
	if errText, _ := res["error"].(string); strings.Contains(strings.ToLower(errText), "decrypt") || !strings.Contains(errText, "Unsupported device type") {
		t.Fatalf("result error = %q, want the job past the decrypt (failing on the unknown device type)", errText)
	}
}

// D-P7: an unsealed credentials map is refused, never used as plaintext.
func TestProtocol1_UnsealedCredentialsAreRefused(t *testing.T) {
	p := fakeplatform.New(t)
	c, exec := enrolledExecutor(t, p)
	p.SetMisbehaviour(fakeplatform.UnsealedCredentials)
	p.QueueAgentJob(fakeJob("device_interrogation"), map[string]any{"username": "u", "password": "device-password"})
	pollAndRun(t, c, exec)
	res := lastResult(t, p)
	if res["success"] != false || !strings.Contains(res["error"].(string), "not sealed") {
		t.Fatalf("result = %v, want a failure saying the credentials were not sealed", res)
	}
	if strings.Contains(res["error"].(string), "device-password") {
		t.Fatal("the unsealed password reached the result")
	}
}

// D-P2: a job type the agent does not run (cloud collection is hosted), and a
// device_discovery job the platform did not negotiate, are refused with
// failure_code unsupported_command.
func TestProtocol1_UnsupportedJobsAreRefused(t *testing.T) {
	p := fakeplatform.New(t)
	c, exec := enrolledExecutor(t, p)
	p.QueueAgentJob(fakeJob("cloud_discovery"), nil)
	pollAndRun(t, c, exec)
	if res := lastResult(t, p); res["failure_code"] != managedprotocol.CodeUnsupportedCommand {
		t.Fatalf("cloud_discovery result = %v, want failure_code %s", res, managedprotocol.CodeUnsupportedCommand)
	}

	p2 := fakeplatform.New(t)
	p2.SetCapabilities() // offers nothing: device_discovery is not negotiated
	c2, exec2 := enrolledExecutor(t, p2)
	if c2.Gate().Has(di.CapabilityDeviceDiscovery) {
		t.Fatal("setup: device_discovery negotiated")
	}
	p2.QueueAgentJob(fakeJob(di.JobTypeDeviceDiscovery), map[string]any{"password": "device-password"})
	pollAndRun(t, c2, exec2)
	if res := lastResult(t, p2); res["failure_code"] != managedprotocol.CodeUnsupportedCommand {
		t.Fatalf("un-negotiated device_discovery result = %v, want failure_code %s", res, managedprotocol.CodeUnsupportedCommand)
	}
}
