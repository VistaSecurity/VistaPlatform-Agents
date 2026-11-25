package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocoltest"
	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory"
)

// The job poll declares what this build can run beyond device_interrogation.
// The platform offers a device_discovery job only to an agent that declares it
// (#1492 slice B) — an agent that predates the job type sends nothing and is
// never handed one it would strand in_progress. So a build that CAN run it but
// stops sending the header silently loses agent-routed Add device.
func TestGetNextJob_DeclaresDeviceDiscoveryCapability(t *testing.T) {
	var header string
	srv := httptest.NewServer(protocoltest.Speak1(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get(di.AgentCapabilitiesHeader)
		w.WriteHeader(http.StatusNoContent)
	})))
	defer srv.Close()

	c := NewOutboundClient(&config.Config{PlatformURL: srv.URL, AgentID: uuid.New().String()})
	if _, err := c.GetNextJob(); err != nil {
		t.Fatalf("GetNextJob: %v", err)
	}
	if !di.ParseAgentCapabilities(header)[di.CapabilityDeviceDiscovery] {
		t.Fatalf("poll declared %q, want it to include %q", header, di.CapabilityDeviceDiscovery)
	}
}

// kubernetes_inventory_v1 is offered only by an agent running in a cluster:
// outside one the job could only ever be refused, so it is not advertised.
func TestAgentCapabilities_KubernetesInventoryOnlyInACluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for _, c := range AgentCapabilities() {
		if c == kubeinventory.Capability {
			t.Fatalf("capabilities outside a cluster: %v", AgentCapabilities())
		}
	}
	// Outside a cluster: the shared device capabilities and host_crypto_v1.
	if len(AgentCapabilities()) != len(di.AgentCapabilities())+1 {
		t.Errorf("capabilities = %v", AgentCapabilities())
	}
}
