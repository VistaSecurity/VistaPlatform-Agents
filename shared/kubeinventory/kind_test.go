package kubeinventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocolschema"
)

// TestKindCollection checks a collection made in a real cluster by
// scripts/test-kubernetes.sh, which runs the agent's image in a kind cluster
// and passes the output here. It is skipped everywhere else.
//
//	VISTA_KIND_INVENTORY  the standalone output (JSON Lines) of the run
//	VISTA_KIND_TLS_KEY    set for a run with TLS Secrets enabled: the PEM
//	VISTA_KIND_TLS_CERT   key and certificate of the Secret the script made
func TestKindCollection(t *testing.T) {
	path := os.Getenv("VISTA_KIND_INVENTORY")
	if path == "" {
		t.Skip("VISTA_KIND_INVENTORY is not set: this test checks a collection scripts/test-kubernetes.sh made in a kind cluster")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var inv *Inventory
	var data json.RawMessage
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 1<<20), 256<<20)
	for scanner.Scan() {
		var rec struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("the output is not JSON Lines: %v\n%s", err, scanner.Text())
		}
		if rec.Kind == "kubernetes_inventory" {
			data = rec.Data
		}
	}
	if data == nil {
		t.Fatal("no kubernetes_inventory record")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		t.Fatalf("the record does not decode into the record type: %v", err)
	}
	// The record as the agent wrote it, held to the published schema.
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(map[string]any{
		"job_id": "5d0c2a4e-7b1f-4c3a-9e2d-6f8a1b0c9d7e", "success": true,
		"completed_at": time.Now().UTC().Format(time.RFC3339), "kubernetes_inventory": data,
	})
	if err := set.ValidateJSON("job-result.device-agent", result); err != nil {
		t.Fatalf("a collection from a real cluster does not match the schema:\n%v", err)
	}

	optIn := os.Getenv("VISTA_KIND_TLS_KEY") != ""

	// The role is enough: nothing the collector asked for was refused.
	for _, class := range Classes {
		s := inv.Sections[class]
		if s.Status == StatusFailed {
			t.Errorf("%s: failed, %s (%s)", class, s.Reason, s.Message)
		}
	}
	for _, class := range []string{ClassCluster, ClassNodes, ClassNamespaces, ClassWorkloads, ClassPods, ClassServices, ClassIngresses,
		ClassCSRs, ClassAdmissionWebhooks, ClassAPIServices, ClassAPIServerCert, ClassKubeletCerts} {
		section(t, inv, class, StatusOK, "")
	}
	// kind has no cert-manager, Gateway API or mesh: absent, not empty.
	for _, class := range []string{ClassCertManager, ClassGateways, ClassMeshIstio, ClassMeshLinkerd, ClassMeshCilium} {
		section(t, inv, class, StatusUnsupported, ReasonNotInstalled)
	}

	if inv.Cluster.ID == "" || inv.Cluster.Distribution != "kubeadm" || !strings.HasPrefix(inv.Cluster.KubernetesVersion, "v1.") ||
		inv.Cluster.NodeCount == nil || *inv.Cluster.NodeCount < 1 || len(inv.Cluster.CACertificates) == 0 || len(inv.Cluster.APIEndpoints) == 0 {
		t.Errorf("cluster: %+v", inv.Cluster)
	}
	if len(inv.Cluster.PodCIDRs) == 0 {
		t.Errorf("no pod range: %+v", inv.Cluster)
	}

	workloads := map[string]Workload{}
	for _, w := range inv.Workloads {
		workloads[w.Namespace+"/"+w.Kind+"/"+w.Name] = w
	}
	for _, want := range []string{"kube-system/Deployment/coredns", "kube-system/DaemonSet/kube-proxy", "vista-agents/Deployment/vista-device-agent", "vista-agents/Deployment/vista-sensor"} {
		if _, ok := workloads[want]; !ok {
			t.Errorf("no workload %s", want)
		}
	}
	static := 0
	for key := range workloads {
		if strings.HasPrefix(key, "kube-system/Node/") {
			static++
		}
	}
	if static == 0 {
		t.Error("the control plane's static pods were attributed to no Node workload")
	}
	if len(inv.Pods) == 0 {
		t.Fatal("no pods")
	}
	for _, p := range inv.Pods {
		if _, ok := workloads[p.Namespace+"/"+p.Workload.Kind+"/"+p.Workload.Name]; !ok {
			t.Errorf("pod %s/%s names workload %+v, which has no row", p.Namespace, p.Name, p.Workload)
		}
	}
	services := map[string]Service{}
	for _, s := range inv.Services {
		services[s.Namespace+"/"+s.Name] = s
	}
	if s := services["default/kubernetes"]; s.Backing != BackingManualEndpoints {
		t.Errorf("default/kubernetes: %+v", s)
	}
	if s := services["kube-system/kube-dns"]; s.Backing != BackingWorkloads || len(s.Workloads) != 1 || s.Workloads[0] != (WorkloadRef{Kind: "Deployment", Name: "coredns"}) || len(s.Ports) == 0 {
		t.Errorf("kube-system/kube-dns: %+v", s)
	}

	// The control plane as the agent reached it.
	if h := inv.APIServer; h == nil || h.Status != handshakeOK || len(h.CertificateChain) == 0 || h.ChainsToClusterCA == nil || !*h.ChainsToClusterCA {
		t.Errorf("API server handshake: %+v", h)
	}
	if len(inv.Kubelets) == 0 {
		t.Error("no kubelet handshake")
	}
	for _, k := range inv.Kubelets {
		if k.Status != handshakeOK || len(k.CertificateChain) == 0 || k.TLSVersion == "" {
			t.Errorf("kubelet of %s: %+v", k.Node, k.Handshake)
		}
	}
	if len(inv.Certificates) == 0 {
		t.Error("no certificates")
	}

	// Secrets.
	if bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("opaque-secret-value")) || bytes.Contains(data, []byte(`"data"`)) {
		t.Error("Secret content is in the record")
	}
	if !optIn {
		section(t, inv, ClassTLSSecrets, StatusUnsupported, ReasonNotEnabled)
		if inv.Collector.TLSSecrets != "not_enabled" || len(inv.TLSSecrets) != 0 {
			t.Errorf("TLS Secrets without the opt-in: %+v, %d rows", inv.Collector, len(inv.TLSSecrets))
		}
		return
	}
	section(t, inv, ClassTLSSecrets, StatusOK, "")
	certPEM, err := os.ReadFile(os.Getenv("VISTA_KIND_TLS_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(os.Getenv("VISTA_KIND_TLS_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	want := newCertTable(false).addPEM(certPEM)
	found := false
	for _, s := range inv.TLSSecrets {
		if s.Namespace == "default" && s.Name == "stored-not-served" {
			found = len(s.CertificateChain) == 1 && s.CertificateChain[0] == want[0]
		}
		if s.Name == "not-a-certificate" {
			t.Error("a Secret that is not a TLS Secret was read")
		}
	}
	if !found {
		t.Errorf("the TLS Secret's certificate %s is not in the record: %+v", want[0], inv.TLSSecrets)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("the test key is not PEM")
	}
	body := bytes.Split(bytes.TrimSpace(keyPEM), []byte("\n"))[1]
	if bytes.Contains(data, body) || bytes.Contains(data, block.Bytes) {
		t.Error("the TLS Secret's private key is in the record")
	}
	for _, ns := range inv.Namespaces {
		if ns.TLSSecretsReadable == nil || !*ns.TLSSecretsReadable {
			t.Errorf("namespace %s: TLS Secrets readable = %v", ns.Name, ns.TLSSecretsReadable)
		}
	}
}
