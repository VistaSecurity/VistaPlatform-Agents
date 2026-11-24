package kubeinventory

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocolschema"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory/kubetest"
)

func fullCluster(t *testing.T) (*kubetest.Cluster, *Client) {
	t.Helper()
	cl := kubetest.New(t)
	cl.Load(filepath.Join("testdata", "full"))
	return cl, testClient(t, cl)
}

func testClient(t *testing.T, cl *kubetest.Cluster) *Client {
	t.Helper()
	host, port := cl.HostPort()
	c, err := NewClient(host, port, cl.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func collect(t *testing.T, c *Client, opts Options) *Inventory {
	t.Helper()
	inv, err := Collect(context.Background(), c, opts)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	validate(t, inv)
	return inv
}

// validate holds a document to the published schema, as the job result that
// carries it.
func validate(t *testing.T, inv *Inventory) {
	t.Helper()
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{
		"job_id": "5d0c2a4e-7b1f-4c3a-9e2d-6f8a1b0c9d7e", "success": true,
		"completed_at": time.Now().UTC().Format(time.RFC3339), "kubernetes_inventory": inv,
	}
	if err := set.Validate("job-result.device-agent", result); err != nil {
		t.Fatalf("the collection does not match the schema:\n%v", err)
	}
}

func section(t *testing.T, inv *Inventory, class string, status Status, reason string) {
	t.Helper()
	s, ok := inv.Sections[class]
	if !ok {
		t.Errorf("%s: no answer", class)
		return
	}
	if s.Status != status || s.Reason != reason {
		t.Errorf("%s: %s %q (%s), want %s %q", class, s.Status, s.Reason, s.Message, status, reason)
	}
}

func TestCollectFullCluster(t *testing.T) {
	cl, c := fullCluster(t)
	inv := collect(t, c, Options{ReadTLSSecrets: true})

	for _, class := range Classes {
		switch class {
		case ClassControlPlaneFiles:
			section(t, inv, class, StatusUnsupported, ReasonNotCollected)
		default:
			section(t, inv, class, StatusOK, "")
		}
	}

	// Cluster.
	nsUID := ""
	for _, ns := range inv.Namespaces {
		if ns.Name == "kube-system" {
			nsUID = ns.UID
		}
	}
	if inv.Cluster.ID == "" || inv.Cluster.ID != nsUID {
		t.Errorf("cluster id %q, want the kube-system namespace UID %q", inv.Cluster.ID, nsUID)
	}
	if inv.Cluster.Distribution != "kubeadm" || inv.Cluster.KubernetesVersion != "v1.33.4" || *inv.Cluster.NodeCount != 2 {
		t.Errorf("cluster: %+v", inv.Cluster)
	}
	if got := strings.Join(inv.Cluster.PodCIDRs, ","); got != "198.51.100.0/25,198.51.100.128/25" {
		t.Errorf("pod ranges: %s", got)
	}
	if got := strings.Join(inv.Cluster.ServiceCIDRs, ","); got != "203.0.113.0/24" {
		t.Errorf("service ranges: %s", got)
	}
	if len(inv.Cluster.APIEndpoints) != 1 || inv.Cluster.APIEndpoints[0] != (APIEndpoint{Address: "192.0.2.10", Port: 6443}) {
		t.Errorf("API endpoints: %+v", inv.Cluster.APIEndpoints)
	}
	if len(inv.Cluster.CACertificates) != 1 {
		t.Errorf("cluster CA: %v", inv.Cluster.CACertificates)
	}

	// Nodes.
	if n := inv.Nodes[0]; n.Name != "node-a" || strings.Join(n.Roles, ",") != "control-plane" || n.Labels["example.test/rack"] != "" ||
		n.Labels["topology.kubernetes.io/zone"] != "zone-a" || n.ProviderID != "example://zone-a/node-a" || !*n.Ready {
		t.Errorf("node-a: %+v", n)
	}

	// Every pod names a workload that has a row, in the pod's namespace.
	workloads := map[string]Workload{}
	for _, w := range inv.Workloads {
		workloads[w.Namespace+"/"+w.Kind+"/"+w.Name] = w
	}
	wantPods := map[string]string{
		"shop/web-7c9d8f6b5-aaaaa":          "Deployment/web",
		"shop/web-7c9d8f6b5-bbbbb":          "Deployment/web",
		"shop/db-0":                         "StatefulSet/db",
		"shop/canary-6f6f6f6f6-ccccc":       "Rollout/canary",
		"default/debug":                     "Pod/debug",
		"kube-system/kube-apiserver-node-a": "Node/node-a",
		"kube-system/node-exporter-aaaaa":   "DaemonSet/node-exporter",
		"mesh/api-5d5d5d5d5-ddddd":          "Deployment/api",
	}
	gotPods := map[string]string{}
	for _, p := range inv.Pods {
		gotPods[p.Namespace+"/"+p.Name] = p.Workload.Kind + "/" + p.Workload.Name
		if _, ok := workloads[p.Namespace+"/"+p.Workload.Kind+"/"+p.Workload.Name]; !ok {
			t.Errorf("pod %s/%s names workload %+v, which has no row", p.Namespace, p.Name, p.Workload)
		}
	}
	if !reflect.DeepEqual(gotPods, wantPods) {
		t.Errorf("pods and their workloads:\n got %v\nwant %v", gotPods, wantPods)
	}
	// The finished Job's pod is not a pod row, but its CronJob is a workload.
	if _, ok := workloads["shop/CronJob/report"]; !ok {
		t.Error("the CronJob has no workload row")
	}
	if w := workloads["shop/Rollout/canary"]; w.APIGroup != "argoproj.io" || len(w.Containers) != 1 {
		t.Errorf("a workload of another controller is described from its pod: %+v", w)
	}

	web := workloads["shop/Deployment/web"]
	if *web.ReplicasDesired != 2 || *web.ReplicasReady != 2 || web.ServiceAccount != "web" || strings.Join(web.SecretVolumes, ",") != "web-tls" ||
		web.MeshProxy != "istio" || web.MTLSMode != mtlsStrict || web.Labels["team"] != "" || web.Labels["app.kubernetes.io/name"] != "web" {
		t.Errorf("web: %+v", web)
	}
	if len(web.Containers) != 2 || web.Containers[0].Ports[0] != (ContainerPort{Name: "https", Port: 8443, Protocol: "TCP"}) || !web.Containers[1].Init {
		t.Errorf("web containers: %+v", web.Containers)
	}
	for key, want := range map[string]string{
		"shop/StatefulSet/db": mtlsDisabled, "mesh/Deployment/api": mtlsStrict, "default/Pod/debug": mtlsNotMeshed,
		"kube-system/Node/node-a": mtlsNotMeshed, "shop/Rollout/canary": mtlsNotMeshed,
	} {
		if got := workloads[key].MTLSMode; got != want {
			t.Errorf("%s mTLS mode %q, want %q", key, got, want)
		}
	}
	if !workloads["kube-system/Node/node-a"].HostNetwork {
		t.Error("the static pod's workload is on the host network")
	}

	// Services: what backs each, and which workloads.
	services := map[string]Service{}
	for _, s := range inv.Services {
		services[s.Namespace+"/"+s.Name] = s
	}
	for key, want := range map[string]struct {
		backing   string
		workloads string
	}{
		"shop/web": {BackingWorkloads, "Deployment/web"}, "shop/web-lb": {BackingWorkloads, "Deployment/web"},
		"shop/db": {BackingWorkloads, "StatefulSet/db"}, "shop/payments-upstream": {BackingExternalName, ""},
		"shop/idle": {BackingWorkloads, "Deployment/idle"}, "shop/orphan": {BackingNone, ""},
		"default/kubernetes": {BackingManualEndpoints, ""},
	} {
		s, ok := services[key]
		var refs []string
		for _, w := range s.Workloads {
			refs = append(refs, w.Kind+"/"+w.Name)
		}
		if !ok || s.Backing != want.backing || strings.Join(refs, ",") != want.workloads {
			t.Errorf("service %s: backing %q workloads %v, want %q %q", key, s.Backing, refs, want.backing, want.workloads)
		}
	}
	if s := services["shop/web"]; *s.EndpointsReady != 1 || *s.EndpointsNotReady != 1 || s.Ports[0].TargetPort != "https" ||
		!reflect.DeepEqual(s.Ports[0].ResolvedTargetPorts, []int{8443}) || s.Ports[0].AppProtocol != "https" {
		t.Errorf("shop/web: %+v", s)
	}
	if s := services["shop/web-lb"]; s.Type != "LoadBalancer" || strings.Join(s.LoadBalancerAddresses, ",") != "192.0.2.80,lb.example.test" || s.Ports[0].NodePort != 30443 {
		t.Errorf("shop/web-lb: %+v", s)
	}
	if s := services["shop/db"]; !s.Headless || len(s.ClusterIPs) != 0 || s.Ports[0].TargetPort != "5432" {
		t.Errorf("shop/db: %+v", s)
	}

	// Ingress and Gateway.
	in := inv.Ingresses[0]
	if in.Controller != "k8s.io/ingress-nginx" || in.TLS[0].SecretName != "web-tls" || len(in.Rules) != 3 ||
		!in.Rules[0].TLS || in.Rules[0].SecretName != "web-tls" || !in.Rules[1].TLS || in.Rules[2].TLS ||
		in.Rules[0].Paths[0].ServicePort != "https" || in.Rules[2].Paths[0].ServicePort != "443" || in.DefaultBackend.Service != "web" {
		t.Errorf("ingress: %+v", in)
	}
	gw := inv.Gateways[0]
	if gw.Controller != "istio.io/gateway-controller" || len(gw.Listeners) != 2 || gw.Listeners[0].TLSMode != "Terminate" ||
		gw.Listeners[0].CertificateRefs[0] != (ObjectRef{Kind: "Secret", Name: "web-tls"}) || *gw.Listeners[0].AttachedRoutes != 1 || gw.Listeners[1].TLSMode != "" {
		t.Errorf("gateway: %+v", gw)
	}
	if r := inv.Routes[0]; r.Kind != "HTTPRoute" || r.Parents[0].SectionName != "https" || r.Backends[0].Name != "web" {
		t.Errorf("route: %+v", r)
	}

	// cert-manager.
	webFP, caFP := cl.Fingerprint("web"), cl.Fingerprint("ca-internal")
	cert := inv.CertManagerCertificates[1]
	if cert.Name != "web" {
		cert = inv.CertManagerCertificates[0]
	}
	if cert.SecretName != "web-tls" || cert.IssuerRef.Name != "internal-ca" || cert.Duration != "2160h0m0s" ||
		*cert.KeyRequest != (KeyRequest{Algorithm: "ECDSA", Size: 256, Encoding: "PKCS8", RotationPolicy: "Always"}) ||
		cert.Ready.Status != "true" || cert.Revision != 3 || cert.NotAfter == nil {
		t.Errorf("certificate: %+v", cert)
	}
	issuers := map[string]CertManagerIssuer{}
	for _, i := range inv.CertManagerIssuers {
		issuers[i.Scope+"/"+i.Name] = i
	}
	if i := issuers["cluster/internal-ca"]; i.Type != "ca" || i.CASecretName != "internal-ca-root" || i.Namespace != "" {
		t.Errorf("cluster issuer: %+v", i)
	}
	if i := issuers["namespace/public"]; i.Type != "acme" || i.ACMEServer != "https://acme.example.test/directory" ||
		strings.Join(i.ACMESolvers, ",") != "dns01,http01" || i.Ready.Status != "false" {
		t.Errorf("acme issuer: %+v", i)
	}
	if issuers["namespace/selfsigned"].Type != "self_signed" || issuers["namespace/vault"].VaultPath != "pki/sign/shop" {
		t.Errorf("issuers: %+v", issuers)
	}
	if r := inv.CertManagerRequests[0]; r.CertificateName != "web" || r.Approval != "approved" || r.CSR.KeyAlgorithm != "ECDSA" || r.CSR.KeySize != 256 ||
		!reflect.DeepEqual(r.CertificateChain, []string{webFP}) || !reflect.DeepEqual(r.CACertificates, []string{caFP}) {
		t.Errorf("certificate request: %+v", r)
	}
	if r := inv.CertificateSigningRequests; len(r) != 2 || r[0].SignerName != "kubernetes.io/kubelet-serving" || r[0].Approval != "approved" ||
		r[0].CertificateChain[0] != cl.Fingerprint("kubelet-node-a") || r[1].Approval != "pending" || r[1].CertificateChain != nil {
		t.Errorf("signing requests: %+v", r)
	}

	// TLS Secrets: only the TLS ones, certificates only.
	secrets := map[string]TLSSecret{}
	for _, s := range inv.TLSSecrets {
		secrets[s.Namespace+"/"+s.Name] = s
	}
	if len(secrets) != 3 {
		t.Errorf("TLS secrets: %v", secrets)
	}
	if s := secrets["shop/web-tls"]; !reflect.DeepEqual(s.CertificateChain, []string{webFP}) || !reflect.DeepEqual(s.CACertificates, []string{caFP}) ||
		s.CertManagerCertificate != "web" || s.Owner.Kind != "Certificate" {
		t.Errorf("web-tls: %+v", s)
	}
	if s := secrets["shop/unreferenced-tls"]; strings.Join(s.UnparsedEntries, ",") != "tls.crt" || s.CertificateChain != nil {
		t.Errorf("a tls.crt that is not a certificate: %+v", s)
	}
	for _, ns := range inv.Namespaces {
		if ns.TLSSecretsReadable == nil || !*ns.TLSSecretsReadable {
			t.Errorf("namespace %s: TLS Secrets readable = %v", ns.Name, ns.TLSSecretsReadable)
		}
	}

	// Meshes.
	if m := inv.Mesh.Istio; !m.Present || m.RootNamespace != "istio-system" || m.MeshMTLSMode != mtlsPermissive || m.TrustAnchors[0] != cl.Fingerprint("ca-mesh") {
		t.Errorf("istio: %+v", m)
	}
	for _, ns := range inv.Namespaces {
		want := mtlsPermissive
		if ns.Name == "shop" {
			want = mtlsStrict
		}
		if ns.IstioMTLSMode != want {
			t.Errorf("namespace %s istio mode %q, want %q", ns.Name, ns.IstioMTLSMode, want)
		}
		if ns.Name == "shop" && (ns.IstioInjection != "enabled" || ns.Labels["team"] != "") {
			t.Errorf("shop: %+v", ns)
		}
		if ns.Name == "mesh" && (ns.LinkerdInjection != "enabled" || ns.LinkerdDefaultInboundPolicy != "all-authenticated") {
			t.Errorf("mesh: %+v", ns)
		}
	}
	if pa := inv.IstioPeerAuthentications; len(pa) != 3 || pa[0].Scope != "mesh" || pa[1].Scope != "namespace" || pa[2].Scope != "workload" ||
		pa[2].Selector["app"] != "db" || pa[2].PortModes[0] != (PortMode{Port: 5432, Mode: "DISABLE"}) {
		t.Errorf("peer authentications: %+v", pa)
	}
	if dr := inv.IstioDestinationRules[0]; dr.TLSMode != "ISTIO_MUTUAL" || dr.PortTLSModes[0] != (PortMode{Port: 5432, Mode: "DISABLE"}) {
		t.Errorf("destination rule: %+v", dr)
	}
	if m := inv.Mesh.Linkerd; !m.Present || m.Namespace != "linkerd" || m.TrustAnchors[0] != cl.Fingerprint("ca-linkerd") {
		t.Errorf("linkerd: %+v", m)
	}
	if inv.LinkerdServers[0].Port != "http" || inv.LinkerdAuthorizationPolicies[0].RequiredAuthentications[0].Kind != "MeshTLSAuthentication" {
		t.Errorf("linkerd policy: %+v %+v", inv.LinkerdServers, inv.LinkerdAuthorizationPolicies)
	}
	if m := inv.Mesh.Cilium; !m.Present || m.Encryption != "wireguard" || *m.NodeEncryption {
		t.Errorf("cilium: %+v", m)
	}

	// Control plane.
	if h := inv.APIServer; h.Status != handshakeOK || h.Address != "127.0.0.1" || h.TLSVersion != "TLS 1.3" || h.CipherSuite == "" ||
		len(h.CertificateChain) != 1 || !*h.ChainsToClusterCA {
		t.Errorf("API server handshake: %+v", h)
	}
	if len(inv.Kubelets) != 2 {
		t.Fatalf("kubelets: %+v", inv.Kubelets)
	}
	// node-a's kubelet serves a self-signed certificate. The handshake is
	// verified against the cluster CA and so does not complete; what the
	// kubelet served and what was negotiated are recorded all the same.
	if k := inv.Kubelets[0]; k.Node != "node-a" || k.Status != handshakeOK || k.CertificateChain[0] != cl.Fingerprint("kubelet-node-a") || *k.ChainsToClusterCA ||
		k.TLSVersion != "TLS 1.3" || !strings.HasPrefix(k.CipherSuite, "TLS_") {
		t.Errorf("node-a kubelet (self-signed): %+v", k)
	}
	if k := inv.Kubelets[1]; k.Node != "node-b" || k.Status != handshakeRefused || k.CertificateChain != nil {
		t.Errorf("node-b kubelet (nothing listening): %+v", k)
	}

	// Webhooks and aggregated APIs.
	hooks := inv.AdmissionWebhooks
	if len(hooks) != 2 || hooks[0].Kind != "validating" || hooks[0].Service.Name != "cert-manager-webhook" || hooks[0].CABundle[0] != cl.Fingerprint("ca-webhook") ||
		hooks[1].Kind != "mutating" || hooks[1].URLHost != "hooks.example.test:8443" || hooks[1].CABundle == nil || len(hooks[1].CABundle) != 0 {
		t.Errorf("webhooks: %+v", hooks)
	}
	if a := inv.APIServices; len(a) != 1 || a[0].Name != "v1beta1.metrics.k8s.io" || !a[0].InsecureSkipTLSVerify || !*a[0].Available {
		t.Errorf("API services: %+v", a)
	}

	// Every fingerprint a row names is a row of certificates, and none is
	// there that nothing names.
	known := map[string]bool{}
	for _, c := range inv.Certificates {
		known[c.FingerprintSHA256] = true
		if !strings.HasPrefix(c.CertificatePEM, "-----BEGIN CERTIFICATE-----\n") {
			t.Errorf("certificate %s has no PEM", c.FingerprintSHA256)
		}
	}
	doc, _ := json.Marshal(inv)
	named := map[string]bool{}
	for _, fp := range regexp.MustCompile(`"[0-9a-f]{64}"`).FindAllString(string(doc), -1) {
		named[strings.Trim(fp, `"`)] = true
	}
	if !reflect.DeepEqual(known, named) {
		t.Errorf("certificates table has %d entries, rows name %d fingerprints", len(known), len(named))
	}
}

// What the collector must leave in the cluster: the fixture marks every such
// value, and none may reach the result.
func TestNothingButTheProjectionLeavesTheCluster(t *testing.T) {
	_, c := fullCluster(t)
	for _, optIn := range []bool{false, true} {
		inv := collect(t, c, Options{ReadTLSSecrets: optIn, ExtraLabelKeys: []string{"team"}})
		doc, _ := json.Marshal(inv)
		if i := bytes.Index(doc, []byte("secret-value")); i >= 0 {
			t.Errorf("opt-in %v: a value the collector must not carry is in the result: ...%s...", optIn, doc[max(0, i-120):min(len(doc), i+40)])
		}
		for _, forbidden := range []string{`"env"`, `"command"`, `"args"`, `"annotations"`, `"managedFields"`, `"data"`, "PRIVATE KEY", "ops@example.test", "last-applied"} {
			if bytes.Contains(doc, []byte(forbidden)) {
				t.Errorf("opt-in %v: %s is in the result", optIn, forbidden)
			}
		}
		// The label a job asked for by name is reported; the allowlist is
		// what kept it out before.
		if !bytes.Contains(doc, []byte(`"team":"payments"`)) {
			t.Errorf("opt-in %v: an extra label key was not reported", optIn)
		}
	}
}

func TestDefaultNeverCallsTheSecretsAPI(t *testing.T) {
	cl, c := fullCluster(t)
	inv := collect(t, c, Options{})
	section(t, inv, ClassTLSSecrets, StatusUnsupported, ReasonNotEnabled)
	if inv.Collector.TLSSecrets != "not_enabled" || len(inv.TLSSecrets) != 0 {
		t.Errorf("collector %+v, %d TLS secrets", inv.Collector, len(inv.TLSSecrets))
	}
	for _, r := range cl.Requests() {
		if strings.Contains(r.Path, "secrets") {
			t.Errorf("the collector asked for %s without the opt-in", r.Path)
		}
	}
	for _, ns := range inv.Namespaces {
		if ns.TLSSecretsReadable != nil {
			t.Errorf("namespace %s says whether Secrets are readable though they were never asked for", ns.Name)
		}
	}
	// A parameter cannot turn it on.
	params, err := ParseParameters(map[string]any{"read_tls_secrets": true, "tls_secrets": "enabled", "classes": []any{"tls_secrets"}})
	if err != nil || params.Options.ReadTLSSecrets {
		t.Errorf("a job parameter enabled reading Secrets: %+v, %v", params.Options, err)
	}
}

// The private key of a TLS Secret is on the wire (Kubernetes cannot leave it
// out) and must be nowhere after that.
func TestTLSKeyNeverReachesTheResult(t *testing.T) {
	cl, c := fullCluster(t)
	inv := collect(t, c, Options{ReadTLSSecrets: true})
	if len(inv.TLSSecrets) == 0 {
		t.Fatal("no TLS Secret was read; the test would prove nothing")
	}

	var haystacks [][]byte
	for _, part := range append(Split(inv, MinMaxPartBytes), inv) {
		doc, err := json.Marshal(part)
		if err != nil {
			t.Fatal(err)
		}
		haystacks = append(haystacks, doc, []byte(fmt.Sprintf("%+v", part)))
	}
	served := 0
	for _, name := range []string{"web", "ca-internal", "stray"} {
		keyPEM := cl.KeyPEM(name)
		block, _ := pem.Decode(keyPEM)
		needles := map[string][]byte{
			"the key as the API server sent it (base64 of the PEM)": []byte(base64.StdEncoding.EncodeToString(keyPEM)),
			"the PEM body":      bytes.Split(keyPEM, []byte("\n"))[1],
			"the DER as base64": []byte(base64.StdEncoding.EncodeToString(block.Bytes)[:48]),
			"the DER":           block.Bytes,
		}
		for _, h := range haystacks {
			for what, needle := range needles {
				if bytes.Contains(h, needle) {
					t.Errorf("%s of %q is in the result", what, name)
				}
			}
			if bytes.Contains(h, []byte("PRIVATE KEY")) {
				t.Error("a PRIVATE KEY block is in the result")
			}
		}
		// The proof is empty unless the server really did send the key.
		raw, err := os.ReadFile(filepath.Join("testdata", "full", "api", "v1", "secrets.json"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("{{KEY:"+name+"}}")) {
			served++
		}
	}
	if served != 3 {
		t.Fatalf("the fixture serves %d of the 3 keys", served)
	}
	sawSelector := false
	for _, r := range cl.Requests() {
		if strings.HasSuffix(r.Path, "/secrets") {
			if r.Query.Get("fieldSelector") != "type=kubernetes.io/tls" {
				t.Errorf("Secrets were listed without the TLS type selector: %v", r.Query)
			}
			sawSelector = true
		}
	}
	if !sawSelector {
		t.Fatal("the Secrets API was not called")
	}
}

// The struct a TLS Secret is decoded into is the reason the key is never
// held. It declares the two certificate entries and nothing else.
func TestTLSSecretProjectionDeclaresOnlyCertificates(t *testing.T) {
	data, _ := reflect.TypeOf(tlsSecretObject{}).FieldByName("Data")
	var tags []string
	for i := 0; i < data.Type.NumField(); i++ {
		tags = append(tags, data.Type.Field(i).Tag.Get("json"))
	}
	if strings.Join(tags, ",") != "tls.crt,ca.crt" || data.Type.Kind() != reflect.Struct {
		t.Fatalf("tlsSecretObject.Data declares %v; it may declare only tls.crt and ca.crt, as a struct", tags)
	}
	var s tlsSecretObject
	if err := json.Unmarshal([]byte(`{"type":"kubernetes.io/tls","data":{"tls.key":"S0VZLUJZVEVT","tls.crt":"Q0VSVA==","extra":"WA=="},"stringData":{"tls.key":"KEY-BYTES"}}`), &s); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%+v", s); strings.Contains(got, "KEY-BYTES") || strings.Contains(got, "S0VZ") || string(s.Data.TLSCrt) != "CERT" {
		t.Errorf("decoded: %s", got)
	}
}

// No projection may hold an arbitrary value: no interface, no raw JSON, and
// no map except the label and selector maps.
func TestProjectionsHoldNoOpenValues(t *testing.T) {
	allowedMaps := map[string]bool{"Labels": true, "MatchLabels": true, "Selector": true, "PortLevelMTLS": true}
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice:
			walk(path, typ.Elem())
		case reflect.Interface:
			t.Errorf("%s is an interface", path)
		case reflect.Map:
			name := path[strings.LastIndexByte(path, '.')+1:]
			if !allowedMaps[name] || typ.Key().Kind() != reflect.String {
				t.Errorf("%s is a map", path)
			}
			if typ.Elem().Kind() != reflect.String {
				walk(path, typ.Elem())
			}
		case reflect.Struct:
			if typ == reflect.TypeOf(time.Time{}) {
				return
			}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if f.Type == reflect.TypeOf(json.RawMessage{}) {
					t.Errorf("%s.%s is raw JSON", path, f.Name)
					continue
				}
				walk(path+"."+f.Name, f.Type)
			}
		}
	}
	for _, v := range []any{
		versionObject{}, namespaceObject{}, nodeObject{}, podObject{}, workloadObject{}, object{}, serviceObject{}, endpointSliceObject{},
		istioRootConfigMap{}, linkerdTrustConfigMap{}, ciliumConfigMap{}, tlsSecretObject{}, ingressObject{}, ingressClassObject{},
		serviceCIDRObject{}, gatewayClassObject{}, gatewayObject{}, routeObject{}, cmCertificateObject{}, cmIssuerObject{}, cmRequestObject{},
		csrObject{}, peerAuthenticationObject{}, destinationRuleObject{}, linkerdServerObject{}, linkerdAuthorizationPolicyObject{},
		webhookConfigurationObject{}, apiServiceObject{},
	} {
		walk(reflect.TypeOf(v).Name(), reflect.TypeOf(v))
	}
}

func TestClassAnswers(t *testing.T) {
	const (
		deployments = "/apis/apps/v1/deployments"
		pods        = "/api/v1/pods"
		cmCerts     = "/apis/cert-manager.io/v1/certificates"
	)
	t.Run("a forbidden list is failed, not_permitted, and never reads as empty", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetStatus(deployments, http.StatusForbidden)
		inv := collect(t, c, Options{SkipKubeletProbe: true})
		section(t, inv, ClassWorkloads, StatusFailed, ReasonNotPermitted)
		section(t, inv, ClassPods, StatusOK, "")
		if len(inv.Workloads) == 0 {
			t.Error("the workloads that could be read are still sent")
		}
		section(t, inv, ClassKubeletCerts, StatusUnsupported, ReasonNotRequested)
	})
	t.Run("pods that cannot be read fail everything attributed through them", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetStatus(pods, http.StatusForbidden)
		inv := collect(t, c, Options{SkipKubeletProbe: true})
		section(t, inv, ClassPods, StatusFailed, ReasonNotPermitted)
		section(t, inv, ClassWorkloads, StatusFailed, ReasonNotPermitted)
		section(t, inv, ClassServices, StatusFailed, ReasonNotPermitted)
	})
	t.Run("an API the cluster does not serve is unsupported, not_installed", func(t *testing.T) {
		cl := kubetest.New(t)
		cl.Load(filepath.Join("testdata", "full"))
		for _, p := range []string{cmCerts, "/apis/security.istio.io/v1/peerauthentications", "/apis/gateway.networking.k8s.io/v1/gateways",
			"/apis/policy.linkerd.io/v1beta3/servers", "/api/v1/namespaces/kube-system/configmaps/cilium-config"} {
			cl.SetStatus(p, http.StatusNotFound)
		}
		inv := collect(t, testClient(t, cl), Options{SkipKubeletProbe: true})
		for _, class := range []string{ClassCertManager, ClassMeshIstio, ClassGateways, ClassMeshLinkerd, ClassMeshCilium} {
			section(t, inv, class, StatusUnsupported, ReasonNotInstalled)
		}
		if inv.Mesh.Istio.Present || inv.Mesh.Linkerd.Present || inv.Mesh.Cilium.Present {
			t.Errorf("mesh: %+v %+v %+v", inv.Mesh.Istio, inv.Mesh.Linkerd, inv.Mesh.Cilium)
		}
		for _, ns := range inv.Namespaces {
			if ns.IstioMTLSMode != mtlsNotMeshed {
				t.Errorf("namespace %s: %q without Istio", ns.Name, ns.IstioMTLSMode)
			}
		}
		// A sidecar is still seen on the pod; without the policies its mode
		// is not guessed.
		for _, w := range inv.Workloads {
			if w.Name == "web" && w.MTLSMode != mtlsUnknown {
				t.Errorf("web: %q", w.MTLSMode)
			}
		}
	})
	t.Run("a server error is failed, api_error", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetStatus("/apis/networking.k8s.io/v1/ingresses", http.StatusInternalServerError)
		cl.SetStatus("/api/v1/namespaces/kube-system/configmaps/cilium-config", http.StatusForbidden)
		inv := collect(t, c, Options{SkipKubeletProbe: true})
		section(t, inv, ClassIngresses, StatusFailed, ReasonAPIError)
		section(t, inv, ClassMeshCilium, StatusFailed, ReasonNotPermitted)
	})
	t.Run("more rows than the limit is failed, item_limit, with the rows read", func(t *testing.T) {
		_, c := fullCluster(t)
		inv := collect(t, c, Options{SkipKubeletProbe: true, MaxItemsPerClass: 3})
		section(t, inv, ClassPods, StatusFailed, ReasonItemLimit)
		if len(inv.Pods) == 0 || len(inv.Pods) > 3 {
			t.Errorf("%d pods", len(inv.Pods))
		}
	})
	t.Run("only the classes asked for are sent, attributed as ever", func(t *testing.T) {
		_, c := fullCluster(t)
		inv := collect(t, c, Options{Classes: []string{ClassServices}})
		section(t, inv, ClassServices, StatusOK, "")
		section(t, inv, ClassCluster, StatusOK, "")
		for _, class := range []string{ClassPods, ClassWorkloads, ClassNodes, ClassCertManager, ClassKubeletCerts, ClassTLSSecrets} {
			section(t, inv, class, StatusUnsupported, ReasonNotRequested)
		}
		if inv.Pods != nil || inv.Workloads != nil || inv.Nodes != nil || inv.Kubelets != nil || len(inv.Services) == 0 {
			t.Errorf("lists: %d pods, %d workloads, %d nodes, %d services", len(inv.Pods), len(inv.Workloads), len(inv.Nodes), len(inv.Services))
		}
		for _, s := range inv.Services {
			if s.Name == "web" && (s.Backing != BackingWorkloads || s.Workloads[0].Name != "web") {
				t.Errorf("web: %+v", s)
			}
		}
	})
	t.Run("without the cluster's id nothing is sent", func(t *testing.T) {
		cl := kubetest.New(t)
		cl.SetList("/api/v1/namespaces", map[string]any{"metadata": map[string]string{"name": "default", "uid": "11111111-2222-4333-8444-555555555555"}})
		if _, err := Collect(context.Background(), testClient(t, cl), Options{}); !errors.Is(err, ErrClusterIdentity) {
			t.Errorf("err = %v", err)
		}
		cl.SetStatus("/api/v1/namespaces", http.StatusForbidden)
		if _, err := Collect(context.Background(), testClient(t, cl), Options{}); !errors.Is(err, ErrClusterIdentity) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the opt-in role bound in some namespaces only", func(t *testing.T) {
		cl, c := fullCluster(t)
		cl.SetStatus("/api/v1/secrets", http.StatusForbidden)
		for _, ns := range []string{"kube-system", "default", "istio-system", "cert-manager", "vista-agents", "linkerd", "mesh"} {
			cl.SetStatus("/api/v1/namespaces/"+ns+"/secrets", http.StatusForbidden)
		}
		inv := collect(t, c, Options{SkipKubeletProbe: true, ReadTLSSecrets: true})
		section(t, inv, ClassTLSSecrets, StatusOK, "")
		for _, ns := range inv.Namespaces {
			if got := *ns.TLSSecretsReadable; got != (ns.Name == "shop") {
				t.Errorf("namespace %s readable = %v", ns.Name, got)
			}
		}
		for _, s := range inv.TLSSecrets {
			if s.Namespace != "shop" {
				t.Errorf("a Secret of %s was read", s.Namespace)
			}
		}
		if len(inv.TLSSecrets) != 2 {
			t.Errorf("%d TLS Secrets", len(inv.TLSSecrets))
		}

		cl.SetStatus("/api/v1/namespaces/shop/secrets", http.StatusForbidden)
		inv = collect(t, c, Options{SkipKubeletProbe: true, ReadTLSSecrets: true})
		section(t, inv, ClassTLSSecrets, StatusFailed, ReasonNotPermitted)
	})
}

// A cluster with nothing but the built-in APIs: every optional class answers
// unsupported, and the rest are ok and empty.
func TestCollectBareCluster(t *testing.T) {
	cl := kubetest.New(t)
	cl.SetObject("/version", map[string]string{"major": "1", "minor": "32", "gitVersion": "v1.32.5+k3s1", "platform": "linux/arm64"})
	cl.SetList("/api/v1/namespaces", map[string]any{"metadata": map[string]string{"name": "kube-system", "uid": "11111111-2222-4333-8444-555555555555"}})
	for _, p := range []string{"/api/v1/nodes", "/api/v1/pods", "/api/v1/services", "/apis/apps/v1/deployments", "/apis/apps/v1/statefulsets",
		"/apis/apps/v1/daemonsets", "/apis/apps/v1/replicasets", "/apis/batch/v1/cronjobs", "/apis/batch/v1/jobs", "/apis/discovery.k8s.io/v1/endpointslices",
		"/apis/networking.k8s.io/v1/ingresses", "/apis/networking.k8s.io/v1/ingressclasses", "/apis/certificates.k8s.io/v1/certificatesigningrequests",
		"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations", "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
		"/apis/apiregistration.k8s.io/v1/apiservices"} {
		cl.SetList(p)
	}
	inv := collect(t, testClient(t, cl), Options{})
	if inv.Cluster.Distribution != "k3s" || inv.Cluster.ServiceCIDRs != nil || *inv.Cluster.NodeCount != 0 {
		t.Errorf("cluster: %+v", inv.Cluster)
	}
	for _, class := range []string{ClassCluster, ClassNodes, ClassNamespaces, ClassWorkloads, ClassPods, ClassServices, ClassIngresses, ClassCSRs,
		ClassAdmissionWebhooks, ClassAPIServices, ClassAPIServerCert, ClassKubeletCerts} {
		section(t, inv, class, StatusOK, "")
	}
	for _, class := range []string{ClassGateways, ClassCertManager, ClassMeshIstio, ClassMeshLinkerd, ClassMeshCilium} {
		section(t, inv, class, StatusUnsupported, ReasonNotInstalled)
	}
	section(t, inv, ClassTLSSecrets, StatusUnsupported, ReasonNotEnabled)
}

func TestDistribution(t *testing.T) {
	node := func(labels map[string]string) []nodeObject {
		var n nodeObject
		n.Metadata.Labels = labels
		return []nodeObject{n}
	}
	for _, tc := range []struct {
		version string
		nodes   []nodeObject
		want    string
	}{
		{"v1.33.4+rke2r1", nil, "rke2"}, {"v1.32.5+k3s1", nil, "k3s"}, {"v1.33.1-eks-1a2b3c4", nil, "eks"}, {"v1.33.2-gke.1234000", nil, "gke"},
		{"v1.33.4", node(map[string]string{"kubernetes.azure.com/cluster": "x"}), "aks"},
		{"v1.33.4", node(map[string]string{"node.openshift.io/os_id": "rhcos"}), "openshift"},
		{"v1.33.4", node(map[string]string{"eks.amazonaws.com/nodegroup": "x"}), "eks"},
		{"v1.33.4", node(nil), "unknown"}, {"", nil, "unknown"},
	} {
		if got := distribution(tc.version, tc.nodes); got != tc.want {
			t.Errorf("distribution(%q) = %q, want %q", tc.version, got, tc.want)
		}
	}
}

// Every request the collector makes is one of Calls(), with that entry's
// verb; and with everything installed and the opt-in on, every entry of
// Calls() is used. The manifest's role is tested against the same table.
func TestRequestsAreExactlyTheDeclaredCalls(t *testing.T) {
	pathRE := regexp.MustCompile(`^(?:/api/v1|/apis/([^/]+)/([^/]+))(?:/namespaces/([^/]+))?/([a-z]+)(?:/([^/]+))?$`)
	for _, optIn := range []bool{false, true} {
		_, c := fullCluster(t)
		collect(t, c, Options{ReadTLSSecrets: optIn})
		declared := append([]Resource{}, Calls(false)...)
		if optIn {
			declared = append(declared, Calls(true)...)
		}
		used := map[string]bool{}
		for _, r := range c.Requests() {
			if r.Path == "/version" {
				continue
			}
			m := pathRE.FindStringSubmatch(r.Path)
			if m == nil {
				t.Errorf("request %s is not a resource path", r.Path)
				continue
			}
			group, resource, name := m[1], m[4], m[5]
			if group != r.Group || resource != r.Resource || name != r.Name {
				t.Errorf("request %s was recorded as %+v", r.Path, r)
			}
			ok := false
			for _, d := range declared {
				if d.Group != group || d.Name != resource {
					continue
				}
				switch {
				case d.Verb == VerbList && name == "" && r.Verb == VerbList:
					ok = true
				case d.Verb == VerbGet && contains(d.Names, name) && r.Verb == VerbGet:
					ok = true
				}
				if ok {
					used[d.Group+"/"+d.Name] = true
				}
			}
			if !ok {
				t.Errorf("opt-in %v: request %s (%s %s/%s %q) is not a declared call", optIn, r.Path, r.Verb, group, resource, name)
			}
		}
		for _, d := range declared {
			// The fixture's Gateway API has no TLSRoute or TCPRoute kinds;
			// the collector still asks, and is told 404.
			if !used[d.Group+"/"+d.Name] {
				t.Errorf("opt-in %v: %s/%s is declared and was never requested", optIn, d.Group, d.Name)
			}
		}
	}
	for _, r := range allResources {
		if r.Verb != VerbGet && r.Verb != VerbList {
			t.Errorf("%s: verb %q", r.Name, r.Verb)
		}
		if (r.Verb == VerbGet) != (len(r.Names) > 0) {
			t.Errorf("%s: a get needs names and a list has none", r.Name)
		}
		if strings.ContainsAny(r.Group+r.Name+strings.Join(r.Names, ""), "*/") {
			t.Errorf("%s: wildcard or subresource", r.Name)
		}
	}
}

func TestClientRefusesUndeclaredReads(t *testing.T) {
	cl, c := fullCluster(t)
	before := len(cl.Requests())
	if _, err := getNamed[ciliumConfigMap](context.Background(), c, resConfigMaps, "shop", "app-config"); err == nil {
		t.Error("a ConfigMap that is not on the list was read")
	}
	if _, err := list[object](context.Background(), c, resConfigMaps, "", nil, 0); err == nil {
		t.Error("ConfigMaps were listed")
	}
	if len(cl.Requests()) != before {
		t.Error("a refused read reached the server")
	}
}

func TestListFollowsPages(t *testing.T) {
	cl := kubetest.New(t)
	var items []any
	for i := 0; i < listPageSize*2+7; i++ {
		items = append(items, map[string]any{"metadata": map[string]string{"name": fmt.Sprintf("p%d", i), "namespace": "x"}})
	}
	cl.SetList("/api/v1/pods", items...)
	c := testClient(t, cl)
	rows, err := list[object](context.Background(), c, resPods, "", nil, 0)
	if err != nil || len(rows) != len(items) || rows[len(rows)-1].Metadata.Name != fmt.Sprintf("p%d", len(items)-1) {
		t.Fatalf("%d rows, %v", len(rows), err)
	}
	if n := len(cl.Requests()); n != 3 {
		t.Errorf("%d requests for 3 pages", n)
	}
	rows, err = list[object](context.Background(), c, resPods, "", nil, 600)
	if !errors.Is(err, ErrItemLimit) || len(rows) != 600 {
		t.Errorf("%d rows, %v", len(rows), err)
	}
}

func TestClientNeedsAServiceAccount(t *testing.T) {
	if _, err := NewClient("127.0.0.1", "6443", t.TempDir()); !errors.Is(err, ErrNotInCluster) {
		t.Errorf("err = %v", err)
	}
	t.Setenv(envServiceHost, "")
	if _, err := InCluster(); !errors.Is(err, ErrNotInCluster) {
		t.Errorf("err = %v", err)
	}
	if InClusterAvailable() {
		t.Error("available without an API server address")
	}
	// A wrong token is the API server's 401, reported as not permitted.
	cl := kubetest.New(t)
	cl.SetList("/api/v1/namespaces", map[string]any{"metadata": map[string]string{"name": "kube-system", "uid": "11111111-2222-4333-8444-555555555555"}})
	if err := os.WriteFile(filepath.Join(cl.Dir, "token"), []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Collect(context.Background(), testClient(t, cl), Options{})
	if !errors.Is(err, ErrClusterIdentity) || strings.Contains(err.Error(), "wrong") {
		t.Errorf("err = %v", err)
	}
}

// NewClient takes an address and a directory, which is what a test needs and
// what the agent must never offer: nothing shipped may call it.
func TestOnlyInClusterIsUsedOutsideTests(t *testing.T) {
	root, err := repo.Root()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"cmd", "internal", "shared"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			if strings.Contains(filepath.ToSlash(path), "/testsupport/") || strings.Contains(filepath.ToSlash(path), "/kubetest/") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			calls := bytes.Count(data, []byte("NewClient(host, port, ServiceAccountDir)"))
			if bytes.Contains(data, []byte("kubeinventory.NewClient(")) ||
				(strings.HasSuffix(filepath.ToSlash(path), "shared/kubeinventory/client.go") && (calls != 1 || bytes.Count(data, []byte("NewClient(")) != 2)) {
				t.Errorf("%s builds a Kubernetes client from an address; only InCluster may", path)
			}
			return nil
		})
	}
}

func TestParseParameters(t *testing.T) {
	p, err := ParseParameters(map[string]any{
		"classes": []any{"services", "pods"}, "probe_kubelets": false, "include_certificate_pem": false,
		"extra_label_keys": []any{"team.example.test/owner", "not a key", 7}, "max_items_per_class": float64(500),
		"max_part_bytes": float64(2 << 20), "timeout_seconds": float64(90), "unknown": "ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Parameters{MaxPartBytes: 2 << 20, Timeout: 90 * time.Second, Options: Options{
		Classes: []string{"services", "pods"}, SkipKubeletProbe: true, OmitCertificatePEM: true,
		ExtraLabelKeys: []string{"team.example.test/owner"}, MaxItemsPerClass: 500,
	}}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("got %+v\nwant %+v", p, want)
	}
	if p, err := ParseParameters(nil); err != nil || p.MaxPartBytes != DefaultMaxPartBytes || p.Timeout != DefaultTimeout {
		t.Errorf("defaults: %+v, %v", p, err)
	}
	// Out-of-range numbers fall back to the defaults rather than switch a
	// bound off.
	if p, _ := ParseParameters(map[string]any{"max_part_bytes": float64(1), "timeout_seconds": float64(999999), "max_items_per_class": float64(0)}); p.MaxPartBytes != DefaultMaxPartBytes || p.Timeout != DefaultTimeout || p.Options.MaxItemsPerClass != 0 {
		t.Errorf("out of range: %+v", p)
	}
	for _, bad := range []map[string]any{
		{"kubeconfig": "apiVersion: v1"}, {"token": "x"}, {"api_server": "https://other.example.test"}, {"classes": []any{"secrets"}}, {"classes": "pods"},
	} {
		if _, err := ParseParameters(bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

func TestOmitCertificatePEM(t *testing.T) {
	_, c := fullCluster(t)
	inv := collect(t, c, Options{OmitCertificatePEM: true, SkipKubeletProbe: true})
	if len(inv.Certificates) == 0 {
		t.Fatal("no certificates")
	}
	for _, cert := range inv.Certificates {
		if cert.CertificatePEM != "" || cert.SubjectDN == "" || cert.KeyAlgorithm == "" {
			t.Errorf("certificate: %+v", cert)
		}
	}
}

func TestSplit(t *testing.T) {
	_, c := fullCluster(t)
	inv := collect(t, c, Options{ReadTLSSecrets: true})
	if parts := Split(inv, DefaultMaxPartBytes); len(parts) != 1 || parts[0].Part != (Part{0, 1}) {
		t.Fatalf("a small cluster is %d parts", len(parts))
	}

	// A large cluster: the same rows many times over.
	big := *inv
	for i := 0; i < 30000; i++ {
		p := inv.Pods[i%len(inv.Pods)]
		p.Name = fmt.Sprintf("%s-%d", p.Name, i)
		big.Pods = append(big.Pods, p)
	}
	for i := 0; i < 2000; i++ {
		big.Certificates = append(big.Certificates, inv.Certificates[i%len(inv.Certificates)])
	}
	parts := Split(&big, MinMaxPartBytes)
	if len(parts) < 4 {
		t.Fatalf("%d parts", len(parts))
	}
	var joined Inventory
	for i, p := range parts {
		doc, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc) > MinMaxPartBytes {
			t.Errorf("part %d is %d bytes, over the limit of %d", i, len(doc), MinMaxPartBytes)
		}
		if p.Part != (Part{Index: i, Count: len(parts)}) || p.CollectionID != big.CollectionID || p.Cluster.ID != big.Cluster.ID {
			t.Errorf("part %d: %+v %s %s", i, p.Part, p.CollectionID, p.Cluster.ID)
		}
		if (p.Sections != nil) != (i == 0) || (p.Collector != nil) != (i == 0) || (p.APIServer != nil) != (i == 0) {
			t.Errorf("part %d: what is not a list belongs to part 0 only", i)
		}
		validate(t, p)
		for _, f := range listFields {
			for r := 0; r < f.rows(p); r++ {
				f.move(&joined, p, r)
			}
		}
	}
	// Put together again, the parts are the collection: nothing lost,
	// nothing twice, order kept.
	whole := big
	clearLists(&whole)
	for _, f := range listFields {
		for r := 0; r < f.rows(&big); r++ {
			f.move(&whole, &big, r)
		}
	}
	a, _ := json.Marshal(struct{ A, B, C, D any }{joined.Pods, joined.Certificates, joined.Services, joined.Workloads})
	b, _ := json.Marshal(struct{ A, B, C, D any }{whole.Pods, whole.Certificates, whole.Services, whole.Workloads})
	if !bytes.Equal(a, b) {
		t.Error("the parts do not add up to the collection")
	}
	if len(inv.Pods) == len(big.Pods) {
		t.Error("Split changed its input")
	}
}

// A list added to the record must also be dealt out by Split and cleared from
// part 0, or its rows would be lost or sent twice.
func TestSplitCoversEveryList(t *testing.T) {
	typ := reflect.TypeOf(Inventory{})
	lists := 0
	full := reflect.New(typ).Elem()
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() == reflect.Slice {
			lists++
			full.Field(i).Set(reflect.MakeSlice(typ.Field(i).Type, 1, 1))
		}
	}
	if lists != len(listFields) {
		t.Fatalf("Inventory has %d lists, Split deals out %d", lists, len(listFields))
	}
	inv := full.Interface().(Inventory)
	total := 0
	for _, f := range listFields {
		total += f.rows(&inv)
	}
	if total != lists {
		t.Errorf("listFields reaches %d of %d lists", total, lists)
	}
	clearLists(&inv)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() == reflect.Slice && reflect.ValueOf(inv).Field(i).Len() != 0 {
			t.Errorf("clearLists leaves %s", typ.Field(i).Name)
		}
	}
}
