package kubeinventory

// The manifest (deploy/kubernetes/) against the collector: the role grants
// exactly what the collector calls, and the pods are as locked down as the
// documentation says. These tests read the files a customer applies.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
)

const (
	manifestDir        = "deploy/kubernetes"
	agentsNamespace    = "vista-agents"
	deviceAgentAccount = "vista-device-agent"
	sensorAccount      = "vista-sensor"
)

type manifestObject = map[string]any

func kindOf(o manifestObject) string { return str(o["kind"]) }
func nameOf(o manifestObject) string { return str(dig(o, "metadata", "name")) }

func dig(v any, path ...string) any {
	for _, key := range path {
		m, ok := v.(manifestObject)
		if !ok {
			return nil
		}
		v = m[key]
	}
	return v
}

func str(v any) string { s, _ := v.(string); return s }

func seq(v any) []any { l, _ := v.([]any); return l }

func strs(v any) []string {
	var out []string
	for _, e := range seq(v) {
		out = append(out, str(e))
	}
	return out
}

func loadManifest(t *testing.T, file string) []manifestObject {
	t.Helper()
	data, err := os.ReadFile(repo.Path(t, filepath.Join(filepath.FromSlash(manifestDir), file)))
	if err != nil {
		t.Fatal(err)
	}
	var out []manifestObject
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var obj manifestObject
		err := dec.Decode(&obj)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if obj != nil {
			out = append(out, obj)
		}
	}
	return out
}

func find(t *testing.T, objs []manifestObject, kind, name string) manifestObject {
	t.Helper()
	for _, o := range objs {
		if kindOf(o) == kind && nameOf(o) == name {
			return o
		}
	}
	t.Fatalf("no %s %q in the manifest", kind, name)
	return nil
}

// grants flattens a role's rules to "verb group/resource[/name]" lines, and
// fails on anything that is not a plain, named grant.
func grants(t *testing.T, role manifestObject) []string {
	t.Helper()
	var out []string
	for i, r := range seq(role["rules"]) {
		rule := r.(manifestObject)
		verbs := strs(rule["verbs"])
		if len(verbs) == 0 {
			t.Errorf("%s rule %d has no verb", nameOf(role), i)
		}
		for _, v := range append(append(append(strs(rule["verbs"]), strs(rule["apiGroups"])...), strs(rule["resources"])...), strs(rule["resourceNames"])...) {
			if strings.Contains(v, "*") {
				t.Errorf("%s rule %d: wildcard %q", nameOf(role), i, v)
			}
		}
		for _, res := range strs(rule["resources"]) {
			if strings.Contains(res, "/") {
				t.Errorf("%s rule %d: subresource %q", nameOf(role), i, res)
			}
		}
		for key := range rule {
			switch key {
			case "apiGroups", "resources", "resourceNames", "verbs", "nonResourceURLs":
			default:
				t.Errorf("%s rule %d: unexpected member %q", nameOf(role), i, key)
			}
		}
		for _, verb := range verbs {
			for _, u := range strs(rule["nonResourceURLs"]) {
				out = append(out, verb+" "+u)
			}
			for _, group := range strs(rule["apiGroups"]) {
				for _, res := range strs(rule["resources"]) {
					names := strs(rule["resourceNames"])
					if len(names) == 0 {
						out = append(out, fmt.Sprintf("%s %s/%s", verb, group, res))
					}
					for _, n := range names {
						out = append(out, fmt.Sprintf("%s %s/%s/%s", verb, group, res, n))
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// declared is what the collector can call, in the same lines.
func declared(optIn bool) []string {
	var out []string
	for _, r := range Calls(optIn) {
		if len(r.Names) == 0 {
			out = append(out, fmt.Sprintf("%s %s/%s", r.Verb, r.Group, r.Name))
		}
		for _, n := range r.Names {
			out = append(out, fmt.Sprintf("%s %s/%s/%s", r.Verb, r.Group, r.Name, n))
		}
	}
	if !optIn {
		for _, u := range NonResourceURLs {
			out = append(out, VerbGet+" "+u)
		}
	}
	sort.Strings(out)
	return out
}

func diff(t *testing.T, what string, granted, called []string) {
	t.Helper()
	have := map[string]bool{}
	for _, g := range granted {
		have[g] = true
	}
	want := map[string]bool{}
	for _, c := range called {
		want[c] = true
		if !have[c] {
			t.Errorf("%s: the collector calls %q and the role does not grant it", what, c)
		}
	}
	for _, g := range granted {
		if !want[g] {
			t.Errorf("%s: the role grants %q and the collector never calls it", what, g)
		}
	}
}

func TestDefaultRoleGrantsExactlyWhatTheCollectorCalls(t *testing.T) {
	objs := loadManifest(t, "vista-agents.yaml")
	role := find(t, objs, "ClusterRole", "vista-device-agent-inventory")
	granted := grants(t, role)
	diff(t, "default role", granted, declared(false))
	for _, g := range granted {
		verb := strings.Fields(g)[0]
		if verb != VerbGet && verb != VerbList {
			t.Errorf("the role grants a verb that is not get or list: %q", g)
		}
		if strings.Contains(g, "/secrets") {
			t.Errorf("the default role reaches Secrets: %q", g)
		}
		// A get is only ever of a named object or a non-resource URL.
		if verb == VerbGet && strings.Count(g, "/") == 1 && !strings.HasPrefix(strings.Fields(g)[1], "/") {
			t.Errorf("an unnamed get: %q", g)
		}
	}
	if len(granted) < 30 {
		t.Fatalf("only %d grants were read from the role; the test is not reading the manifest", len(granted))
	}
}

func TestOptInRoleGrantsOnlyListingSecrets(t *testing.T) {
	objs := loadManifest(t, "tls-secrets-opt-in.yaml")
	role := find(t, objs, "ClusterRole", "vista-device-agent-tls-secrets")
	granted := grants(t, role)
	diff(t, "opt-in role", granted, declared(true))
	if strings.Join(granted, ";") != "list /secrets" {
		t.Errorf("the opt-in role grants %v", granted)
	}
	// The setting the agent reads is the one the opt-in file sets, and only
	// that file sets it.
	const env = "VISTA_KUBERNETES_READ_TLS_SECRETS"
	options := find(t, objs, "ConfigMap", "vista-device-agent-options")
	if data, _ := options["data"].(manifestObject); len(data) != 1 || str(data[env]) != "true" {
		t.Errorf("options ConfigMap: %v", options["data"])
	}
	main, err := os.ReadFile(repo.Path(t, filepath.Join(filepath.FromSlash(manifestDir), "vista-agents.yaml")))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(main, []byte(env)) {
		t.Errorf("vista-agents.yaml sets %s; only the opt-in file may", env)
	}
	source, err := os.ReadFile(repo.Path(t, filepath.Join("internal", "deviceagent", "devices", "kubernetes_inventory.go")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte(`EnvReadTLSSecrets = "`+env+`"`)) {
		t.Errorf("the agent does not read %s", env)
	}
}

// Who is bound to what: the device agent to its two roles and nothing else,
// the sensor to nothing at all.
func TestBindings(t *testing.T) {
	bound := map[string][]string{}
	for _, file := range []string{"vista-agents.yaml", "tls-secrets-opt-in.yaml", "networkpolicy-agents.yaml", "networkpolicy-allow-sensor.yaml"} {
		for _, o := range loadManifest(t, file) {
			switch kindOf(o) {
			case "ClusterRoleBinding", "RoleBinding":
				role := str(dig(o, "roleRef", "kind")) + "/" + str(dig(o, "roleRef", "name"))
				for _, s := range seq(o["subjects"]) {
					subject := s.(manifestObject)
					if str(subject["kind"]) != "ServiceAccount" || str(subject["namespace"]) != agentsNamespace {
						t.Errorf("%s binds %v", nameOf(o), subject)
					}
					bound[str(subject["name"])] = append(bound[str(subject["name"])], role)
				}
			case "Role":
				t.Errorf("%s: an unexpected Role %s", file, nameOf(o))
			case "ClusterRole":
				if file == "vista-agents.yaml" && nameOf(o) != "vista-device-agent-inventory" {
					t.Errorf("an unexpected ClusterRole %s", nameOf(o))
				}
			}
		}
	}
	if got := strings.Join(bound[deviceAgentAccount], ","); got != "ClusterRole/vista-device-agent-inventory,ClusterRole/vista-device-agent-tls-secrets" {
		t.Errorf("the device agent is bound to %s", got)
	}
	if len(bound[sensorAccount]) != 0 || len(bound) != 1 {
		t.Errorf("bindings: %v; the sensor has no access to the Kubernetes API", bound)
	}
	sensor := find(t, loadManifest(t, "vista-agents.yaml"), "ServiceAccount", sensorAccount)
	if v, ok := sensor["automountServiceAccountToken"].(bool); !ok || v {
		t.Error("the sensor's service account mounts a token")
	}
}

func TestPodsAreLockedDown(t *testing.T) {
	objs := loadManifest(t, "vista-agents.yaml")
	ns := find(t, objs, "Namespace", agentsNamespace)
	if str(dig(ns, "metadata", "labels", "pod-security.kubernetes.io/enforce")) != "restricted" {
		t.Error("the namespace does not enforce the restricted Pod Security Standard")
	}
	for name, want := range map[string]struct {
		account   string
		automount bool
		env       map[string]string
	}{
		"vista-device-agent": {deviceAgentAccount, true, map[string]string{"DATA_PATH": "/var/lib/vista", "HOST_INVENTORY_ENABLED": "false"}},
		"vista-sensor":       {sensorAccount, false, map[string]string{"DATA_PATH": "/var/lib/vista", "CAPTURE_DISABLED": "true"}},
	} {
		d := find(t, objs, "Deployment", name)
		if str(dig(d, "metadata", "namespace")) != agentsNamespace {
			t.Errorf("%s is not in %s", name, agentsNamespace)
		}
		if str(dig(d, "spec", "strategy", "type")) != "Recreate" {
			t.Errorf("%s: two pods would share one identity during a rollout", name)
		}
		pod := dig(d, "spec", "template", "spec").(manifestObject)
		if str(pod["serviceAccountName"]) != want.account || pod["automountServiceAccountToken"] != want.automount {
			t.Errorf("%s: service account %v, automount %v", name, pod["serviceAccountName"], pod["automountServiceAccountToken"])
		}
		for _, forbidden := range []string{"hostNetwork", "hostPID", "hostIPC", "initContainers", "nodeName", "shareProcessNamespace"} {
			if _, ok := pod[forbidden]; ok {
				t.Errorf("%s sets %s", name, forbidden)
			}
		}
		psc := dig(pod, "securityContext")
		if dig(psc, "runAsNonRoot") != true || dig(psc, "runAsUser") != 65532 || str(dig(psc, "seccompProfile", "type")) != "RuntimeDefault" {
			t.Errorf("%s pod security context: %v", name, psc)
		}
		writable := map[string]bool{}
		for _, v := range seq(pod["volumes"]) {
			vol := v.(manifestObject)
			switch {
			case vol["persistentVolumeClaim"] != nil, vol["emptyDir"] != nil:
				writable[str(vol["name"])] = true
			default:
				t.Errorf("%s: volume %v is neither the data volume nor a scratch directory (no hostPath, no Secret volume)", name, vol)
			}
		}
		containers := seq(pod["containers"])
		if len(containers) != 1 {
			t.Fatalf("%s has %d containers", name, len(containers))
		}
		c := containers[0].(manifestObject)
		sc := dig(c, "securityContext")
		if dig(sc, "allowPrivilegeEscalation") != false || dig(sc, "readOnlyRootFilesystem") != true ||
			strings.Join(strs(dig(sc, "capabilities", "drop")), ",") != "ALL" || dig(sc, "capabilities", "add") != nil || dig(sc, "privileged") != nil {
			t.Errorf("%s container security context: %v", name, sc)
		}
		if c["ports"] != nil {
			t.Errorf("%s declares ports; the agents listen on nothing", name)
		}
		mounts := map[string]bool{}
		for _, m := range seq(c["volumeMounts"]) {
			mounts[str(m.(manifestObject)["mountPath"])] = writable[str(m.(manifestObject)["name"])]
		}
		if !mounts["/var/lib/vista"] || !mounts["/tmp"] || len(mounts) != 2 {
			t.Errorf("%s mounts %v; with a read-only root it needs exactly its data directory and /tmp", name, mounts)
		}
		env := map[string]string{}
		for _, e := range seq(c["env"]) {
			entry := e.(manifestObject)
			if v, ok := entry["value"].(string); ok {
				env[str(entry["name"])] = v
			} else if ref := str(dig(entry, "valueFrom", "secretKeyRef", "name")); ref != "vista-agents-enrollment" {
				t.Errorf("%s: %s comes from %v", name, entry["name"], entry["valueFrom"])
			} else {
				env[str(entry["name"])] = "secret:" + str(dig(entry, "valueFrom", "secretKeyRef", "key"))
			}
		}
		for k, v := range want.env {
			if env[k] != v {
				t.Errorf("%s: %s=%q, want %q", name, k, env[k], v)
			}
		}
		if !strings.HasPrefix(env["REGISTRATION_KEY"], "secret:") {
			t.Errorf("%s: the registration key does not come from the enrollment Secret", name)
		}
		if strings.Contains(str(c["image"]), "latest") || !strings.HasPrefix(str(c["image"]), "ghcr.io/vistasecurity/"+name) {
			t.Errorf("%s image: %v", name, c["image"])
		}
	}
	// The sensor's environment names no Kubernetes API setting, and the
	// device agent's Deployment is the only thing that reads the options.
	sensor := dig(find(t, objs, "Deployment", "vista-sensor"), "spec", "template", "spec", "containers").([]any)[0].(manifestObject)
	if sensor["envFrom"] != nil {
		t.Error("the sensor reads the device agent's options")
	}
	// The enrollment Secret ships with placeholders, never with a value.
	secret := find(t, objs, "Secret", "vista-agents-enrollment")
	for key, v := range secret["stringData"].(manifestObject) {
		if s := str(v); s != "" && !strings.Contains(s, "REPLACE") {
			t.Errorf("the enrollment Secret ships a value for %s", key)
		}
	}
}

func TestNetworkPolicies(t *testing.T) {
	deny := find(t, loadManifest(t, "networkpolicy-agents.yaml"), "NetworkPolicy", "vista-agents-deny-ingress")
	if str(dig(deny, "metadata", "namespace")) != agentsNamespace || dig(deny, "spec", "ingress") != nil ||
		strings.Join(strs(dig(deny, "spec", "policyTypes")), ",") != "Ingress" {
		t.Errorf("deny-ingress policy: %v", deny["spec"])
	}
	allow := find(t, loadManifest(t, "networkpolicy-allow-sensor.yaml"), "NetworkPolicy", "allow-vista-sensor-scan")
	if dig(allow, "metadata", "namespace") != nil {
		t.Error("the allow policy names a namespace; it is applied into each namespace to be scanned")
	}
	from := seq(dig(allow, "spec", "ingress").([]any)[0].(manifestObject)["from"])
	if len(from) != 1 {
		t.Fatalf("allow policy admits %d peers", len(from))
	}
	peer := from[0].(manifestObject)
	// One peer with both selectors: the sensor's pods in the agents'
	// namespace. As two peers it would admit the whole namespace, or every
	// pod with the sensor's label anywhere.
	if str(dig(peer, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")) != agentsNamespace ||
		str(dig(peer, "podSelector", "matchLabels", "app.kubernetes.io/name")) != "vista-sensor" {
		t.Errorf("allow policy peer: %v", peer)
	}
}
