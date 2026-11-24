package devices

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/models"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocolschema"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory/kubetest"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// The executor's kubernetes_inventory branch, driven through the real Execute
// dispatch against a fake API server.

func kubeExecutor(t *testing.T, readSecrets bool) (*JobExecutor, *recordingClient, *kubetest.Cluster) {
	t.Helper()
	cl := kubetest.New(t)
	cl.Load(repo.Path(t, filepath.Join("shared", "kubeinventory", "testdata", "full")))
	exec, rec := newTestExecutor()
	exec.kube = kubernetesSource{
		client: func() (*kubeinventory.Client, error) {
			host, port := cl.HostPort()
			return kubeinventory.NewClient(host, port, cl.Dir)
		},
		readTLSSecrets: func() bool { return readSecrets },
	}
	return exec, rec, cl
}

func kubeJob(params map[string]interface{}) *models.Job {
	return &models.Job{ID: uuid.New(), Type: kubeinventory.JobType, Parameters: params}
}

func validResult(t *testing.T, res *models.JobResult) {
	t.Helper()
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Validate("job-result.device-agent", res); err != nil {
		t.Fatalf("the result the executor sends does not match the schema:\n%v", err)
	}
}

func TestExecute_KubernetesInventorySendsTheCollection(t *testing.T) {
	exec, rec, cl := kubeExecutor(t, false)
	job := kubeJob(map[string]interface{}{"probe_kubelets": false})
	if err := exec.Execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if len(rec.results) != 1 {
		t.Fatalf("%d results for a small cluster", len(rec.results))
	}
	res := rec.last()
	validResult(t, res)
	inv := res.KubernetesInventory
	if !res.Success || res.JobID != job.ID || inv == nil || inv.Cluster.ID == "" || len(inv.Workloads) == 0 || inv.Part != (kubeinventory.Part{Index: 0, Count: 1}) {
		t.Fatalf("result: %+v", res)
	}
	if res.Assets != nil || res.Facts != nil || res.Metadata != nil {
		t.Error("a Kubernetes inventory travels in its own member and nowhere else")
	}
	if s := inv.Sections[kubeinventory.ClassKubeletCerts]; s.Reason != kubeinventory.ReasonNotRequested {
		t.Errorf("the job's parameters were not applied: %+v", s)
	}
	if s := inv.Sections[kubeinventory.ClassTLSSecrets]; s.Reason != kubeinventory.ReasonNotEnabled {
		t.Errorf("TLS secrets: %+v", s)
	}
	for _, r := range cl.Requests() {
		if strings.Contains(r.Path, "secrets") {
			t.Errorf("the Secrets API was called: %s", r.Path)
		}
	}
}

// Reading TLS Secrets follows the deployment's setting and nothing a job says.
func TestExecute_KubernetesInventoryTLSSecretsAreTheDeploymentsChoice(t *testing.T) {
	exec, rec, cl := kubeExecutor(t, false)
	job := kubeJob(map[string]interface{}{"probe_kubelets": false, "read_tls_secrets": true, "tls_secrets": "enabled", EnvReadTLSSecrets: "true"})
	if err := exec.Execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if inv := rec.last().KubernetesInventory; inv.Collector.TLSSecrets != "not_enabled" || len(inv.TLSSecrets) != 0 {
		t.Errorf("a job turned on reading Secrets: %+v", inv.Collector)
	}
	for _, r := range cl.Requests() {
		if strings.Contains(r.Path, "secrets") {
			t.Errorf("the Secrets API was called: %s", r.Path)
		}
	}

	exec, rec, _ = kubeExecutor(t, true)
	if err := exec.Execute(context.Background(), kubeJob(map[string]interface{}{"probe_kubelets": false})); err != nil {
		t.Fatal(err)
	}
	validResult(t, rec.last())
	if inv := rec.last().KubernetesInventory; inv.Collector.TLSSecrets != "enabled" || len(inv.TLSSecrets) == 0 {
		t.Errorf("the deployment's setting was not applied: %+v", inv.Collector)
	}

	t.Setenv(EnvReadTLSSecrets, "")
	if ReadTLSSecretsEnabled() {
		t.Error("enabled with the variable unset")
	}
	t.Setenv(EnvReadTLSSecrets, " True ")
	if !ReadTLSSecretsEnabled() {
		t.Error("not enabled by the variable")
	}
	t.Setenv(EnvReadTLSSecrets, "1")
	if ReadTLSSecretsEnabled() {
		t.Error("anything but \"true\" enables nothing")
	}
}

func TestExecute_KubernetesInventoryLargeClusterIsSentInParts(t *testing.T) {
	exec, rec, cl := kubeExecutor(t, false)
	var pods []any
	for i := 0; i < 6000; i++ {
		pods = append(pods, map[string]any{
			"metadata": map[string]any{"name": fmt.Sprintf("load-%d", i), "namespace": "shop", "uid": uuid.NewString()},
			"spec":     map[string]any{"nodeName": "node-a", "containers": []any{map[string]any{"name": "c", "image": "registry.example.test/load:1"}}},
			"status":   map[string]any{"phase": "Running", "podIPs": []any{map[string]string{"ip": "198.51.100.200"}}},
		})
	}
	cl.SetList("/api/v1/pods", pods...)
	job := kubeJob(map[string]interface{}{"probe_kubelets": false, "max_part_bytes": float64(kubeinventory.MinMaxPartBytes), "max_items_per_class": float64(10000)})
	if err := exec.Execute(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if len(rec.results) < 2 {
		t.Fatalf("%d results", len(rec.results))
	}
	pods = nil
	for i, res := range rec.results {
		validResult(t, res)
		inv := res.KubernetesInventory
		if !res.Success || res.JobID != job.ID || inv.Part.Index != i || inv.Part.Count != len(rec.results) ||
			inv.CollectionID != rec.results[0].KubernetesInventory.CollectionID || inv.Cluster.ID == "" {
			t.Errorf("result %d: part %+v", i, inv.Part)
		}
		for range inv.Pods {
			pods = append(pods, nil)
		}
	}
	if len(pods) != 6000 {
		t.Errorf("%d pods across the parts", len(pods))
	}
}

// failingAfter accepts n results and then fails.
type failingAfter struct {
	n       int
	results int
}

func (f *failingAfter) SubmitResult(*models.JobResult) error {
	f.results++
	if f.results > f.n {
		return errors.New("the platform is unreachable")
	}
	return nil
}

// A part that cannot be sent ends the job with an error, which the agent's
// job loop reports as a failure; the parts are not silently short.
func TestExecute_KubernetesInventoryStopsWhenAPartCannotBeSent(t *testing.T) {
	exec, _, _ := kubeExecutor(t, false)
	sub := &failingAfter{n: 0}
	exec.submitter = sub
	err := exec.Execute(context.Background(), kubeJob(map[string]interface{}{"probe_kubelets": false}))
	if err == nil || !strings.Contains(err.Error(), "part 1 of 1") {
		t.Fatalf("err = %v", err)
	}
}

func TestExecute_KubernetesInventoryRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*models.Job, *JobExecutor)
		code   string
		says   string
	}{
		"sealed credentials": {func(j *models.Job, _ *JobExecutor) { j.Credentials = map[string]interface{}{"encrypted_data": "AAAA"} }, FailureInvalidJob, "no credentials"},
		"a kubeconfig": {func(j *models.Job, _ *JobExecutor) {
			j.Parameters = map[string]interface{}{"kubeconfig": "apiVersion: v1"}
		}, FailureInvalidJob, "kubeconfig"},
		"another API server": {func(j *models.Job, _ *JobExecutor) {
			j.Parameters = map[string]interface{}{"api_server": "https://other.example.test"}
		}, FailureInvalidJob, "api_server"},
		"a token": {func(j *models.Job, _ *JobExecutor) { j.Parameters = map[string]interface{}{"token": "synthetic"} }, FailureInvalidJob, "token"},
		"an unknown class": {func(j *models.Job, _ *JobExecutor) {
			j.Parameters = map[string]interface{}{"classes": []interface{}{"secrets"}}
		}, FailureInvalidJob, "unknown class"},
		"not negotiated": {func(_ *models.Job, e *JobExecutor) { e.negotiated = func(string) bool { return false } }, managedprotocol.CodeUnsupportedCommand, kubeinventory.Capability},
	} {
		t.Run(name, func(t *testing.T) {
			exec, rec, cl := kubeExecutor(t, true)
			job := kubeJob(nil)
			tc.mutate(job, exec)
			if err := exec.Execute(context.Background(), job); err != nil {
				t.Fatal(err)
			}
			res := rec.last()
			if len(rec.results) != 1 || res.Success || res.FailureCode != tc.code || !strings.Contains(res.Error, tc.says) || res.KubernetesInventory != nil {
				t.Fatalf("result: %+v", res)
			}
			validResult(t, res)
			if n := len(cl.Requests()); n != 0 {
				t.Errorf("a refused job made %d requests to the API server", n)
			}
		})
	}
}

func TestExecute_KubernetesInventoryOutsideACluster(t *testing.T) {
	exec, rec := newTestExecutor()
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if err := exec.Execute(context.Background(), kubeJob(nil)); err != nil {
		t.Fatal(err)
	}
	if res := rec.last(); res.Success || res.FailureCode != FailureNotInCluster {
		t.Fatalf("result: %+v", res)
	}
}

func TestExecute_KubernetesInventoryWithoutAClusterIdentity(t *testing.T) {
	exec, rec, cl := kubeExecutor(t, false)
	cl.SetStatus("/api/v1/namespaces", 403)
	if err := exec.Execute(context.Background(), kubeJob(nil)); err != nil {
		t.Fatal(err)
	}
	res := rec.last()
	if len(rec.results) != 1 || res.Success || res.FailureCode != FailureClusterIdentity || res.KubernetesInventory != nil {
		t.Fatalf("result: %+v", res)
	}
	validResult(t, res)
}

func TestKubernetesInventoryJobTimeout(t *testing.T) {
	exec, _ := newTestExecutor()
	if got := exec.timeoutFor(kubeJob(nil)); got != kubeinventory.DefaultTimeout {
		t.Errorf("default %v", got)
	}
	if got := exec.timeoutFor(kubeJob(map[string]interface{}{"timeout_seconds": float64(90)})); got.Seconds() != 90 {
		t.Errorf("with timeout_seconds: %v", got)
	}
}
