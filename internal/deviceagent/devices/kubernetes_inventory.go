package devices

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/models"
	"github.com/vistasecurity/vistaplatform-agents/shared/kubeinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/redact"
)

// The kubernetes_inventory job (docs/design/kubernetes-inventory.md): the
// agent describes the cluster it runs in, through its own service account.
//
// Unlike every other job it has no target and no credentials. There is nothing
// for the platform to name: the cluster is wherever this process is, and the
// credential is the pod's. A job that tries to supply either is refused, so a
// platform (or anyone who can queue a job) cannot point an in-cluster agent at
// a different API server or hand it a token.

// EnvReadTLSSecrets is the environment variable that enables reading Secrets
// of type kubernetes.io/tls ("true"). It is set on the agent's Deployment by
// the cluster's administrators together with the opt-in role; nothing the
// platform sends can set it.
const EnvReadTLSSecrets = "VISTA_KUBERNETES_READ_TLS_SECRETS"

// Failure codes of a kubernetes_inventory job.
const (
	FailureNotInCluster    = "not_in_cluster"
	FailureClusterIdentity = "cluster_identity_unreadable"
	FailureInvalidJob      = "invalid_job"
)

// ReadTLSSecretsEnabled reports whether this agent was set up to read TLS
// Secrets.
func ReadTLSSecretsEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(EnvReadTLSSecrets)), "true")
}

// kubernetesSource is where the collection's client and settings come from.
// Tests replace it; the zero value is the real thing.
type kubernetesSource struct {
	client         func() (*kubeinventory.Client, error)
	readTLSSecrets func() bool
}

func (s kubernetesSource) withDefaults() kubernetesSource {
	if s.client == nil {
		s.client = kubeinventory.InCluster
	}
	if s.readTLSSecrets == nil {
		s.readTLSSecrets = ReadTLSSecretsEnabled
	}
	return s
}

func (e *JobExecutor) executeKubernetesInventory(ctx context.Context, job *models.Job) error {
	if e.negotiated != nil && !e.negotiated(kubeinventory.Capability) {
		return e.submitUnsupported(job, "the platform did not negotiate "+kubeinventory.Capability+" with this agent")
	}
	if len(job.Credentials) > 0 {
		return e.submitKubernetesFailure(job, FailureInvalidJob,
			"a kubernetes_inventory job carries no credentials: the agent reads the cluster it runs in with its own service account")
	}
	params, err := kubeinventory.ParseParameters(job.Parameters)
	if err != nil {
		return e.submitKubernetesFailure(job, FailureInvalidJob, err.Error())
	}
	src := e.kube.withDefaults()
	client, err := src.client()
	if err != nil {
		return e.submitKubernetesFailure(job, FailureNotInCluster, err.Error())
	}
	// Reading TLS Secrets is this deployment's setting. ParseParameters does
	// not touch it.
	params.Options.ReadTLSSecrets = src.readTLSSecrets()

	inv, err := kubeinventory.Collect(ctx, client, params.Options)
	if err != nil {
		code := ""
		if errors.Is(err, kubeinventory.ErrClusterIdentity) {
			code = FailureClusterIdentity
		}
		if e.auditLogger != nil {
			e.auditLogger.LogInterrogation(job.ID.String(), "", kubeinventory.JobType, "failure", map[string]interface{}{"job_type": job.Type}, err)
		}
		return e.submitKubernetesFailure(job, code, fmt.Sprintf("Kubernetes inventory failed: %v", err))
	}

	parts := kubeinventory.Split(inv, params.MaxPartBytes)
	for _, part := range parts {
		if err := e.submitter.SubmitResult(&models.JobResult{
			JobID: job.ID, Success: true, KubernetesInventory: part, CompletedAt: time.Now(),
		}); err != nil {
			// The platform holds an incomplete collection, which it discards
			// when the failure that the caller reports arrives.
			return fmt.Errorf("part %d of %d could not be sent: %w", part.Part.Index+1, part.Part.Count, err)
		}
	}
	if e.auditLogger != nil {
		e.auditLogger.LogInterrogation(job.ID.String(), "", kubeinventory.JobType, "success", map[string]interface{}{
			"job_type": job.Type, "cluster_id": inv.Cluster.ID, "parts": len(parts),
			"workloads": len(inv.Workloads), "services": len(inv.Services), "certificates": len(inv.Certificates),
			"tls_secrets": inv.Collector.TLSSecrets,
		}, nil)
	}
	return nil
}

func (e *JobExecutor) submitKubernetesFailure(job *models.Job, code, msg string) error {
	return e.submitter.SubmitResult(&models.JobResult{
		JobID: job.ID, Success: false, Error: redact.Text(msg), FailureCode: code, CompletedAt: time.Now(),
	})
}
