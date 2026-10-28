package devices

import (
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/models"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentcreds"
)

// testAgentSecret is the agent secret the tests' agents hold. Managed protocol
// 1 sends credentials only sealed under it (D-P7), so a test about something
// else seals its job's credentials the way a protocol-1 platform does.
const testAgentSecret = "test-agent-secret-0123456789abcdef"

// secretConfig is an enrolled agent's configuration: it holds testAgentSecret.
func secretConfig() *config.Config {
	cfg := &config.Config{}
	cfg.SetEnrolledAgentSecret(testAgentSecret, 1)
	return cfg
}

// sealJob replaces job's plaintext credentials with the envelope a protocol-1
// platform sends, sealed for job.ID under testAgentSecret, and returns job.
func sealJob(job *models.Job) *models.Job {
	if len(job.Credentials) == 0 || agentcreds.IsSealed(job.Credentials) {
		return job
	}
	env, err := agentcreds.Seal(job.Credentials, job.ID.String(), testAgentSecret)
	if err != nil {
		panic(err)
	}
	job.Credentials = env
	return job
}
