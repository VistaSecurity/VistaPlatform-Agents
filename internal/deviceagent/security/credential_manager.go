package security

import (
	"encoding/base64"
	"errors"

	"github.com/vistasecurity/vistaplatform-agents/shared/agentcreds"
)

// CredentialManager handles credential decryption for device jobs
type CredentialManager struct {
	// Credentials are decrypted in-memory only and cleared after use
}

// DecryptCredentials decrypts the credential payload the platform attached to a
// job. Credentials are decrypted in-memory only and never stored.
//
// The envelope shape, the key derivation and the crypto all live in
// shared/agentcreds, which the platform links against too — this file is a thin
// agent-side adapter over it. Keeping one implementation is the point: the agent
// and the platform previously each carried their own idea of this payload and
// disagreed three ways, so no remote interrogation needing credentials worked
// (#1028).
//
// Managed protocol 1 (D-P7): credentials travel only sealed. An unsealed
// credentials map is refused (ErrUnsealedCredentials), never used as
// plaintext, and no key is derived without an agent secret
// (ErrNoAgentSecret): there is no registration-key or job-id-only derivation.
// A job with no credentials at all (nil or empty) has nothing to open.
//
// credentialSecrets are the agent secrets the envelope may be sealed under, in
// the order to try them (Config.CredentialSecrets): the agent secret and,
// briefly after a rotation, the one it replaced.
func DecryptCredentials(encryptedData map[string]interface{}, jobKey string, credentialSecrets ...string) (map[string]interface{}, error) {
	if len(encryptedData) == 0 {
		return map[string]interface{}{}, nil
	}
	if !agentcreds.IsSealed(encryptedData) {
		return nil, ErrUnsealedCredentials
	}
	secrets := make([]string, 0, len(credentialSecrets))
	for _, s := range credentialSecrets {
		if s != "" {
			secrets = append(secrets, s)
		}
	}
	if len(secrets) == 0 {
		return nil, ErrNoAgentSecret
	}
	return agentcreds.OpenAny(encryptedData, jobKey, secrets)
}

// ErrUnsealedCredentials is a job whose credentials are not a sealed envelope.
var ErrUnsealedCredentials = errors.New("the job's credentials are not sealed; managed protocol 1 accepts sealed credential envelopes only, so nothing was run")

// ErrNoAgentSecret is a sealed envelope this agent holds no agent secret to
// open.
var ErrNoAgentSecret = errors.New("this agent holds no agent secret to open the job's credentials; managed protocol 1 derives no key without one")

// EncryptCredentials seals credentials into the canonical envelope. The platform
// uses shared/agentcreds directly; this wrapper exists for agent-side tests and
// tooling.
func EncryptCredentials(credentials map[string]interface{}, jobKey, credentialSecret string) (map[string]interface{}, error) {
	return agentcreds.Seal(credentials, jobKey, credentialSecret)
}

// DeriveKey derives the AES-256 key for a (jobKey, credentialSecret) pair.
// credentialSecret must be the agent secret so the key is not predictable from
// the job ID alone.
func DeriveKey(jobKey, credentialSecret string) []byte {
	return agentcreds.DeriveKey(jobKey, credentialSecret)
}

// ClearCredentials clears credentials from memory.
func ClearCredentials(creds map[string]interface{}) {
	agentcreds.Clear(creds)
}

// DecodeBase64 decodes base64-encoded data
func DecodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
