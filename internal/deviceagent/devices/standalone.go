package devices

import (
	"context"

	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
)

// The helpers below let the standalone `device-agent collect` command
// (cmd/device-agent) interrogate a device exactly the way a managed job does,
// rather than keeping a second copy of the same steps that could drift.

// InterrogateBounded is interrogateBounded for the standalone command: ctx's
// deadline frees the caller even when a collector ignores its context, and a
// collector panic is re-raised in the caller's goroutine so it can recover it.
func InterrogateBounded(ctx context.Context, i di.DeviceInterrogator, device di.DeviceInfo, creds di.Credentials) (*di.InterrogateResult, error) {
	return interrogateBounded(ctx, i, device, creds)
}

// CredentialsFromMap maps credentials read from a file or the environment onto
// the shared core's Credentials, the same way a managed job's decrypted
// credentials are mapped: username, password, api_key and token by name, and
// the whole map as Custom for the vendor-specific keys. insecureSkipVerify is
// the operator's flag; a key of that name in the map does not override it.
func CredentialsFromMap(secrets map[string]interface{}, insecureSkipVerify bool) di.Credentials {
	return buildCredentials(secrets, map[string]interface{}{"insecure_skip_verify": insecureSkipVerify})
}
