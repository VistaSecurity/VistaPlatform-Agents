package api

// Managed protocol version 1 on the sensor's side (docs/managed-protocol.md).
//
// Every call goes through call: the request names the protocol in its header,
// a 426 or an answer naming another protocol closes the gate, and a result
// (discoveries, unit reports, completion, command acknowledgements) is sent
// only while the gate is open. The heartbeat answer is what opens it, after
// registration: it must carry the platform's protocol object.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch"
)

// maxAnswerBytes bounds every answer the sensor reads from the platform. It
// bounds memory, not shape: a heartbeat answer carries every pending command,
// and a discovery_job plan may hold up to 1,000 targets each with its own port
// list and skip addresses, so a 1 MiB bound could truncate a legitimate answer
// into "failed to decode commands" on every heartbeat. Before protocol 1 these
// answers were read unbounded; 32 MiB matches the platform's own bound on an
// agent's request.
const maxAnswerBytes = 32 << 20

// SensorCapabilities is what this build of the sensor can do. The names are
// the ones the platform has always read from the heartbeat.
func SensorCapabilities() []string {
	return []string{
		sensordispatch.IdentityDNSCapability,
		sensordispatch.ScanPlanCapability,
		sensordispatch.VerifyCertificateCapability,
	}
}

// Gate is the client's view of the platform's protocol. The sensor's
// registration client shares it (SensorManagerClient.UseGate) so a refusal seen
// by either is seen by both.
func (c *OutboundClient) Gate() *managedprotocol.Gate { return c.gate }

// call sends one managed-protocol request. payload is JSON-encoded when not
// nil. It returns the answer's status and body (bounded); a 426, or an answer
// whose protocol header names another version, is returned as the
// IncompatibleError and closes the gate.
func call(client *http.Client, gate *managedprotocol.Gate, method, url string, payload any) (int, http.Header, []byte, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to marshal request: %v", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := managedprotocol.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err := managedprotocol.FromStatus(resp.StatusCode, resp.Header, data); err != nil {
		return resp.StatusCode, resp.Header, data, gate.Observe(err)
	}
	if err := managedprotocol.CheckHeaderIfPresent(resp.Header, resp.StatusCode); err != nil {
		return resp.StatusCode, resp.Header, data, gate.Observe(err)
	}
	return resp.StatusCode, resp.Header, data, nil
}
