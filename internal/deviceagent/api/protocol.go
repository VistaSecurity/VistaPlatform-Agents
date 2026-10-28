package api

// Managed protocol version 1 on the device agent's side
// (docs/managed-protocol.md).
//
// Every call goes through call: the request names the protocol in its header,
// and a 426 or an answer naming another protocol closes the gate. The job poll
// and the heartbeat answer must name the platform's protocol (the job poll's
// 204 in its header, every other answer in its body); a job is handed to the
// executor, and a result submitted, only while the gate is open.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// maxAnswerBytes bounds every answer the agent reads from the platform other
// than the job itself.
const maxAnswerBytes = 1 << 20

// maxJobBytes bounds a job answer (its parameters may carry a device list).
const maxJobBytes = 8 << 20

// hostInventoryNegotiationWait is how long a host-inventory submission made at
// start-up waits for the first heartbeat to name the platform's protocol: the
// collection runs as the agent starts, beside that first heartbeat.
const hostInventoryNegotiationWait = 2 * time.Minute

// AgentCapabilities is what this build of the device agent can do; the names
// are the ones the platform has always read from X-Agent-Capabilities.
func AgentCapabilities() []string { return di.AgentCapabilities() }

// Gate is the client's view of the platform's protocol.
func (c *OutboundClient) Gate() *managedprotocol.Gate { return c.gate }

// call sends one managed-protocol request. payload is JSON-encoded when not
// nil. It returns the answer's status, headers and body (bounded by limit); a
// 426, or an answer whose protocol header names another version, is returned
// as the IncompatibleError and closes the gate.
func (c *OutboundClient) call(method, url string, payload any, limit int64, extra http.Header) (int, http.Header, []byte, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := managedprotocol.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range extra {
		req.Header[k] = v
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err := managedprotocol.FromStatus(resp.StatusCode, resp.Header, data); err != nil {
		return resp.StatusCode, resp.Header, data, c.gate.Observe(err)
	}
	if err := managedprotocol.CheckHeaderIfPresent(resp.Header, resp.StatusCode); err != nil {
		return resp.StatusCode, resp.Header, data, c.gate.Observe(err)
	}
	return resp.StatusCode, resp.Header, data, nil
}
