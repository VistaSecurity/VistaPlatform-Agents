package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostcrypto"
	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// HostCryptoSubmission is the body of a LOCAL host crypto post
// (schemas/managed/v1/host-crypto.submission.schema.json).
type HostCryptoSubmission struct {
	AgentID      uuid.UUID       `json:"agent_id"`
	Mode         string          `json:"mode"`
	CollectedAt  time.Time       `json:"collected_at"`
	AgentVersion string          `json:"agent_version,omitempty"`
	Report       json.RawMessage `json:"report"`
}

// ErrHostCryptoNotNegotiated is returned when the platform has not offered
// host_crypto_v1: it has nowhere to put a local collection, so none is sent
// (and the schedule does not collect one).
var ErrHostCryptoNotNegotiated = errors.New("the platform has not negotiated " + hostcrypto.CapabilityHostCrypto + "; host crypto inventory is not sent")

// HostCryptoNegotiated waits, as a local host-inventory post does, for the
// first answer to name the platform's protocol, then reports whether it
// offered host_crypto_v1.
func (c *OutboundClient) HostCryptoNegotiated() error {
	if err := c.gate.WaitReady(hostInventoryNegotiationWait); err != nil {
		return err
	}
	if !c.gate.Has(hostcrypto.CapabilityHostCrypto) {
		return ErrHostCryptoNotNegotiated
	}
	return nil
}

// SubmitHostCrypto posts a LOCAL host crypto collection: one the agent made
// on its own schedule, with no job, to its own endpoint, for the reason
// SubmitHostInventory gives. A collection the platform asked for is a job
// and returns through SubmitResult.
//
// The report is serialized, bounded and checked here
// (hostcrypto.ResultPayload), so what was checked is what is sent.
func (c *OutboundClient) SubmitHostCrypto(report *hostcrypto.Report) error {
	if c.agentID == uuid.Nil {
		return fmt.Errorf("agent not registered")
	}
	if report == nil {
		return fmt.Errorf("host crypto submission is empty")
	}
	if report.Mode != hostinventory.ModeLocal {
		return fmt.Errorf("only a local collection is posted on its own; a remote one is a job result")
	}
	if err := c.HostCryptoNegotiated(); err != nil {
		return err
	}
	payload, _, err := hostcrypto.ResultPayload(report, hostcrypto.DefaultMaxResultBytes)
	if err != nil {
		return err
	}
	body := HostCryptoSubmission{
		AgentID:      c.agentID,
		Mode:         string(hostinventory.ModeLocal),
		CollectedAt:  report.Collected,
		AgentVersion: c.agentVersion,
		Report:       payload,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal host crypto: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/%s/host-crypto", c.baseURL, c.agentID.String())
	status, _, msg, err := c.call(http.MethodPost, url, json.RawMessage(data), 4096, nil)
	if err != nil {
		if managedprotocol.IsIncompatible(err) {
			return err
		}
		return fmt.Errorf("failed to send host crypto inventory: %w", err)
	}
	if status == http.StatusRequestEntityTooLarge {
		return &ReportTooLargeError{Bytes: len(data), Detail: strings.TrimSpace(string(msg))}
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusAccepted {
		return fmt.Errorf("failed to submit host crypto inventory: %s (status: %d)", string(msg), status)
	}
	return nil
}
