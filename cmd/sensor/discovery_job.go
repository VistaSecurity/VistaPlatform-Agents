package main

// Dispatched discovery jobs (#1839): the sensor's side of "run this scan from
// the sensor that can actually see the host".
//
// The command arrives on a heartbeat like every other command. It is validated
// on the spot — a payload nothing can run is acknowledged as FAILED right away,
// so the platform records the refusal instead of waiting for a completion
// that never comes — and then queued for the job worker, which runs one job at
// a time on the shared scan engine (plan_job.go): every host is reported as it
// finishes, then completion, then the acknowledgement.
//
// Only a PLANNED job is run: in managed protocol 1 the scan plan is the only
// job shape (D-P5). The older protocols × ports payload is not parsed at all;
// one reaching this sensor is acknowledged as refused with
// unsupported_command, like any other work this sensor does not run.

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/models"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch"
)

// discoveryJobQueueDepth bounds how many dispatched jobs may wait behind the
// one running. Small on purpose: the platform dispatches a job per sweep per
// sensor, and a backlog deeper than this means something upstream is wrong.
// The value is shared with the platform (sensordispatch.JobQueueDepth), which
// budgets its unattended work against it.
const discoveryJobQueueDepth = sensordispatch.JobQueueDepth

// legacyPayloadRefusal is the reason a protocols × ports command is refused.
const legacyPayloadRefusal = "this sensor runs scans only from a scan plan, the only discovery job shape of managed protocol " +
	"1; the command carried the older protocols × ports payload, which protocol 1 does not have. Nothing was scanned"

// startDiscoveryJobWorker creates the queue and starts the single worker.
// Idempotent, so a restart-in-place cannot start two.
func (s *Sensor) startDiscoveryJobWorker() {
	s.mu.Lock()
	if s.jobQueue != nil {
		s.mu.Unlock()
		return
	}
	s.jobQueue = make(chan models.Command, discoveryJobQueueDepth)
	queue := s.jobQueue
	s.mu.Unlock()
	go s.runDiscoveryJobs(queue)
}

// handleDiscoveryJob validates and queues a discovery_job command.
//
// Returns a FAILED acknowledgement for a command that cannot be run (malformed
// payload, a protocols × ports payload, queue full) and nil for one that was
// accepted — the worker acknowledges that one when the job finishes.
func (s *Sensor) handleDiscoveryJob(command models.Command) *models.CommandResponse {
	payload, err := sensordispatch.ParsePayload(command.Payload)
	if errors.Is(err, sensordispatch.ErrLegacyPayload) {
		log.Printf("❌ Discovery job command %s refused: protocols × ports payload, which managed protocol 1 does not have", command.ID)
		return s.unsupportedCommand(command, legacyPayloadRefusal)
	}
	if err != nil {
		log.Printf("❌ Discovery job command %s refused: %v", command.ID, err)
		return s.discoveryJobRefusal(command, err.Error())
	}
	if payload.Plan.VerifyCertificate != nil && !s.capabilityNegotiated(sensordispatch.VerifyCertificateCapability) {
		return s.unsupportedCommand(command, "the platform did not negotiate "+sensordispatch.VerifyCertificateCapability+" with this sensor")
	}
	s.mu.RLock()
	queue := s.jobQueue
	s.mu.RUnlock()
	if queue == nil {
		return s.discoveryJobRefusal(command, "sensor job worker is not running")
	}
	select {
	case queue <- command:
		log.Printf("📥 Discovery job command %s queued (%d waiting)", command.ID, len(queue))
		return nil
	default:
		return s.discoveryJobRefusal(command, fmt.Sprintf("%s: %d discovery jobs already queued", sensordispatch.SensorBusyPrefix, cap(queue)))
	}
}

// unsupportedCommand acknowledges work this sensor does not run (an unknown
// command type, the legacy payload, work whose capability the platform did
// not negotiate) as refused with code unsupported_command (managed protocol 1,
// D-P2). Nothing was run.
func (s *Sensor) unsupportedCommand(command models.Command, reason string) *models.CommandResponse {
	resp := s.discoveryJobRefusal(command, reason)
	resp.ResponseData["code"] = managedprotocol.CodeUnsupportedCommand
	return resp
}

// capabilityNegotiated reports whether the platform's last answer negotiated
// capability c with this sensor. A sensor with no control-plane client (a
// test, test mode) has nothing to negotiate with.
func (s *Sensor) capabilityNegotiated(c string) bool {
	if s.apiClient == nil {
		return true
	}
	return s.apiClient.Gate().Has(c)
}

func (s *Sensor) discoveryJobRefusal(command models.Command, reason string) *models.CommandResponse {
	return &models.CommandResponse{
		ID:           uuid.New(),
		CommandID:    command.ID,
		SensorID:     s.config.SensorID,
		Status:       "error",
		Message:      reason,
		ResponseData: map[string]interface{}{"refused": true, "reason": reason},
		Timestamp:    time.Now(),
	}
}

// runDiscoveryJobs is the worker: one job at a time, for the life of the
// process.
func (s *Sensor) runDiscoveryJobs(queue <-chan models.Command) {
	for command := range queue {
		s.executeDiscoveryJob(command)
	}
}

// executeDiscoveryJob runs one dispatched job on the shared engine
// (#2170 WP2b). handleDiscoveryJob queues only a parsed, planned command; one
// that is not is acknowledged as refused rather than dropped.
func (s *Sensor) executeDiscoveryJob(command models.Command) {
	payload, err := sensordispatch.ParsePayload(command.Payload)
	if err == nil {
		s.executePlanJob(command, payload)
		return
	}
	refusal := s.discoveryJobRefusal(command, err.Error())
	if errors.Is(err, sensordispatch.ErrLegacyPayload) {
		refusal = s.unsupportedCommand(command, legacyPayloadRefusal)
	}
	log.Printf("❌ Discovery job command %s refused at run time: %s", command.ID, refusal.Message)
	if client := s.planClientFor(); client != nil {
		if aerr := client.AcknowledgeCommand(command.ID, refusal); aerr != nil {
			log.Printf("❌ Failed to acknowledge discovery job command %s: %v", command.ID, aerr)
		}
	}
}

func completionMessage(c sensordispatch.Completion) string {
	if c.Status == "failed" {
		return "Discovery job failed: " + c.ErrorMessage
	}
	msg := fmt.Sprintf("Discovery job completed: %d/%d target(s) answered, %d result(s) submitted",
		c.SuccessfulTargets, c.TotalTargets, c.DiscoveriesSubmitted)
	if c.ErrorMessage != "" {
		msg += " (" + c.ErrorMessage + ")"
	}
	return msg
}
