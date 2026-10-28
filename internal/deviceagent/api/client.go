package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/certificates"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/models"
	// Aliased: the device-agent has its own `certificates` package, above.
	"github.com/vistasecurity/vistaplatform-agents/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentlogs"
	sharedcerts "github.com/vistasecurity/vistaplatform-agents/shared/certificates"
	di "github.com/vistasecurity/vistaplatform-agents/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform-agents/shared/httpclient"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
	sharednetwork "github.com/vistasecurity/vistaplatform-agents/shared/network"
)

// OutboundClient handles outbound-only communication with the platform
type OutboundClient struct {
	config     *config.Config
	httpClient *http.Client
	agentID    uuid.UUID
	baseURL    string
	// agentVersion is the running binary's stamped version (main.Version),
	// reported on registration and on every heartbeat. Set via SetAgentVersion
	// at startup; empty is sent as-is and the platform treats it as
	// "not reported" rather than blanking the stored value.
	agentVersion string
	// configApplier is the desired-state handler (#1785). Nil in an agent built
	// without one, which is what makes the exchange additive: no report goes
	// up, no config is applied, and the heartbeat is byte-for-byte what it was.
	configApplier ConfigApplier
	// restart is called with the AGE of the platform's restart request on every
	// heartbeat that carries one. An age, not a timestamp: see
	// agentconfig.ShouldRestart on why two clocks must not be compared.
	restart func(requestAge time.Duration)
	// logs is this agent's recent log lines, sent when the platform's heartbeat
	// answer carries a log request. Nil in an agent built without it, which
	// then neither claims the capability nor reads a request.
	logs *agentlogs.Ring
	// lastLogRequest is the id of the request already answered, so a request
	// still pending on the next beat (its clearing raced the beat) is not sent
	// twice. Only SendHeartbeat touches it, from the heartbeat loop.
	lastLogRequest string
	// gate is the platform's managed protocol as last answered (protocol.go).
	gate *managedprotocol.Gate
}

// ConfigApplier is the slice of desiredstate.Applier the client needs. An
// interface rather than the concrete type so the client can be tested without
// the agent's runtime, and so this package does not depend on the applier's
// internals.
type ConfigApplier interface {
	// Report is what this agent is running now.
	Report() (revision string, failures map[string]string, pendingRestart []string)
	// Running is the value of each managed setting as it stands on this agent,
	// including the ones that came from its own configuration file.
	Running() agentconfig.Values
	// Apply makes the platform's answer true.
	Apply(revision string, values agentconfig.Values)
}

// maxHeartbeatResponseBytes bounds the heartbeat answer. The desired-state
// block is a handful of scalars; anything approaching this is not a
// configuration.
const maxHeartbeatResponseBytes = 1 << 20

// SetConfigApplier wires the desired-state handler.
func (c *OutboundClient) SetConfigApplier(a ConfigApplier) { c.configApplier = a }

// SetRestartHandler wires what happens when the platform has asked this agent
// to restart, receiving how long ago it was asked. Nil means an agent that
// ignores restart requests, which is what an older build does anyway.
func (c *OutboundClient) SetRestartHandler(f func(requestAge time.Duration)) { c.restart = f }

// SetLogSource wires the buffer of recent log lines this agent sends when the
// console asks for its logs.
func (c *OutboundClient) SetLogSource(r *agentlogs.Ring) { c.logs = r }

// SetAgentVersion records the running binary's version for liveness reporting.
func (c *OutboundClient) SetAgentVersion(v string) { c.agentVersion = v }

// NewOutboundClient creates a new outbound API client
func NewOutboundClient(cfg *config.Config) *OutboundClient {
	// Parse agent ID if provided
	var agentID uuid.UUID
	if cfg.AgentID != "" {
		if id, err := uuid.Parse(cfg.AgentID); err == nil {
			agentID = id
		}
	}

	// Configure HTTP client with TLS if certificates are available
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Server anchor and client identity are configured independently: a pinned
	// ServerCACert must apply BEFORE the agent holds a client cert, because
	// registration — the call that issues that cert — is itself an HTTPS request
	// that has to verify the platform. Gating both on having a client cert made
	// the pin unreachable at the one moment it mattered, so an agent facing a
	// platform with a privately-signed edge cert could never get past x509.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	configured := false

	if cfg.Security.ServerCACert != "" {
		caPool := x509.NewCertPool()
		if caPool.AppendCertsFromPEM([]byte(cfg.Security.ServerCACert)) {
			tlsConfig.RootCAs = caPool
			configured = true
		} else {
			log.Printf("⚠️  Failed to parse server CA certificate; falling back to system trust store")
		}
	}

	if cfg.Security.UseTLS && cfg.Security.ClientCert != "" && cfg.Security.ClientKey != "" {
		// Load client certificate from PEM strings (not files)
		cert, err := tls.X509KeyPair([]byte(cfg.Security.ClientCert), []byte(cfg.Security.ClientKey))
		if err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
			configured = true
		}
	}

	if configured {
		httpClient.Transport = httpclient.NewTransport(tlsConfig)
	}

	return &OutboundClient{
		config:     cfg,
		httpClient: httpClient,
		agentID:    agentID,
		baseURL:    cfg.PlatformURL,
		gate:       managedprotocol.NewGate(AgentCapabilities()),
	}
}

// Register registers the agent with the platform using CSR-based flow.
// version is reported to the platform (e.g. main.Version); empty defaults to "dev".
func (c *OutboundClient) Register(version string) error {
	if version == "" {
		version = "dev"
	}
	c.agentVersion = version
	// Generate agent ID (UUID) that will be used as certificate CN
	agentID := uuid.New()
	if c.config.AgentID != "" {
		// If agent ID already exists (from previous registration), use it
		var err error
		agentID, err = uuid.Parse(c.config.AgentID)
		if err != nil {
			// Invalid existing ID, generate new one
			agentID = uuid.New()
		}
	}

	// Generate keypair and CSR locally (private key never leaves agent)
	csrGen := certificates.NewCSRGenerator()
	privateKey, err := csrGen.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	csrPEM, err := csrGen.GenerateCSR(agentID, privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Store private key securely (will be saved to config)
	privateKeyPEM, err := csrGen.EncodePrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/register", c.baseURL)

	if csrPEM == "" {
		return fmt.Errorf("refusing to register without a certificate signing request")
	}
	reqBody := map[string]interface{}{
		"registration_key": c.config.RegistrationKey,
		"platform":         registrationPlatform(),
		"version":          version,
		"csr":              csrPEM,           // Include CSR in registration request
		"agent_id":         agentID.String(), // Proposed agent ID
		// Managed protocol 1, which always issues the per-agent secret
		// (#2437): there is no flag asking for it.
		"agent_kind": managedprotocol.AgentKindDeviceAgent,
		"protocol":   managedprotocol.Offer(c.gate.Own()),
	}

	status, _, body, err := c.call(http.MethodPost, url, reqBody, maxAnswerBytes, nil)
	if err != nil {
		if managedprotocol.IsIncompatible(err) {
			return err
		}
		return fmt.Errorf("failed to send registration request: %w", err)
	}

	if status != http.StatusOK && status != http.StatusCreated {
		if isPermanentRegistrationStatus(status) {
			return &RegistrationRejectedError{StatusCode: status, Body: string(body)}
		}
		return fmt.Errorf("registration failed: %s (status: %d)", string(body), status)
	}

	var result struct {
		AgentID              string                    `json:"agent_id"`
		ClientCert           string                    `json:"client_cert"`       // Signed certificate (no private key)
		ClientKey            string                    `json:"client_key"`        // never accepted: see below
		ServerCACert         string                    `json:"server_ca_cert"`    // CA certificate for trust
		ControlPlaneURL      string                    `json:"control_plane_url"` // mTLS passthrough URL to switch to (#1033)
		CertificateExpiresAt string                    `json:"certificate_expires_at"`
		AgentSecret          string                    `json:"agent_secret"`
		AgentSecretVersion   int                       `json:"agent_secret_version"`
		Protocol             *managedprotocol.Protocol `json:"protocol"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	// Nothing from the answer is applied before it is known to be protocol 1.
	caps, err := managedprotocol.Negotiate(result.Protocol, status, c.gate.Own())
	if err != nil {
		return c.gate.Observe(err)
	}
	// The key pair is this agent's; a platform that generated one has seen a
	// private key it must never hold.
	if result.ClientKey != "" {
		return &managedprotocol.ViolationError{Reason: "it carries a private key the platform generated (client_key); this agent only ever uses the key it generated for its certificate signing request"}
	}
	if result.AgentSecret == "" {
		return &managedprotocol.ViolationError{Reason: "it carries no agent_secret, which protocol 1 always issues at enrollment"}
	}
	c.gate.Compatible(caps)

	parsedID, err := uuid.Parse(result.AgentID)
	if err != nil {
		return fmt.Errorf("invalid agent_id in registration response: %w", err)
	}
	c.agentID = parsedID
	c.config.AgentID = result.AgentID

	// The per-agent secret the platform will seal job credentials under (#2437).
	// It is returned once; the caller persists it with the certificate, and only
	// then does the config stop keeping the registration key.
	if result.AgentSecret != "" {
		c.config.SetEnrolledAgentSecret(result.AgentSecret, result.AgentSecretVersion)
	}

	// Store certificate (signed by platform)
	if result.ClientCert != "" {
		c.config.Security.ClientCert = result.ClientCert
	}

	// Store private key locally (never sent to platform)
	c.config.Security.ClientKey = privateKeyPEM

	// ADD the platform's CA to the trust pool rather than replacing what is
	// there. The existing anchor is the one the operator approved at setup and
	// is what verifies the ordinary edge endpoint; the CA arriving here issues
	// the mTLS passthrough listener's certificate, which only exists when
	// agentMtls is enabled — not the chart default. Replacing left the agent
	// trusting a CA that had not signed the endpoint it was still talking to,
	// so enrollment succeeded and everything after it failed the handshake.
	if result.ServerCACert != "" {
		c.config.Security.ServerCACert = sharedcerts.MergeCAPEMs(
			c.config.Security.ServerCACert, result.ServerCACert)
	}

	if c.config.Security.ClientCert != "" && c.config.Security.ClientKey != "" {
		c.config.Security.UseTLS = true
	}

	// Switch to the advertised mTLS passthrough endpoint (#1033) before
	// reconfiguring TLS. Registration happens on the edge-terminated public
	// host (no client cert held yet, and the passthrough listener requires one
	// at the handshake); every later call must reach the passthrough listener
	// or the proxy strips the client cert and fail-closed enforcement 401s.
	// The caller's saveConfigFile persists the switched platform_url.
	if u := applyAdvertisedPlatformURL(c.config, result.ControlPlaneURL); u {
		c.baseURL = c.config.PlatformURL
	}

	// Reconfigure HTTP client with new certificate
	if err := c.reconfigureTLS(); err != nil {
		return fmt.Errorf("failed to reconfigure TLS after registration: %w", err)
	}

	return nil
}

// RegistrationRejectedError is a registration the control plane refused for a
// reason retrying cannot fix: the key is invalid, expired or already used, or
// the tenant cannot take another agent. Callers stop rather than loop, and say
// a new key is needed.
type RegistrationRejectedError struct {
	StatusCode int
	Body       string
}

func (e *RegistrationRejectedError) Error() string {
	return fmt.Sprintf("registration rejected: %s (status: %d)", e.Body, e.StatusCode)
}

// isPermanentRegistrationStatus: a 4xx is the platform's answer about this
// request, except the ones that mean "not now" (timeout, too early, rate
// limited). A 5xx is the platform's own trouble and may clear.
func isPermanentRegistrationStatus(status int) bool {
	if status < 400 || status >= 500 {
		return false
	}
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	}
	return true
}

// applyAdvertisedPlatformURL validates and applies the mTLS passthrough URL
// advertised in a registration response (#1033); see Register for why the URL
// switches after registration. Returns true when the config URL changed. An
// empty advertised URL is the normal non-mTLS case; an invalid or non-https
// one is rejected so a misconfigured platform cannot break a working agent.
func applyAdvertisedPlatformURL(cfg *config.Config, advertised string) bool {
	advertised = strings.TrimRight(strings.TrimSpace(advertised), "/")
	if advertised == "" || advertised == cfg.PlatformURL {
		return false
	}
	u, err := url.Parse(advertised)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		log.Printf("⚠️  Ignoring invalid advertised platform URL %q (want https://host[:port])", advertised)
		return false
	}
	log.Printf("🔀 Platform advertised mTLS endpoint — switching from %s to %s", cfg.PlatformURL, advertised)
	cfg.PlatformURL = advertised
	return true
}

// GetNextJob polls the platform for the next available job.
//
// The answer must name the platform's managed protocol: the 204 "nothing to
// do" in its Vista-Agent-Protocol header, a job in its body. One that names
// none, or another version, closes the gate and no job is returned, so nothing
// is run.
func (c *OutboundClient) GetNextJob() (*models.Job, error) {
	if c.agentID == uuid.Nil {
		return nil, fmt.Errorf("agent not registered")
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/%s/jobs", c.baseURL, c.agentID.String())

	// The job types this build runs beyond device_interrogation. The platform
	// hands a newer job type only to an agent that declares it, so an agent
	// that predates one is never given a job it would strand.
	extra := http.Header{}
	extra.Set(di.AgentCapabilitiesHeader, strings.Join(di.AgentCapabilities(), ","))

	status, header, body, err := c.call(http.MethodGet, url, nil, maxJobBytes, extra)
	if err != nil {
		if managedprotocol.IsIncompatible(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if status == http.StatusNoContent {
		// No job available; the header names the protocol.
		caps, err := managedprotocol.NegotiateHeader(header, status, c.gate.Own())
		if err != nil {
			return nil, c.gate.Observe(err)
		}
		c.gate.Compatible(caps)
		return nil, nil
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("failed to get job: %s (status: %d)", string(body), status)
	}

	var job models.Job
	if err := json.Unmarshal(body, &job); err != nil {
		return nil, fmt.Errorf("failed to decode job: %w", err)
	}
	caps, err := managedprotocol.Negotiate(job.Protocol, status, c.gate.Own())
	if err != nil {
		return nil, c.gate.Observe(err)
	}
	c.gate.Compatible(caps)
	return &job, nil
}

// SubmitResult submits job results to the platform. Nothing is sent unless
// the platform's protocol is known to be version 1.
func (c *OutboundClient) SubmitResult(result *models.JobResult) error {
	if c.agentID == uuid.Nil {
		return fmt.Errorf("agent not registered")
	}
	if err := c.gate.Ready(); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/%s/results", c.baseURL, c.agentID.String())

	status, _, body, err := c.call(http.MethodPost, url, result, maxAnswerBytes, nil)
	if err != nil {
		if managedprotocol.IsIncompatible(err) {
			return err
		}
		return fmt.Errorf("failed to send result: %w", err)
	}

	if status != http.StatusOK && status != http.StatusCreated {
		return &SubmitStatusError{StatusCode: status, Body: string(body)}
	}

	return nil
}

// ReportJobError reports a job execution error to the platform
func (c *OutboundClient) ReportJobError(jobID uuid.UUID, errorMsg string) error {
	result := &models.JobResult{
		JobID:       jobID,
		Success:     false,
		Error:       errorMsg,
		CompletedAt: time.Now(),
	}
	return c.SubmitResult(result)
}

// SendHeartbeat sends a heartbeat to the platform
func (c *OutboundClient) SendHeartbeat() error {
	if c.agentID == uuid.Nil {
		return fmt.Errorf("agent not registered")
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/%s/heartbeat", c.baseURL, c.agentID.String())

	// The agent's own address, and the rest of its bound addresses. Only the
	// agent can know these: by the time a request reaches the platform, NAT and
	// ingress have rewritten the connection source to a proxy or node address.
	// Resolved once so the primary flagged in interfaces matches ip_address.
	primaryIP := sharednetwork.PrimarySourceIPv4(c.baseURL)

	reqBody := map[string]interface{}{
		"status":    "active",
		"timestamp": time.Now(),
		// The binary's stamped version rides every heartbeat so an in-place
		// binary swap is reflected without re-enrollment (registration-only
		// recording left upgraded agents reporting their old version forever).
		"version":    c.agentVersion,
		"ip_address": primaryIP,
		"interfaces": sharednetwork.HostAddresses(primaryIP),
	}
	// Tells the platform this build can send its logs, so the console can
	// tell an older agent from one that has simply not checked in yet.
	if c.logs != nil {
		reqBody["log_export"] = true
	}

	// The desired-state exchange (#1785). What this agent is actually running
	// goes UP; what it should be running comes back in the response. Reported
	// only when a config handler is wired, so an agent built without one sends
	// exactly the body it sent before — the platform reads an absent revision
	// as "this build does not speak desired state", which is true.
	if c.configApplier != nil {
		revision, failures, pendingRestart := c.configApplier.Report()
		reqBody["config_revision"] = revision
		if len(failures) > 0 {
			reqBody["config_failures"] = failures
		}
		if len(pendingRestart) > 0 {
			reqBody["config_pending_restart"] = pendingRestart
		}
		// What this agent is running RIGHT NOW, file configuration included.
		// On the first beat from an agent the platform has never been told
		// anything about, this is what stops the answer being built-in
		// defaults that switch off whatever the file had turned on.
		if running := c.configApplier.Running(); len(running) > 0 {
			reqBody["config_running"] = running
		}
	}

	// The refusal line, while the platform's last answer named no managed
	// protocol this agent implements (managed protocol 1, D-P2).
	if problem := c.gate.Problem(); problem != "" {
		reqBody["protocol_error"] = problem
	}

	status, _, body, err := c.call(http.MethodPost, url, reqBody, maxHeartbeatResponseBytes, nil)
	if err != nil {
		if managedprotocol.IsIncompatible(err) {
			return err
		}
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	if status != http.StatusOK {
		return fmt.Errorf("heartbeat failed: %s (status: %d)", string(body), status)
	}

	// The platform's answer: its protocol, and what this agent should be
	// running. An answer that does not name protocol 1 closes the gate and
	// nothing in it is applied: a configuration or a log request from a
	// platform this agent does not speak to is not one to act on.
	var answer struct {
		Protocol    *managedprotocol.Protocol `json:"protocol"`
		Config      json.RawMessage           `json:"config"`
		LogsRequest json.RawMessage           `json:"logs_request"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return c.gate.Observe(&managedprotocol.IncompatibleError{StatusCode: status, Detail: "the heartbeat answer is not a JSON object"})
	}
	caps, err := managedprotocol.Negotiate(answer.Protocol, status, c.gate.Own())
	if err != nil {
		return c.gate.Observe(err)
	}
	c.gate.Compatible(caps)

	// A config block absent from the answer is not an instruction to revert:
	// the agent keeps what it has. A malformed one is logged and ignored: a
	// bad answer must not cost the agent its liveness reporting.
	if c.configApplier != nil && present(answer.Config) {
		var cfg agentconfig.ExchangePayload
		if err := json.Unmarshal(answer.Config, &cfg); err != nil {
			log.Printf("⚠️  Could not read the configuration from the heartbeat response: %v", err)
		} else {
			c.configApplier.Apply(cfg.Revision, cfg.Values)
			// A restart is decided here rather than inside the applier: it
			// is not a setting, and the applier's job is to make values
			// true, not to end the process.
			if c.restart != nil {
				c.restart(time.Duration(cfg.RestartRequestAgeSeconds) * time.Second)
			}
		}
	}
	if c.logs != nil && present(answer.LogsRequest) {
		var req agentlogs.Request
		if err := json.Unmarshal(answer.LogsRequest, &req); err != nil {
			log.Printf("⚠️  Could not read the log request from the heartbeat response: %v", err)
		} else if req.ID != c.lastLogRequest {
			c.answerLogRequest(req)
		}
	}

	return nil
}

// present reports whether a JSON member was sent with a value.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// answerLogRequest sends this agent's recent log lines in reply to req. A
// failure is logged and does not fail the heartbeat; the request is retried on
// the next beat unless the platform refused it as no longer current.
func (c *OutboundClient) answerLogRequest(req agentlogs.Request) {
	c.lastLogRequest = req.ID
	err := c.SendLogs(req)
	var status *LogUploadStatusError
	switch {
	case err == nil:
		log.Printf("📤 Sent recent log lines to the console (request %s)", req.ID)
	case errors.As(err, &status) && status.StatusCode == http.StatusConflict:
		// Replaced by a newer request, which the next beat will carry.
		log.Printf("⚠️  Log request %s is no longer current; not retrying", req.ID)
	default:
		c.lastLogRequest = ""
		log.Printf("⚠️  Could not send log lines to the console: %v", err)
	}
}

// SendLogs uploads the last req.Lines log lines, redacted, for req.
func (c *OutboundClient) SendLogs(req agentlogs.Request) error {
	if c.agentID == uuid.Nil {
		return fmt.Errorf("agent not registered")
	}
	if c.logs == nil {
		return fmt.Errorf("no log source")
	}
	n := agentlogs.ClampLines(req.Lines)
	// Cleaned BEFORE it leaves the host: a credential in a log line must not
	// cross the network. The platform cleans again as a backstop.
	upload := agentlogs.Upload{RequestID: req.ID, Lines: agentlogs.Clean(c.logs.Tail(n), n)}
	if err := c.gate.Ready(); err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/%s/logs", c.baseURL, c.agentID.String())
	status, _, body, err := c.call(http.MethodPost, url, upload, 4096, nil)
	if err != nil {
		if managedprotocol.IsIncompatible(err) {
			return err
		}
		return fmt.Errorf("failed to send logs: %w", err)
	}
	if status != http.StatusOK {
		return &LogUploadStatusError{StatusCode: status, Body: string(body)}
	}
	return nil
}

// LogUploadStatusError is a non-200 answer to a log upload. A 409 means the
// request was replaced or has expired.
type LogUploadStatusError struct {
	StatusCode int
	Body       string
}

func (e *LogUploadStatusError) Error() string {
	return fmt.Sprintf("log upload refused: %s (status: %d)", e.Body, e.StatusCode)
}

// registrationPlatform returns OS for device_agents.platform (linux, windows, darwin, etc.).
func registrationPlatform() string {
	return runtime.GOOS
}
