package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/certificates"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/models"
	// Aliased: the sensor has its own `certificates` package, imported above.
	sharedcerts "github.com/vistasecurity/vistaplatform-agents/shared/certificates"
	"github.com/vistasecurity/vistaplatform-agents/shared/httpclient"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// SensorManagerClient handles communication with the sensor manager service
type SensorManagerClient struct {
	config     *config.Config
	httpClient *http.Client
	baseURL    string
	// gate is the platform's managed protocol (protocol.go); main shares the
	// OutboundClient's through UseGate.
	gate *managedprotocol.Gate
}

// UseGate makes this client record what it learns of the platform's protocol
// in g, the gate the OutboundClient checks before it submits anything.
func (c *SensorManagerClient) UseGate(g *managedprotocol.Gate) {
	if g != nil {
		c.gate = g
	}
}

// NewSensorManagerClient creates a new sensor manager client
func NewSensorManagerClient(cfg *config.Config) *SensorManagerClient {
	// Configure HTTP client with TLS if configured
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Server anchor and client identity are configured independently. This is
	// the client that performs registration, so it is the one that most needs a
	// pinned ServerCACert to apply WITHOUT a client cert — at this point the
	// sensor has none, and registration is what issues it. See the note on
	// buildTLSTransport in outbound_client.go.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	configured := false

	if cfg.Security.ServerCACert != "" {
		caPool := x509.NewCertPool()
		if caPool.AppendCertsFromPEM([]byte(cfg.Security.ServerCACert)) {
			tlsConfig.RootCAs = caPool
			configured = true
		} else {
			fmt.Printf("Warning: Failed to parse server CA certificate\n")
		}
	}

	if cfg.Security.UseTLS && cfg.Security.ClientCert != "" && cfg.Security.ClientKey != "" {
		// Load client certificate from PEM strings (not files)
		cert, err := tls.X509KeyPair([]byte(cfg.Security.ClientCert), []byte(cfg.Security.ClientKey))
		if err != nil {
			fmt.Printf("Warning: Failed to load client certificate: %v\n", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
			configured = true
		}
	}

	if configured {
		httpClient.Transport = httpclient.NewTransport(tlsConfig)
	}

	return &SensorManagerClient{
		config:     cfg,
		httpClient: httpClient,
		baseURL:    cfg.ControlPlaneURL,
		gate:       managedprotocol.NewGate(SensorCapabilities()),
	}
}

// Register registers the sensor with the control plane using CSR-based flow
func (c *SensorManagerClient) Register() (*models.SensorConfig, error) {
	// Generate sensor ID (UUID) that will be used as certificate CN
	// The sensor "claims" its ID, and the platform will use it
	sensorID := uuid.New()
	if c.config.SensorID != "" {
		// If sensor ID already exists (from previous registration), use it
		var err error
		sensorID, err = uuid.Parse(c.config.SensorID)
		if err != nil {
			// Invalid existing ID, generate new one
			sensorID = uuid.New()
		}
	}

	// Generate keypair and CSR locally (private key never leaves sensor)
	csrGen := certificates.NewCSRGenerator()
	privateKey, err := csrGen.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	csrPEM, err := csrGen.GenerateCSR(sensorID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %v", err)
	}

	// Store private key securely (will be saved to config file)
	privateKeyPEM, err := csrGen.EncodePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %v", err)
	}

	// Registration request with CSR. Protocol 1 has no other kind.
	if csrPEM == "" {
		return nil, fmt.Errorf("refusing to register without a certificate signing request")
	}
	registration := models.SensorRegistration{
		RegistrationKey:     c.config.RegistrationKey,
		Name:                c.config.Name,
		Description:         c.config.Description,
		Platform:            c.config.Platform,
		Version:             c.config.Version,
		Profile:             c.config.Profile,
		NetworkInterfaces:   c.config.Capture.Interfaces,
		AvailableInterfaces: AvailableInterfaceNames(),
		IPAddress:           c.getRegistrationIPAddress(),
		CSR:                 csrPEM,            // Include CSR in registration request
		SensorID:            sensorID.String(), // Proposed sensor ID
		AgentKind:           managedprotocol.AgentKindSensor,
		Protocol:            managedprotocol.Offer(c.gate.Own()),
	}

	url := fmt.Sprintf("%s/api/v1/sensor-manager/sensors/register", c.baseURL)
	status, _, body, err := call(c.httpClient, c.gate, http.MethodPost, url, registration)
	if err != nil {
		if managedprotocol.IsIncompatible(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to send registration request: %v", err)
	}

	if status != http.StatusOK {
		err := fmt.Errorf("registration failed with status %d: %s", status, string(body))
		if IsPermanentRegistrationStatus(status) {
			// A rejected key, a duplicate sensor id, an unknown route: retrying
			// changes nothing, so the caller must stop rather than loop.
			return nil, &RegistrationRejectedError{StatusCode: status, Body: strings.TrimSpace(string(body)), err: err}
		}
		return nil, err
	}

	var registrationResp struct {
		SensorID             string                    `json:"sensor_id"`
		ClientCert           string                    `json:"client_cert"`       // Signed certificate (no private key)
		ClientKey            string                    `json:"client_key"`        // never accepted: see below
		ServerCACert         string                    `json:"server_ca_cert"`    // CA certificate for trust
		ControlPlaneURL      string                    `json:"control_plane_url"` // mTLS passthrough URL to switch to (#1033)
		CertificateExpiresAt string                    `json:"certificate_expires_at"`
		ReportingInterval    int                       `json:"reporting_interval"` // Top-level field from server
		Features             map[string]bool           `json:"features"`           // Top-level field from server
		Config               models.SensorConfig       `json:"config"`             // For backward compatibility
		AgentSecret          string                    `json:"agent_secret"`
		AgentSecretVersion   int                       `json:"agent_secret_version"`
		Protocol             *managedprotocol.Protocol `json:"protocol"`
	}

	if err := json.Unmarshal(body, &registrationResp); err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %v", err)
	}

	// Nothing from the answer is applied before it is known to be protocol 1.
	caps, err := managedprotocol.Negotiate(registrationResp.Protocol, status, c.gate.Own())
	if err != nil {
		return nil, c.gate.Observe(err)
	}
	// The key pair is this sensor's; a platform that generated one has seen a
	// private key it must never hold.
	if registrationResp.ClientKey != "" {
		return nil, &managedprotocol.ViolationError{Reason: "it carries a private key the platform generated (client_key); this sensor only ever uses the key it generated for its certificate signing request"}
	}
	if registrationResp.AgentSecret == "" {
		return nil, &managedprotocol.ViolationError{Reason: "it carries no agent_secret, which protocol 1 always issues at enrollment"}
	}
	c.gate.Compatible(caps)

	// Update sensor ID in config
	c.config.SensorID = registrationResp.SensorID

	// The per-sensor secret (#2437). Returned once; the caller persists it with
	// the certificate, and only then does the config stop keeping the
	// registration key.
	if registrationResp.AgentSecret != "" {
		c.config.SetEnrolledAgentSecret(registrationResp.AgentSecret, registrationResp.AgentSecretVersion)
	}

	// Store certificate (signed by platform)
	if registrationResp.ClientCert != "" {
		c.config.Security.ClientCert = registrationResp.ClientCert
	}

	// Store private key locally (never sent to platform)
	c.config.Security.ClientKey = privateKeyPEM

	// ADD the platform's CA to the trust pool; do not replace what is there.
	// This is the live registration path (cmd/main.go calls
	// SensorManagerClient.Register, not OutboundClient.Register). Replacing
	// dropped the operator-approved edge anchor, so registration succeeded and
	// every subsequent handshake failed when agentMtls is off (the chart default).
	if registrationResp.ServerCACert != "" {
		c.config.Security.ServerCACert = sharedcerts.MergeCAPEMs(
			c.config.Security.ServerCACert, registrationResp.ServerCACert)
	}

	// Switch to the advertised mTLS passthrough endpoint (#1033). The
	// OutboundClient picks the new URL up in ActivateMTLS (main.register calls
	// it right after this returns), and saveConfigFile persists it.
	if applyAdvertisedControlPlaneURL(c.config, registrationResp.ControlPlaneURL) {
		c.baseURL = c.config.ControlPlaneURL
	}
	if c.config.Security.ClientCert != "" && c.config.Security.ClientKey != "" {
		c.config.Security.UseTLS = true
	}
	if err := c.reconfigureTLS(); err != nil {
		// Log and continue — deliberately NOT fatal. This runs after the
		// platform has consumed the single-use registration key but before
		// saveCertificates/saveConfigFile, so returning an error here discards a
		// freshly issued certificate permanently and re-registration is refused
		// with "Registration key has already been used". A CA PEM that fails
		// AppendCertsFromPEM is only a warning in buildTLSTransport but a hard
		// error here, so that is a reachable path, not a theoretical one.
		//
		// A client left on its previous transport can still be rotated; a
		// sensor that threw away its enrollment cannot be recovered without
		// operator intervention. This matches OutboundClient.ActivateMTLS,
		// which is no-op-on-failure for the same reason.
		log.Printf("⚠️  sensor-manager client: TLS reconfigure after registration failed (%v); continuing on the existing transport — certificate rotation will retry", err)
	}

	// Build config from top-level fields (server returns these at top level, not nested)
	config := registrationResp.Config
	if registrationResp.ReportingInterval > 0 {
		config.ReportingInterval = registrationResp.ReportingInterval
	}
	if registrationResp.Features != nil {
		config.Features = registrationResp.Features
		// Sync CaptureConfig from features so updateConfig() applies the correct
		// active probing setting from the deployment profile at startup.
		if ap, ok := registrationResp.Features["active_probing"]; ok {
			config.CaptureConfig.ActiveProbing = ap
		}
		if nd, ok := registrationResp.Features["network_discovery"]; ok {
			config.CaptureConfig.NetworkDiscovery = nd
		}
		if ho, ok := registrationResp.Features["host_observation"]; ok {
			config.CaptureConfig.HostObservation = &ho
		}
	}

	return &config, nil
}

// getRegistrationIPAddress reports this host's address at enrollment; "" means
// undetermined. See the OutboundClient equivalent for why loopback is not a
// safe fallback.
func (c *SensorManagerClient) getRegistrationIPAddress() string {
	return c.config.CurrentIPAddress()
}

// Helper function to generate batch ID
