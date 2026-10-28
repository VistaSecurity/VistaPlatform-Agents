// Package fakeplatform is an in-process stand-in for the Vista Platform side of
// managed protocol 1, for the agents' public tests. It is test support, not a
// product: it implements exactly the calls the two agents make, with a test CA
// generated at test time, so the agents' real clients, TLS pinning, mTLS,
// enrollment, rotation and job flows run without any private component.
//
// It validates every request an agent sends against schemas/managed/v1, and,
// while it behaves, every answer it gives; a request that does not validate is
// a test failure (reported when the test ends), so a drift between the agents
// and the published schemas fails on both sides.
//
// Misbehaviour is configurable (SetMisbehaviour): answers without a protocol,
// with version 2, a 426 on every call, a private key or no agent secret in the
// registration answer, unsealed credentials in a job. The platform's real
// handlers are qualified privately against the same schemas; nothing here
// stands in for that.
package fakeplatform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocolschema"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// Misbehaviour is a way the fake platform breaks protocol 1 on purpose.
type Misbehaviour int

const (
	// Behave answers as protocol 1 says.
	Behave Misbehaviour = iota
	// NoProtocol answers without the protocol object and without the header,
	// as a platform that predates protocol 1 does.
	NoProtocol
	// Version2 names managed protocol 2 in every answer: in the protocol
	// object of an answer with a body, in the header of one without.
	Version2
	// Upgrade426 answers every call 426 agent_protocol_unsupported, as a
	// platform that supports only protocol 2 does.
	Upgrade426
	// ServerGeneratedKey puts a private key (client_key) in the registration
	// and rotation answers.
	ServerGeneratedKey
	// NoAgentSecret leaves agent_secret out of the registration answer.
	NoAgentSecret
	// UnsealedCredentials hands a device-agent job its credentials as a
	// plaintext map instead of a sealed envelope.
	UnsealedCredentials
)

// Capabilities is what the fake platform offers each agent kind by default.
var Capabilities = []string{"device_discovery", "identity_dns_v1", "scan_plan_v1", "verify_certificate_v1"}

// Request is one call an agent made.
type Request struct {
	Message string // schema name, "" for a route with no body
	Method  string
	Path    string
	Header  http.Header
	Body    map[string]any
	// PeerCN is the CN of the client certificate the call presented, "" for none.
	PeerCN string
}

// Platform is the fake control plane.
type Platform struct {
	t       testing.TB
	server  *httptest.Server
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	caPEM   string
	schemas *protocolschema.Set

	mu           sync.Mutex
	misbehave    Misbehaviour
	capabilities []string
	requests     []Request
	violations   []string
	secrets      map[string]string // agent id -> current agent secret
	secretVer    map[string]int
	activeSerial map[string]string // agent id -> serial of its only valid certificate
	commands     []map[string]any  // sensor commands for the next heartbeat
	// unchecked is set when a queued command is one protocol 1 does not allow
	// (QueueOutOfProtocolCommand): the answer carrying it is not validated.
	unchecked  bool
	jobs       []queuedJob // device-agent jobs for the next poll
	unitAnswer *answer     // set to make the next unit report answer differently
}

type queuedJob struct {
	job   map[string]any
	creds map[string]any
}

type answer struct {
	status int
	body   map[string]any
}

// New starts a fake platform over TLS. Its server certificate is issued by a
// CA generated for this test; an agent trusts it by pinning CAPEM, exactly as
// trust bootstrap pins a platform's anchor.
func New(t testing.TB) *Platform {
	t.Helper()
	set, err := protocolschema.Shared()
	if err != nil {
		t.Fatalf("fakeplatform: schemas: %v", err)
	}
	p := &Platform{
		t: t, schemas: set, capabilities: append([]string(nil), Capabilities...),
		secrets: map[string]string{}, secretVer: map[string]int{}, activeSerial: map[string]string{},
	}
	p.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fakeplatform test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &p.caKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.caCert, _ = x509.ParseCertificate(der)
	p.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fakeplatform"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, DNSNames: []string{"localhost"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, p.caCert, &serverKey.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	p.server = httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	p.server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: serverKey}},
		// Enrollment has no client certificate yet; every later call must
		// present the one this platform issued (checked per route).
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
	}
	p.server.StartTLS()
	t.Cleanup(func() {
		p.server.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, v := range p.violations {
			t.Errorf("fakeplatform: %s", v)
		}
	})
	return p
}

// URL is the platform's base URL.
func (p *Platform) URL() string { return p.server.URL }

// CAPEM is the anchor an agent pins to trust this platform.
func (p *Platform) CAPEM() string { return p.caPEM }

// SetMisbehaviour changes how the platform answers from now on.
func (p *Platform) SetMisbehaviour(m Misbehaviour) {
	p.mu.Lock()
	p.misbehave = m
	p.mu.Unlock()
}

// SetCapabilities changes the capabilities the platform offers.
func (p *Platform) SetCapabilities(caps ...string) {
	p.mu.Lock()
	p.capabilities = append([]string{}, caps...)
	p.mu.Unlock()
}

// QueueSensorCommand hands cmd to the sensor on its next heartbeat.
func (p *Platform) QueueSensorCommand(cmd map[string]any) {
	p.mu.Lock()
	p.commands = append(p.commands, cmd)
	p.mu.Unlock()
}

// QueueOutOfProtocolCommand hands the sensor, on its next heartbeat, a command
// protocol 1 does not allow (a protocols × ports discovery_job), to prove the
// sensor refuses it. The answer carrying it is not held to the schema.
func (p *Platform) QueueOutOfProtocolCommand(cmd map[string]any) {
	p.mu.Lock()
	p.commands = append(p.commands, cmd)
	p.unchecked = true
	p.mu.Unlock()
}

// QueueAgentJob hands job to the device agent on its next poll, with creds
// sealed under the agent secret this platform issued it (or, misbehaving,
// unsealed). A nil creds sends the job with no credentials.
func (p *Platform) QueueAgentJob(job map[string]any, creds map[string]any) {
	p.mu.Lock()
	p.jobs = append(p.jobs, queuedJob{job: job, creds: creds})
	p.mu.Unlock()
}

// AnswerNextUnitReport makes the next unit report answer status with body.
func (p *Platform) AnswerNextUnitReport(status int, body map[string]any) {
	p.mu.Lock()
	p.unitAnswer = &answer{status: status, body: body}
	p.mu.Unlock()
}

// Requests returns the calls received for message (all calls for "").
func (p *Platform) Requests(message string) []Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Request
	for _, r := range p.requests {
		if message == "" || r.Message == message {
			out = append(out, r)
		}
	}
	return out
}

// AgentSecret is the agent secret this platform last issued id.
func (p *Platform) AgentSecret(id string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.secrets[id]
}

func (p *Platform) violation(format string, args ...any) {
	p.violations = append(p.violations, fmt.Sprintf(format, args...))
}

// route is one call of the protocol.
type route struct {
	method, prefix, suffix string
	message                string // request schema; "" for no body
	enroll                 bool   // reached without a client certificate
	handle                 func(p *Platform, id string, segs []string, body map[string]any) (int, map[string]any, string)
}

const (
	sensorBase = "/api/v1/sensor-manager/sensors/"
	agentBase  = "/api/v1/device-interrogation-service/agents/"
)

var routes = []route{
	{http.MethodPost, sensorBase + "register", "", "registration.request", true, (*Platform).register},
	{http.MethodPost, agentBase + "register", "", "registration.request", true, (*Platform).register},
	{http.MethodPost, sensorBase, "/heartbeat", "heartbeat.sensor.request", false, (*Platform).sensorHeartbeat},
	{http.MethodPost, sensorBase, "/discoveries", "discovery-batch", false, ok},
	{http.MethodPost, sensorBase, "/units", "unit-batch", false, (*Platform).units},
	{http.MethodPost, sensorBase, "/complete", "completion", false, ok},
	{http.MethodPost, sensorBase, "/ack", "command-ack", false, ok},
	{http.MethodPost, sensorBase, "/certificates/rotate", "rotation.request", false, (*Platform).rotate},
	{http.MethodGet, agentBase, "/jobs", "", false, (*Platform).nextJob},
	{http.MethodPost, agentBase, "/results", "job-result.device-agent", false, ok},
	{http.MethodPost, agentBase, "/heartbeat", "heartbeat.device-agent.request", false, (*Platform).agentHeartbeat},
	{http.MethodPost, agentBase, "/certificates/rotate", "rotation.request", false, (*Platform).rotate},
}

func ok(*Platform, string, []string, map[string]any) (int, map[string]any, string) {
	return http.StatusOK, map[string]any{"message": "accepted"}, ""
}

func (p *Platform) serve(w http.ResponseWriter, r *http.Request) {
	var rt *route
	for i := range routes {
		c := &routes[i]
		if r.Method == c.method && strings.HasPrefix(r.URL.Path, c.prefix) && strings.HasSuffix(r.URL.Path, c.suffix) &&
			(c.suffix != "" || r.URL.Path == c.prefix) {
			rt = c
			break
		}
	}
	if rt == nil {
		http.NotFound(w, r)
		return
	}
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, rt.prefix), "/")
	id := ""
	if !rt.enroll {
		id = segs[0]
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	var body map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &body)
	}
	req := Request{Message: rt.message, Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		req.PeerCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}

	p.mu.Lock()
	p.requests = append(p.requests, req)
	if rt.message != "" {
		if err := p.schemas.ValidateJSON(rt.message, raw); err != nil {
			p.violation("%s %s: the agent sent a %s that does not match its schema: %v\n%s", r.Method, r.URL.Path, rt.message, err, raw)
		}
	}
	misbehave := p.misbehave
	p.mu.Unlock()

	// The platform refuses before decoding a body: every request names the
	// protocol (D-P1), and one that does not, or names another, gets 426.
	if v := r.Header.Get(managedprotocol.Header); v != fmt.Sprint(managedprotocol.Version) || misbehave == Upgrade426 {
		agentVersion := 0
		if pv, okp, err := managedprotocol.ParseHeader(v); okp && err == nil {
			agentVersion = pv.Version
		}
		if misbehave != Upgrade426 {
			p.mu.Lock()
			p.violation("%s %s: the request does not carry %s: %d (got %q)", r.Method, r.URL.Path, managedprotocol.Header, managedprotocol.Version, v)
			p.mu.Unlock()
		}
		supported := managedprotocol.Version
		if misbehave == Upgrade426 {
			supported = 2
		}
		p.write(w, http.StatusUpgradeRequired, map[string]any{
			"code": managedprotocol.CodeProtocolUnsupported, "agent_protocol": agentVersion, "supported": []int{supported},
			"message": fmt.Sprintf("This agent speaks managed protocol %d; this platform supports %d. Install the agent version listed under Discovery -> Sensors & Agents.", agentVersion, supported),
		}, "error", false)
		return
	}

	// mTLS on every call after enrollment (OD-1): the certificate this
	// platform issued for the path id, and only the current one.
	if !rt.enroll {
		p.mu.Lock()
		serial, known := p.activeSerial[id]
		p.mu.Unlock()
		switch {
		case r.TLS == nil || len(r.TLS.PeerCertificates) == 0:
			p.write(w, http.StatusUnauthorized, map[string]any{"code": "client_certificate_required"}, "error", false)
			return
		case !known || r.TLS.PeerCertificates[0].Subject.CommonName != id:
			p.write(w, http.StatusUnauthorized, map[string]any{"code": "certificate_identity_mismatch"}, "error", false)
			return
		case r.TLS.PeerCertificates[0].SerialNumber.String() != serial:
			p.write(w, http.StatusUnauthorized, map[string]any{"code": "certificate_revoked", "reason": "rotated"}, "error", false)
			return
		}
	}

	status, resp, schema := rt.handle(p, id, segs, body)
	p.write(w, status, resp, schema, true)
}

// write answers. Protocol answers (schema set, body carrying protocol) get the
// misbehaviour applied; while behaving, every answer with a schema is
// validated before it is sent.
func (p *Platform) write(w http.ResponseWriter, status int, body map[string]any, schema string, protocolAnswer bool) {
	p.mu.Lock()
	misbehave := p.misbehave
	caps := append([]string{}, p.capabilities...)
	p.mu.Unlock()

	proto := managedprotocol.Protocol{Version: managedprotocol.Version, Capabilities: caps}
	switch misbehave {
	case Version2, Upgrade426:
		proto.Version = 2
	}
	// The header goes on every answer of a behaving platform. A Version2
	// platform puts it only where D-P1 requires it (an answer with no body),
	// so the agent's body check is what has to catch an answer with one.
	if misbehave != NoProtocol && (misbehave != Version2 || body == nil) {
		w.Header().Set(managedprotocol.Header, managedprotocol.FormatHeader(proto))
	}
	if body != nil {
		if _, has := body["protocol"]; has && protocolAnswer {
			switch misbehave {
			case NoProtocol:
				delete(body, "protocol")
			case Version2:
				body["protocol"] = proto
			}
		}
	}
	if body == nil {
		w.WriteHeader(status)
		return
	}
	data, err := json.Marshal(body)
	if err != nil {
		p.t.Errorf("fakeplatform: marshal answer: %v", err)
		return
	}
	if schema != "" && (misbehave == Behave || !protocolAnswer) {
		if err := p.schemas.ValidateJSON(schema, data); err != nil {
			p.mu.Lock()
			p.violation("the fake's own %s answer does not match its schema: %v\n%s", schema, err, data)
			p.mu.Unlock()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (p *Platform) protocolObject() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]any{"version": managedprotocol.Version, "capabilities": append([]string{}, p.capabilities...)}
}

// sign issues a client certificate for the CSR, whose CN must be the agent id.
func (p *Platform) sign(csrPEM, wantCN string) (string, string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", "", fmt.Errorf("csr is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", "", err
	}
	if csr.Subject.CommonName != wantCN {
		return "", "", fmt.Errorf("csr CN %q is not the agent id %q", csr.Subject.CommonName, wantCN)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: wantCN},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, csr.PublicKey, p.caKey)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), serial.String(), nil
}

func (p *Platform) issueSecret(id string) (string, int) {
	secret, err := agentcreds.GenerateSecret()
	if err != nil {
		p.t.Errorf("fakeplatform: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.secrets[id] = secret
	p.secretVer[id]++
	return secret, p.secretVer[id]
}

func (p *Platform) register(_ string, _ []string, body map[string]any) (int, map[string]any, string) {
	kind, _ := body["agent_kind"].(string)
	idKey, status := "sensor_id", http.StatusOK
	if kind == managedprotocol.AgentKindDeviceAgent {
		idKey, status = "agent_id", http.StatusCreated
	}
	id, _ := body[idKey].(string)
	csr, _ := body["csr"].(string)
	cert, serial, err := p.sign(csr, id)
	if err != nil {
		return http.StatusBadRequest, map[string]any{"code": "invalid_csr", "message": err.Error()}, "error"
	}
	p.mu.Lock()
	p.activeSerial[id] = serial
	misbehave := p.misbehave
	p.mu.Unlock()
	resp := map[string]any{
		idKey: id, "client_cert": cert, "server_ca_cert": p.caPEM,
		"certificate_expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"protocol":               p.protocolObject(),
	}
	if misbehave != NoAgentSecret {
		resp["agent_secret"], resp["agent_secret_version"] = p.issueSecret(id)
	}
	if misbehave == ServerGeneratedKey {
		resp["client_key"] = "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----\n"
	}
	if kind == managedprotocol.AgentKindSensor {
		resp["reporting_interval"] = 30
		resp["features"] = map[string]any{"active_probing": false, "network_discovery": false, "host_observation": false}
		resp["config"] = map[string]any{}
	}
	return status, resp, "registration.response"
}

func (p *Platform) rotate(id string, _ []string, body map[string]any) (int, map[string]any, string) {
	csr, _ := body["csr"].(string)
	cert, serial, err := p.sign(csr, id)
	if err != nil {
		return http.StatusBadRequest, map[string]any{"code": "invalid_csr", "message": err.Error()}, "error"
	}
	p.mu.Lock()
	p.activeSerial[id] = serial // every other certificate of the agent is revoked
	misbehave := p.misbehave
	p.mu.Unlock()
	secret, ver := p.issueSecret(id)
	resp := map[string]any{
		"client_cert": cert, "server_ca_cert": p.caPEM, "message": "Certificate rotated",
		"certificate_expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"agent_secret":           secret, "agent_secret_version": ver,
	}
	if misbehave == ServerGeneratedKey {
		resp["client_key"] = "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----\n"
	}
	return http.StatusOK, resp, "rotation.response"
}

func (p *Platform) sensorHeartbeat(id string, _ []string, _ map[string]any) (int, map[string]any, string) {
	p.mu.Lock()
	cmds, unchecked := p.commands, p.unchecked
	p.commands, p.unchecked = nil, false
	p.mu.Unlock()
	list := make([]any, 0, len(cmds))
	for _, c := range cmds {
		list = append(list, c)
	}
	schema := "heartbeat.response"
	if unchecked {
		schema = ""
	}
	return http.StatusOK, map[string]any{"protocol": p.protocolObject(), "sensor_id": id, "commands": list}, schema
}

func (p *Platform) agentHeartbeat(string, []string, map[string]any) (int, map[string]any, string) {
	return http.StatusOK, map[string]any{"protocol": p.protocolObject(), "message": "Heartbeat received"}, "heartbeat.response"
}

func (p *Platform) units(_ string, _ []string, body map[string]any) (int, map[string]any, string) {
	p.mu.Lock()
	a := p.unitAnswer
	p.unitAnswer = nil
	p.mu.Unlock()
	if a != nil {
		return a.status, a.body, ""
	}
	units, _ := body["units"].([]any)
	return http.StatusOK, map[string]any{"job_status": "running", "accepted": len(units), "duplicate": 0, "stale": 0, "unknown": 0}, "unit-batch.response"
}

func (p *Platform) nextJob(id string, _ []string, _ map[string]any) (int, map[string]any, string) {
	p.mu.Lock()
	if len(p.jobs) == 0 {
		p.mu.Unlock()
		return http.StatusNoContent, nil, ""
	}
	q := p.jobs[0]
	p.jobs = p.jobs[1:]
	misbehave := p.misbehave
	secret := p.secrets[id]
	p.mu.Unlock()
	job := map[string]any{}
	for k, v := range q.job {
		job[k] = v
	}
	job["protocol"] = p.protocolObject()
	switch {
	case q.creds == nil:
		job["credentials"] = nil
	case misbehave == UnsealedCredentials:
		job["credentials"] = q.creds
	default:
		jobID, _ := job["id"].(string)
		env, err := agentcreds.Seal(q.creds, jobID, secret)
		if err != nil {
			p.t.Errorf("fakeplatform: seal: %v", err)
		}
		job["credentials"] = env
	}
	return http.StatusOK, job, "job.device-agent"
}
