package main

// #2437: the agent's credential key is rooted in a per-agent secret the platform
// issues at enrolment and at each certificate rotation, and the single-use
// registration key is no longer kept once that secret is on disk. These tests run
// the REAL client against a fake platform, then the real persistence
// (saveCertificates + saveConfigFile) and the real config loader, and open
// envelopes sealed the way the platform seals them (shared/agentcreds). Managed
// protocol 1 always issues the secret and never derives a key from the
// registration key (D-P7).

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/security"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocoltest"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

const testRegKey = "REG-0123456789abcdef0123456789abcdef"

// fakePlatform signs the CSRs it is sent and hands out the agent secrets it is
// told to, the way the real registration and rotation routes do.
type fakePlatform struct {
	t       *testing.T
	srv     *httptest.Server
	caKey   *rsa.PrivateKey
	caCert  *x509.Certificate
	mu      sync.Mutex
	secrets []string // issued in order: enrolment first, then one per rotation
	issued  int
	// issue controls whether a secret is returned at all (false: an older platform).
	issue      bool
	sawRequest []map[string]any
}

func newFakePlatform(t *testing.T, issue bool, secrets ...string) *fakePlatform {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	f := &fakePlatform{t: t, caKey: caKey, caCert: caCert, secrets: secrets, issue: issue}
	f.srv = httptest.NewServer(protocoltest.Speak1(http.HandlerFunc(f.serve)))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePlatform) signCSR(csrPEM string) string {
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		f.t.Fatalf("csr: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (f *fakePlatform) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.sawRequest = append(f.sawRequest, body)
	resp := map[string]any{"client_cert": f.signCSR(body["csr"].(string))}
	if f.issue && f.issued < len(f.secrets) {
		f.issued++
		resp["agent_secret"] = f.secrets[f.issued-1]
		resp["agent_secret_version"] = f.issued
	}
	f.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/agents/register"):
		resp["agent_id"] = "6f1f0a7e-1d3c-4f0e-9a52-0c3b6f3d2a11"
		w.WriteHeader(http.StatusCreated)
	case strings.HasSuffix(r.URL.Path, "/certificates/rotate"):
		resp["agent_id"] = "6f1f0a7e-1d3c-4f0e-9a52-0c3b6f3d2a11"
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func persist(t *testing.T, cfg *config.Config, path string) {
	t.Helper()
	if err := saveCertificates(cfg); err != nil {
		t.Fatalf("saveCertificates: %v", err)
	}
	if err := saveConfigFile(path, cfg); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}
}

func sealedFor(t *testing.T, secret string) (map[string]interface{}, string) {
	t.Helper()
	jobID := "5f2b1c7a-9c3e-4a1f-8b6d-2e7c1a4d9f30"
	env, err := agentcreds.Seal(map[string]interface{}{"username": "admin", "password": "device-pw"}, jobID, secret)
	if err != nil {
		t.Fatal(err)
	}
	return env, jobID
}

func opens(cfg *config.Config, env map[string]interface{}, jobID string) bool {
	creds, err := security.DecryptCredentials(env, jobID, cfg.CredentialSecrets()...)
	return err == nil && creds["password"] == "device-pw"
}

func reload(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return cfg
}

func newEnrolling(t *testing.T, p *fakePlatform) (*config.Config, *api.OutboundClient, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{PlatformURL: p.srv.URL, RegistrationKey: testRegKey, DataPath: dir,
		PollInterval: 30 * time.Second, HeartbeatInterval: time.Minute}
	return cfg, api.NewOutboundClient(cfg), filepath.Join(dir, "agent-config.yaml")
}

// Enrolment: the secret is returned, kept 0600 beside the certificate, the
// registration key is gone from the config, and credentials sealed under the
// secret open on the reloaded agent while the spent key opens nothing.
func TestAgentSecret_EnrolmentDropsTheRegistrationKey(t *testing.T) {
	p := newFakePlatform(t, true, "agent-secret-one")
	cfg, client, path := newEnrolling(t, p)

	if err := client.Register("test"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	proto, _ := p.sawRequest[0]["protocol"].(map[string]any)
	if proto["version"] != float64(managedprotocol.Version) || p.sawRequest[0]["agent_kind"] != managedprotocol.AgentKindDeviceAgent {
		t.Fatalf("registration request protocol = %v, agent_kind = %v; want protocol 1 from a device agent", p.sawRequest[0]["protocol"], p.sawRequest[0]["agent_kind"])
	}
	if _, asked := p.sawRequest[0]["supports_agent_secret"]; asked {
		t.Fatal("registration request still asks for an agent secret; protocol 1 always issues one")
	}
	persist(t, cfg, path)

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), testRegKey) || strings.Contains(string(body), "registration_key:") {
		t.Fatalf("the config still holds the registration key:\n%s", body)
	}
	if !strings.Contains(string(body), "registration_key_sha256:") || !strings.Contains(string(body), "agent_secret_path:") {
		t.Fatalf("config lacks the fingerprint / secret path:\n%s", body)
	}
	secretFile := filepath.Join(cfg.DataPath, "certs", agentcreds.SecretFileName)
	data, err := os.ReadFile(secretFile)
	if err != nil || !strings.Contains(string(data), "agent-secret-one") {
		t.Fatalf("secret file: %v %q", err, data)
	}
	if strings.Contains(string(data), testRegKey) {
		t.Fatal("the secret file carries the registration key")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(secretFile); fi.Mode().Perm() != 0o600 {
			t.Fatalf("secret file mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	re := reload(t, path)
	if re.RegistrationKey != "" {
		t.Fatalf("reloaded RegistrationKey = %q, want none", re.RegistrationKey)
	}
	env, jobID := sealedFor(t, "agent-secret-one")
	if !opens(re, env, jobID) {
		t.Fatal("credentials sealed under the agent secret do not open on the reloaded agent")
	}
	spent, _ := sealedFor(t, testRegKey)
	if opens(re, spent, jobID) {
		t.Fatal("an envelope sealed under the spent registration key opened")
	}
}

// A platform that enrols without issuing the secret protocol 1 always issues has
// broken the protocol: nothing from the answer is applied, and the agent stops
// (exit 78) rather than run with credentials it could never open.
func TestAgentSecret_EnrolmentWithoutASecretIsRefused(t *testing.T) {
	p := newFakePlatform(t, false)
	cfg, client, _ := newEnrolling(t, p)
	err := client.Register("test")
	if !managedprotocol.IsViolation(err) || !strings.Contains(err.Error(), "agent_secret") {
		t.Fatalf("Register = %v, want a protocol violation naming agent_secret", err)
	}
	if code := registrationFailureExitCode(err); code != exitNeedsOperator {
		t.Fatalf("exit code = %d, want %d", code, exitNeedsOperator)
	}
	if cfg.AgentID != "" || cfg.Security.ClientCert != "" {
		t.Fatalf("the refused answer was applied: agent %q, cert held %v", cfg.AgentID, cfg.Security.ClientCert != "")
	}
}

// A config written by a build that predates agent secrets (registration key, no
// secret) opens nothing: protocol 1 derives no key from the registration key.
func TestAgentSecret_PreChangeConfigOpensNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent-config.yaml")
	if err := os.WriteFile(path, []byte("agent_id: \"6f1f0a7e-1d3c-4f0e-9a52-0c3b6f3d2a11\"\nplatform_url: \"https://p.example.test\"\nregistration_key: \""+testRegKey+"\"\ndata_path: \""+dir+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := reload(t, path)
	env, jobID := sealedFor(t, testRegKey)
	if opens(cfg, env, jobID) {
		t.Fatal("an envelope sealed under the registration key opened")
	}
}

// Rotation issues a new secret; the replaced one keeps working for the window
// and then does not. Survives a restart (the window is on disk).
func TestAgentSecret_RotationWindow(t *testing.T) {
	p := newFakePlatform(t, true, "agent-secret-one", "agent-secret-two")
	cfg, client, path := newEnrolling(t, p)
	if err := client.Register("test"); err != nil {
		t.Fatal(err)
	}
	persist(t, cfg, path)

	if err := client.RotateCertificate(); err != nil {
		t.Fatalf("RotateCertificate: %v", err)
	}
	if _, asked := p.sawRequest[1]["supports_agent_secret"]; asked {
		t.Fatal("rotation request still asks for an agent secret; protocol 1 always issues one")
	}
	persist(t, cfg, path)

	oldEnv, jobID := sealedFor(t, "agent-secret-one")
	newEnv, _ := sealedFor(t, "agent-secret-two")
	re := reload(t, path)
	if !opens(re, newEnv, jobID) {
		t.Fatal("the new secret does not open")
	}
	if !opens(re, oldEnv, jobID) {
		t.Fatal("an in-flight envelope sealed under the replaced secret no longer opens inside the window")
	}

	// Past the window the replaced secret is dead, in memory and on disk.
	st := re.AgentSecretState()
	st.PreviousUntil = time.Now().Add(-time.Second)
	re.SetAgentSecretState(st)
	if opens(re, oldEnv, jobID) {
		t.Fatal("the replaced secret still opens after the window")
	}
	if !opens(re, newEnv, jobID) {
		t.Fatal("the current secret stopped opening after the window")
	}
	if !re.PruneAgentSecrets(time.Now()) {
		t.Fatal("PruneAgentSecrets reported nothing to drop")
	}
	if err := saveCertificates(re); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(cfg.DataPath, "certs", agentcreds.SecretFileName))
	if strings.Contains(string(data), "agent-secret-one") {
		t.Fatalf("the replaced secret is still on disk after its window:\n%s", data)
	}
}

// The installer decides "this host already enrolled with this key" from what the
// agent leaves in the config. With the key no longer kept, it must recognise the
// fingerprint — and only the fingerprint of THIS key — or a re-run of the same
// install command would discard a working enrolment.
func TestAgentSecret_InstallerRecognisesTheFingerprint(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	p := newFakePlatform(t, true, "agent-secret-one")
	cfg, client, path := newEnrolling(t, p)
	if err := client.Register("test"); err != nil {
		t.Fatal(err)
	}
	persist(t, cfg, path)

	raw, err := os.ReadFile(deviceAgentInstaller)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	sections := installerSection(t, script, `^read_config_value\(\) \{`, `^\}`) + "\n" +
		installerSection(t, script, `^sha256_of\(\) \{`, `^\}`) + "\n" +
		installerSection(t, script, `^enrolled_with_key\(\) \{`, `^\}`)
	check := func(key string) string {
		return strings.TrimSpace(runInstallerBash(t, sections+"\nif enrolled_with_key "+path+" "+key+"; then echo yes; else echo no; fi"))
	}
	if got := check(testRegKey); got != "yes" {
		t.Fatalf("installer does not recognise the key this host enrolled with (%s) — a re-run would discard the enrolment", got)
	}
	if got := check("REG-another-hosts-key"); got != "no" {
		t.Fatalf("installer recognises a different key (%s)", got)
	}
}

// The agent's own daily check drops a replaced secret from disk once its window
// has passed, through the real method the rotation monitor calls.
func TestAgentSecret_DailyCheckDropsAnExpiredPreviousSecret(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataPath: dir, PlatformURL: "https://p.example.test", AgentID: "6f1f0a7e-1d3c-4f0e-9a52-0c3b6f3d2a11",
		PollInterval: time.Minute, HeartbeatInterval: time.Minute}
	cfg.Security.ClientCert, cfg.Security.ClientKey = "CERT", "KEY"
	cfg.SetAgentSecretState(agentcreds.SecretState{Secret: "current", Version: 2, Previous: "replaced", PreviousUntil: time.Now().Add(-time.Minute)})
	a := &DeviceAgent{config: cfg, configPath: filepath.Join(dir, "agent-config.yaml")}

	a.pruneAgentSecrets()

	data, err := os.ReadFile(filepath.Join(dir, "certs", agentcreds.SecretFileName))
	if err != nil {
		t.Fatalf("secret file not written: %v", err)
	}
	if strings.Contains(string(data), "replaced") || !strings.Contains(string(data), "current") {
		t.Fatalf("secret file after the daily check:\n%s", data)
	}
}
