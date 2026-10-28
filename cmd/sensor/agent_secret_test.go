package main

// #2437: the sensor is issued a per-sensor secret at enrolment and a fresh one at
// every certificate rotation, keeps it 0600 beside its certificate, and no longer
// keeps the single-use registration key once the secret is on disk. Managed
// protocol 1 always issues the secret, so an enrolment answer without one is
// refused. These run the
// REAL client against a fake platform, then the real persistence and the real
// config loader — and the installer's own text, because the installer decides
// "already enrolled with this key" from what the sensor leaves in the file.

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

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocoltest"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

const (
	testSensorRegKey = "REG-0123456789abcdef0123456789abcdef"
	testSensorID     = "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59"
)

type fakeSensorPlatform struct {
	t          *testing.T
	srv        *httptest.Server
	caKey      *rsa.PrivateKey
	caCert     *x509.Certificate
	mu         sync.Mutex
	secrets    []string
	issued     int
	issue      bool
	sawRequest []map[string]any
}

func newFakeSensorPlatform(t *testing.T, issue bool, secrets ...string) *fakeSensorPlatform {
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
	f := &fakeSensorPlatform{t: t, caKey: caKey, caCert: caCert, secrets: secrets, issue: issue}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSensorPlatform) sign(csrPEM string) string {
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

func (f *fakeSensorPlatform) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	f.sawRequest = append(f.sawRequest, body)
	resp := map[string]any{"sensor_id": testSensorID, "client_cert": f.sign(body["csr"].(string)), "reporting_interval": 60, "protocol": protocoltest.V1()}
	if f.issue && f.issued < len(f.secrets) {
		f.issued++
		resp["agent_secret"] = f.secrets[f.issued-1]
		resp["agent_secret_version"] = f.issued
	}
	f.mu.Unlock()
	if !strings.HasSuffix(r.URL.Path, "/sensors/register") && !strings.HasSuffix(r.URL.Path, "/certificates/rotate") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func enrollingSensor(t *testing.T, p *fakeSensorPlatform) (*Sensor, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor-config.yaml")
	body := "# Vista sensor\nsensorId: \"\"\ncontrolPlaneUrl: " + p.srv.URL + "\nregistrationKey: \"" + testSensorRegKey + "\"\nreportingIntervalSeconds: 60\nstorage:\n  dataPath: \"" + dir + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return &Sensor{config: cfg, configPath: path, sensorManager: api.NewSensorManagerClient(cfg)}, path
}

func TestSensorSecret_EnrolmentDropsTheRegistrationKey(t *testing.T) {
	p := newFakeSensorPlatform(t, true, "sensor-secret-one")
	s, path := enrollingSensor(t, p)
	if err := s.register(); err != nil {
		t.Fatalf("register: %v", err)
	}
	proto, _ := p.sawRequest[0]["protocol"].(map[string]any)
	if proto["version"] != float64(managedprotocol.Version) || p.sawRequest[0]["agent_kind"] != managedprotocol.AgentKindSensor {
		t.Fatalf("registration request protocol = %v, agent_kind = %v; want protocol 1 from a sensor", p.sawRequest[0]["protocol"], p.sawRequest[0]["agent_kind"])
	}
	if _, asked := p.sawRequest[0]["supports_agent_secret"]; asked {
		t.Fatal("registration request still asks for an agent secret; protocol 1 always issues one")
	}

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), testSensorRegKey) || strings.Contains(string(body), "registrationKey:") {
		t.Fatalf("the config still holds the registration key:\n%s", body)
	}
	for _, want := range []string{"registrationKeySha256:", "agentSecretPath:", "sensorId: \"" + testSensorID + "\""} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("config lacks %q:\n%s", want, body)
		}
	}
	secretFile := filepath.Join(s.config.Storage.DataPath, "certs", agentcreds.SecretFileName)
	data, err := os.ReadFile(secretFile)
	if err != nil || !strings.Contains(string(data), "sensor-secret-one") || strings.Contains(string(data), testSensorRegKey) {
		t.Fatalf("secret file: %v %q", err, data)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(secretFile); fi.Mode().Perm() != 0o600 {
			t.Fatalf("secret file mode = %v, want 0600", fi.Mode().Perm())
		}
	}

	re, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if re.RegistrationKey != "" {
		t.Fatalf("reloaded RegistrationKey = %q, want none", re.RegistrationKey)
	}
	if st := re.AgentSecretState(); st.Secret != "sensor-secret-one" || st.Version != 1 {
		t.Fatalf("reloaded secret state = %+v", st)
	}
	if !isRegistered(re) {
		t.Fatal("the reloaded sensor does not read as registered — it would try to enrol again with no key")
	}

	// The installer recognises the host from the fingerprint, not the key.
	if runtime.GOOS != "windows" {
		assertInstallerRecognisesKey(t, path, testSensorRegKey, true)
		assertInstallerRecognisesKey(t, path, "REG-some-other-key", false)
	}
}

// assertInstallerRecognisesKey runs install-sensor.sh's own enrolled_with_key.
func assertInstallerRecognisesKey(t *testing.T, cfgPath, key string, want bool) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	raw, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	readConfigValue := installerSection(t, script, `^read_config_value\(\) \{`, `^\}`)
	sha := installerSection(t, script, `^sha256_of\(\) \{`, `^\}`)
	enrolled := installerSection(t, script, `^enrolled_with_key\(\) \{`, `^\}`)
	out := strings.TrimSpace(runBash(t, readConfigValue+"\n"+sha+"\n"+enrolled+
		"\nif enrolled_with_key "+cfgPath+" "+key+"; then echo yes; else echo no; fi"))
	if (out == "yes") != want {
		t.Fatalf("installer enrolled_with_key(%q) = %s, want %v — a re-run would %s", key, out, want,
			map[bool]string{true: "discard a working enrolment", false: "keep another host's enrolment"}[want])
	}
}

// A platform that answers an enrolment without the secret protocol 1 always
// issues has broken the protocol: the sensor applies nothing from the answer,
// keeps its registration key and writes no identity.
func TestSensorSecret_EnrolmentWithoutASecretIsRefused(t *testing.T) {
	p := newFakeSensorPlatform(t, false)
	s, path := enrollingSensor(t, p)
	err := s.register()
	if !managedprotocol.IsViolation(err) || !strings.Contains(err.Error(), "agent_secret") {
		t.Fatalf("register = %v, want a protocol violation naming agent_secret", err)
	}
	if !isProtocolRefusal(err) {
		t.Fatal("the refusal is not one the startup path stops on (exit 78)")
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), testSensorRegKey) {
		t.Fatalf("the registration key was dropped though the enrolment was refused:\n%s", body)
	}
	if s.config.SensorID != "" || s.config.Security.ClientCert != "" {
		t.Fatalf("the refused answer was applied: sensor id %q, cert held %v", s.config.SensorID, s.config.Security.ClientCert != "")
	}
	if _, err := os.Stat(filepath.Join(s.config.Storage.DataPath, "certs", agentcreds.SecretFileName)); err == nil {
		t.Fatal("a secret file was written though none was issued")
	}
}

// Rotation replaces the secret; the replaced one is honoured for the window and
// then dropped from disk. The registration key is never one of them.
func TestSensorSecret_Rotation(t *testing.T) {
	fastRotationRetries(t)

	p := newFakeSensorPlatform(t, true, "zeroth-secret", "first-secret", "second-secret")
	s, path := enrollingSensor(t, p)
	if err := s.register(); err != nil {
		t.Fatalf("register: %v", err)
	}

	reloaded, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rs := &Sensor{config: reloaded, configPath: path, sensorManager: api.NewSensorManagerClient(reloaded)}
	rs.rotateCertificateIfNeeded(rs.sensorManager)
	if _, asked := p.sawRequest[1]["supports_agent_secret"]; asked {
		t.Fatal("rotation request still asks for an agent secret; protocol 1 always issues one")
	}

	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), testSensorRegKey) || strings.Contains(string(body), "registrationKey:") {
		t.Fatalf("the registration key is in the config after rotation:\n%s", body)
	}
	after, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st := after.AgentSecretState()
	if st.Secret != "first-secret" || st.Previous != "zeroth-secret" {
		t.Fatalf("after rotation state = %+v, want first-secret with zeroth-secret as the previous", st)
	}

	// Second rotation: replaced again, previous is now the first secret.
	as := &Sensor{config: after, configPath: path, sensorManager: api.NewSensorManagerClient(after)}
	as.rotateCertificateIfNeeded(as.sensorManager)
	again, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st = again.AgentSecretState()
	if st.Secret != "second-secret" || st.Version != 3 || st.Previous != "first-secret" {
		t.Fatalf("after second rotation state = %+v", st)
	}

	// Past the window the replaced secret is dropped from disk.
	st.PreviousUntil = time.Now().Add(-time.Second)
	again.SetAgentSecretState(st)
	ps := &Sensor{config: again, configPath: path}
	ps.pruneAgentSecrets()
	data, _ := os.ReadFile(filepath.Join(again.Storage.DataPath, "certs", agentcreds.SecretFileName))
	if strings.Contains(string(data), "first-secret") {
		t.Fatalf("the replaced secret is still on disk after its window:\n%s", data)
	}
	if !strings.Contains(string(data), "second-secret") {
		t.Fatalf("pruning lost the current secret:\n%s", data)
	}
}
