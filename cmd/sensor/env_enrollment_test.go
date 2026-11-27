package main

// A sensor configured by its environment alone — the container image in a
// Kubernetes pod: CONTROL_PLANE_URL, a single-use REGISTRATION_KEY from a
// Secret, DATA_PATH on a volume, no config file — must come back from a pod
// replacement as the same sensor. These run the sensor's start-up steps
// (findDefaultConfigFile → loadConfig → resolveRegistrationAtStartup, as
// runSensor does) twice against a fake platform that, like the real one,
// refuses a registration key the second time it is presented.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
)

// singleUseKeyPlatform answers the first registration as the fake platform
// does and every later one with the platform's refusal of a spent key.
type singleUseKeyPlatform struct {
	srv           *httptest.Server
	registrations atomic.Int32
}

func newSingleUseKeyPlatform(t *testing.T, alreadySpent bool) *singleUseKeyPlatform {
	t.Helper()
	inner := newFakeSensorPlatform(t, true, "sensor-secret-one")
	p := &singleUseKeyPlatform{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/sensors/register") {
			if n := p.registrations.Add(1); alreadySpent || n > 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"Registration key has already been used"}`))
				return
			}
		}
		inner.serve(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// podEnv is the environment the shipped manifest gives the sensor.
func podEnv(t *testing.T, platformURL, dataPath string) {
	t.Helper()
	t.Setenv("CONTROL_PLANE_URL", platformURL)
	t.Setenv("REGISTRATION_KEY", testSensorRegKey)
	t.Setenv("DATA_PATH", dataPath)
	t.Setenv("CAPTURE_DISABLED", "true")
}

// startPod runs the start-up path of one pod and reports the exit codes the
// sensor asked for (none means it went on to run).
func startPod(t *testing.T) (*Sensor, []int) {
	t.Helper()
	var exited []int
	orig := exitProcess
	exitProcess = func(code int) { exited = append(exited, code) }
	t.Cleanup(func() { exitProcess = orig })

	path := findDefaultConfigFile()
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig(%q): %v", path, err)
	}
	s := &Sensor{config: cfg, configPath: path, sensorManager: api.NewSensorManagerClient(cfg)}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	s.resolveRegistrationAtStartup(false, stop)
	return s, exited
}

// assertEnrollmentRecord checks the record a first start leaves: the identity
// and nothing else, no registration key.
func assertEnrollmentRecord(t *testing.T, data string) {
	t.Helper()
	raw, err := os.ReadFile(enrolledConfigPath(data))
	if err != nil {
		t.Fatalf("the enrolment was not recorded on the volume: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"environmentEnrollment: true",
		"sensorId: " + testSensorID,
		"registrationKeySha256: " + config.HashRegistrationKey(testSensorRegKey),
		"clientCertPath: " + filepath.Join(data, "certs", "client.crt"),
		"clientKeyPath: " + filepath.Join(data, "certs", "client.key"),
		"agentSecretPath: ",
		"useTLS: true",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("record lacks %q:\n%s", want, text)
		}
	}
	for _, never := range []string{testSensorRegKey, "registrationKey:", "PRIVATE KEY", "BEGIN CERTIFICATE", "capture:", "activeProbing"} {
		if strings.Contains(text, never) {
			t.Errorf("record holds %q:\n%s", never, text)
		}
	}
	if runtime.GOOS != "windows" {
		for _, f := range []string{enrolledConfigPath(data), filepath.Join(data, "certs", "client.key")} {
			info, err := os.Stat(f)
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("%s has mode %o, want 0600", f, mode)
			}
		}
	}
}

func TestEnvOnlySensor_RestartedPodKeepsItsIdentity(t *testing.T) {
	logs := captureLog(t)
	p := newSingleUseKeyPlatform(t, false)
	data := t.TempDir()
	podEnv(t, p.srv.URL, data)
	t.Setenv("ACTIVE_PROBING", "false")
	t.Setenv("OWNED_NETWORKS", "198.51.100.0/24")
	t.Setenv("MAX_CONNECTIONS", "17")

	// First pod: no config file anywhere, so it enrols.
	first, exited := startPod(t)
	if first.configPath != enrolledConfigPath(data) {
		t.Errorf("after enrolment the sensor uses config %q, want %q", first.configPath, enrolledConfigPath(data))
	}
	if len(exited) != 0 || !first.isRegisteredNow() || p.registrations.Load() != 1 {
		t.Fatalf("first start: exits %v, registered %v, registrations %d; want none, true, 1\n%s", exited, first.isRegisteredNow(), p.registrations.Load(), logs)
	}
	assertEnrollmentRecord(t, data)
	if strings.Contains(logs.String(), testSensorRegKey) {
		t.Fatalf("the registration key reached the log:\n%s", logs)
	}

	// The platform delivers a capture setting; the sensor keeps it in the file.
	if err := first.persistCaptureSetting("hostObservation", false); err != nil {
		t.Fatalf("the record cannot take a delivered setting: %v", err)
	}

	// Second pod: same volume, the spent key still in the environment, and the
	// manifest edited: one setting changed, one removed, the URL changed.
	t.Setenv("ACTIVE_PROBING", "true")
	t.Setenv("OWNED_NETWORKS", "")
	t.Setenv("MAX_CONNECTIONS", "")
	t.Setenv("CONTROL_PLANE_URL", "https://elsewhere.example")
	logs.Reset()
	second, exited := startPod(t)
	if got := p.registrations.Load(); got != 1 {
		t.Fatalf("the restarted pod registered again (%d registrations in all); it must use the stored identity\n%s", got, logs)
	}
	if len(exited) != 0 || !second.isRegisteredNow() {
		t.Fatalf("restarted pod: exits %v, registered %v; want it running as the enrolled sensor\n%s", exited, second.isRegisteredNow(), logs)
	}
	if second.configPath != enrolledConfigPath(data) {
		t.Fatalf("restarted pod read config %q, want %q", second.configPath, enrolledConfigPath(data))
	}
	c1, c2 := first.config, second.config
	if c2.SensorID != testSensorID || c2.Security.ClientCert != c1.Security.ClientCert || c2.Security.ClientKey != c1.Security.ClientKey || c2.Security.ClientCert == "" {
		t.Fatalf("restarted pod does not present the stored identity: id %q", c2.SensorID)
	}
	if c2.AgentSecretState().IsZero() {
		t.Fatal("restarted pod lost the agent secret")
	}
	if c2.ControlPlaneURL != p.srv.URL {
		t.Errorf("control-plane URL %q, want the enrolled %q", c2.ControlPlaneURL, p.srv.URL)
	}
	// The environment decides every setting, as on a first start.
	if !c2.Capture.Disabled || !c2.Capture.ActiveProbing || c2.Capture.OwnedNetworks != nil || c2.Capture.MaxConnections != 1000 {
		t.Errorf("restarted pod does not follow its environment: disabled %v activeProbing %v ownedNetworks %v maxConnections %d",
			c2.Capture.Disabled, c2.Capture.ActiveProbing, c2.Capture.OwnedNetworks, c2.Capture.MaxConnections)
	}
	// ...except what the platform delivered.
	if c2.Capture.HostObservation {
		t.Error("a setting the platform delivered was lost on restart")
	}
}

// The record alone, exactly as the one write leaves it, is a complete
// enrollment: a start that finds it does not register.
func TestEnvOnlySensor_TheRecordAloneIsEnough(t *testing.T) {
	logs := captureLog(t)
	p := newSingleUseKeyPlatform(t, false)
	data := t.TempDir()
	podEnv(t, p.srv.URL, data)

	enrolled := &Sensor{config: config.Load()}
	enrolled.sensorManager = api.NewSensorManagerClient(enrolled.config)
	if _, err := enrolled.sensorManager.Register(); err != nil {
		t.Fatal(err)
	}
	if err := saveCertificates(enrolled.config); err != nil {
		t.Fatal(err)
	}
	if err := writeEnvironmentEnrollment(enrolledConfigPath(data), enrolled.config); err != nil {
		t.Fatal(err)
	}
	assertEnrollmentRecord(t, data)

	s, exited := startPod(t)
	if got := p.registrations.Load(); got != 1 || len(exited) != 0 || !s.isRegisteredNow() || s.config.SensorID != testSensorID {
		t.Fatalf("registrations %d, exits %v, registered %v, id %q; want 1, none, true, %s\n%s", got, exited, s.isRegisteredNow(), s.config.SensorID, testSensorID, logs)
	}
}

// A later save that fails (a rotation, a delivered setting, a full volume)
// leaves the record as it was, so the next start still does not register.
func TestEnvOnlySensor_FailedLaterSaveKeepsTheEnrollment(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the test cannot write")
	}
	logs := captureLog(t)
	p := newSingleUseKeyPlatform(t, false)
	data := t.TempDir()
	podEnv(t, p.srv.URL, data)

	first, _ := startPod(t)
	if p.registrations.Load() != 1 {
		t.Fatalf("first start did not enrol\n%s", logs)
	}
	if err := os.Chmod(data, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(data, 0o700) })
	if err := first.saveConfigFile(); err == nil {
		t.Fatal("the save succeeded in a read-only directory; the test proves nothing")
	}
	if err := first.persistCaptureSetting("hostObservation", false); err == nil {
		t.Fatal("the setting save succeeded in a read-only directory; the test proves nothing")
	}
	if err := os.Chmod(data, 0o700); err != nil {
		t.Fatal(err)
	}
	assertEnrollmentRecord(t, data)

	second, exited := startPod(t)
	if got := p.registrations.Load(); got != 1 || len(exited) != 0 || !second.isRegisteredNow() {
		t.Fatalf("after a failed save: registrations %d, exits %v, registered %v; want 1, none, true\n%s", got, exited, second.isRegisteredNow(), logs)
	}
}

// With nothing stored on the volume, a spent key fails as it always has: the
// sensor stops with the clear message instead of running unregistered.
func TestEnvOnlySensor_SpentKeyWithNothingStoredStops(t *testing.T) {
	logs := captureLog(t)
	p := newSingleUseKeyPlatform(t, true)
	data := t.TempDir()
	podEnv(t, p.srv.URL, data)

	s, exited := startPod(t)
	if len(exited) != 1 || exited[0] != exitNeedsOperator {
		t.Fatalf("exits %v, want [%d]\n%s", exited, exitNeedsOperator, logs)
	}
	if s.isRegisteredNow() {
		t.Fatal("reported registered after a refusal")
	}
	for _, want := range []string{"REJECTED", "already been used", "Refusing to start"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs)
		}
	}
	if _, err := os.Stat(enrolledConfigPath(data)); err == nil {
		t.Fatal("a config was recorded for an enrolment that never happened")
	}
}

// A sensor whose config file is in use (every installer) records its
// enrollment in that file, as before, and creates nothing in the data path.
func TestPersistEnrollment_ConfigFileInUseIsTheOneWritten(t *testing.T) {
	s := testSensor(t)
	s.config.Storage.DataPath = t.TempDir()
	s.config.SensorID = testSensorID
	s.config.Security.ClientCert, s.config.Security.ClientKey = "C", "K"
	installed := s.configPath
	if err := s.persistEnrollment(); err != nil {
		t.Fatal(err)
	}
	if s.configPath != installed {
		t.Fatalf("config path moved from %q to %q", installed, s.configPath)
	}
	if _, err := os.Stat(enrolledConfigPath(s.config.Storage.DataPath)); err == nil {
		t.Fatal("a second config was written beside the installed one")
	}
}
