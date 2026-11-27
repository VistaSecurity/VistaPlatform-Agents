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
	// A setting only the environment carries (config.Load reads it, the file
	// merge does not): it must survive the restart too.
	t.Setenv("ACTIVE_PROBING", "false")
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

func TestEnvOnlySensor_RestartedPodKeepsItsIdentity(t *testing.T) {
	logs := captureLog(t)
	p := newSingleUseKeyPlatform(t, false)
	data := t.TempDir()
	podEnv(t, p.srv.URL, data)

	// First pod: no config file anywhere, so it enrols.
	first, exited := startPod(t)
	if first.configPath != enrolledConfigPath(data) {
		t.Errorf("after enrolment the sensor uses config %q, want %q", first.configPath, enrolledConfigPath(data))
	}
	if len(exited) != 0 || !first.isRegisteredNow() || p.registrations.Load() != 1 {
		t.Fatalf("first start: exits %v, registered %v, registrations %d; want none, true, 1\n%s", exited, first.isRegisteredNow(), p.registrations.Load(), logs)
	}
	raw, err := os.ReadFile(enrolledConfigPath(data))
	if err != nil {
		t.Errorf("the enrolment was not recorded on the volume: %v", err)
	}
	if strings.Contains(string(raw), testSensorRegKey) || strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatalf("the recorded config holds a secret or key material:\n%s", raw)
	}
	if runtime.GOOS != "windows" && raw != nil {
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
	if strings.Contains(logs.String(), testSensorRegKey) {
		t.Fatalf("the registration key reached the log:\n%s", logs)
	}

	// Second pod: same volume, same environment, the spent key still in it.
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
	if !c2.Capture.Disabled || c2.Capture.ActiveProbing != c1.Capture.ActiveProbing || c2.ReportingInterval != c1.ReportingInterval {
		t.Fatalf("restarted pod runs differently: disabled %v activeProbing %v→%v interval %v→%v",
			c2.Capture.Disabled, c1.Capture.ActiveProbing, c2.Capture.ActiveProbing, c1.ReportingInterval, c2.ReportingInterval)
	}

	// The recorded file is an ordinary sensor config: the platform's setting
	// updates can edit it.
	if err := second.persistCaptureSetting("hostObservation", false); err != nil {
		t.Fatalf("the recorded config cannot take a setting update: %v", err)
	}
	if err := second.persistMonitoredInterfaces([]string{"eth1"}); err != nil {
		t.Fatalf("the recorded config cannot take an interface update: %v", err)
	}
	if _, err := loadConfig(enrolledConfigPath(data)); err != nil {
		t.Fatalf("the config no longer loads after the updates: %v", err)
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
