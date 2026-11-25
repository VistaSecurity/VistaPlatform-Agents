package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/capture"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
)

// A sensor with passive capture off (the sensor in a Kubernetes pod) enrolls
// and starts without opening an interface. The same configuration with capture
// on is TestCannotCaptureDoesNotSpendTheRegistrationKey: there the interface
// that does not exist stops the sensor before it registers.
func TestCaptureOff_EnrollsAndStartsWithoutAnInterface(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "the platform is restarting", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	var exited []int
	orig := exitProcess
	exitProcess = func(code int) { exited = append(exited, code) }
	defer func() { exitProcess = orig }()

	cfg := &config.Config{ControlPlaneURL: server.URL, RegistrationKey: "REG-fresh", SensorID: "s"}
	cfg.Storage.DataPath = t.TempDir()
	cfg.Capture.Interfaces = []string{"vista-no-such-interface-0"}
	cfg.Capture.Disabled = true
	pc := capture.NewPacketCapture(cfg)
	defer pc.Stop()
	s := &Sensor{config: cfg, packetCapture: pc, sensorManager: api.NewSensorManagerClient(cfg)}

	if !s.captureOff() {
		t.Fatal("capture.disabled did not turn capture off")
	}
	if err := s.capturePreflight(); err != nil {
		t.Fatalf("preflight with capture off: %v", err)
	}
	logs := captureLog(t)
	stop := make(chan struct{})
	s.resolveRegistrationAtStartup(false, stop)
	close(stop)
	if calls.Load() == 0 {
		t.Fatal("the sensor did not try to register; with capture off there is no interface to wait for")
	}
	for _, code := range exited {
		if code == exitCannotCapture {
			t.Fatalf("the sensor exited as unable to capture: %v", exited)
		}
	}

	// start opens nothing: the interface does not exist, and it still succeeds.
	if err := s.start(); err != nil {
		t.Fatalf("start with capture off: %v", err)
	}
	if !strings.Contains(logs.String(), "Passive capture is off") {
		t.Errorf("the log does not say capture is off:\n%s", logs.String())
	}
	// And nothing the platform sends can turn it on.
	if err := s.reinitCapture(); err == nil || !strings.Contains(err.Error(), "capture is off") {
		t.Errorf("reinitCapture = %v", err)
	}

	cfg.Capture.Disabled = false
	if s.captureOff() != !capture.Built {
		t.Error("capture is off without the setting in a build that can capture")
	}
}

func TestCaptureDisabled_FromEnvironmentAndFile(t *testing.T) {
	t.Setenv("CAPTURE_DISABLED", "true")
	if !config.Load().Capture.Disabled {
		t.Error("CAPTURE_DISABLED=true did not disable capture")
	}
	t.Setenv("CAPTURE_DISABLED", "")
	if config.Load().Capture.Disabled {
		t.Error("capture is disabled by default")
	}

	path := filepath.Join(t.TempDir(), "sensor-config.yaml")
	if err := os.WriteFile(path, []byte("controlPlaneURL: https://platform.example.test\ncapture:\n  disabled: true\n  interfaces: [eth0]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Capture.Disabled {
		t.Error("capture.disabled in the file was not read")
	}
	t.Setenv("CAPTURE_DISABLED", "false")
	if cfg, _ = config.LoadFromFile(path); cfg.Capture.Disabled {
		t.Error("the environment did not override the file")
	}
}

// With DATA_PATH set (a container), the sensor finds the enrollment it saved
// there on its next start instead of enrolling again with a spent key.
func TestFindDefaultConfigFile_HonoursDataPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(t.TempDir())
	t.Setenv("DATA_PATH", dir)
	if got := findDefaultConfigFile(); got != "" {
		t.Fatalf("found %q in an empty data directory", got)
	}
	path := filepath.Join(dir, "sensor-config.yaml")
	if err := os.WriteFile(path, []byte("sensorId: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := findDefaultConfigFile(); got != path {
		t.Errorf("findDefaultConfigFile() = %q, want %q", got, path)
	}
}
