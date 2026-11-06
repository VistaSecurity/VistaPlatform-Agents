package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/api"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/capture"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
)

// A sensor that cannot capture used to register first and then exit with
// "no interfaces available for capture", spending the single-use key on a
// sensor that would never heartbeat. The startup decision now checks capture
// first: with an interface that does not exist, the platform must see no
// registration at all, and the sensor exits with exitCannotCapture.
//
// This drives the real startup decision with a real PacketCapture, so
// removing the preflight from resolveRegistrationAtStartup turns it red.
func TestCannotCaptureDoesNotSpendTheRegistrationKey(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()

	var exited []int
	orig := exitProcess
	exitProcess = func(code int) { exited = append(exited, code) }
	defer func() { exitProcess = orig }()

	cfg := &config.Config{ControlPlaneURL: server.URL, RegistrationKey: "REG-fresh", SensorID: "s"}
	cfg.Storage.DataPath = t.TempDir()
	cfg.Capture.Interfaces = []string{"vista-no-such-interface-0"}
	pc := capture.NewPacketCapture(cfg)
	defer pc.Stop()
	s := &Sensor{config: cfg, packetCapture: pc, sensorManager: api.NewSensorManagerClient(cfg)}

	stop := make(chan struct{})
	defer close(stop)
	s.resolveRegistrationAtStartup(false, stop)

	if n := calls.Load(); n != 0 {
		t.Fatalf("the platform saw %d request(s); a sensor that cannot capture must not register", n)
	}
	if len(exited) != 1 || exited[0] != exitCannotCapture {
		t.Fatalf("exit calls = %v, want exactly [%d]", exited, exitCannotCapture)
	}
}
