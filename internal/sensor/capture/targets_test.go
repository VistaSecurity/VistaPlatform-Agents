package capture

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/capture/ifselect"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/config"
)

// fakeHost replaces the system calls behind resolveTargets and Preflight with
// a Windows host as Npcap and GetAdaptersAddresses describe it.
func fakeHost(t *testing.T, devs []Device, adapters []ifselect.Adapter, windows bool, probe func(string) error) *[]string {
	t.Helper()
	oldDevs, oldAdapters, oldProbe, oldAuto, oldOS := listCaptureDevices, listHostAdapters, probeDevice, autoSelectWhenUnconfigured, targetsGOOS
	t.Cleanup(func() {
		listCaptureDevices, listHostAdapters, probeDevice, autoSelectWhenUnconfigured, targetsGOOS = oldDevs, oldAdapters, oldProbe, oldAuto, oldOS
	})
	listCaptureDevices = func() ([]Device, error) { return devs, nil }
	listHostAdapters = func() ([]ifselect.Adapter, error) { return adapters, nil }
	autoSelectWhenUnconfigured = windows
	targetsGOOS = "linux"
	if windows {
		targetsGOOS = "windows"
	}
	var probed []string
	probeDevice = func(d string) error {
		probed = append(probed, d)
		if probe != nil {
			return probe(d)
		}
		return nil
	}
	return &probed
}

const ethDev = `\Device\NPF_{6B29FC40-CA47-1067-B31D-00DD010662DA}`

var (
	fakeWinDevices = []Device{
		{Name: `\Device\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}`, Description: "WAN Miniport (Network Monitor)"},
		{Name: ethDev, Description: "Intel(R) Ethernet Connection (7) I219-V", Addresses: []net.IP{net.ParseIP("10.0.0.10")}},
		{Name: `\Device\NPF_Loopback`, Description: "Adapter for loopback traffic capture", Loopback: true, Up: true},
	}
	fakeWinAdapters = []ifselect.Adapter{
		{GUID: "{6B29FC40-CA47-1067-B31D-00DD010662DA}", FriendlyName: "Ethernet 2", Description: "Intel(R) Ethernet Connection (7) I219-V", Up: true, Addresses: []net.IP{net.ParseIP("10.0.0.10")}},
		{GUID: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", FriendlyName: "Local Area Connection* 1", Description: "WAN Miniport (Network Monitor)", Up: true},
	}
)

// The installer's default: `interfaces: []`. On Windows the sensor picks the
// adapter that is up with an address instead of failing.
func TestPreflight_UnconfiguredOnWindowsPicksTheUsableAdapter(t *testing.T) {
	probed := fakeHost(t, fakeWinDevices, fakeWinAdapters, true, nil)
	pc := NewPacketCapture(&config.Config{SensorID: "s"})
	defer pc.cancel()
	if err := pc.Preflight(); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if len(*probed) != 1 || (*probed)[0] != ethDev {
		t.Fatalf("probed %v, want only %s", *probed, ethDev)
	}
}

// Outside Windows an empty list still fails, and says so.
func TestPreflight_UnconfiguredElsewhereFails(t *testing.T) {
	fakeHost(t, []Device{{Name: "eth0", Up: true, Addresses: []net.IP{net.ParseIP("10.0.0.5")}}}, nil, false, nil)
	pc := NewPacketCapture(&config.Config{SensorID: "s"})
	defer pc.cancel()
	err := pc.Preflight()
	if err == nil || !strings.Contains(err.Error(), "none is configured") || !strings.Contains(err.Error(), "eth0") {
		t.Fatalf("Preflight = %v, want an error saying none is configured and listing eth0", err)
	}
}

// The name the sensor reports (`Ethernet 2`) is a name it captures on.
func TestPreflight_FriendlyNameResolves(t *testing.T) {
	probed := fakeHost(t, fakeWinDevices, fakeWinAdapters, true, nil)
	cfg := &config.Config{SensorID: "s"}
	cfg.Capture.Interfaces = []string{"Ethernet 2"}
	pc := NewPacketCapture(cfg)
	defer pc.cancel()
	if err := pc.Preflight(); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if len(*probed) != 1 || (*probed)[0] != ethDev {
		t.Fatalf("probed %v, want %s", *probed, ethDev)
	}
}

// With Npcap present and the device listed, the failure names what happened,
// not a missing library or a missing Administrator.
func TestPreflight_ErrorsSayWhatHappened(t *testing.T) {
	t.Run("unknown name", func(t *testing.T) {
		fakeHost(t, fakeWinDevices, fakeWinAdapters, true, nil)
		cfg := &config.Config{SensorID: "s"}
		cfg.Capture.Interfaces = []string{"Ethernet 9"}
		pc := NewPacketCapture(cfg)
		defer pc.cancel()
		err := pc.Preflight()
		if err == nil {
			t.Fatal("Preflight succeeded for an unknown name")
		}
		for _, want := range []string{`"Ethernet 9"`, "matches no capture device", `"Ethernet 2"`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
		}
		for _, wrong := range []string{"not installed", "Administrator"} {
			if strings.Contains(err.Error(), wrong) {
				t.Errorf("error %q blames %q", err, wrong)
			}
		}
	})
	t.Run("device does not open", func(t *testing.T) {
		fakeHost(t, fakeWinDevices, fakeWinAdapters, true, func(string) error { return errors.New("Error opening adapter: Access is denied.") })
		pc := NewPacketCapture(&config.Config{SensorID: "s"})
		defer pc.cancel()
		err := pc.Preflight()
		if err == nil || !strings.Contains(err.Error(), "Access is denied") || !strings.Contains(err.Error(), "Ethernet 2") {
			t.Fatalf("Preflight = %v, want the open error for Ethernet 2", err)
		}
		if strings.Contains(err.Error(), "not installed") {
			t.Errorf("error %q blames a missing library", err)
		}
	})
	t.Run("no devices", func(t *testing.T) {
		fakeHost(t, nil, fakeWinAdapters, true, nil)
		pc := NewPacketCapture(&config.Config{SensorID: "s"})
		defer pc.cancel()
		err := pc.Preflight()
		if err == nil || !strings.Contains(err.Error(), "Npcap is installed") || !strings.Contains(err.Error(), "sc.exe query npcap") {
			t.Fatalf("Preflight = %v, want the no-device explanation", err)
		}
	})
	t.Run("library missing", func(t *testing.T) {
		fakeHost(t, nil, nil, true, nil)
		listCaptureDevices = func() ([]Device, error) { return nil, errors.New("couldn't load wpcap.dll") }
		pc := NewPacketCapture(&config.Config{SensorID: "s"})
		defer pc.cancel()
		err := pc.Preflight()
		if err == nil || !strings.Contains(err.Error(), "not installed") || !strings.Contains(err.Error(), "npcap.com") {
			t.Fatalf("Preflight = %v, want the missing-library explanation", err)
		}
	})
}

// Start goes through the same resolution: a configured name that does not
// resolve is reported as failed, and no device is opened for it.
func TestStart_UnresolvedNamesAreReportedFailed(t *testing.T) {
	fakeHost(t, fakeWinDevices, fakeWinAdapters, true, nil)
	cfg := &config.Config{SensorID: "s"}
	cfg.Capture.Interfaces = []string{"Ethernet 9"}
	pc := NewPacketCapture(cfg)
	defer pc.cancel()
	if err := pc.Start(); err == nil || !strings.Contains(err.Error(), "matches no capture device") {
		t.Fatalf("Start = %v, want the resolution error", err)
	}
	if got := pc.FailedInterfaces(); len(got) != 1 || got[0] != "Ethernet 9" {
		t.Fatalf("FailedInterfaces = %v, want [Ethernet 9]", got)
	}
}
