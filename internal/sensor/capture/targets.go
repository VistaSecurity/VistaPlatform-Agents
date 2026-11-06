package capture

import (
	"fmt"
	"log"
	"runtime"
	"strings"

	"github.com/gopacket/gopacket/pcap"
	"github.com/vistasecurity/vistaplatform-agents/internal/sensor/capture/ifselect"
)

// The system calls behind resolveTargets and Preflight, replaceable in tests.
var (
	listCaptureDevices = ListDevices
	listHostAdapters   = hostAdapters
	// probeDevice opens a capture device and closes it again.
	probeDevice = func(device string) error {
		h, err := pcap.OpenLive(device, 128, true, pcap.BlockForever)
		if err != nil {
			return err
		}
		h.Close()
		return nil
	}
	// autoSelectWhenUnconfigured: with no interface configured, pick the
	// adapters that are up and have an address. Windows only: there the
	// installer leaves the list empty and the sensor is the only thing that
	// can see Npcap's device names. The Linux installer writes the interfaces
	// it detected, and Linux and macOS keep the behaviour they had.
	autoSelectWhenUnconfigured = runtime.GOOS == "windows"
	targetsGOOS                = runtime.GOOS
)

// resolveTargets decides which capture devices Start opens: the configured
// names resolved to devices (a name that does not resolve is logged, marked
// failed and skipped, as an interface that fails to open always was), or, on
// Windows with nothing configured, the usable adapters. The configured names
// that do not resolve come back too, for Start to log and report. It fails
// only when nothing is left to open, with an error that says why.
func (pc *PacketCapture) resolveTargets() ([]ifselect.Resolution, []ifselect.Unresolved, error) {
	devs, err := listCaptureDevices()
	if err != nil {
		return nil, nil, captureLibraryError(err)
	}
	if len(devs) == 0 {
		return nil, nil, noDevicesError()
	}
	adapters, err := listHostAdapters()
	if err != nil {
		// Device names and descriptions still resolve; adapter (friendly)
		// names do not.
		log.Printf("Could not list the network adapters (%v); interfaces can be named only by capture device name or description", err)
		adapters = nil
	}

	if len(pc.interfaces) == 0 {
		if !autoSelectWhenUnconfigured {
			return nil, nil, fmt.Errorf("no interfaces available for capture: none is configured (capture.interfaces is empty). Capture devices: %v",
				ifselect.Labels(devs, adapters))
		}
		picked := ifselect.AutoSelect(devs, adapters)
		if len(picked) == 0 {
			return nil, nil, fmt.Errorf("no interfaces available for capture: none is configured, and no capture device belongs to an adapter that is up with an address (loopback, tunnel and WAN Miniport devices are never picked). Name one in capture.interfaces. Capture devices: %v",
				ifselect.Labels(devs, adapters))
		}
		names := make([]string, 0, len(picked))
		for _, p := range picked {
			names = append(names, p.Configured)
		}
		log.Printf("No interfaces configured: capturing on the adapters that are up with an address: %v", names)
		return picked, nil, nil
	}

	resolved, failed := ifselect.ResolveAll(pc.interfaces, devs, adapters)
	if len(resolved) == 0 {
		msgs := make([]string, 0, len(failed))
		for _, f := range failed {
			msgs = append(msgs, f.Err.Error())
		}
		return nil, failed, fmt.Errorf("no interfaces available for capture: %s", strings.Join(msgs, "; "))
	}
	return resolved, failed, nil
}

// Preflight checks, without starting capture, that Start would capture on at
// least one interface: the configured names resolve (or, unconfigured on
// Windows, an adapter is picked) and the device opens. The sensor runs it
// before it spends a single-use registration key, so a sensor that cannot
// capture stops with the key unused.
func (pc *PacketCapture) Preflight() error {
	targets, _, err := pc.resolveTargets()
	if err != nil {
		return err
	}
	var openErrs []string
	for _, t := range targets {
		if err := probeDevice(t.Device); err != nil {
			openErrs = append(openErrs, fmt.Sprintf("failed to open interface %s (%s): %v", t.Configured, t.Device, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("no interfaces available for capture: no capture device could be opened: %s%s",
		strings.Join(openErrs, "; "), openPermissionHint())
}

// captureLibraryError explains a failure to list the capture devices.
func captureLibraryError(err error) error {
	if strings.Contains(err.Error(), "wpcap.dll") {
		return fmt.Errorf("failed to find network interfaces: %v: the packet capture library is not installed. "+
			"Install Npcap from https://npcap.com/ with 'WinPcap API-compatible Mode' enabled, then start the sensor again", err)
	}
	return fmt.Errorf("failed to find network interfaces: %v", err)
}

// noDevicesError explains a capture library that loads and lists no device.
func noDevicesError() error {
	if targetsGOOS == "windows" {
		return fmt.Errorf("no interfaces available for capture: Npcap is installed (its library loaded) but lists no capture device. " +
			"Check that the Npcap driver is running (sc.exe query npcap). If Npcap was installed with " +
			"'Restrict Npcap driver's access to Administrators only', the sensor must run as an administrator or as LocalSystem, as the service does")
	}
	return fmt.Errorf("no interfaces available for capture: libpcap lists no capture device; " +
		"the sensor needs root, or CAP_NET_RAW and CAP_NET_ADMIN, to see them")
}

// openPermissionHint says what usually stops a listed device from opening.
func openPermissionHint() string {
	if targetsGOOS == "windows" {
		return " (if Npcap restricts its driver to administrators, run the sensor as an administrator or as LocalSystem, as the service does)"
	}
	return " (capture needs root, or CAP_NET_RAW and CAP_NET_ADMIN)"
}
