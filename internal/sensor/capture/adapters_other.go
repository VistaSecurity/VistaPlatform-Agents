//go:build !windows

package capture

import "github.com/vistasecurity/vistaplatform-agents/internal/sensor/capture/ifselect"

// hostAdapters has nothing to add outside Windows: libpcap's device names are
// the interface names there, so the devices alone are enough.
func hostAdapters() ([]ifselect.Adapter, error) { return nil, nil }
