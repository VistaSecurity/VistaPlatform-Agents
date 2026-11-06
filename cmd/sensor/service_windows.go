//go:build windows

package main

import "github.com/vistasecurity/vistaplatform-agents/shared/agentservice"

// defaultServiceName is install-sensor.ps1's service name. The SCM passes the
// real name to the service; this is only the fallback.
const defaultServiceName = "VistaSensor"

// runAsWindowsService runs the sensor under the Service Control Manager when
// the SCM started this process, and reports whether it did. A console run
// returns false at once and main carries on as before. The SCM state machine
// is shared with the device agent (shared/agentservice).
func runAsWindowsService(flags sensorFlags) bool {
	return agentservice.RunIfService(agentservice.Service{
		Name:  defaultServiceName,
		Label: "Vista Platform sensor",
		Run: func(host agentservice.Host) agentservice.Outcome {
			return runSensor(flags, sensorHost{
				logToFile: true,
				event:     host.Event,
				started:   host.Started,
				stop:      host.Stop,
			})
		},
	})
}
