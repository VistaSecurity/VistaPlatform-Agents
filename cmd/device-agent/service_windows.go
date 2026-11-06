//go:build windows

package main

import "github.com/vistasecurity/vistaplatform-agents/shared/agentservice"

// defaultServiceName is install-device-agent.ps1's service name. The SCM
// passes the real name to the service; this is only the fallback.
const defaultServiceName = "VistaDeviceAgent"

// runAsWindowsService runs the device agent under the Service Control Manager
// when the SCM started this process, and reports whether it did. A console run
// returns false at once and main carries on as before. The SCM state machine
// is the sensor's (shared/agentservice).
func runAsWindowsService(flags agentFlags) bool {
	return agentservice.RunIfService(agentservice.Service{
		Name:  defaultServiceName,
		Label: "Vista Platform device agent",
		Run: func(host agentservice.Host) agentservice.Outcome {
			return runDeviceAgent(flags, serviceHost(host))
		},
	})
}
