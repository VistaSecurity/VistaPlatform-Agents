package main

import "github.com/vistasecurity/vistaplatform-agents/shared/agentservice"

// serviceHost is how the device agent runs under the Windows Service Control
// Manager: no stderr (it is not a usable handle there), a log file under the
// data path, lifecycle messages in the Event Log, Running reported once the
// loops are up, and a console restart that returns to the supervisor (which
// exits non-zero so the SCM's failure action starts the agent again) instead
// of exiting the process, which the SCM would record as a crash.
//
// Kept outside service_windows.go so it is tested on every platform.
func serviceHost(h agentservice.Host) agentHost {
	return agentHost{
		logToFile:        true,
		event:            h.Event,
		started:          h.Started,
		stop:             h.Stop,
		restartInProcess: true,
	}
}
