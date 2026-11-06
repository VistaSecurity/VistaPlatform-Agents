package agentservice

// Service describes one agent to RunIfService.
type Service struct {
	// Name is the service name the installer registers (VistaSensor,
	// VistaDeviceAgent). The SCM passes the real one to Execute; this is the
	// fallback and the Event Log source when Execute is never reached.
	Name string
	// Label begins every Event Log message ("Vista Platform sensor").
	Label string
	// Run runs the agent until host.Stop delivers a value or the agent asks
	// for a restart, calling host.Started once it is up.
	Run func(host Host) Outcome
}

// Host is what the agent gets from the Service Control Manager.
type Host struct {
	// Event writes a lifecycle message to the Windows Event Log.
	Event func(isError bool, msg string)
	// Started tells the SCM the agent is up (SERVICE_RUNNING).
	Started func()
	// Stop delivers a stop or shutdown request; the value says who asked.
	Stop <-chan string
}
