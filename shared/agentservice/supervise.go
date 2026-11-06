// Package agentservice runs an agent (the sensor or the device agent) as a
// Windows service.
//
// Supervise is the state machine, without the Windows types: what the Service
// Control Manager is told, and when. It compiles and is tested on every
// platform; windows.go adapts golang.org/x/sys/windows/svc onto it. The SCM
// rules it encodes:
//
//   - A service must report SERVICE_RUNNING or the SCM's caller gives up on it
//     (Start-Service fails with error 1053) and the SCM kills the process.
//     A pending state stays alive by advancing its checkpoint within the wait
//     hint.
//   - It must accept Stop and Shutdown only once running, answer Interrogate
//     with its current status, and report STOP_PENDING while it cleans up.
//   - SERVICE_STOPPED is reported by the svc package once Execute returns; its
//     exit code decides whether the SCM's failure actions (restart) run.
package agentservice

import (
	"sync"
	"time"
)

// Outcome is why an agent's run ended.
type Outcome int

const (
	// Stopped: a signal or a service stop request; cleanup has run.
	Stopped Outcome = iota
	// RestartRequested: the control plane asked for a restart; cleanup has
	// run and the supervisor is expected to start the agent again.
	RestartRequested
)

// State is the SCM state the supervisor reports.
type State int

const (
	StartPending State = iota
	Running
	StopPending
)

func (s State) String() string {
	switch s {
	case StartPending:
		return "start-pending"
	case Running:
		return "running"
	case StopPending:
		return "stop-pending"
	}
	return "unknown"
}

// Status is one status report to the SCM.
type Status struct {
	State State
	// AcceptsStop: the SCM may send Stop and Shutdown.
	AcceptsStop bool
	// CheckPoint advances while a pending state makes progress.
	CheckPoint uint32
	// WaitHint is how long the SCM should wait for the next report.
	WaitHint time.Duration
}

// Command is a control request from the SCM.
type Command int

const (
	CmdInterrogate Command = iota
	CmdStop
	CmdShutdown
	// CmdOther is any control the service never accepts.
	CmdOther
)

// ExitRestart is the service-specific exit code reported when the
// control plane asked for a restart. A non-zero exit queues the SCM's failure
// actions — which the installers (install-*.ps1) set to "restart" and enable
// for non-crash failures (sc.exe failureflag) — so the SCM relaunches the
// agent, as systemd's Restart=always does on Linux.
const ExitRestart uint32 = 1

// RunFunc runs the agent's lifecycle: it calls started once the agent is up
// and returns after a value arrives on stop (or a restart request).
type RunFunc func(started func(), stop <-chan string) Outcome

// Timings are the supervisor's clocks; tests shorten them.
type Timings struct {
	// Progress is how often a pending state advances its checkpoint.
	Progress time.Duration
	// WaitHint is the wait hint sent with every pending report.
	WaitHint time.Duration
}

// Supervise runs the agent under the SCM's control and returns the
// exit code to report with SERVICE_STOPPED (0, or ExitRestart).
func Supervise(run RunFunc, cmds <-chan Command, report func(Status), timings Timings) uint32 {
	started := make(chan struct{})
	var startOnce sync.Once
	// Buffered: the request is delivered even if it arrives before the agent
	// loop is reading, and the supervisor never blocks on it.
	stop := make(chan string, 1)
	done := make(chan Outcome, 1)

	current := Status{State: StartPending, CheckPoint: 1, WaitHint: timings.WaitHint}
	report(current)

	go func() {
		done <- run(func() { startOnce.Do(func() { close(started) }) }, stop)
	}()

	progress := time.NewTicker(timings.Progress)
	defer progress.Stop()

	stopRequested := false
	for {
		select {
		case <-started:
			started = nil // a closed channel would fire forever
			if current.State == StartPending {
				current = Status{State: Running, AcceptsStop: true}
				report(current)
			}

		case <-progress.C:
			if current.State != Running {
				current.CheckPoint++
				report(current)
			}

		case cmd := <-cmds:
			switch cmd {
			case CmdInterrogate:
				report(current)
			case CmdStop, CmdShutdown:
				if stopRequested {
					continue
				}
				stopRequested = true
				current = Status{State: StopPending, CheckPoint: 1, WaitHint: timings.WaitHint}
				report(current)
				reason := "Service stop requested"
				if cmd == CmdShutdown {
					reason = "System shutdown"
				}
				stop <- reason
			}

		case outcome := <-done:
			// An operator's stop wins over a restart that raced it: a stopped
			// service must stay stopped.
			if outcome == RestartRequested && !stopRequested {
				return ExitRestart
			}
			return 0
		}
	}
}
