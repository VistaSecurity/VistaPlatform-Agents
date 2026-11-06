//go:build windows

package agentservice

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// eventID is the single event ID an agent writes to the Event Log.
const eventID = 1

var defaultTimings = Timings{Progress: 5 * time.Second, WaitHint: 30 * time.Second}

// RunIfService runs the agent under the Service Control Manager when the SCM
// started this process, and reports whether it did. A console run returns
// false at once and the caller carries on as before.
//
// Without this a service start never reports SERVICE_RUNNING: Start-Service
// fails with error 1053 and the SCM kills the process.
func RunIfService(s Service) bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}
	// The name is ignored for a service that owns its process.
	if err := svc.Run(s.Name, &handler{s: s}); err != nil {
		if elog, openErr := eventlog.Open(s.Name); openErr == nil {
			_ = elog.Error(eventID, fmt.Sprintf("%s could not run as a service: %v", s.Label, err))
			_ = elog.Close()
		}
		os.Exit(1)
	}
	return true
}

// handler adapts svc.Handler onto Supervise.
type handler struct {
	s Service
}

func (h *handler) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	name := h.s.Name
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		name = args[0]
	}
	elog := openEventLog(name)
	if elog != nil {
		defer func() { _ = elog.Close() }()
	}
	event := func(isError bool, msg string) {
		if elog == nil {
			return
		}
		if isError {
			_ = elog.Error(eventID, msg)
		} else {
			_ = elog.Info(eventID, msg)
		}
	}

	done := make(chan struct{})
	defer close(done)
	cmds := make(chan Command)
	go func() {
		for {
			select {
			case <-done:
				return
			case r := <-requests:
				select {
				case cmds <- toCommand(r.Cmd):
				case <-done:
					return
				}
			}
		}
	}()

	// svc's dispatcher always accepts a status while it waits to deliver a
	// request, so this send cannot deadlock against the request forwarder.
	var last State = -1
	report := func(st Status) {
		changes <- toSvcStatus(st)
		if st.State == last {
			return
		}
		last = st.State
		switch st.State {
		case Running:
			event(false, h.s.Label+" is running.")
		case StopPending:
			event(false, h.s.Label+" is stopping.")
		}
	}

	code := Supervise(func(started func(), stop <-chan string) Outcome {
		return h.s.Run(Host{Event: event, Started: started, Stop: stop})
	}, cmds, report, defaultTimings)

	if code == ExitRestart {
		event(false, h.s.Label+" stopped for a restart requested by the control plane.")
	} else {
		event(false, h.s.Label+" stopped.")
	}
	return code != 0, code
}

func toCommand(c svc.Cmd) Command {
	switch c {
	case svc.Interrogate:
		return CmdInterrogate
	case svc.Stop:
		return CmdStop
	case svc.Shutdown:
		return CmdShutdown
	}
	return CmdOther
}

func toSvcStatus(s Status) svc.Status {
	out := svc.Status{
		CheckPoint: s.CheckPoint,
		WaitHint:   uint32(s.WaitHint.Milliseconds()),
	}
	switch s.State {
	case StartPending:
		out.State = svc.StartPending
	case Running:
		out.State = svc.Running
	case StopPending:
		out.State = svc.StopPending
	}
	if s.AcceptsStop {
		out.Accepts = svc.AcceptStop | svc.AcceptShutdown
	}
	return out
}

// openEventLog opens the Application event log under the service's name,
// registering the source first so messages render without "the description
// for Event ID 1 cannot be found". The service runs as LocalSystem, which may
// write the registration; on a later start it already exists. Returns nil if
// the log cannot be opened; the agent's log file still works.
func openEventLog(name string) *eventlog.Log {
	// Fails harmlessly with "registry key already exists" after the first run.
	_ = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
	elog, err := eventlog.Open(name)
	if err != nil {
		return nil
	}
	return elog
}
