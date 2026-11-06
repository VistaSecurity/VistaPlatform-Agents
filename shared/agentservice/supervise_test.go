package agentservice

import (
	"testing"
	"time"
)

// fakeSensor stands in for runSensor under Supervise.
type fakeSensor struct {
	started    chan func()  // the run's started callback, once it is running
	stopReason chan string  // what arrived on the stop channel
	finish     chan Outcome // tells the run to return
}

func newFakeSensor() *fakeSensor {
	return &fakeSensor{
		started:    make(chan func(), 1),
		stopReason: make(chan string, 1),
		finish:     make(chan Outcome, 1),
	}
}

// run behaves like runSensor: it returns on a stop request (with
// Stopped) or when the test injects an outcome (a restart request).
func (f *fakeSensor) run(started func(), stop <-chan string) Outcome {
	f.started <- started
	select {
	case reason := <-stop:
		f.stopReason <- reason
		return Stopped
	case outcome := <-f.finish:
		return outcome
	}
}

type serviceHarness struct {
	t        *testing.T
	sensor   *fakeSensor
	cmds     chan Command
	statuses chan Status
	exit     chan uint32
}

// startService runs Supervise with a progress tick long enough that it
// never fires unless a test asks for it.
func startService(t *testing.T, timings Timings) *serviceHarness {
	t.Helper()
	h := &serviceHarness{
		t:        t,
		sensor:   newFakeSensor(),
		cmds:     make(chan Command),
		statuses: make(chan Status, 64),
		exit:     make(chan uint32, 1),
	}
	go func() {
		h.exit <- Supervise(h.sensor.run, h.cmds, func(s Status) { h.statuses <- s }, timings)
	}()
	return h
}

var quietTimings = Timings{Progress: time.Hour, WaitHint: 30 * time.Second}

func (h *serviceHarness) nextStatus() Status {
	h.t.Helper()
	select {
	case s := <-h.statuses:
		return s
	case <-time.After(5 * time.Second):
		h.t.Fatal("no status reported")
	}
	return Status{}
}

func (h *serviceHarness) noStatus() {
	h.t.Helper()
	select {
	case s := <-h.statuses:
		h.t.Fatalf("unexpected status report: %+v", s)
	case <-time.After(50 * time.Millisecond):
	}
}

func (h *serviceHarness) send(c Command) {
	h.t.Helper()
	select {
	case h.cmds <- c:
	case <-time.After(5 * time.Second):
		h.t.Fatal("supervisor is not reading commands")
	}
}

func (h *serviceHarness) exitCode() uint32 {
	h.t.Helper()
	return waitExit(h.t, h.exit)
}

func waitExit(t *testing.T, exit <-chan uint32) uint32 {
	t.Helper()
	select {
	case code := <-exit:
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not return")
	}
	return 0
}

// markStarted waits for the sensor run to begin and reports it started.
func (h *serviceHarness) markStarted() {
	h.t.Helper()
	select {
	case started := <-h.sensor.started:
		started()
	case <-time.After(5 * time.Second):
		h.t.Fatal("sensor run never began")
	}
}

func TestSuperviseService_ReportsRunningOnlyOnceTheSensorHasStarted(t *testing.T) {
	h := startService(t, quietTimings)

	first := h.nextStatus()
	if first.State != StartPending || first.AcceptsStop || first.WaitHint <= 0 {
		t.Fatalf("first report = %+v, want start-pending with a wait hint and no stop accepted", first)
	}
	// The run has begun but not said it is up: Running would be a lie.
	h.noStatus()

	h.markStarted()
	running := h.nextStatus()
	if running.State != Running || !running.AcceptsStop {
		t.Fatalf("after started: %+v, want running and accepting stop", running)
	}

	h.send(CmdStop)
	if s := h.nextStatus(); s.State != StopPending || s.AcceptsStop {
		t.Fatalf("after stop: %+v, want stop-pending, no longer accepting stop", s)
	}
	if code := h.exitCode(); code != 0 {
		t.Fatalf("exit code after an operator stop = %d, want 0", code)
	}
}

func TestSuperviseService_StopAndShutdownReachTheSensorLoop(t *testing.T) {
	for _, tc := range []struct {
		cmd    Command
		reason string
	}{
		{CmdStop, "Service stop requested"},
		{CmdShutdown, "System shutdown"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			h := startService(t, quietTimings)
			h.nextStatus()
			h.markStarted()
			h.nextStatus()

			h.send(tc.cmd)
			select {
			case got := <-h.sensor.stopReason:
				if got != tc.reason {
					t.Fatalf("stop reason = %q, want %q", got, tc.reason)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the sensor loop never received the stop request")
			}
			// Supervision does not end until the sensor has cleaned up and
			// returned: SERVICE_STOPPED follows Execute's return.
			if code := h.exitCode(); code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
		})
	}
}

func TestSuperviseService_InterrogateEchoesTheCurrentStatus(t *testing.T) {
	h := startService(t, quietTimings)
	h.nextStatus()

	h.send(CmdInterrogate)
	if s := h.nextStatus(); s.State != StartPending {
		t.Fatalf("interrogate while starting = %+v, want start-pending", s)
	}

	h.markStarted()
	h.nextStatus()
	h.send(CmdInterrogate)
	if s := h.nextStatus(); s.State != Running || !s.AcceptsStop {
		t.Fatalf("interrogate while running = %+v, want running", s)
	}

	h.send(CmdOther) // never accepted, so ignored
	h.noStatus()

	h.send(CmdStop)
	h.nextStatus()
	h.exitCode()
}

func TestSuperviseService_PendingStatesAdvanceTheirCheckpoint(t *testing.T) {
	h := startService(t, Timings{Progress: 5 * time.Millisecond, WaitHint: time.Second})

	first := h.nextStatus()
	second := h.nextStatus()
	if second.State != StartPending || second.CheckPoint <= first.CheckPoint {
		t.Fatalf("start-pending progress: %+v then %+v, want an advancing checkpoint", first, second)
	}

	h.markStarted()
	// Drain the start-pending ticks that raced the start.
	var s Status
	for s = h.nextStatus(); s.State == StartPending; s = h.nextStatus() {
	}
	if s.State != Running {
		t.Fatalf("got %+v, want running", s)
	}
	// Running does not tick.
	h.noStatus()

	h.send(CmdStop)
	h.exitCode()
}

func TestSuperviseService_StopPendingTicksWhileTheSensorCleansUp(t *testing.T) {
	// A sensor whose cleanup takes a while (it submits its last discoveries).
	cleanupDone := make(chan struct{})
	run := func(started func(), stop <-chan string) Outcome {
		started()
		<-stop
		<-cleanupDone
		return Stopped
	}
	statuses := make(chan Status, 64)
	cmds := make(chan Command)
	exit := make(chan uint32, 1)
	go func() {
		exit <- Supervise(run, cmds, func(s Status) { statuses <- s },
			Timings{Progress: 5 * time.Millisecond, WaitHint: time.Second})
	}()

	waitFor := func(want State) Status {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case s := <-statuses:
				if s.State == want {
					return s
				}
			case <-deadline:
				t.Fatalf("never reported %v", want)
			}
		}
	}
	waitFor(Running)
	cmds <- CmdStop
	first := waitFor(StopPending)
	next := waitFor(StopPending)
	if next.CheckPoint <= first.CheckPoint {
		t.Fatalf("stop-pending checkpoint did not advance: %d then %d", first.CheckPoint, next.CheckPoint)
	}
	close(cleanupDone)
	if code := waitExit(t, exit); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestSuperviseService_RepeatedStopIsIgnored(t *testing.T) {
	cleanupDone := make(chan struct{})
	stopsSeen := make(chan string, 4)
	run := func(started func(), stop <-chan string) Outcome {
		started()
		stopsSeen <- <-stop
		<-cleanupDone
		return Stopped
	}
	statuses := make(chan Status, 64)
	cmds := make(chan Command)
	exit := make(chan uint32, 1)
	go func() {
		exit <- Supervise(run, cmds, func(s Status) { statuses <- s }, quietTimings)
	}()

	cmds <- CmdStop
	// A system shutdown arriving during cleanup must neither block the
	// supervisor nor restart stop-pending's checkpoint.
	cmds <- CmdShutdown
	cmds <- CmdStop
	close(cleanupDone)
	if code := waitExit(t, exit); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	close(statuses)
	stopPending := 0
	for s := range statuses {
		if s.State == StopPending {
			stopPending++
		}
	}
	if stopPending != 1 {
		t.Fatalf("stop-pending reported %d times, want 1", stopPending)
	}
	if len(stopsSeen) != 1 {
		t.Fatalf("sensor saw %d stop requests, want 1", len(stopsSeen))
	}
}

// A restart command from the control plane ends the sensor loop by itself.
// The service must stop with a failure exit code so the SCM's restart action
// brings it back — exit 0 would leave it stopped for good.
func TestSuperviseService_ControlPlaneRestartExitsNonZero(t *testing.T) {
	h := startService(t, quietTimings)
	h.nextStatus()
	h.markStarted()
	h.nextStatus()

	h.sensor.finish <- RestartRequested
	if code := h.exitCode(); code != ExitRestart || code == 0 {
		t.Fatalf("exit code after a restart request = %d, want %d", code, ExitRestart)
	}
}

// An operator who stops the service gets a stopped service, even if a
// control-plane restart raced the stop.
func TestSuperviseService_OperatorStopBeatsARacingRestart(t *testing.T) {
	stopped := make(chan struct{})
	run := func(started func(), stop <-chan string) Outcome {
		started()
		<-stop
		close(stopped)
		return RestartRequested
	}
	cmds := make(chan Command)
	exit := make(chan uint32, 1)
	go func() {
		exit <- Supervise(run, cmds, func(Status) {}, quietTimings)
	}()
	cmds <- CmdStop
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the sensor loop never received the stop request")
	}
	if code := waitExit(t, exit); code != 0 {
		t.Fatalf("exit code = %d, want 0: the SCM would restart a service the operator stopped", code)
	}
}
