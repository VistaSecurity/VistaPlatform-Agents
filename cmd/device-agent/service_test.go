package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/protocoltest"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform-agents/shared/agentservice"
)

// The device agent under the Windows Service Control Manager runs through
// runAgent with serviceHost: these drive that real path (minus the SCM, whose
// state machine shared/agentservice tests) on every platform.

// stubPlatform answers every call; heartbeats carry restartAge as the age of
// a console restart request (0: none).
func stubPlatform(t *testing.T, restartAge time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(protocoltest.Speak1(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"config": agentconfig.ExchangePayload{
					Revision:                 "r1",
					RestartRequestAgeSeconds: int64(restartAge / time.Second),
				},
			})
		case strings.HasSuffix(r.URL.Path, "/jobs"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	})))
	t.Cleanup(srv.Close)
	return srv
}

func serviceTestConfig(url string, t *testing.T) *config.Config {
	return &config.Config{
		PlatformURL:       url,
		AgentID:           uuid.New().String(),
		DataPath:          t.TempDir(),
		PollInterval:      time.Hour,
		HeartbeatInterval: 100 * time.Millisecond,
	}
}

// A service stop reaches the agent: runAgent reports Running first (started),
// stops cleanly and returns Stopped, which the supervisor turns into exit 0.
func TestServiceHost_StopRequestStopsTheAgent(t *testing.T) {
	cfg := serviceTestConfig(stubPlatform(t, 0).URL, t)
	stop := make(chan string, 1)
	started := make(chan struct{})
	host := serviceHost(agentservice.Host{Started: func() { close(started) }, Stop: stop})

	done := make(chan agentservice.Outcome, 1)
	go func() { done <- runAgent(cfg, "", nil, host) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("runAgent never reported the agent started; the SCM would kill it (error 1053)")
	}
	stop <- "Service stop requested"
	select {
	case got := <-done:
		if got != agentservice.Stopped {
			t.Fatalf("outcome = %v, want Stopped", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a service stop request did not stop the agent")
	}
}

// A restart requested from the console must come back to the supervisor as
// RestartRequested (exit 1, so the SCM's failure action starts the agent
// again) instead of the console path's os.Exit(0), which under the SCM is a
// crash with no SERVICE_STOPPED.
//
// Mutation: drop restartInProcess from serviceHost and this test ends the
// test binary through exitForRestart.
func TestServiceHost_ConsoleRestartReturnsToTheSupervisor(t *testing.T) {
	// The request is 1 s old: the agent restarts once its own uptime passes
	// that, a little over a second after it starts.
	cfg := serviceTestConfig(stubPlatform(t, time.Second).URL, t)
	stop := make(chan string)
	host := serviceHost(agentservice.Host{Stop: stop})

	done := make(chan agentservice.Outcome, 1)
	go func() { done <- runAgent(cfg, "", nil, host) }()
	select {
	case got := <-done:
		if got != agentservice.RestartRequested {
			t.Fatalf("outcome = %v, want RestartRequested", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the console's restart request never ended the run")
	}
}

// A service has no stderr: the log goes to <data_path>/logs/device-agent.log,
// the file install-device-agent.ps1 reads and points operators at.
func TestServiceHost_LogsToTheFileTheInstallerReads(t *testing.T) {
	h := serviceHost(agentservice.Host{})
	if h.logToStderr || !h.logToFile || !h.restartInProcess {
		t.Fatalf("serviceHost = %+v, want a log file, no stderr and in-process restarts", h)
	}

	ps1, err := os.ReadFile("../../scripts/install-device-agent.ps1")
	if err != nil {
		t.Fatal(err)
	}
	if want := `Join-Path $DataDir "logs\` + deviceAgentLogFileName + `"`; !strings.Contains(string(ps1), want) {
		t.Fatalf("install-device-agent.ps1 does not read the agent's log (%s)", want)
	}

	savedOut := log.Writer()
	t.Cleanup(func() { log.SetOutput(savedOut) })
	dataPath := t.TempDir()
	path, err := teeLogToFile(dataPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dataPath, "logs", deviceAgentLogFileName); path != want {
		t.Fatalf("log path = %q, want %q", path, want)
	}
}
