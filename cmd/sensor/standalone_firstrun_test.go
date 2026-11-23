package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/agentoutput"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch"
)

// `crypto-sensor --help` must name every standalone command, or a person who
// downloads the sensor to use it on its own never learns they exist.
func TestTopLevelHelpNamesEveryStandaloneCommand(t *testing.T) {
	for _, cmd := range []string{"capture", "scan"} {
		if !standaloneCommand([]string{cmd}) {
			t.Fatalf("%s is not dispatched as a standalone command", cmd)
		}
		if !strings.Contains(standaloneUsageHint, "\n  "+cmd+" ") {
			t.Errorf("the top-level help does not list %q:\n%s", cmd, standaloneUsageHint)
		}
	}
}

// A long scan says how far it has got, at most once per interval, never
// after the last address and never with --quiet.
func TestScanProgressIsThrottledAndQuietable(t *testing.T) {
	w, err := agentoutput.Open(agentoutput.Options{Agent: standaloneAgent, AgentVersion: "test", Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Quiet: true},
		agentoutput.Run{Command: "scan"})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	var progress bytes.Buffer
	r := &scanReporter{w: w, names: map[string]string{}, progress: &progress, total: 4, now: func() time.Time { return clock }}
	r.lastShown = clock
	unit := []sensordispatch.UnitResult{{Address: "192.0.2.1"}}

	_ = r.Report(context.Background(), unit) // 1 of 4, no time has passed
	if progress.Len() != 0 {
		t.Fatalf("progress before the interval: %q", progress.String())
	}
	clock = clock.Add(scanProgressEvery)
	_ = r.Report(context.Background(), unit) // 2 of 4
	if got := progress.String(); got != "crypto-sensor scan: 2 of 4 addresses done\n" {
		t.Fatalf("progress = %q", got)
	}
	clock = clock.Add(time.Second)
	_ = r.Report(context.Background(), unit) // 3 of 4, too soon
	clock = clock.Add(scanProgressEvery)
	_ = r.Report(context.Background(), unit) // 4 of 4: the summary says the rest
	if n := strings.Count(progress.String(), "\n"); n != 1 {
		t.Errorf("progress lines = %d; want 1:\n%s", n, progress.String())
	}

	r2 := &scanReporter{w: w, names: map[string]string{}, total: 2, now: func() time.Time { return clock.Add(time.Hour) }}
	_ = r2.Report(context.Background(), unit) // --quiet: no writer, nothing printed, no panic
	_, _ = w.Close(false, "")
}
