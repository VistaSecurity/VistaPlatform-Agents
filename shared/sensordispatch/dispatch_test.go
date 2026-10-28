package sensordispatch

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const jobID = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42"

// Managed protocol 1 has one job shape, the scan plan (D-P5). The older
// protocols × ports payload is refused as ErrLegacyPayload, never parsed and
// never run, whether or not a plan rides beside it.
func TestParsePayload_RefusesTheLegacyShape(t *testing.T) {
	for _, key := range []string{"targets", "protocols", "ports"} {
		for _, withPlan := range []bool{false, true} {
			m := map[string]interface{}{"job_id": jobID, key: []interface{}{"192.0.2.10"}}
			if withPlan {
				m["plan"] = map[string]interface{}{}
			}
			_, err := ParsePayload(m)
			if !errors.Is(err, ErrLegacyPayload) {
				t.Fatalf("ParsePayload(%v) = %v, want ErrLegacyPayload", m, err)
			}
			if errors.Is(err, ErrMalformedPayload) {
				t.Fatalf("the legacy shape is refused as unsupported, not as malformed: %v", err)
			}
		}
	}
}

// Every other refusal must be ErrMalformedPayload: the sensor answers those
// with a FAILED acknowledgement the platform records, never with silence.
func TestParsePayload_RejectsWhatCannotBeRun(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]interface{}
	}{
		{"nil", nil},
		{"no job id", map[string]interface{}{"plan": map[string]interface{}{}}},
		{"job id not a uuid", map[string]interface{}{"job_id": "job-1", "plan": map[string]interface{}{}}},
		{"no plan", map[string]interface{}{"job_id": jobID}},
		{"plan is null", map[string]interface{}{"job_id": jobID, "plan": nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePayload(tc.in)
			if !errors.Is(err, ErrMalformedPayload) {
				t.Fatalf("ParsePayload(%v) = %v, want ErrMalformedPayload", tc.in, err)
			}
		})
	}
}

func TestLivenessWindow(t *testing.T) {
	cases := []struct {
		interval int
		want     time.Duration
	}{
		{0, DefaultLivenessWindow},
		{-5, DefaultLivenessWindow},
		{10, minLivenessWindow},   // 50s → floor
		{60, 5 * time.Minute},     // 5 × 60s
		{120, 10 * time.Minute},   // 5 × 120s
		{600, maxLivenessWindow},  // 50 min → ceiling
		{3600, maxLivenessWindow}, // 5h → ceiling
	}
	for _, tc := range cases {
		if got := LivenessWindow(tc.interval); got != tc.want {
			t.Errorf("LivenessWindow(%d) = %v, want %v", tc.interval, got, tc.want)
		}
	}
	if DispatchTimeout(60) != LivenessWindow(60) {
		t.Error("DispatchTimeout must equal LivenessWindow — a sensor that was live at dispatch has this long to collect")
	}
}

func TestIsLive(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-30 * time.Second)
	stale := now.Add(-20 * time.Minute)
	future := now.Add(time.Minute)

	cases := []struct {
		name      string
		status    string
		heartbeat *time.Time
		interval  int
		want      bool
	}{
		{"active and fresh", "active", &fresh, 30, true},
		{"active, case-insensitive", "ACTIVE ", &fresh, 30, true},
		{"active but stale", "active", &stale, 30, false},
		{"active, never beat", "active", nil, 30, false},
		{"active, zero beat", "active", &time.Time{}, 30, false},
		{"active, clock skew (future beat)", "active", &future, 30, false},
		{"offline, fresh", "offline", &fresh, 30, false},
		{"pending, fresh", "pending", &fresh, 30, false},
		{"inactive, fresh", "inactive", &fresh, 30, false},
		{"error, fresh", "error", &fresh, 30, false},
		// The window follows the cadence: a 4-minute-old beat is fine for a
		// sensor reporting every 2 minutes (window 10m) and dead for one
		// reporting every 10 seconds (window floors at 3m).
		{"cadence widens the window", "active", ptr(now.Add(-4 * time.Minute)), 120, true},
		{"cadence narrows the window", "active", ptr(now.Add(-4 * time.Minute)), 10, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLive(tc.status, tc.heartbeat, tc.interval, now); got != tc.want {
				t.Fatalf("IsLive(%q, %v, %d) = %v, want %v", tc.status, tc.heartbeat, tc.interval, got, tc.want)
			}
		})
	}
}

func ptr(t time.Time) *time.Time { return &t }

func TestCompletionValidate(t *testing.T) {
	if err := (Completion{Status: "completed"}).Validate(); err != nil {
		t.Errorf("completed with zero counts is legitimate: %v", err)
	}
	if err := (Completion{Status: "failed", ErrorMessage: "x"}).Validate(); err != nil {
		t.Errorf("failed: %v", err)
	}
	if err := (Completion{Status: "partial"}).Validate(); err == nil {
		t.Error("unknown status accepted")
	}
	if err := (Completion{Status: "completed", FailedTargets: -1}).Validate(); err == nil {
		t.Error("negative count accepted")
	}
}

func TestSensorOfflineMessage(t *testing.T) {
	if got := SensorOfflineMessage("", nil); got != "sensor offline; nothing was scanned" {
		t.Errorf("bare message = %q", got)
	}
	beat := time.Date(2026, 9, 17, 11, 58, 0, 0, time.UTC)
	got := SensorOfflineMessage("xps16-sensor", &beat)
	for _, want := range []string{"xps16-sensor", "nothing was scanned", "2026-09-17T11:58:00Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q lacks %q", got, want)
		}
	}
}
