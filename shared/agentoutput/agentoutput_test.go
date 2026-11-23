package agentoutput

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixedNow() func() time.Time {
	t := time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func open(t *testing.T, opts Options) (*Writer, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	opts.Stdout, opts.Stderr, opts.Now = &stdout, &stderr, fixedNow()
	if opts.Agent == "" {
		opts.Agent, opts.AgentVersion = "crypto-sensor", "test"
	}
	w, err := Open(opts, Run{Command: "scan", Targets: []string{"10.0.0.1"}})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return w, &stdout, &stderr
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"": FormatJSONL, "jsonl": FormatJSONL, "JSON": FormatJSON, " csv ": FormatCSV} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("ParseFormat(xml) succeeded")
	}
}

func TestJSONLEnvelopeOrderAndStreaming(t *testing.T) {
	w, stdout, _ := open(t, Options{Format: FormatJSONL})
	// Standard output streams: the run record is there before Close.
	if !strings.Contains(stdout.String(), `"kind":"run"`) {
		t.Fatalf("run record not streamed: %q", stdout.String())
	}
	if err := w.Write(KindScanHost, map[string]any{"address": "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Error("10.0.0.2", "scan", "refused"); err != nil {
		t.Fatal(err)
	}
	sum, err := w.Close(false, "2 addresses")
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Partial || sum.Errors != 1 {
		t.Errorf("summary = %+v; want partial with one error", sum)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	var kinds []Kind
	for _, l := range lines {
		var r Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		if r.Schema != Schema || r.Agent != "crypto-sensor" || r.RunID != w.RunID() || r.ObservedAt.IsZero() {
			t.Errorf("bad envelope: %+v", r)
		}
		kinds = append(kinds, r.Kind)
	}
	want := []Kind{KindRun, KindScanHost, KindError, KindSummary}
	if strings.Join(kindStrings(kinds), ",") != strings.Join(kindStrings(want), ",") {
		t.Errorf("kinds = %v; want %v", kinds, want)
	}
}

func kindStrings(ks []Kind) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = string(k)
	}
	return out
}

func TestReservedKindsRefused(t *testing.T) {
	w, _, _ := open(t, Options{})
	for _, k := range []Kind{KindRun, KindSummary, KindError} {
		if err := w.Write(k, nil); err == nil {
			t.Errorf("Write(%s) accepted", k)
		}
	}
	if _, err := w.Close(false, ""); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(KindScanHost, nil); err == nil {
		t.Error("Write after Close accepted")
	}
}

func TestJSONDocument(t *testing.T) {
	w, stdout, _ := open(t, Options{Format: FormatJSON})
	if stdout.Len() != 0 {
		t.Fatalf("json wrote before Close: %q", stdout.String())
	}
	_ = w.Write(KindDeviceInterrogation, map[string]any{"assets": []any{}})
	if _, err := w.Close(false, ""); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Run     Record   `json:"run"`
		Records []Record `json:"records"`
		Summary Record   `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, stdout.String())
	}
	if doc.Run.Kind != KindRun || doc.Summary.Kind != KindSummary || len(doc.Records) != 1 || doc.Records[0].Kind != KindDeviceInterrogation {
		t.Errorf("document = %+v", doc)
	}
}

func TestJSONDocumentWithNoRecordsHasEmptyArray(t *testing.T) {
	w, stdout, _ := open(t, Options{Format: FormatJSON})
	if _, err := w.Close(false, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"records": []`) {
		t.Errorf("empty run should carry records: []: %s", stdout.String())
	}
}

func TestCSVEndpointsDeduplicated(t *testing.T) {
	w, stdout, _ := open(t, Options{Format: FormatCSV})
	ep := Endpoint{Address: "10.0.0.1", Port: 443, Transport: "tcp", Protocol: "tls", ProtocolVersion: "TLS 1.2", CertificateKeySize: 2048}
	_ = w.Write(KindPassiveObservation, map[string]any{}, ep)
	_ = w.Write(KindPassiveObservation, map[string]any{}, ep) // same handshake seen again
	_ = w.Write(KindPassiveObservation, map[string]any{}, Endpoint{Address: "10.0.0.2", Port: 22, Protocol: "ssh"})
	_ = w.Write(KindHostInventory, map[string]any{}) // no endpoint: not in the CSV
	sum, err := w.Close(false, "")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(stdout).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || strings.Join(rows[0], ",") != strings.Join(CSVHeader, ",") {
		t.Fatalf("rows = %v", rows)
	}
	if rows[1][0] != "passive_observation" || rows[1][3] != "443" || rows[1][13] != "2048" {
		t.Errorf("row = %v", rows[1])
	}
	if rows[2][13] != "" {
		t.Errorf("an unknown key size must be empty, not 0: %v", rows[2])
	}
	if sum.Endpoints != 2 {
		t.Errorf("endpoints = %d; want 2", sum.Endpoints)
	}
}

func TestFileAppearsOnlyOnCloseWithRestrictedMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")
	w, stdout, stderr := open(t, Options{Path: path})
	_ = w.Write(KindScanHost, map[string]any{"a": 1})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("output exists before Close: %v", err)
	}
	if _, err := w.Close(false, ""); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Errorf("file output leaked to stdout: %q", stdout.String())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v; want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary file left behind: %v", entries)
	}
	data, _ := os.ReadFile(path)
	if n := strings.Count(string(data), "\n"); n != 3 {
		t.Errorf("lines = %d; want 3 (run, scan_host, summary)", n)
	}
	if !strings.Contains(stderr.String(), "output: "+path) || !strings.Contains(stderr.String(), "nothing was assessed or uploaded") {
		t.Errorf("summary = %q", stderr.String())
	}
}

func TestQuietPrintsNothing(t *testing.T) {
	w, _, stderr := open(t, Options{Quiet: true})
	if _, err := w.Close(false, ""); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Errorf("quiet printed %q", stderr.String())
	}
}

func TestExitCode(t *testing.T) {
	if c := ExitCode(Summary{}, nil, false); c != 0 {
		t.Errorf("complete = %d", c)
	}
	if c := ExitCode(Summary{Partial: true}, nil, false); c != 2 {
		t.Errorf("partial = %d", c)
	}
	if c := ExitCode(Summary{}, os.ErrClosed, false); c != 1 {
		t.Errorf("write error = %d", c)
	}
	if c := ExitCode(Summary{Partial: true}, nil, true); c != 1 {
		t.Errorf("nothing worked = %d", c)
	}
}

func TestOpenRefusesUnknownFormat(t *testing.T) {
	if _, err := Open(Options{Format: "xml", Stdout: &bytes.Buffer{}}, Run{}); err == nil {
		t.Error("Open accepted an unknown format")
	}
}

// A path that exists and is not a regular file (/dev/null, a pipe) cannot
// take a temporary file beside it or a rename: it is written in place.
func TestOutputToDevNullIsWrittenInPlace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/null on Windows")
	}
	w, _, stderr := open(t, Options{Path: os.DevNull})
	if err := w.Write(KindScanHost, map[string]any{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(false, ""); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !strings.Contains(stderr.String(), "output: "+os.DevNull) {
		t.Errorf("summary = %q", stderr.String())
	}
	if info, err := os.Stat(os.DevNull); err != nil || info.Mode().IsRegular() {
		t.Fatalf("%s was replaced: %v %v", os.DevNull, info, err)
	}
}

func TestOutputToADirectoryIsRefused(t *testing.T) {
	_, err := Open(Options{Path: t.TempDir(), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, Run{})
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("Open(dir) = %v; want a directory refusal", err)
	}
}

// A run that did no useful work exits 1; its summary must not call the
// result partial (which means exit 2).
func TestFailedRunSummarySaysFailedNotPartial(t *testing.T) {
	w, _, stderr := open(t, Options{})
	_ = w.Error("en0", "capture", "permission denied")
	w.Fail()
	sum, err := w.Close(true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Partial || ExitCode(sum, nil, true) != 1 {
		t.Fatalf("summary %+v", sum)
	}
	if s := stderr.String(); !strings.Contains(s, "the run failed") || strings.Contains(s, "partial") {
		t.Errorf("summary text = %q", s)
	}
}
