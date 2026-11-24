package hostcrypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// tgtFakeRunner is a scripted [hostinventory.Runner] that records every call.
//
// The remote targets' tests drive it to assert the EXACT argv each operation
// sends and, for the ReadFile guard, that nothing which could print a file's
// content was sent at all. Answers come from a handler so a test can answer by
// operation (the identify script, a batched stat) rather than by a literal
// string that would hide what changed.
type tgtFakeRunner struct {
	handler func(argv []string) tgtResult

	mu    sync.Mutex
	runs  [][]string
	reads []string
	// readData answers ReadFile by path.
	readData map[string][]byte
}

type tgtResult struct {
	stdout string
	stderr string
	exit   int
	err    error
}

func newTgtFakeRunner(h func(argv []string) tgtResult) *tgtFakeRunner {
	if h == nil {
		h = func([]string) tgtResult { return tgtResult{stderr: "command not found", exit: 127} }
	}
	return &tgtFakeRunner{handler: h, readData: map[string][]byte{}}
}

func (f *tgtFakeRunner) Run(_ context.Context, argv []string) ([]byte, []byte, int, error) {
	f.mu.Lock()
	f.runs = append(f.runs, append([]string(nil), argv...))
	f.mu.Unlock()
	r := f.handler(argv)
	return []byte(r.stdout), []byte(r.stderr), r.exit, r.err
}

func (f *tgtFakeRunner) ReadFile(_ context.Context, path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, path)
	b, ok := f.readData[path]
	if !ok {
		return nil, errors.New("no such file")
	}
	return append([]byte(nil), b...), nil
}

func (f *tgtFakeRunner) recordedRuns() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.runs))
	copy(out, f.runs)
	return out
}

func (f *tgtFakeRunner) recordedReads() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reads...)
}

var _ hostinventory.Runner = (*tgtFakeRunner)(nil)

// tgtRecordingRunner wraps a real runner and records argv, so a test against
// the real tools on this machine can still assert what was sent.
type tgtRecordingRunner struct {
	inner hostinventory.Runner
	mu    sync.Mutex
	runs  [][]string
	reads []string
}

func (r *tgtRecordingRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	r.mu.Lock()
	r.runs = append(r.runs, append([]string(nil), argv...))
	r.mu.Unlock()
	return r.inner.Run(ctx, argv)
}

func (r *tgtRecordingRunner) ReadFile(ctx context.Context, path string) ([]byte, error) {
	r.mu.Lock()
	r.reads = append(r.reads, path)
	r.mu.Unlock()
	return r.inner.ReadFile(ctx, path)
}

// tgtPSArgsRE finds the base64 argument literal in a decoded script.
var tgtPSArgsRE = regexp.MustCompile(`FromBase64String\('([A-Za-z0-9+/=]*)'\)`)

// tgtDecodePS takes a PowerShell argv as RemoteWindowsTarget builds it and
// returns the script and its decoded $a arguments. It fails the test when the
// argv is not exactly the five-element -EncodedCommand form.
func tgtDecodePS(t *testing.T, argv []string) (script string, args map[string]any) {
	t.Helper()
	if len(argv) != 5 || argv[0] != "powershell" || argv[1] != "-NoProfile" ||
		argv[2] != "-NonInteractive" || argv[3] != "-EncodedCommand" {
		t.Fatalf("not a PowerShell -EncodedCommand argv: %q", argv)
	}
	raw, err := base64.StdEncoding.DecodeString(argv[4])
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("encoded command is not UTF-16LE base64")
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	script = string(utf16.Decode(units))
	m := tgtPSArgsRE.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("script carries no argument literal")
	}
	j, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("argument literal is not base64")
	}
	if err := json.Unmarshal(j, &args); err != nil {
		t.Fatalf("argument literal is not JSON: %v", err)
	}
	return script, args
}

// tgtPSKind names which of the target's scripts a decoded script is.
func tgtPSKind(script string) string {
	switch {
	case strings.Contains(script, "ToBase64String([System.IO.File]::ReadAllBytes"):
		return "read"
	case strings.Contains(script, "Select-String"):
		return "identify"
	case strings.Contains(script, "$stack"):
		return "list"
	case strings.Contains(script, "psAcl $i.FullName"):
		return "stat"
	}
	return "unknown"
}
