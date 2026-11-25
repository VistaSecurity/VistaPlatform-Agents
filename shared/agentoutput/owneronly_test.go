package agentoutput

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// On Linux and macOS an owner-only output is 0600, as every output is.
func TestOwnerOnlyOutputMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows ACL test covers it")
	}
	path := filepath.Join(t.TempDir(), "o.jsonl")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	w, err := Open(Options{Path: path, Agent: "device-agent", AgentVersion: "t", OwnerOnly: true, Stdout: &out, Stderr: &errb}, Run{Command: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(false, ""); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", info.Mode().Perm(), err)
	}
}
