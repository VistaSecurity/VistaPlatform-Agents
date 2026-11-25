//go:build windows

package agentoutput

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// aclTrustees reads a file's DACL back through a handle of its own.
func aclTrustees(t *testing.T, path string) ([]string, error) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	got, err := ownerOnlyTrustees(h)
	sort.Strings(got)
	return got, err
}

func wantTrustees(t *testing.T) []string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	w := []string{user.User.Sid.String(), system.String(), admins.String()}
	sort.Strings(w)
	return w
}

func writeOwnerOnly(t *testing.T, path string, ownerOnly bool) {
	t.Helper()
	var out, errb strings.Builder
	w, err := Open(Options{Path: path, Format: FormatJSONL, Agent: "device-agent", AgentVersion: "t", OwnerOnly: ownerOnly,
		Stdout: &out, Stderr: &errb}, Run{Command: "host-crypto"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(false, "test"); err != nil {
		t.Fatal(err)
	}
}

// An owner-only output file holds exactly three trustees (the running user,
// SYSTEM, Administrators), inherits nothing, and replaces an existing file
// that was readable more widely; a file written without OwnerOnly keeps the
// folder's inherited permissions (the other commands, unchanged).
func TestOwnerOnlyOutputACL(t *testing.T) {
	dir := t.TempDir()
	want := wantTrustees(t)

	plain := filepath.Join(dir, "plain.jsonl")
	writeOwnerOnly(t, plain, false)
	if _, err := aclTrustees(t, plain); err == nil {
		t.Fatal("a file written without OwnerOnly reads as owner-only: the check proves nothing")
	}

	existing := filepath.Join(dir, "crypto.jsonl")
	if err := os.WriteFile(existing, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := aclTrustees(t, existing); err == nil {
		t.Fatal("the fixture file is already owner-only")
	}
	writeOwnerOnly(t, existing, true)
	got, err := aclTrustees(t, existing)
	if err != nil {
		t.Fatalf("the replaced output is not owner-only: %v", err)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("trustees %v, want %v", got, want)
	}
	b, _ := os.ReadFile(existing)
	if strings.Contains(string(b), "old") || !strings.Contains(string(b), `"kind":"run"`) {
		t.Fatalf("not replaced: %q", b)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".*partial*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
	t.Logf("owner-only output %s: %v", existing, got)
	if keep := os.Getenv("AGENTOUTPUT_KEEP"); keep != "" {
		writeOwnerOnly(t, keep, true)
	}
}
