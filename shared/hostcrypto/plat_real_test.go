package hostcrypto

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// Real hosts, opt-in. These run the platform passes against a host reached
// with the workstation's own ssh client (key authentication, no prompt), so
// a developer can see the real commands answer on a real host:
//
//	HOSTCRYPTO_PLAT_SSH_LINUX=host     a Linux host
//	HOSTCRYPTO_PLAT_SSH_DARWIN=host    a macOS host
//	HOSTCRYPTO_PLAT_SSH_WINDOWS=user@host   a Windows host (PowerShell 5.1)
//
// HOSTCRYPTO_PLAT_DUMP=1 prints the Report; HOSTCRYPTO_PLAT_HOME=1 turns on
// the home-directories opt-in. They change nothing on the host.

// platSSHExec is a runner over the ssh binary: POSIX-quoted argv for a
// Unix host, a space-joined argv for Windows (whose argv here is the fixed
// PowerShell bootstrap).
type platSSHExec struct {
	host    string
	windows bool
}

func (r platSSHExec) command(argv []string) string {
	if r.windows {
		return strings.Join(argv, " ")
	}
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(parts, " ")
}

func (r platSSHExec) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return r.RunInput(ctx, argv, nil)
}

func (r platSSHExec) RunInput(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", r.host, r.command(argv))
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return []byte(out.String()), []byte(errb.String()), ee.ExitCode(), nil
	}
	if err != nil {
		return nil, nil, -1, err
	}
	return []byte(out.String()), []byte(errb.String()), 0, nil
}

func (r platSSHExec) ReadFile(context.Context, string) ([]byte, error) {
	return nil, ErrNotPublic
}

var _ hostinventory.InputRunner = platSSHExec{}

func platRealHost(t *testing.T, env, platform string) {
	host := os.Getenv(env)
	if host == "" {
		t.Skip("set " + env + " to run against a real host")
	}
	var target Target
	r := platSSHExec{host: host, windows: platform == hostinventory.PlatformWindows}
	if r.windows {
		target = NewRemoteWindowsTarget(r)
	} else {
		target = NewRemoteUnixTarget(r, platform)
	}
	saved := passes
	passes = []pass{platPass, platRunningPass}
	defer func() { passes = saved }()
	rep, err := Collect(context.Background(), target, Options{Platform: platform, HomeDirectories: os.Getenv("HOSTCRYPTO_PLAT_HOME") == "1"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	if os.Getenv("HOSTCRYPTO_PLAT_DUMP") == "1" {
		t.Logf("%s", b)
	}
	for _, s := range []string{SectionDiskEncryption, SectionTPM, SectionSecureBoot, SectionTokens, SectionLibraries, SectionProcesses} {
		if rep.Sections[s] == "" || rep.Sections[s] == SectionFailed {
			t.Errorf("%s: %q", s, rep.Sections[s])
		}
	}
	t.Logf("sections %v", rep.Sections)
	for _, e := range rep.Errors {
		t.Logf("error %s: %s", e.Step, e.Message)
	}
}

func TestPlatRealLinuxHost(t *testing.T) {
	platRealHost(t, "HOSTCRYPTO_PLAT_SSH_LINUX", hostinventory.PlatformLinux)
}

func TestPlatRealDarwinHost(t *testing.T) {
	platRealHost(t, "HOSTCRYPTO_PLAT_SSH_DARWIN", hostinventory.PlatformDarwin)
}

func TestPlatRealWindowsHost(t *testing.T) {
	platRealHost(t, "HOSTCRYPTO_PLAT_SSH_WINDOWS", hostinventory.PlatformWindows)
}
