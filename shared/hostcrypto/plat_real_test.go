package hostcrypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	calls   *atomic.Int64 // commands sent, when set
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
	if r.calls != nil {
		r.calls.Add(1)
	}
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
	calls := &atomic.Int64{}
	r := platSSHExec{host: host, windows: platform == hostinventory.PlatformWindows, calls: calls}
	if r.windows {
		target = NewRemoteWindowsTarget(r)
	} else {
		target = NewRemoteUnixTarget(r, platform)
	}
	// Every pass, in the collector's order, each timed.
	saved := passes
	defer func() { passes = saved }()
	var timed []pass
	for _, p := range saved {
		p := p
		name := runtime.FuncForPC(reflect.ValueOf(p).Pointer()).Name()
		name = name[strings.LastIndexByte(name, '.')+1:]
		timed = append(timed, func(ctx context.Context, c *collection) {
			start, n := time.Now(), calls.Load()
			p(ctx, c)
			t.Logf("pass %s: %s, %d commands", name, time.Since(start).Round(100*time.Millisecond), calls.Load()-n)
		})
	}
	passes = timed
	rep, err := Collect(context.Background(), target, Options{Platform: platform, HomeDirectories: os.Getenv("HOSTCRYPTO_PLAT_HOME") == "1"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	if os.Getenv("HOSTCRYPTO_PLAT_DUMP") == "1" {
		t.Logf("%s", b)
	}
	for _, s := range []string{SectionDiskEncryption, SectionTPM, SectionSecureBoot, SectionTokens, SectionFIPSMode, SectionLibraries, SectionProcesses} {
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

// TestPlatRealWindowsCommandLine starts, on the Windows host, a PowerShell
// process of its own in a temp directory of its own: it listens on
// 127.0.0.1 and was started with a password, a keystore path and a Java
// keystore password on its command line. The running program then runs in
// the same session, the process is stopped by its id and the directory is
// deleted. Nothing that crosses may hold either password; the keystore path
// must cross.
func TestPlatRealWindowsCommandLine(t *testing.T) {
	host := os.Getenv("HOSTCRYPTO_PLAT_SSH_WINDOWS")
	if host == "" {
		t.Skip("set HOSTCRYPTO_PLAT_SSH_WINDOWS to run against a real host")
	}
	full, err := psScript(platPSPrelude+platPSRunning, struct {
		Max int `json:"Max"`
	}{platMaxProcesses})
	if err != nil {
		t.Fatal(err)
	}
	runner := `$plTd = Join-Path ([System.IO.Path]::GetTempPath()) ('vista-plat-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $plTd)
$plLs = Join-Path $plTd 'listen.ps1'
Set-Content -LiteralPath $plLs -Value '$plL = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $plL.Start(); Start-Sleep -Seconds 90'
$plKs = Join-Path $plTd 'store.p12'
$plP = Start-Process -FilePath 'powershell' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $plLs, '--password=hunter2', '--keystore', $plKs, '-Djavax.net.ssl.keyStorePassword=hunter3') -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5
[Console]::Out.WriteLine('K:' + $plKs)
try {
  $plProg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString([]byte(full)) + `'))
  [Console]::Out.WriteLine('E:' + [string]$plP.Id)
  $plAns = & ([scriptblock]::Create($plProg))
  [Console]::Out.WriteLine('')
} finally {
  Stop-Process -Id $plP.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
  Remove-Item -LiteralPath $plTd -Recurse -Force -ErrorAction SilentlyContinue
  [Console]::Out.WriteLine('G:' + [string](Test-Path -LiteralPath $plTd))
}
`
	r := platSSHExec{host: host, windows: true}
	out, stderr, exit, err := r.RunInput(t.Context(), psStdinArgv, psStdin(runner))
	if err != nil || exit != 0 {
		t.Fatalf("exit %d %v: %s", exit, err, stderr)
	}
	ks, ans, gone := "", "", ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "K:"):
			ks = line[2:]
		case strings.HasPrefix(line, "J:"):
			ans = line
		case strings.HasPrefix(line, "G:"):
			gone = line[2:]
		}
	}
	if gone != "False" {
		t.Errorf("the temp directory was not deleted: %q", gone)
	}
	kind, b, err := psDecode([]byte(ans))
	if err != nil || kind != 'J' {
		t.Fatalf("answer: %v %q", err, ans)
	}
	for _, blob := range []string{string(out), string(stderr), string(b)} {
		if strings.Contains(blob, "hunter2") || strings.Contains(blob, "hunter3") {
			t.Fatal("a password crossed the connection")
		}
	}
	rr, err := platParseWindowsRunning(b)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range rr.procs {
		for _, a := range p.args {
			if strings.EqualFold(a, ks) {
				found = true
				t.Logf("process %s: args %v listeners %d", p.name, p.args, len(p.listeners))
			}
		}
	}
	if !found {
		t.Fatalf("the keystore path %q did not cross: %s", ks, b)
	}
}
