package hostcrypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
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
	// Remote known_hosts: never misread as key lines.
	for _, kh := range rep.SSH.KnownHosts {
		if kh.Hashed != nil || kh.Entries != nil && *kh.Entries != 0 {
			t.Errorf("remote known_hosts %s: entries %v hashed %v", kh.Location.Path, kh.Entries, kh.Hashed)
		}
	}
	// Every visited file says who can read it, or its section says it could not.
	for _, k := range rep.PrivateKeys {
		if k.Location.Path != "" && k.Location.WorldReadable == nil && rep.Sections[SectionPrivateKeys] == SectionOK && rep.Sections[SectionSSH] == SectionOK {
			t.Errorf("%s: permissions unknown and the sections say ok", k.Location.Path)
		}
		if r.windows && strings.Contains(strings.ToLower(k.Location.Path), `\ssh\ssh_host_`) {
			t.Logf("host key %s: owner %q world_readable %v", k.Location.Path, k.Location.Owner, platPtrStr(k.Location.WorldReadable))
			if k.Location.Owner == "" || k.Location.WorldReadable == nil {
				t.Errorf("host key without owner or ACL: %+v", k.Location)
			}
		}
	}

	// HOSTCRYPTO_PLAT_DEADLINE=15s: the same collection under the caller's
	// deadline. A section ok there must hold what the full run found; any
	// other is partial with the limit; none failed.
	if d, err := time.ParseDuration(os.Getenv("HOSTCRYPTO_PLAT_DEADLINE")); err == nil {
		passes = saved
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		start := time.Now()
		cut, err := Collect(ctx, target, Options{Platform: platform})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("deadline %s: took %s; sections %v", d, time.Since(start).Round(100*time.Millisecond), cut.Sections)
		full, short := platRealCounts(rep), platRealCounts(cut)
		for sec, st := range cut.Sections {
			switch {
			case st == SectionFailed && rep.Sections[sec] != SectionFailed:
				t.Errorf("deadline: %s failed", sec)
			case st == SectionOK && short[sec] != full[sec]:
				t.Errorf("deadline: %s ok with %d of %d", sec, short[sec], full[sec])
			}
		}
		for _, l := range cut.Limits {
			if l.Limit == "max_duration" {
				t.Logf("limit %s: %s", l.Section, l.Detail)
				if !strings.Contains(l.Detail, "caller's deadline") {
					t.Errorf("limit detail %q does not name the caller's deadline", l.Detail)
				}
			}
		}
	}
}

func platPtrStr(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprint(*b)
}

// platRealCounts counts the items of every section that has a list.
func platRealCounts(rep *Report) map[string]int {
	m := platSectionCounts(rep)
	m[SectionLibraries] = len(rep.Libraries)
	m[SectionDiskEncryption] = len(rep.Protection.Volumes)
	m[SectionTokens] = len(rep.Protection.Tokens)
	return m
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
$plSk = Join-Path $plTd 'shipping\proc.key'
$plP = Start-Process -FilePath 'powershell' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $plLs, '--password=hunter2', '--keystore', $plKs, '-Djavax.net.ssl.keyStorePassword=hunter3', '--keystore-password', 'hunter4', '--key', $plSk) -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5
[Console]::Out.WriteLine('K:' + $plKs)
[Console]::Out.WriteLine('S:' + $plSk)
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
	ks, sk, ans, gone := "", "", "", ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "K:"):
			ks = line[2:]
		case strings.HasPrefix(line, "S:"):
			sk = line[2:]
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
		if strings.Contains(blob, "hunter2") || strings.Contains(blob, "hunter3") || strings.Contains(blob, "hunter4") {
			t.Fatal("a password crossed the connection")
		}
	}
	rr, err := platParseWindowsRunning(b)
	if err != nil {
		t.Fatal(err)
	}
	found, foundKey := false, false
	for _, p := range rr.procs {
		for _, a := range p.args {
			if strings.EqualFold(a, ks) {
				found = true
				t.Logf("process %s: args %v listeners %d", p.name, p.args, len(p.listeners))
			}
			foundKey = foundKey || strings.EqualFold(a, sk)
		}
	}
	if !found || !foundKey {
		t.Fatalf("the keystore path %q (%v) or the key under shipping %q (%v) did not cross: %s", ks, found, sk, foundKey, b)
	}
}

// TestPlatRealLinuxCommandLine starts, on the Linux host, a listener of its
// own in a temp directory of its own (python3, listening on 127.0.0.1, its
// arguments naming a certificate under a "shipping" directory and a secret
// option with its value), runs pass 3 against it, stops it by its PID and
// deletes the directory. The certificate must be found through the process;
// the secret value must not cross.
func TestPlatRealLinuxCommandLine(t *testing.T) {
	host := os.Getenv("HOSTCRYPTO_PLAT_SSH_LINUX")
	if host == "" {
		t.Skip("set HOSTCRYPTO_PLAT_SSH_LINUX to run against a real host")
	}
	k := platNewKey(t, "localhost")
	r := platSSHExec{host: host}
	run := func(script string, stdin []byte, args ...string) string {
		out, stderr, exit, err := r.RunInput(t.Context(), platSh(script, args...), stdin)
		if err != nil || exit != 0 {
			t.Fatalf("%s: exit %d %v %s", script[:20], exit, err, stderr)
		}
		return strings.TrimSpace(string(out))
	}
	dir := run(`mktemp -d /tmp/vista-plat-XXXXXXXX`, nil)
	defer run(`rm -rf -- "$1"; [ -e "$1" ] && echo left || echo gone`, nil, dir)
	run(`mkdir -p "$1/shipping" && cat > "$1/shipping/proc.crt"`, k.certPEM, dir)
	pid := run(`cd "$1" && nohup python3 -c 'import socket,time
s=socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(); time.sleep(120)' --cert "$1/shipping/proc.crt" --keystore-password hunter3 -Dx.keyStorePassword=hunter4 >/dev/null 2>&1 & echo $!`, nil, dir)
	defer run(`kill "$1" 2>/dev/null; true`, nil, pid)
	run(`sleep 2`, nil)

	out := run(platLinuxRunningScript, nil)
	if strings.Contains(out, "hunter3") || strings.Contains(out, "hunter4") {
		t.Fatal("a secret value crossed")
	}
	target := NewRemoteUnixTarget(r, "linux")
	c := tgtCollection(target, Options{Platform: "linux"})
	platRunningPass(t.Context(), c)
	c.registry.finish(c.report)
	certPath := dir + "/shipping/proc.crt"
	found := false
	for _, cert := range c.report.Certificates {
		if cert.Location.Path == certPath && platHasUsage(cert.Location, "listener", "", 0) {
			found = true
		}
	}
	b, _ := json.Marshal(c.report)
	if strings.Contains(string(b), "hunter3") || strings.Contains(string(b), "hunter4") {
		t.Fatal("a secret value reached the report")
	}
	if !found {
		t.Fatalf("%s was not found through its process: %s", certPath, b)
	}
	t.Logf("found %s with its listener; sections %v", certPath, c.report.Sections)
}

// HOSTCRYPTO_PLAT_MAC_FIXTURE=<dir under /tmp> (on the Mac, the test binary
// copied there): one certificate in dir, held open by this process, which
// listens on 127.0.0.1 and carries the certificate's path with a "//" in it
// on its command line; a LOCAL collection (pass 3 and a sweep of dir) is
// run and its count printed, then the process waits
// HOSTCRYPTO_PLAT_MAC_WAIT seconds for the remote run.
func TestPlatRealDarwinFixtureLocal(t *testing.T) {
	dir := os.Getenv("HOSTCRYPTO_PLAT_MAC_FIXTURE")
	if dir == "" || runtime.GOOS != "darwin" {
		t.Skip("set HOSTCRYPTO_PLAT_MAC_FIXTURE on a Mac")
	}
	k := platNewKey(t, "localhost")
	p := dir + "/cert.pem"
	if err := os.WriteFile(p, k.certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	rep, err := Collect(t.Context(), NewLocalTarget(), Options{Platform: "darwin", SweepRoots: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("LOCAL_COUNT %d\n", platFixtureCount(rep, k))
	if w, _ := strconv.Atoi(os.Getenv("HOSTCRYPTO_PLAT_MAC_WAIT")); w > 0 {
		time.Sleep(time.Duration(w) * time.Second)
	}
}

// TestPlatRealDarwinFixtureRemote is the same count from a REMOTE collection
// of the Mac while the local fixture waits.
func TestPlatRealDarwinFixtureRemote(t *testing.T) {
	host, dir := os.Getenv("HOSTCRYPTO_PLAT_SSH_DARWIN"), os.Getenv("HOSTCRYPTO_PLAT_MAC_FIXTURE")
	if host == "" || dir == "" {
		t.Skip("set HOSTCRYPTO_PLAT_SSH_DARWIN and HOSTCRYPTO_PLAT_MAC_FIXTURE")
	}
	r := platSSHExec{host: host}
	rep, err := Collect(t.Context(), NewRemoteUnixTarget(r, "darwin"), Options{Platform: "darwin", SweepRoots: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, c := range rep.Certificates {
		if strings.Contains(c.Location.Path, strings.TrimPrefix(dir, "/tmp/")) {
			paths = append(paths, c.Location.Path+" "+c.Location.FoundBy)
		}
	}
	fmt.Printf("REMOTE_COUNT %d %v\n", len(paths), paths)
}

// platFixtureCount counts the fixture's certificate records.
func platFixtureCount(rep *Report, k platKey) int {
	cert, _ := ParseCertificateDER(k.certDER)
	n := 0
	for _, c := range rep.Certificates {
		if c.FingerprintSHA256 == cert.FingerprintSHA256 {
			n++
		}
	}
	return n
}
