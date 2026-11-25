package hostcrypto

import (
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// platUnixListing is a hand-written listing in platLinuxRunningScript's
// line protocol. The A lines include what the host filter would never
// print, to show Go refuses them too.
const platUnixListing = `U 1000
L tcp 1234 0100007F:1F90
L tcp 1235 00000000000000000000000001000000:01BB
L udp 1236 00000000:14E9
L tcp 9999 00000000:0016
P 42 nginx
S 1234
S 1235
M /usr/lib/x86_64-linux-gnu/libssl.so.3
M /usr/lib/x86_64-linux-gnu/libc.so.6
F /etc/ssl/server.crt
F /etc/ssl/server.key
F /etc/passwd
A /srv/app/store.jks
A --password=hunter2
A /etc/ssl/password-is-hunter2=.pem
A /etc/ssl/a b.pem
P 43 mdns
S 1236
P notapid x
S 1234
D 7
D 8
`

func TestPlatParseUnixRunning(t *testing.T) {
	r := platParseUnixRunning([]byte(platUnixListing))
	if r.uid != "1000" || r.elevated == nil || *r.elevated || r.denied != 2 || r.unowned != 1 || r.truncated {
		t.Fatalf("%+v", r)
	}
	if len(r.procs) != 2 {
		t.Fatalf("procs: %d", len(r.procs))
	}
	p := r.procs[0]
	if p.name != "nginx" || len(p.listeners) != 2 || p.listeners[0] != (Usage{Kind: "listener", Process: "nginx", Address: "127.0.0.1", Port: 8080, Transport: "tcp"}) ||
		p.listeners[1].Address != "::1" || p.listeners[1].Port != 443 {
		t.Fatalf("nginx: %+v", p)
	}
	if strings.Join(p.libs, ",") != "/usr/lib/x86_64-linux-gnu/libssl.so.3" || strings.Join(p.files, ",") != "/etc/ssl/server.crt,/etc/ssl/server.key" ||
		strings.Join(p.args, ",") != "/srv/app/store.jks" {
		t.Fatalf("nginx: libs %v files %v args %v", p.libs, p.files, p.args)
	}
	if q := r.procs[1]; q.listeners[0].Transport != "udp" || q.listeners[0].Port != 5353 || q.listeners[0].Address != "0.0.0.0" {
		t.Fatalf("mdns: %+v", q)
	}
	if strings.Contains(platJSON(t, r.procs[0].args), "hunter2") {
		t.Fatal("a secret argument was kept")
	}
	// The pid is parsed but never part of a usage.
	if strings.Contains(platJSON(t, p.listeners), "42") {
		t.Fatal("a pid reached a usage")
	}
}

func TestPlatAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:1F90":                         "127.0.0.1 8080",
		"00000000:0016":                         "0.0.0.0 22",
		"00000000000000000000000001000000:01BB": "::1 443",
		"00000000000000000000000000000000:0050": ":: 80",
	} {
		a, p, ok := platProcNetAddr(in)
		if !ok || a+" "+strconv.Itoa(p) != want {
			t.Errorf("%s: %s %d %v", in, a, p, ok)
		}
	}
	for _, bad := range []string{"", "zz:1", "0100007F", "0100007F:XYZ", "01007F:0016"} {
		if _, _, ok := platProcNetAddr(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	for in, want := range map[string]string{"*:7000": "* 7000", "127.0.0.1:631": "127.0.0.1 631", "[::1]:631": "::1 631"} {
		a, p, ok := platLsofAddr(in)
		if !ok || a+" "+strconv.Itoa(p) != want {
			t.Errorf("%s: %s %d", in, a, p)
		}
	}
	for _, bad := range []string{"host.example:22", "*:0", "*:x", "nocolon"} {
		if _, _, ok := platLsofAddr(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPlatArgPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/ssl/a.pem": true, "/etc/ssl/A.KEY": true, "/srv/ks.jks": true,
		"relative.pem": false, "/etc/passwd": false, "/etc/x=y.pem": false, "/etc/pass/a.pem": false,
		"/etc/token.pem": false, "/etc/a b.pem": false, "/etc/a\x01.pem": false,
	} {
		if _, ok := platArgPath(p, false); ok != want {
			t.Errorf("%q: %v", p, ok)
		}
	}
	if _, ok := platArgPath(`C:\certs\a.pfx`, true); !ok {
		t.Error("windows path refused")
	}
	if _, ok := platArgPath(`/a.pfx`, true); ok {
		t.Error("unix path accepted as windows")
	}
}

// TestPlatArgsAwkReal runs the host-side filter through this machine's sh
// and awk: what crosses from a command line is a crypto path and nothing
// else, and an argument whose option name says secret crosses nothing. The
// mutated filter (secret check removed) lets the password path through,
// so the test can fail.
func TestPlatArgsAwkReal(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk")
	}
	in := strings.Join([]string{
		"A --password=/run/secrets/hunter2.pem",
		"A -Djavax.net.ssl.keyStorePassword=/x/changeit.jks",
		"A --token=abcdef",
		"A hunter2",
		"A -Djavax.net.ssl.keyStore=/etc/app/ks.jks",
		"A --cert=/etc/ssl/a.pem,/etc/ssl/b.crt",
		"A /etc/ssl/c.key",
		"A /etc/ssl/quote'd.pem",
		"M /usr/lib/x86_64-linux-gnu/libssl.so.3",
		"M /usr/lib/x86_64-linux-gnu/libc.so.6",
		"M /opt/java/bcprov-jdk18on-1.78.jar",
		"F /etc/ssl/server.key",
		"F /etc/hosts",
		"X anything",
	}, "\n") + "\n"
	run := func(prog string) string {
		cmd := exec.Command("sh", "-c", "awk '"+prog+"'")
		cmd.Stdin = strings.NewReader(in)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("awk: %v", err)
		}
		return string(out)
	}
	got := run(platArgsAwk)
	want := "A /etc/app/ks.jks\nA /etc/ssl/a.pem\nA /etc/ssl/b.crt\nA /etc/ssl/c.key\nM /usr/lib/x86_64-linux-gnu/libssl.so.3\nM /opt/java/bcprov-jdk18on-1.78.jar\nF /etc/ssl/server.key\n"
	if got != want {
		t.Fatalf("filter output:\n%s\nwant:\n%s", got, want)
	}
	mutated := strings.Replace(platArgsAwk, `if (e > 0 && tolower(substr(v, 1, e - 1)) ~ /(pass|secret|pin|token|cred|pwd)/) next`, ``, 1)
	if mutated == platArgsAwk {
		t.Fatal("the mutation did not apply")
	}
	if !strings.Contains(run(mutated), "hunter2") {
		t.Fatal("the mutated filter did not leak: the test cannot see a leak")
	}
}

// platRunningFake is a host with nginx holding a certificate open (one the
// known-locations pass already found), a key file, a keystore on its
// command line, and libssl mapped.
func platRunningFake(t *testing.T, local bool, k platKey) (*tgtFakeTarget, *collection) {
	ft := newTgtFakeTarget(local)
	ft.file("/etc/ssl/server.crt", k.certPEM)
	ft.fileMode("/etc/ssl/server.key", k.keyPEM, 0o600)
	ft.file("/srv/app/store.jks", append(append([]byte(nil), magicJKS...), 0, 0, 0, 2))
	ft.script(platSh(platLinuxRunningScript), tgtResult{stdout: platUnixListing})
	c := tgtCollection(ft, Options{Platform: hostinventory.PlatformLinux})
	cert, err := ParseCertificateDER(k.certDER)
	if err != nil {
		t.Fatal(err)
	}
	cert.Location = Location{Path: "/etc/ssl/server.crt", FoundBy: FoundByKnownLocation}
	c.registry.addCertificate(cert)
	c.registry.addLibrary(CryptoLibrary{Name: "openssl", Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Source: "file"})
	return ft, c
}

func TestPlatRunningPass(t *testing.T) {
	k := platNewKey(t, "running")
	for _, local := range []bool{true, false} {
		ft, c := platRunningFake(t, local, k)
		platRunningPass(t.Context(), c)
		c.registry.finish(c.report)
		rep := c.report
		if rep.Sections[SectionProcesses] != SectionPartial || !platErrorsContain(rep, SectionProcesses, "2 processes") {
			t.Fatalf("local=%v: %v %+v", local, rep.Sections, rep.Errors)
		}
		if len(rep.Certificates) != 1 {
			t.Fatalf("certificates: %+v", rep.Certificates)
		}
		cl := rep.Certificates[0].Location
		if cl.FoundBy != FoundByProcess || !platHasUsage(cl, "process", "nginx", 0) || !platHasUsage(cl, "listener", "nginx", 8080) || !platHasUsage(cl, "listener", "nginx", 443) {
			t.Fatalf("certificate usage: %+v", cl)
		}
		if len(rep.PrivateKeys) != 1 {
			t.Fatalf("keys: %+v", rep.PrivateKeys)
		}
		pk := rep.PrivateKeys[0]
		if pk.Location.Path != "/etc/ssl/server.key" || pk.Location.FoundBy != FoundByProcess || pk.Location.Mode != "0600" || !platHasUsage(pk.Location, "listener", "nginx", 8080) {
			t.Fatalf("key: %+v", pk)
		}
		if local {
			if pk.Algorithm != "ECDSA" || pk.PublicKeySHA256 != rep.Certificates[0].PublicKeySHA256 {
				t.Fatalf("local key not parsed: %+v", pk)
			}
		} else {
			if pk.Algorithm != "" || pk.Unknown == "" || pk.Format != KeyFormatPKCS8 {
				t.Fatalf("remote key: %+v", pk)
			}
			for _, call := range ft.recorded() {
				if strings.HasPrefix(call, "read") && strings.Contains(call, "server.key") {
					t.Fatalf("the remote key file was read: %q", call)
				}
			}
		}
		keyAssertNoLeak(t, "running", rep, k.secret())
		if len(rep.Keystores) != 1 || rep.Keystores[0].Type != KeystoreJKS || !platHasUsage(rep.Keystores[0].Location, "process", "nginx", 0) {
			t.Fatalf("keystores: %+v", rep.Keystores)
		}
		if len(rep.Libraries) != 1 || strings.Join(rep.Libraries[0].LoadedBy, ",") != "nginx" || rep.Libraries[0].Source != "file" {
			t.Fatalf("libraries: %+v", rep.Libraries)
		}
		if strings.Contains(platJSON(t, rep), "hunter2") {
			t.Fatal("a secret argument reached the report")
		}
		// The process id is not part of the report.
		if strings.Contains(platJSON(t, rep.Certificates[0].Location.UsedBy), `"42"`) {
			t.Fatal("a pid reached the report")
		}
	}
}

func TestPlatRunningRootAndMissing(t *testing.T) {
	ft := newTgtFakeTarget(true)
	ft.script(platSh(platLinuxRunningScript), tgtResult{stdout: "U 0\nL tcp 1 0100007F:0016\nP 1 sshd\nS 1\n"})
	c := tgtCollection(ft, Options{Platform: hostinventory.PlatformLinux})
	platRunningPass(t.Context(), c)
	if c.report.Sections[SectionProcesses] != SectionOK || c.report.Access.Elevated == nil || !*c.report.Access.Elevated {
		t.Fatalf("%v %+v", c.report.Sections, c.report.Access)
	}
	// macOS without lsof: unsupported.
	ft = newTgtFakeTarget(false)
	ft.script(platSh(platDarwinRunningScript), tgtResult{stdout: "U 501\n", exit: 127})
	c = tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin})
	platRunningPass(t.Context(), c)
	if c.report.Sections[SectionProcesses] != SectionUnsupported {
		t.Fatalf("%v", c.report.Sections)
	}
	// macOS as a user: what lsof shows is used, and the section says what
	// it could not see.
	ft = newTgtFakeTarget(false)
	ft.script(platSh(platDarwinRunningScript), tgtResult{stdout: "U 501\nP 9 ControlCenter\nN tcp *:7000\nN udp [::1]:5353\nP 9\nM /opt/homebrew/opt/openssl@3/lib/libssl.3.dylib\n"})
	c = tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin})
	platRunningPass(t.Context(), c)
	c.registry.finish(c.report)
	if c.report.Sections[SectionProcesses] != SectionPartial || len(c.report.Libraries) != 1 || c.report.Libraries[0].Source != "process" ||
		strings.Join(c.report.Libraries[0].LoadedBy, ",") != "ControlCenter" {
		t.Fatalf("darwin: %v %+v", c.report.Sections, c.report.Libraries)
	}
}

func TestPlatWindowsRunning(t *testing.T) {
	ans := platJSON(t, map[string]any{
		"Elevated": true, "Error": "", "Truncated": false,
		"Listeners": []map[string]any{
			{"Proto": "tcp", "Addr": "0.0.0.0", "Port": 443, "Id": 1200},
			{"Proto": "tcp", "Addr": "::", "Port": 3389, "Id": 900},
			{"Proto": "udp", "Addr": "not-an-ip", "Port": 53, "Id": 1200},
			{"Proto": "tcp", "Addr": "0.0.0.0", "Port": 445, "Id": 4},
		},
		"Procs": []map[string]any{
			{"Id": 1200, "Name": "httpd", "Denied": false, "Libs": []string{`C:\Apache\bin\libssl-3-x64.dll`, `C:\Windows\system32\kernel32.dll`},
				"Args": []string{`C:\Apache\conf\server.crt`, `--password=C:\x.pem`, `C:\Apache\conf\pass\k.pem`}, "CommandLine": "httpd.exe --password=hunter2"},
			{"Id": 900, "Name": "svchost", "Denied": true, "Libs": `C:\Windows\system32\schannel.DLL`, "Args": []string{}},
		},
	})
	r, err := platParseWindowsRunning([]byte(ans))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.procs) != 2 || r.denied != 1 || r.unowned != 0 {
		t.Fatalf("%+v", r)
	}
	h := r.procs[0]
	if len(h.listeners) != 1 || h.listeners[0].Port != 443 || strings.Join(h.libs, ",") != `C:\Apache\bin\libssl-3-x64.dll` || strings.Join(h.args, ",") != `C:\Apache\conf\server.crt` {
		t.Fatalf("httpd: %+v", h)
	}
	if strings.Contains(platJSON(t, map[string]any{"a": h.args, "l": h.libs}), "hunter2") {
		t.Fatal("the command line crossed")
	}

	k := platNewKey(t, "win")
	for _, local := range []bool{true, false} {
		ft := newPlatFakeWin(t, local)
		ft.answers["running"] = ans
		c := tgtCollection(ft, Options{Platform: hostinventory.PlatformWindows})
		// The configuration pass found the certificate; Windows paths match
		// without regard to case.
		cert, err := ParseCertificateDER(k.certDER)
		if err != nil {
			t.Fatal(err)
		}
		cert.Location = Location{Path: `c:\apache\CONF\server.crt`, FoundBy: FoundByConfig}
		c.registry.addCertificate(cert)
		c.registry.addLibrary(CryptoLibrary{Name: "schannel", Path: `C:\Windows\system32\schannel.dll`, Version: "10.0", Source: "file"})
		platRunningPass(t.Context(), c)
		c.registry.finish(c.report)
		rep := c.report
		if rep.Sections[SectionProcesses] != SectionPartial {
			t.Fatalf("%v %+v", rep.Sections, rep.Errors)
		}
		if len(rep.Certificates) != 1 || !platHasUsage(rep.Certificates[0].Location, "listener", "httpd", 443) || rep.Certificates[0].Location.FoundBy != FoundByProcess {
			t.Fatalf("certificates: %+v", rep.Certificates)
		}
		var sch *CryptoLibrary
		for i := range rep.Libraries {
			if rep.Libraries[i].Name == "schannel" {
				sch = &rep.Libraries[i]
			}
		}
		if sch == nil || len(rep.Libraries) != 2 || strings.Join(sch.LoadedBy, ",") != "svchost" {
			t.Fatalf("schannel is one library whatever the case of its path: %+v", rep.Libraries)
		}
	}
}

// TestPlatRealRunningLinux runs pass 3 on this machine: the test listens on
// 127.0.0.1 with a generated certificate and holds the certificate and key
// files open, and the pass must find both, with the listener as a user.
// No root is needed: the process is the test's own.
func TestPlatRealRunningLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("no /proc")
	}
	k := platNewKey(t, "localhost")
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, k.certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, k.keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{certPath, keyPath} {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
	}
	pair, err := tls.X509KeyPair(k.certPEM, k.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	exe, _ := os.Executable()
	name := filepath.Base(exe)

	c := tgtCollection(NewLocalTarget(), Options{Platform: hostinventory.PlatformLinux})
	c.registry.resolve = localRealPath
	platRunningPass(t.Context(), c)
	c.registry.finish(c.report)
	rep := c.report
	if s := rep.Sections[SectionProcesses]; s != SectionOK && s != SectionPartial {
		t.Fatalf("processes: %v %+v", rep.Sections, rep.Errors)
	}
	real := func(p string) string { r, _ := filepath.EvalSymlinks(p); return r }
	var cert *Certificate
	for i := range rep.Certificates {
		if real(rep.Certificates[i].Location.Path) == real(certPath) {
			cert = &rep.Certificates[i]
		}
	}
	if cert == nil || !platHasUsage(cert.Location, "listener", name, port) || cert.Location.FoundBy != FoundByProcess {
		t.Fatalf("the held certificate was not found with its listener (%s:%d): %+v", name, port, rep.Certificates)
	}
	var key *PrivateKey
	for i := range rep.PrivateKeys {
		if real(rep.PrivateKeys[i].Location.Path) == real(keyPath) {
			key = &rep.PrivateKeys[i]
		}
	}
	if key == nil || key.PublicKeySHA256 != cert.PublicKeySHA256 {
		t.Fatalf("the held key: %+v", rep.PrivateKeys)
	}
	keyAssertNoLeak(t, "real running", rep, k.secret())
}
