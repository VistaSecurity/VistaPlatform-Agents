package hostcrypto

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// tgtHostilePaths are names that would change a command's structure if any
// of them reached a shell as text.
var tgtHostilePaths = []string{
	"/srv/has space/key.pem",
	"/srv/it's/a'quote.pem",
	`/srv/dq"uote.pem`,
	"/srv/$(touch pwned).pem",
	"/srv/`id`.pem",
	"/srv/semi;rm -rf x.pem",
	"/srv/new\nline.pem",
	"/srv/-leading-dash.pem",
	"-rf",
	"/srv/glob*?[x].pem",
	"/srv/back\\slash.pem",
}

// tgtIdentifyOut is identifyScript's answer for given markers.
func tgtIdentifyOut(magic []byte, private bool, labels ...string) string {
	var b strings.Builder
	b.WriteString("magic:" + hex.EncodeToString(magic) + "\n")
	if private {
		b.WriteString("private:1\n")
	} else {
		b.WriteString("private:0\n")
	}
	for _, l := range labels {
		b.WriteString("label:-----BEGIN " + l + "-----\n")
	}
	return b.String()
}

func TestRemoteUnixArgv(t *testing.T) {
	for _, platform := range []string{hostinventory.PlatformLinux, hostinventory.PlatformDarwin} {
		for _, p := range tgtHostilePaths {
			fr := newTgtFakeRunner(func(argv []string) tgtResult {
				if argv[2] == "sh" {
					return tgtResult{stdout: tgtIdentifyOut([]byte("# conf\n"), false)}
				}
				return tgtResult{exit: 1, stderr: "stat: x: No such file or directory"}
			})
			rt := NewRemoteUnixTarget(fr, platform)
			_, _ = rt.Identify(context.Background(), p)
			_, _ = rt.Stat(context.Background(), p)
			runs := fr.recordedRuns()
			if len(runs) != 2 {
				t.Fatalf("%s %q: %d runs", platform, p, len(runs))
			}
			wantID := []string{"env", "LC_ALL=C", "sh", "-c", identifyScript, "sh", p}
			if !reflect.DeepEqual(runs[0], wantID) {
				t.Errorf("%s identify argv for %q:\n got %q\nwant %q", platform, p, runs[0], wantID)
			}
			wantStat := []string{"env", "LC_ALL=C", "stat", "-c", "%s|%f|%U|%G|%u|%g|%Y|%n", "--", p}
			if platform == hostinventory.PlatformDarwin {
				wantStat = []string{"env", "LC_ALL=C", "stat", "-f", "%z|%p|%Su|%Sg|%u|%g|%m|%N", "--", p}
			}
			if !reflect.DeepEqual(runs[1], wantStat) {
				t.Errorf("%s stat argv for %q:\n got %q\nwant %q", platform, p, runs[1], wantStat)
			}
			// The fixed script never contains the path.
			if strings.Contains(identifyScript, p) {
				t.Errorf("path %q appears in the script", p)
			}
		}
	}
}

func TestRemoteUnixListArgv(t *testing.T) {
	fr := newTgtFakeRunner(nil)
	rt := NewRemoteUnixTarget(fr, hostinventory.PlatformLinux)
	_, _ = rt.List(context.Background(), "/etc/", ListOptions{
		MaxDepth: 2, MaxFiles: 10,
		Exclude: []string{"/etc/skip*me", "/etc/ssl/private/"},
		Names:   []string{"*.pem", "*.key"},
	})
	runs := fr.recordedRuns()
	if len(runs) != 1 {
		t.Fatalf("runs = %q", runs)
	}
	want := []string{"env", "LC_ALL=C", "sh", "-c", listScript, "sh", "65536",
		"find", "/etc", "-xdev", "-maxdepth", "3",
		"(", "-path", `/etc/skip\*me`, "-o", "-path", `/etc/skip\*me/*`,
		"-o", "-path", "/etc/ssl/private", "-o", "-path", "/etc/ssl/private/*", ")", "-prune", "-o",
		"(", "-type", "f", "-o", "-type", "l", ")",
		"(", "-name", "*.pem", "-o", "-name", "*.key", ")", "-print0"}
	if !reflect.DeepEqual(runs[0], want) {
		t.Fatalf("list argv:\n got %q\nwant %q", runs[0], want)
	}

	fr2 := newTgtFakeRunner(nil)
	_, _ = NewRemoteUnixTarget(fr2, hostinventory.PlatformDarwin).List(context.Background(), "/", ListOptions{CrossFilesystems: true})
	got := fr2.recordedRuns()[0]
	if got[8] != "/" || got[9] != "-maxdepth" {
		t.Fatalf("root / with CrossFilesystems: %q", got)
	}

	// A relative or dash-led root is refused before anything runs.
	fr3 := newTgtFakeRunner(nil)
	for _, root := range []string{"-delete", "etc", ""} {
		if _, err := NewRemoteUnixTarget(fr3, "linux").List(context.Background(), root, ListOptions{}); err == nil {
			t.Errorf("root %q accepted", root)
		}
	}
	if n := len(fr3.recordedRuns()); n != 0 {
		t.Fatalf("%d commands ran for refused roots", n)
	}
}

func TestRemoteUnixListParsing(t *testing.T) {
	paths := []string{"/r/a.pem", "/r/new\nline|odd.pem", "/r/gone.pem", "/r/link", "/r/big.bin", "/r/x/skip/c.pem"}
	find := strings.Join(paths, "\x00") + "\x00"
	fr := newTgtFakeRunner(func(argv []string) tgtResult {
		switch argv[2] {
		case "sh":
			return tgtResult{stdout: find, stderr: "find: '/r/locked': Permission denied\nfind: '/r/x': Permission denied\n"}
		case "stat":
			// gone.pem vanished between find and stat: no record for it.
			return tgtResult{exit: 1, stdout: "" +
				"10|81a4|root|root|0|0|1700000000|/r/a.pem\n" +
				"5|8180|UNKNOWN|UNKNOWN|1001|1002|1700000000|/r/new\nline|odd.pem\n" +
				"7|a1ff|root|root|0|0|1700000000|/r/link\n" +
				"99999999|81a4|root|root|0|0|1700000000|/r/big.bin\n" +
				"3|81a4|root|root|0|0|1700000000|/r/x/skip/c.pem\n",
				stderr: "stat: cannot statx '/r/gone.pem': No such file or directory\n"}
		case "readlink":
			return tgtResult{stdout: "a.pem\n"}
		}
		return tgtResult{exit: 127}
	})
	files, err := NewRemoteUnixTarget(fr, "linux").List(context.Background(), "/r", ListOptions{
		MaxDepth: 5, MaxSizeBytes: 1000, Exclude: []string{"/r/x/skip"},
	})
	var lerr *ListError
	if !errors.As(err, &lerr) || lerr.DeniedCount != 2 || lerr.Truncated {
		t.Fatalf("err = %v (%+v)", err, lerr)
	}
	if !errors.Is(err, ErrPermission) {
		t.Fatal("denied directories did not match ErrPermission")
	}
	var got []string
	for _, f := range files {
		got = append(got, f.Path)
	}
	want := []string{"/r/a.pem", "/r/new\nline|odd.pem", "/r/link"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("files %q, want %q", got, want)
	}
	a, odd, link := files[0], files[1], files[2]
	if a.Mode != 0o644 || !*a.WorldReadable || !*a.GroupReadable || a.Owner != "root" || a.ModifiedAt != "2023-11-14T22:13:20Z" || a.Size != 10 {
		t.Errorf("a.pem: %+v", a)
	}
	if odd.Mode != 0o600 || *odd.WorldReadable || odd.Owner != "1001" || odd.Group != "1002" {
		t.Errorf("odd: %+v", odd)
	}
	if !link.IsSymlink || link.LinkTarget != "a.pem" {
		t.Errorf("link: %+v", link)
	}
}

func TestRemoteUnixListTruncation(t *testing.T) {
	var find strings.Builder
	for i := 0; i < 5; i++ {
		find.WriteString(fmt.Sprintf("/r/f%d.pem", i) + "\x00")
	}
	fr := newTgtFakeRunner(func(argv []string) tgtResult {
		if argv[2] == "sh" {
			return tgtResult{stdout: find.String()}
		}
		// Answer only the paths asked for, in order.
		var b strings.Builder
		for _, p := range argv[6:] {
			b.WriteString("1|81a4|root|root|0|0|1700000000|" + p + "\n")
		}
		return tgtResult{stdout: b.String()}
	})
	files, err := NewRemoteUnixTarget(fr, "linux").List(context.Background(), "/r", ListOptions{MaxFiles: 3})
	if !errors.Is(err, ErrListTruncated) || len(files) != 3 {
		t.Fatalf("files=%d err=%v", len(files), err)
	}

	// Output cut at the byte bound: the partial last path is dropped.
	cut := strings.Repeat("x", listByteCap(1))
	fr2 := newTgtFakeRunner(func(argv []string) tgtResult {
		if argv[2] == "sh" {
			return tgtResult{stdout: "/r/a.pem\x00" + cut[:len(cut)-len("/r/a.pem\x00")]}
		}
		return tgtResult{stdout: "1|81a4|root|root|0|0|1700000000|/r/a.pem\n"}
	})
	files, err = NewRemoteUnixTarget(fr2, "linux").List(context.Background(), "/r", ListOptions{MaxFiles: 1})
	if !errors.Is(err, ErrListTruncated) || len(files) != 1 || files[0].Path != "/r/a.pem" {
		t.Fatalf("cut: files=%+v err=%v", files, err)
	}
}

func TestRemoteUnixErrors(t *testing.T) {
	cases := []struct {
		exit int
		want error
	}{
		{identifyExitNotExist, ErrNotExist},
		{identifyExitPermission, ErrPermission},
	}
	for _, tc := range cases {
		fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{exit: tc.exit} })
		if _, err := NewRemoteUnixTarget(fr, "linux").Identify(context.Background(), "/x"); !errors.Is(err, tc.want) {
			t.Errorf("exit %d: %v", tc.exit, err)
		}
	}
	for stderr, want := range map[string]error{
		"stat: cannot statx '/x': No such file or directory": ErrNotExist,
		"stat: cannot statx '/x': Permission denied":         ErrPermission,
	} {
		fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{exit: 1, stderr: stderr} })
		if _, err := NewRemoteUnixTarget(fr, "linux").Stat(context.Background(), "/x"); !errors.Is(err, want) {
			t.Errorf("%q: %v", stderr, err)
		}
	}
	// Root missing or unreadable: find says so on stderr and prints nothing.
	for stderr, want := range map[string]error{
		"find: '/r': No such file or directory": ErrNotExist,
		"find: '/r': Permission denied":         ErrPermission,
	} {
		fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{stderr: stderr} })
		if _, err := NewRemoteUnixTarget(fr, "linux").List(context.Background(), "/r", ListOptions{}); !errors.Is(err, want) {
			t.Errorf("list %q: %v", stderr, err)
		}
	}
	// A transport failure is passed through.
	boom := errors.New("connection reset")
	fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{exit: -1, err: boom} })
	if _, err := NewRemoteUnixTarget(fr, "linux").Identify(context.Background(), "/x"); !errors.Is(err, boom) {
		t.Errorf("transport: %v", err)
	}
	// An answer missing the private line is not trusted.
	fr = newTgtFakeRunner(func([]string) tgtResult {
		return tgtResult{stdout: "magic:2d2d2d2d2d424547\nlabel:-----BEGIN CERTIFICATE-----\n"}
	})
	if _, err := NewRemoteUnixTarget(fr, "linux").Identify(context.Background(), "/x"); err == nil {
		t.Error("an incomplete identify answer was accepted")
	}
}

// TestRemoteUnixReadFileGuard is THE guard: for every class that is not
// public, ReadFile returns ErrNotPublic, the runner's ReadFile is never
// called, and the only command sent is the identify script, which prints
// markers and nothing else. Mutation-checked by deleting the Public() test in
// ReadFile: every case below then fails.
func TestRemoteUnixReadFileGuard(t *testing.T) {
	type answer struct {
		name    string
		path    string
		magic   []byte
		private bool
		labels  []string
	}
	notPublic := []answer{
		{"pkcs8", "/etc/ssl/private/server.key", []byte("-----BEG"), true, []string{"PRIVATE KEY"}},
		{"rsa", "/k/rsa.pem", []byte("-----BEG"), true, []string{"RSA PRIVATE KEY"}},
		{"openssh", "/home/u/.ssh/id_ed25519", []byte("-----BEG"), true, []string{"OPENSSH PRIVATE KEY"}},
		{"encrypted", "/k/enc.pem", []byte("-----BEG"), true, []string{"ENCRYPTED PRIVATE KEY"}},
		{"mixed", "/k/both.pem", []byte("-----BEG"), true, []string{"CERTIFICATE", "PRIVATE KEY"}},
		{"key past label bound", "/k/bundle.pem", []byte("-----BEG"), true, []string{"CERTIFICATE"}},
		{"private marker on text", "/k/notes.txt", []byte("notes ab"), true, nil},
		{"jks", "/k/a.jks", magicJKS, false, nil},
		{"jceks", "/k/a.jceks", magicJCEKS, false, nil},
		{"pkcs12 by name", "/k/a.p12", []byte{0x30, 0x82, 1, 2, 2, 1, 3, 0x30}, false, nil},
		{"bare der", "/k/a.der", []byte{0x30, 0x82, 1, 2, 2, 1, 3, 0x30}, false, nil},
		{"keytab", "/etc/krb5.keytab", []byte{5, 2, 0, 0, 0, 0x40, 0, 2}, false, nil},
		{"putty", "/k/a.ppk", []byte("PuTTY-Us"), false, nil},
		{"ssh1", "/k/identity", []byte("SSH PRIV"), false, nil},
		{"nss", "/home/u/.pki/nssdb/key4.db", []byte("SQLite f"), false, nil},
		{"pgp armoured", "/k/sec.asc", []byte("-----BEG"), false, []string{"PGP PRIVATE KEY BLOCK"}},
		{"keychain", "/Library/Keychains/System.keychain", []byte("kych\x00\x01\x00\x00"), false, nil},
		{"unknown label", "/etc/openvpn/static.key", []byte("-----BEG"), false, []string{"OpenVPN Static key V1"}},
		{"binary", "/k/blob", []byte{0, 1, 2, 3, 4, 5, 6, 7}, false, nil},
	}
	for _, platform := range []string{"linux", "darwin"} {
		for _, a := range notPublic {
			t.Run(platform+"/"+a.name, func(t *testing.T) {
				fr := newTgtFakeRunner(func(argv []string) tgtResult {
					return tgtResult{stdout: tgtIdentifyOut(a.magic, a.private, a.labels...)}
				})
				fr.readData[a.path] = []byte("MUST NOT BE READ")
				_, err := NewRemoteUnixTarget(fr, platform).ReadFile(context.Background(), a.path)
				if !errors.Is(err, ErrNotPublic) {
					t.Fatalf("err = %v, want ErrNotPublic", err)
				}
				if reads := fr.recordedReads(); len(reads) != 0 {
					t.Fatalf("runner ReadFile called: %q", reads)
				}
				runs := fr.recordedRuns()
				if len(runs) != 1 || !reflect.DeepEqual(runs[0], NewRemoteUnixTarget(fr, platform).identifyArgv(a.path)) {
					t.Fatalf("commands sent: %q", runs)
				}
				for _, argv := range runs {
					for _, w := range argv {
						if w == "cat" || w == "dd" || w == "base64" || w == "xxd" {
							t.Fatalf("a content-printing program was sent: %q", argv)
						}
					}
				}
			})
		}
	}

	// The other polarity: a public file IS read, once, and returned.
	certPEM, _, _, _ := tgtMaterial(t)
	fr := newTgtFakeRunner(func([]string) tgtResult {
		return tgtResult{stdout: tgtIdentifyOut(certPEM[:8], false, "CERTIFICATE")}
	})
	fr.readData["/etc/ssl/certs/a.pem"] = certPEM
	b, err := NewRemoteUnixTarget(fr, "linux").ReadFile(context.Background(), "/etc/ssl/certs/a.pem")
	if err != nil || string(b) != string(certPEM) {
		t.Fatalf("public read: %v", err)
	}
	if reads := fr.recordedReads(); len(reads) != 1 {
		t.Fatalf("reads = %q", reads)
	}

	// The recheck: the host said "certificate", the bytes are a key.
	_, keyPEM, _, _ := tgtMaterial(t)
	fr = newTgtFakeRunner(func([]string) tgtResult {
		return tgtResult{stdout: tgtIdentifyOut(certPEM[:8], false, "CERTIFICATE")}
	})
	fr.readData["/x/swapped.pem"] = append([]byte(nil), keyPEM...)
	if _, err := NewRemoteUnixTarget(fr, "linux").ReadFile(context.Background(), "/x/swapped.pem"); !errors.Is(err, ErrNotPublic) {
		t.Fatalf("swapped content: %v", err)
	}
}

// tgtRealToolsAvailable reports whether this machine can run the remote Unix
// commands for real, through a LocalRunner.
func tgtRealToolsAvailable() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return false
	}
	for _, p := range []string{"sh", "env", "find", "stat", "grep", "head", "od", "tr", "sed", "readlink"} {
		if _, err := exec.LookPath(p); err != nil {
			return false
		}
	}
	return true
}

// TestRemoteUnixRealTools drives RemoteUnixTarget through a LocalRunner
// against a real directory, so the find, stat, grep, head and od flags are
// checked against the real tools of this machine (GNU on Linux, BSD on
// macOS) rather than against a fake's idea of them.
func TestRemoteUnixRealTools(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	certPEM, keyPEM, certDER, _ := tgtMaterial(t)
	dir := t.TempDir()
	hostile := []string{"has space.pem", "it's.pem", "$(touch pwned).pem", "-dash.pem", "new\nline.pem", "glob*?[x].pem"}
	for _, n := range hostile {
		tgtWrite(t, dir, n, certPEM, 0o644)
	}
	tgtWrite(t, dir, "server.key", keyPEM, 0o600)
	tgtWrite(t, dir, "both.pem", append(append([]byte(nil), certPEM...), keyPEM...), 0o644)
	tgtWrite(t, dir, "c.der", certDER, 0o644)
	tgtWrite(t, dir, "sub/deep/d.crt", certPEM, 0o640)
	tgtWrite(t, dir, "nginx.conf", []byte("ssl_protocols TLSv1.2;\n"), 0o644)
	var bundle []byte
	for i := 0; i < 70; i++ {
		bundle = append(bundle, certPEM...)
	}
	tgtWrite(t, dir, "bundle.pem", append(bundle, keyPEM...), 0o644)
	if err := os.Symlink("server.key", filepath.Join(dir, "link.key")); err != nil {
		t.Fatal(err)
	}

	rr := &tgtRecordingRunner{inner: hostinventory.NewLocalRunner()}
	rt := NewRemoteUnixTarget(rr, runtime.GOOS)
	ctx := context.Background()

	classes := map[string]Class{
		"server.key": ClassPrivateKey, "both.pem": ClassMixed, "c.der": ClassUnknown,
		"nginx.conf": ClassText, "bundle.pem": ClassMixed, "sub/deep/d.crt": ClassCertificate,
	}
	for _, n := range hostile {
		classes[n] = ClassCertificate
	}
	for rel, want := range classes {
		id, err := rt.Identify(ctx, filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("Identify %q: %v", rel, err)
		}
		if id.Class != want {
			t.Errorf("Identify %q = %q, want %q (labels %q)", rel, id.Class, want, id.PEMLabels)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Fatal("a file name was executed")
	}
	if _, err := rt.Identify(ctx, filepath.Join(dir, "missing")); !errors.Is(err, ErrNotExist) {
		t.Errorf("missing: %v", err)
	}

	// Stat: mode, link, hostile name.
	fi, err := rt.Stat(ctx, filepath.Join(dir, "sub/deep/d.crt"))
	if err != nil || fi.Mode != 0o640 || *fi.WorldReadable || !*fi.GroupReadable || fi.Size != int64(len(certPEM)) {
		t.Fatalf("Stat: %+v %v", fi, err)
	}
	fi, err = rt.Stat(ctx, filepath.Join(dir, "link.key"))
	if err != nil || !fi.IsSymlink || fi.LinkTarget != "server.key" {
		t.Fatalf("Stat link: %+v %v", fi, err)
	}
	fi, err = rt.Stat(ctx, filepath.Join(dir, "new\nline.pem"))
	if err != nil || fi.Path != filepath.Join(dir, "new\nline.pem") {
		t.Fatalf("Stat newline: %+v %v", fi, err)
	}
	if _, err := rt.Stat(ctx, filepath.Join(dir, "missing")); !errors.Is(err, ErrNotExist) {
		t.Errorf("Stat missing: %v", err)
	}

	// List: every file, the link reported as a link, the depth bound.
	files, err := rt.List(ctx, dir, ListOptions{MaxDepth: 5})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := tgtRels(t, dir, files); len(got) != len(hostile)+7 {
		t.Fatalf("List got %d: %q", len(got), got)
	}
	shallow, err := rt.List(ctx, dir, ListOptions{MaxDepth: 0, Names: []string{"*.key"}})
	if err != nil || strings.Join(tgtRels(t, dir, shallow), ",") != "link.key,server.key" {
		t.Fatalf("List shallow: %q %v", tgtRels(t, dir, shallow), err)
	}
	for _, f := range shallow {
		if strings.HasSuffix(f.Path, "link.key") && (!f.IsSymlink || f.LinkTarget != "server.key") {
			t.Errorf("link in listing: %+v", f)
		}
	}
	excl, err := rt.List(ctx, dir, ListOptions{MaxDepth: 5, Exclude: []string{filepath.Join(dir, "sub")}, Names: []string{"*.crt"}})
	if err != nil || len(excl) != 0 {
		t.Fatalf("List exclude: %q %v", tgtRels(t, dir, excl), err)
	}
	trunc, err := rt.List(ctx, dir, ListOptions{MaxDepth: 5, MaxFiles: 2})
	if !errors.Is(err, ErrListTruncated) || len(trunc) != 2 {
		t.Fatalf("List truncated: %d %v", len(trunc), err)
	}

	// The guard against the real tools: no read of any non-public file, and
	// a read of a public one.
	rr.reads = nil
	for _, rel := range []string{"server.key", "both.pem", "bundle.pem", "c.der", "link.key"} {
		if _, err := rt.ReadFile(ctx, filepath.Join(dir, rel)); !errors.Is(err, ErrNotPublic) {
			t.Errorf("ReadFile %s: %v", rel, err)
		}
	}
	if len(rr.reads) != 0 {
		t.Fatalf("non-public files were read: %q", rr.reads)
	}
	b, err := rt.ReadFile(ctx, filepath.Join(dir, "has space.pem"))
	if err != nil || string(b) != string(certPEM) {
		t.Fatalf("public ReadFile: %v", err)
	}

	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "sub")
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(locked, 0o755) }()
		_, err := rt.List(ctx, dir, ListOptions{MaxDepth: 5})
		var lerr *ListError
		if !errors.As(err, &lerr) || lerr.DeniedCount != 1 || lerr.Denied[0] != locked {
			t.Fatalf("denied subdirectory: %v %+v", err, lerr)
		}
	}
}
