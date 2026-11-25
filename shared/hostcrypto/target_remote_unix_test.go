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
	"/srv/a=b.conf",
}

// tgtIdentifyOut renders identifyScript's answer for an inspection, so a
// fake host answers exactly as the awk program would for those bytes.
func tgtIdentifyOut(in inspection) string {
	b01 := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	var b strings.Builder
	fmt.Fprintf(&b, "size:%d\nmagic:%s\nnul:%d\nutf16:%d\n", in.size, hex.EncodeToString(in.magic), b01(in.nul), b01(in.utf16Private))
	for _, l := range in.labels {
		b.WriteString("label:" + l + "\n")
	}
	fmt.Fprintf(&b, "flags:%d %d %d %d %d %d %d %d\n", b01(in.bad), b01(in.nonPublic), b01(in.unterminated),
		b01(in.private), b01(in.outsideRun), b01(in.sshBad), in.sshLines, in.nLabel)
	return b.String()
}

// tgtIdentifyFor is the fake host's identify answer for content.
func tgtIdentifyFor(content []byte) string {
	return tgtIdentifyOut(inspect(content, int64(len(content))))
}

func TestRemoteUnixArgv(t *testing.T) {
	for _, platform := range []string{hostinventory.PlatformLinux, hostinventory.PlatformDarwin} {
		for _, p := range tgtHostilePaths {
			fr := newTgtFakeRunner(func(argv []string) tgtResult {
				if len(argv) > 2 && argv[2] == "sh" {
					return tgtResult{stdout: tgtIdentifyFor([]byte("# conf\n"))}
				}
				return tgtResult{exit: 1, stderr: "stat: x: No such file or directory"}
			})
			rt := NewRemoteUnixTarget(fr, platform)
			_, _ = rt.Identify(context.Background(), p)
			_, _ = rt.Stat(context.Background(), p)
			_, _, _ = rt.ReadText(context.Background(), p, []string{"ciphers", "SSL_Protocols", KeepOptStatements})
			runs := fr.recordedRuns()
			if len(runs) != 3 {
				t.Fatalf("%s %q: %d runs", platform, p, len(runs))
			}
			wantID := []string{"env", "LC_ALL=C", "sh", "-c", identifyScript, "sh", p, platform, "10485760"}
			if !reflect.DeepEqual(runs[0], wantID) {
				t.Errorf("%s identify argv for %q:\n got %q\nwant %q", platform, p, runs[0], wantID)
			}
			wantStat := []string{"env", "LC_ALL=C", "QUOTING_STYLE=literal", "stat", "--printf", `%s|%f|%U|%G|%u|%g|%Y|%n\0%N\0`, "--", p}
			if platform == hostinventory.PlatformDarwin {
				wantStat = []string{"env", "LC_ALL=C", "stat", "-f", "%z|%p|%Su|%Sg|%u|%g|%m|%N|%Y", "--", p}
			}
			if !reflect.DeepEqual(runs[1], wantStat) {
				t.Errorf("%s stat argv for %q:\n got %q\nwant %q", platform, p, runs[1], wantStat)
			}
			wantText := []string{"env", "LC_ALL=C", "sh", "-c", readTextScript, "sh", p, platform, "8000000", "ciphers ssl_protocols @statements"}
			if !reflect.DeepEqual(runs[2], wantText) {
				t.Errorf("%s readtext argv for %q:\n got %q", platform, p, runs[2])
			}
			for _, script := range []string{identifyScript, readScript, readTextScript} {
				if strings.Contains(script, p) {
					t.Errorf("path %q appears in a script", p)
				}
			}
		}
	}
}

// TestAwkRulesFitInSingleQuotes: the awk program is embedded in the shell
// scripts in single quotes; a quote inside it would end the literal.
func TestAwkRulesFitInSingleQuotes(t *testing.T) {
	if strings.ContainsRune(awkRules, '\'') {
		t.Fatal("awkRules contains a single quote")
	}
	for _, l := range publicPEMLabels {
		if strings.ContainsAny(l, "|'\"\\") {
			t.Fatalf("label %q cannot be embedded", l)
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

// tgtGNUStat renders GNU stat --printf records for the fake.
func tgtGNUStat(recs ...[3]string) string {
	var b strings.Builder
	for _, r := range recs {
		n := r[1]
		if r[2] != "" {
			n += " -> " + r[2]
		}
		b.WriteString(r[0] + "|" + r[1] + "\x00" + n + "\x00")
	}
	return b.String()
}

func TestRemoteUnixListParsing(t *testing.T) {
	long := "/r/" + strings.Repeat("L", 4150) + ".pem"
	paths := []string{"/r/z.pem", "/r/a.pem", "/r/new\nline|odd.pem", "/r/gone.pem", "/r/link", "/r/big.bin", "/r/x/skip/c.pem", long}
	find := strings.Join(paths, "\x00") + "\x00"
	fr := newTgtFakeRunner(func(argv []string) tgtResult {
		switch argv[2] {
		case "sh":
			return tgtResult{stdout: find, stderr: "find: '/r/locked': Permission denied\nfind: '/r/x': Permission denied\nfind: '/r/deep': File name too long\n"}
		case "QUOTING_STYLE=literal":
			// gone.pem vanished and the long name is too long for stat: no
			// records for either.
			return tgtResult{exit: 1, stdout: tgtGNUStat(
				[3]string{"10|81a4|root|root|0|0|1700000000", "/r/a.pem", ""},
				[3]string{"5|8180|UNKNOWN|UNKNOWN|1001|1002|1700000000", "/r/new\nline|odd.pem", ""},
				[3]string{"7|a1ff|root|root|0|0|1700000000", "/r/link", "a target\nwith newline"},
				[3]string{"99999999|81a4|root|root|0|0|1700000000", "/r/big.bin", ""},
				[3]string{"3|81a4|root|root|0|0|1700000000", "/r/x/skip/c.pem", ""},
				[3]string{"3|81a4|root|root|0|0|1700000000", "/r/z.pem", ""},
			), stderr: "stat: cannot statx '/r/gone.pem': No such file or directory\nstat: cannot statx: File name too long\n"}
		}
		return tgtResult{exit: 127}
	})
	files, err := NewRemoteUnixTarget(fr, "linux").List(context.Background(), "/r", ListOptions{
		MaxDepth: 5, MaxSizeBytes: 1000, Exclude: []string{"/r/x/skip"},
	})
	var lerr *ListError
	if !errors.As(err, &lerr) || lerr.DeniedCount != 2 || lerr.Truncated || lerr.OverSize != 1 || lerr.Unreadable != 3 {
		t.Fatalf("err = %v (%+v)", err, lerr)
	}
	if !errors.Is(err, ErrPermission) || errors.Is(err, ErrListTruncated) {
		t.Fatal("Is() broken by the new counts")
	}
	var got []string
	for _, f := range files {
		got = append(got, f.Path)
	}
	want := []string{"/r/a.pem", "/r/link", "/r/new\nline|odd.pem", "/r/z.pem"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("files %q, want %q", got, want)
	}
	a, link, odd := files[0], files[1], files[2]
	if a.Mode != 0o644 || !*a.WorldReadable || !*a.GroupReadable || a.Owner != "root" || a.ModifiedAt != "2023-11-14T22:13:20Z" || a.Size != 10 {
		t.Errorf("a.pem: %+v", a)
	}
	if odd.Mode != 0o600 || *odd.WorldReadable || odd.Owner != "1001" || odd.Group != "1002" {
		t.Errorf("odd: %+v", odd)
	}
	if !link.IsSymlink || link.LinkTarget != "a target\nwith newline" {
		t.Errorf("link: %+v", link)
	}
	// One stat batch for everything, link targets included: no per-link
	// round trip.
	if n := len(fr.recordedRuns()); n != 2 {
		t.Fatalf("%d commands for one listing, want 2", n)
	}

	// The BSD form.
	fb := newTgtFakeRunner(func(argv []string) tgtResult {
		if argv[2] == "sh" {
			return tgtResult{stdout: "/r/a.pem\x00/r/gone\x00/r/l\x00"}
		}
		return tgtResult{stdout: "10|100644|root|wheel|0|0|1700000000|/r/a.pem|\n7|120755|root|wheel|0|0|1700000000|/r/l|a.pem\n"}
	})
	files, err = NewRemoteUnixTarget(fb, "darwin").List(context.Background(), "/r", ListOptions{MaxDepth: 1})
	if !errors.As(err, &lerr) || lerr.Unreadable != 1 || len(files) != 2 || files[1].LinkTarget != "a.pem" || files[0].Group != "wheel" {
		t.Fatalf("bsd: %+v %v", files, err)
	}
}

func TestRemoteUnixListTruncationIsDeterministic(t *testing.T) {
	// find returns the files in a different order each run; the cut must not.
	orders := [][]int{{4, 2, 0, 3, 1}, {0, 1, 2, 3, 4}, {3, 1, 4, 0, 2}}
	var first []string
	for _, order := range orders {
		var find strings.Builder
		for _, i := range order {
			fmt.Fprintf(&find, "/r/f%d.pem\x00", i)
		}
		fr := newTgtFakeRunner(func(argv []string) tgtResult {
			if argv[2] == "sh" {
				return tgtResult{stdout: find.String()}
			}
			var b strings.Builder
			for _, p := range argv[7:] {
				b.WriteString("1|81a4|root|root|0|0|1700000000|" + p + "\x00" + p + "\x00")
			}
			return tgtResult{stdout: b.String()}
		})
		files, err := NewRemoteUnixTarget(fr, "linux").List(context.Background(), "/r", ListOptions{MaxFiles: 3})
		if !errors.Is(err, ErrListTruncated) || len(files) != 3 {
			t.Fatalf("files=%d err=%v", len(files), err)
		}
		var got []string
		for _, f := range files {
			got = append(got, f.Path)
		}
		if first == nil {
			first = got
		} else if !reflect.DeepEqual(first, got) {
			t.Fatalf("cut depends on find order: %q vs %q", first, got)
		}
	}
	if strings.Join(first, ",") != "/r/f0.pem,/r/f1.pem,/r/f2.pem" {
		t.Fatalf("cut = %q", first)
	}

	// Output cut at the byte bound: the partial last path is dropped.
	cut := strings.Repeat("x", listByteCap(1))
	fr2 := newTgtFakeRunner(func(argv []string) tgtResult {
		if argv[2] == "sh" {
			return tgtResult{stdout: "/r/a.pem\x00" + cut[:len(cut)-len("/r/a.pem\x00")]}
		}
		return tgtResult{stdout: "1|81a4|root|root|0|0|1700000000|/r/a.pem\x00/r/a.pem\x00"}
	})
	files, err := NewRemoteUnixTarget(fr2, "linux").List(context.Background(), "/r", ListOptions{MaxFiles: 1})
	if !errors.Is(err, ErrListTruncated) || len(files) != 1 || files[0].Path != "/r/a.pem" {
		t.Fatalf("cut: files=%+v err=%v", files, err)
	}
}

func TestRemoteUnixErrors(t *testing.T) {
	for exit, want := range map[int]error{3: ErrNotExist, 4: ErrPermission, 6: errNotRegular, 7: ErrFileTooLarge, 8: ErrNotPublic, 9: errChanged} {
		fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{exit: exit} })
		rt := NewRemoteUnixTarget(fr, "linux")
		if _, err := rt.Identify(context.Background(), "/x"); exit != 7 && exit != 8 && !errors.Is(err, want) {
			t.Errorf("identify exit %d: %v", exit, err)
		}
		if _, _, err := rt.ReadText(context.Background(), "/x", []string{"a"}); !errors.Is(err, want) {
			t.Errorf("readtext exit %d: %v", exit, err)
		}
	}
	// errNotRegular is not ErrNotPublic or ErrNotExist.
	if err := scriptError("/x", 6); errors.Is(err, ErrNotPublic) || errors.Is(err, ErrNotExist) {
		t.Errorf("not-regular matched another sentinel: %v", err)
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
	for stderr, want := range map[string]error{
		"find: '/r': No such file or directory": ErrNotExist,
		"find: '/r': Permission denied":         ErrPermission,
	} {
		fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{stderr: stderr} })
		if _, err := NewRemoteUnixTarget(fr, "linux").List(context.Background(), "/r", ListOptions{}); !errors.Is(err, want) {
			t.Errorf("list %q: %v", stderr, err)
		}
	}
	boom := errors.New("connection reset")
	fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{exit: -1, err: boom} })
	if _, err := NewRemoteUnixTarget(fr, "linux").Identify(context.Background(), "/x"); !errors.Is(err, boom) {
		t.Errorf("transport: %v", err)
	}
	// An answer missing a line is not trusted.
	for _, out := range []string{
		"size:10\nmagic:2d2d2d2d2d424547\nlabel:CERTIFICATE\nflags:0 0 0 0 0 0 0 1\n",
		"size:10\nmagic:2d2d2d2d2d424547\nnul:0\nlabel:CERTIFICATE\n",
		"size:10\nmagic:2d2d2d2d2d424547\nnul:0\nlabel:CERTIFICATE\nflags:0 0 0 0 0 0 0\n",
		"size:10\nmagic:2d2d2d2d2d424547\nnul:0\nlabel:CERTIFICATE\nlabel:CERTIFICATE\nflags:0 0 0 0 0 0 0 1\n",
	} {
		fr = newTgtFakeRunner(func([]string) tgtResult { return tgtResult{stdout: out} })
		if _, err := NewRemoteUnixTarget(fr, "linux").Identify(context.Background(), "/x.pem"); err == nil {
			t.Errorf("incomplete answer accepted: %q", out)
		}
	}
	// A label the host returns that is not a valid label makes the file not
	// public and is not kept.
	fr = newTgtFakeRunner(func([]string) tgtResult {
		return tgtResult{stdout: "size:10\nmagic:2d2d2d2d2d424547\nnul:0\nutf16:0\nlabel:CERTIFICATE\nlabel:bad label\nflags:0 0 0 0 0 0 0 2\n"}
	})
	id, err := NewRemoteUnixTarget(fr, "linux").Identify(context.Background(), "/x.pem")
	if err != nil || id.Public() || len(id.PEMLabels) != 1 {
		t.Errorf("bad label: %+v %v", id, err)
	}
	// The host's redaction count is required.
	fr = newTgtFakeRunner(func([]string) tgtResult { return tgtResult{stdout: "a = b\n"} })
	if _, _, err := NewRemoteUnixTarget(fr, "linux").ReadText(context.Background(), "/x", []string{"a"}); err == nil {
		t.Error("readtext without a count accepted")
	}
}

// TestRemoteUnixReadFileGuard is THE guard: for every file that is not
// public, ReadFile returns ErrNotPublic, nothing but the identify script is
// sent, and the runner's own ReadFile is never called. Mutation-checked by
// deleting the Public() test in ReadFile: every case then fails.
func TestRemoteUnixReadFileGuard(t *testing.T) {
	certPEM, keyPEM, certDER, _ := tgtMaterial(t)
	secret := strings.Repeat("Q", 44)
	notPublic := []struct {
		name    string
		path    string
		content []byte
	}{
		{"pkcs8", "/etc/ssl/private/server.key", keyPEM},
		{"mixed", "/k/both.pem", append(append([]byte(nil), certPEM...), keyPEM...)},
		{"dashed private label", "/k/dash.key", []byte("-----BEGIN X-PRIVATE KEY-----\nAAAA\n-----END X-PRIVATE KEY-----\n")},
		{"wireguard text", "/etc/wireguard/wg0.conf", []byte("[Interface]\nPrivateKey = " + secret + "\n")},
		{"bare base64", "/k/private.key", []byte(secret + "\n")},
		{"jks", "/k/a.jks", append(append([]byte(nil), magicJKS...), 0, 0, 0, 2)},
		{"pkcs12 by name", "/k/a.p12", certDER},
		{"bare der", "/k/a.der", certDER},
		{"utf16 cert", "/k/u.pem", []byte("\xff\xfe-\x00-\x00-\x00-\x00-\x00B\x00E\x00G\x00I\x00N\x00")},
		{"base64 label", "/k/l.pem", []byte("-----BEGIN YY99uuY1gWotaYup510A3QVEZh0RN8YzrOkWD0re-----\n")},
		{"tor secret", "/var/lib/tor/hs/hs_ed25519_secret_key", append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), make([]byte, 64)...)},
	}
	for _, platform := range []string{"linux", "darwin"} {
		for _, a := range notPublic {
			t.Run(platform+"/"+a.name, func(t *testing.T) {
				fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{stdout: tgtIdentifyFor(a.content)} })
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
					t.Fatalf("commands sent: %d", len(runs))
				}
			})
		}
	}

	// The other polarity: a public file is identified, read by the read
	// script, and returned.
	fr := newTgtFakeRunner(func(argv []string) tgtResult {
		if argv[4] == readScript {
			return tgtResult{stdout: string(certPEM)}
		}
		return tgtResult{stdout: tgtIdentifyFor(certPEM)}
	})
	b, err := NewRemoteUnixTarget(fr, "linux").ReadFile(context.Background(), "/etc/ssl/certs/a.pem")
	if err != nil || string(b) != string(certPEM) {
		t.Fatalf("public read: %v", err)
	}
	if runs := fr.recordedRuns(); len(runs) != 2 || runs[1][4] != readScript || runs[1][8] != "8000000" {
		t.Fatalf("runs: %d", len(runs))
	}

	// A certificate with a secret pasted after it: the read returns the
	// certificate and nothing else; a host that sent the rest is refused.
	cts := append(append([]byte(nil), certPEM...), "PrivateKey: "+secret+"\n"...)
	for _, honest := range []bool{true, false} {
		fr := newTgtFakeRunner(func(argv []string) tgtResult {
			if argv[4] == readScript {
				if !honest {
					return tgtResult{stdout: string(cts)}
				}
				pub, _ := publicContent(cts)
				return tgtResult{stdout: string(pub)}
			}
			return tgtResult{stdout: tgtIdentifyFor(cts)}
		})
		b, err := NewRemoteUnixTarget(fr, "linux").ReadFile(context.Background(), "/k/cert_then_secret.pem")
		if honest && (err != nil || string(b) != string(certPEM)) {
			t.Fatalf("cert then secret: %v %q", err, b)
		}
		if !honest && !errors.Is(err, ErrNotPublic) {
			t.Fatalf("a host returning the secret was not refused: %v", err)
		}
	}

	// The recheck: the host said "certificate", the bytes are a key.
	fr = newTgtFakeRunner(func(argv []string) tgtResult {
		if argv[4] == readScript {
			return tgtResult{stdout: string(keyPEM)}
		}
		return tgtResult{stdout: tgtIdentifyFor(certPEM)}
	})
	if _, err := NewRemoteUnixTarget(fr, "linux").ReadFile(context.Background(), "/x/swapped.pem"); !errors.Is(err, ErrNotPublic) {
		t.Fatalf("swapped content: %v", err)
	}

	// Over the cap: refused from Identify's size, nothing read.
	big := tgtIdentifyOut(inspection{size: remoteUnixReadMax + 1, magic: []byte("-----BEG"), labels: []string{"CERTIFICATE"}, nLabel: 1})
	fr = newTgtFakeRunner(func([]string) tgtResult { return tgtResult{stdout: big} })
	if _, err := NewRemoteUnixTarget(fr, "linux").ReadFile(context.Background(), "/x/big.pem"); !errors.Is(err, ErrFileTooLarge) || len(fr.recordedRuns()) != 1 {
		t.Fatalf("too large: %v, %d runs", err, len(fr.recordedRuns()))
	}
	// MaxFileBytes reaches the target.
	rt := NewRemoteUnixTarget(fr, "linux")
	rt.SetMaxFileBytes(1000)
	if rt.readCap() != 1000 || rt.identifyArgv("/x")[8] != "1000" {
		t.Fatal("SetMaxFileBytes not honoured")
	}
}

// tgtRealToolsAvailable reports whether this machine can run the remote Unix
// commands for real, through a LocalRunner.
func tgtRealToolsAvailable() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		// Linux pins through /proc/self/fd, macOS through fstat of fd 3; a
		// test binary cross-compiled for a Mac runs every real-tools test.
		return false
	}
	for _, p := range []string{"sh", "env", "find", "stat", "awk", "head", "tail", "od", "tr", "wc", "cat"} {
		if _, err := exec.LookPath(p); err != nil {
			return false
		}
	}
	return true
}

// TestRemoteUnixRealTools drives RemoteUnixTarget through a LocalRunner
// against a real directory, so every flag is checked against this machine's
// real tools rather than a fake's idea of them.
func TestRemoteUnixRealTools(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	if !tgtRealToolsAvailable() {
		t.Skip("Linux POSIX tools not available")
	}
	certPEM, keyPEM, certDER, _ := tgtMaterial(t)
	dir := t.TempDir()
	hostile := []string{"has space.pem", "it's.pem", "$(touch pwned).pem", "-dash.pem", "new\nline.pem", "glob*?[x].pem", "a=b.pem"}
	for _, n := range hostile {
		tgtWrite(t, dir, n, certPEM, 0o644)
	}
	tgtWrite(t, dir, "server.key", keyPEM, 0o600)
	tgtWrite(t, dir, "both.pem", append(append([]byte(nil), certPEM...), keyPEM...), 0o644)
	tgtWrite(t, dir, "c.der", certDER, 0o644)
	tgtWrite(t, dir, "sub/deep/d.crt", certPEM, 0o640)
	tgtWrite(t, dir, "nginx.conf", []byte("ssl_protocols TLSv1.2;\n"), 0o644)
	tgtWrite(t, dir, "big.bin", make([]byte, 2048), 0o644)
	var bundle []byte
	for i := 0; i < 70; i++ {
		bundle = append(bundle, certPEM...)
	}
	tgtWrite(t, dir, "bundle.pem", append(bundle, keyPEM...), 0o644)
	if err := os.Symlink("server.key", filepath.Join(dir, "link.key")); err != nil {
		t.Fatal(err)
	}
	fxSettle()

	rr := &tgtRecordingRunner{inner: hostinventory.NewLocalRunner()}
	rt := NewRemoteUnixTarget(rr, runtime.GOOS)
	lt := NewLocalTarget()
	ctx := context.Background()

	classes := map[string]Class{
		"server.key": ClassPrivateKey, "both.pem": ClassMixed, "c.der": ClassUnknown,
		"nginx.conf": ClassText, "bundle.pem": ClassMixed, "sub/deep/d.crt": ClassCertificate,
		"link.key": ClassPrivateKey, "big.bin": ClassUnknown,
	}
	for _, n := range hostile {
		classes[n] = ClassCertificate
	}
	for rel, want := range classes {
		p := filepath.Join(dir, rel)
		id, err := rt.Identify(ctx, p)
		if err != nil {
			t.Fatalf("Identify %q: %v", rel, err)
		}
		if id.Class != want {
			t.Errorf("Identify %q = %q, want %q (labels %q)", rel, id.Class, want, id.PEMLabels)
		}
		// Parity with the local target, which scans the same window.
		lid, err := lt.Identify(ctx, p)
		if err != nil || !reflect.DeepEqual(lid, id) {
			t.Errorf("Identify %q: local %+v, remote %+v (%v)", rel, lid, id, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Fatal("a file name was executed")
	}
	if _, err := rt.Identify(ctx, filepath.Join(dir, "missing")); !errors.Is(err, ErrNotExist) {
		t.Errorf("missing: %v", err)
	}

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

	files, err := rt.List(ctx, dir, ListOptions{MaxDepth: 5})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := tgtRels(t, dir, files); len(got) != len(hostile)+8 {
		t.Fatalf("List got %d: %q", len(got), got)
	}
	for _, f := range files {
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
	var lerr *ListError
	small, err := rt.List(ctx, dir, ListOptions{MaxDepth: 0, MaxSizeBytes: 1500, Names: []string{"*.bin", "bundle.pem"}})
	if !errors.As(err, &lerr) || lerr.OverSize != 2 || len(small) != 0 {
		t.Fatalf("List oversize: %q %v", tgtRels(t, dir, small), err)
	}

	// The guard against the real tools.
	rr.reads = nil
	for _, rel := range []string{"server.key", "both.pem", "bundle.pem", "c.der", "link.key", "nginx.conf"} {
		if _, err := rt.ReadFile(ctx, filepath.Join(dir, rel)); !errors.Is(err, ErrNotPublic) {
			t.Errorf("ReadFile %s: %v", rel, err)
		}
	}
	if len(rr.reads) != 0 {
		t.Fatalf("the runner's ReadFile was used: %q", rr.reads)
	}
	b, err := rt.ReadFile(ctx, filepath.Join(dir, "has space.pem"))
	if err != nil || string(b) != string(certPEM) {
		t.Fatalf("public ReadFile: %v", err)
	}
	rt.SetMaxFileBytes(100)
	if _, err := rt.ReadFile(ctx, filepath.Join(dir, "has space.pem")); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("bounded ReadFile: %v", err)
	}
	rt.SetMaxFileBytes(0)

	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "sub")
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(locked, 0o755) }()
		_, err := rt.List(ctx, dir, ListOptions{MaxDepth: 5})
		if !errors.As(err, &lerr) || lerr.DeniedCount != 1 || lerr.Denied[0] != locked {
			t.Fatalf("denied subdirectory: %v %+v", err, lerr)
		}
		// A file under an unsearchable directory is permission denied, as
		// Stat says, not missing.
		hidden := filepath.Join(locked, "deep", "d.crt")
		if _, err := rt.Identify(ctx, hidden); !errors.Is(err, ErrPermission) {
			t.Errorf("Identify under a denied directory: %v", err)
		}
		if _, err := rt.Stat(ctx, hidden); !errors.Is(err, ErrPermission) {
			t.Errorf("Stat under a denied directory: %v", err)
		}
		if _, err := lt.Identify(ctx, hidden); !errors.Is(err, ErrPermission) {
			t.Errorf("local Identify under a denied directory: %v", err)
		}
	}
}
