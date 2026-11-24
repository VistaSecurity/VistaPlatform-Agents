package hostcrypto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// tgtWinIdentifyOut is psIdentify's answer for an inspection.
func tgtWinIdentifyOut(in inspection) string {
	b01 := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	b, _ := json.Marshal(map[string]any{
		"Size": in.size, "Magic": hex.EncodeToString(in.magic), "Nul": in.nul, "Labels": in.labels,
		"Flags": map[string]int{"bad": b01(in.bad), "nonpub": b01(in.nonPublic), "unterm": b01(in.unterminated),
			"priv": b01(in.private), "orun": b01(in.outsideRun), "sshbad": b01(in.sshBad), "sshl": in.sshLines, "nl": in.nLabel},
	})
	return string(b)
}

func tgtWinIdentifyFor(content []byte) string {
	return tgtWinIdentifyOut(inspect(content, int64(len(content))))
}

var tgtWinHostile = []string{
	`C:\Program Files\App\server.pem`,
	`C:\x\it's.pem`,
	`C:\x\'; Remove-Item C:\ -Recurse; '.pem`,
	`C:\x\$(Get-Process).pem`,
	"C:\\x\\back`tick.pem",
	`C:\x\[wild]*.pem`,
	`C:\x\%PATH%&calc.pem`,
	`C:\x\"dq".pem`,
	`C:\x\dollar$env:x;ls.pem`,
}

// tgtWinHost answers every script for one file's content.
func tgtWinHost(t *testing.T, content []byte, kinds *[]string) func(argv []string, stdin []byte) tgtResult {
	return func(argv []string, stdin []byte) tgtResult {
		script, args := tgtDecodePS(t, argv, stdin)
		k := tgtPSKind(script)
		if kinds != nil {
			*kinds = append(*kinds, k)
		}
		switch k {
		case "identify":
			return tgtResult{stdout: tgtWinIdentifyFor(content)}
		case "read":
			return tgtResult{stdout: base64.StdEncoding.EncodeToString(content)}
		case "readtext":
			out, n := RedactText(content)
			b, _ := json.Marshal(map[string]any{"Redactions": n, "Data": base64.StdEncoding.EncodeToString(out)})
			return tgtResult{stdout: string(b)}
		case "list":
			return tgtResult{stdout: `{"Files":[],"Denied":[],"DeniedCount":0,"Unreadable":0,"OverSize":0,"Truncated":false}`}
		case "stat":
			return tgtResult{stdout: `{"Path":"x","Size":1,"Modified":"2026-01-02T03:04:05Z","Owner":"BUILTIN\\Administrators","AclOk":true,"Broad":false}`}
		}
		_ = args
		return tgtResult{exit: 1}
	}
}

// TestRemoteWindowsStdinPath: with an InputRunner the ONLY command line is
// the fixed `powershell ... -Command -`; the script and the path travel on
// stdin, the path only inside the base64 argument literal.
func TestRemoteWindowsStdinPath(t *testing.T) {
	certPEM, _, _, _ := tgtMaterial(t)
	for _, p := range tgtWinHostile {
		var kinds []string
		fr := newTgtFakeInputRunner(nil)
		host := tgtWinHost(t, certPEM, &kinds)
		fr.inputHandler = func(argv []string, stdin []byte) tgtResult {
			script, args := tgtDecodePS(t, argv, stdin)
			if strings.Contains(script, p) {
				t.Errorf("path %q appears in script text", p)
			}
			got, _ := args["Path"].(string)
			if got == "" {
				got, _ = args["Root"].(string)
			}
			if got != p {
				t.Errorf("decoded argument = %q, want %q", got, p)
			}
			return host(argv, stdin)
		}
		wt := NewRemoteWindowsTarget(fr)
		ctx := context.Background()
		_, _ = wt.Stat(ctx, p)
		_, _ = wt.List(ctx, p, ListOptions{MaxDepth: 2})
		if b, err := wt.ReadFile(ctx, p); err != nil || string(b) != string(certPEM) {
			t.Fatalf("%q: ReadFile %v", p, err)
		}
		if _, _, err := wt.ReadText(ctx, p); err != nil {
			t.Fatalf("%q: ReadText %v", p, err)
		}
		if strings.Join(kinds, ",") != "stat,list,identify,read,readtext" {
			t.Fatalf("%q: scripts run %q", p, kinds)
		}
		for _, argv := range fr.recordedRuns() {
			if !reflect.DeepEqual(argv, psStdinArgv) {
				t.Fatalf("command line other than the fixed argv: %q", argv)
			}
		}
		for _, in := range fr.stdins {
			if strings.Count(string(in), "\n") != 1 {
				t.Fatal("stdin is not one line")
			}
		}
	}
}

// TestRemoteWindowsArgvFallback: without an InputRunner the scripts would go
// as -EncodedCommand, which cmd.exe cuts at 8,191 characters: every one of
// them is too long, so the target refuses before sending anything.
func TestRemoteWindowsArgvFallback(t *testing.T) {
	fr := newTgtFakeRunner(nil)
	wt := NewRemoteWindowsTarget(fr)
	ctx := context.Background()
	_, err := wt.Stat(ctx, `C:\x`)
	if err == nil || !strings.Contains(err.Error(), "InputRunner") {
		t.Fatalf("err = %v", err)
	}
	if _, err := wt.ReadFile(ctx, `C:\x`); err == nil {
		t.Fatal("ReadFile without InputRunner")
	}
	if n := len(fr.recordedRuns()); n != 0 {
		t.Fatalf("%d commands sent", n)
	}
	// A short script would go, as exactly the five-element argv.
	full, err := psScript("$a = $vistaArgs", psPathArgs{Path: `C:\x`})
	if err != nil {
		t.Fatal(err)
	}
	argv, err := psArgv(full)
	if err != nil || len(argv) != 5 || argv[3] != "-EncodedCommand" {
		t.Fatalf("short script: %q %v", argv, err)
	}
	script, args := tgtDecodePS(t, argv, nil)
	if script != "$a = $vistaArgs" || args["Path"] != `C:\x` {
		t.Fatalf("decoded %q %v", script, args)
	}
	for _, w := range argv {
		if strings.ContainsAny(w, " \t\r\n\"'`$&|<>^%()!;") {
			t.Fatalf("argv element needs quoting: %q", w)
		}
	}
}

func TestRemoteWindowsListArgs(t *testing.T) {
	var got map[string]any
	fr := newTgtFakeInputRunner(func(argv []string, stdin []byte) tgtResult {
		_, got = tgtDecodePS(t, argv, stdin)
		return tgtResult{stdout: `{"Files":[{"Path":"C:\\r\\z.pem","Size":3,"Modified":"2026-01-02T03:04:05Z","IsLink":false,"Target":""},` +
			`{"Path":"C:\\r\\a.pem","Size":3,"Modified":"2026-01-02T03:04:05Z","IsLink":false,"Target":""}],` +
			`"Denied":"C:\\r\\locked","DeniedCount":1,"Unreadable":2,"OverSize":3,"Truncated":true}`}
	})
	files, err := NewRemoteWindowsTarget(fr).List(context.Background(), `C:\r`, ListOptions{
		MaxDepth: 3, MaxFiles: 7, MaxSizeBytes: 99, Exclude: []string{`C:\r\skip`}, Names: []string{"*.pem"},
	})
	if got["Root"] != `C:\r` || got["Depth"] != float64(3) || got["Max"] != float64(7) || got["MaxSize"] != float64(99) || got["Cross"] != false {
		t.Fatalf("args = %v", got)
	}
	var lerr *ListError
	if !errors.As(err, &lerr) || !lerr.Truncated || lerr.DeniedCount != 1 || lerr.Denied[0] != `C:\r\locked` || lerr.Unreadable != 2 || lerr.OverSize != 3 {
		t.Fatalf("err = %v %+v", err, lerr)
	}
	if len(files) != 2 || files[0].Path != `C:\r\a.pem` || files[0].WorldReadable != nil {
		t.Fatalf("files = %+v", files)
	}
}

func TestRemoteWindowsStat(t *testing.T) {
	cases := []struct {
		out   string
		check func(t *testing.T, fi FileInfo, err error)
	}{
		{`{"Path":"C:\\k\\a.pfx","Size":2048,"Modified":"2026-01-02T03:04:05Z","IsDir":false,"IsLink":false,"Target":"","Owner":"HOST\\svc","AclOk":true,"Broad":true}`,
			func(t *testing.T, fi FileInfo, err error) {
				if err != nil || fi.Size != 2048 || fi.Owner != `HOST\svc` || fi.WorldReadable == nil || !*fi.WorldReadable || fi.GroupReadable != nil || fi.Mode != 0 {
					t.Errorf("broad: %+v %v", fi, err)
				}
			}},
		{`{"Path":"C:\\k\\a.pfx","Size":1,"Modified":"2026-01-02T03:04:05Z","Owner":"","AclOk":false,"Broad":false}`,
			func(t *testing.T, fi FileInfo, err error) {
				if err != nil || fi.WorldReadable != nil {
					t.Errorf("acl unreadable must leave nil: %+v %v", fi, err)
				}
			}},
		{"\ufeff" + `{"Error":"not_found"}`, func(t *testing.T, _ FileInfo, err error) {
			if !errors.Is(err, ErrNotExist) {
				t.Errorf("not_found: %v", err)
			}
		}},
		{`{"Error":"denied"}`, func(t *testing.T, _ FileInfo, err error) {
			if !errors.Is(err, ErrPermission) {
				t.Errorf("denied: %v", err)
			}
		}},
		{`not json`, func(t *testing.T, _ FileInfo, err error) {
			if err == nil {
				t.Error("garbage accepted")
			}
		}},
	}
	for _, tc := range cases {
		fr := newTgtFakeInputRunner(func([]string, []byte) tgtResult { return tgtResult{stdout: tc.out} })
		fi, err := NewRemoteWindowsTarget(fr).Stat(context.Background(), `C:\k\a.pfx`)
		tc.check(t, fi, err)
	}
}

// TestRemoteWindowsReadFileGuard is the Windows half of the guard: for every
// file that is not public ReadFile returns ErrNotPublic and the only script
// sent is psIdentify. Mutation-checked by deleting the Public() test in
// ReadFile. It includes the reviewer's xps15 reproductions: a UTF-16 file
// that Select-String decoded as a certificate, and a UTF-16 certificate with
// an ASCII private key after it.
func TestRemoteWindowsReadFileGuard(t *testing.T) {
	certPEM, keyPEM, certDER, _ := tgtMaterial(t)
	utf16 := func(s string) []byte {
		b := []byte{0xff, 0xfe}
		for _, c := range []byte(s) {
			b = append(b, c, 0)
		}
		return b
	}
	notPublic := []struct {
		name    string
		path    string
		content []byte
	}{
		{"pkcs8", `C:\k\server.key`, keyPEM},
		{"mixed", `C:\k\both.pem`, append(append([]byte(nil), certPEM...), keyPEM...)},
		{"utf16 certificate", `C:\k\utf16cert.pem`, utf16(string(certPEM))},
		{"utf16 cert then ascii key", `C:\k\mixenc.pem`, append(utf16(string(certPEM)), keyPEM...)},
		{"cert then secret", `C:\k\cert_then_secret.pem`, append(append([]byte(nil), certPEM...), "PrivateKey: "+strings.Repeat("Q", 44)+"\n"...)},
		{"pfx", `C:\k\server.pfx`, certDER},
		{"jks", `C:\k\a.jks`, append(append([]byte(nil), magicJKS...), 0, 0, 0, 2)},
		{"putty", `C:\Users\u\key.ppk`, []byte("PuTTY-User-Key-File-3: ssh-ed25519\n")},
		{"lowercase label", `C:\k\x.key`, []byte("-----BEGIN OpenVPN Static key V1-----\n")},
	}
	for _, a := range notPublic {
		t.Run(a.name, func(t *testing.T) {
			var kinds []string
			fr := newTgtFakeInputRunner(tgtWinHost(t, a.content, &kinds))
			_, err := NewRemoteWindowsTarget(fr).ReadFile(context.Background(), a.path)
			if !errors.Is(err, ErrNotPublic) {
				t.Fatalf("err = %v, want ErrNotPublic", err)
			}
			if len(fr.recordedReads()) != 0 {
				t.Fatal("runner ReadFile called")
			}
			if strings.Join(kinds, ",") != "identify" {
				t.Fatalf("scripts sent: %q", kinds)
			}
		})
	}

	// The recheck: Identify said certificate, psRead (mis)sent a key.
	fr := newTgtFakeInputRunner(func(argv []string, stdin []byte) tgtResult {
		script, args := tgtDecodePS(t, argv, stdin)
		if tgtPSKind(script) == "read" {
			if args["Max"] != float64(remoteWindowsReadMax) {
				t.Errorf("read bound = %v", args["Max"])
			}
			return tgtResult{stdout: base64.StdEncoding.EncodeToString(keyPEM) + "\r\n"}
		}
		return tgtResult{stdout: tgtWinIdentifyFor(certPEM)}
	})
	if _, err := NewRemoteWindowsTarget(fr).ReadFile(context.Background(), `C:\certs\a.pem`); !errors.Is(err, ErrNotPublic) {
		t.Errorf("swapped: %v", err)
	}

	// The host refusing (its own decision) and too large.
	for word, want := range map[string]error{"not_public": ErrNotPublic, "too_large": ErrFileTooLarge} {
		fr = newTgtFakeInputRunner(func(argv []string, stdin []byte) tgtResult {
			script, _ := tgtDecodePS(t, argv, stdin)
			if tgtPSKind(script) == "read" {
				return tgtResult{stdout: `{"Error":"` + word + `"}`}
			}
			return tgtResult{stdout: tgtWinIdentifyFor(certPEM)}
		})
		if _, err := NewRemoteWindowsTarget(fr).ReadFile(context.Background(), `C:\x\a.pem`); !errors.Is(err, want) {
			t.Errorf("%s: %v", word, err)
		}
	}
	// Over the cap from Identify's size: refused before any read.
	var kinds []string
	big := tgtWinIdentifyOut(inspection{size: remoteWindowsReadMax + 1, magic: []byte("-----BEG"), labels: []string{"CERTIFICATE"}, nLabel: 1})
	fr = newTgtFakeInputRunner(func(argv []string, stdin []byte) tgtResult {
		script, _ := tgtDecodePS(t, argv, stdin)
		kinds = append(kinds, tgtPSKind(script))
		return tgtResult{stdout: big}
	})
	if _, err := NewRemoteWindowsTarget(fr).ReadFile(context.Background(), `C:\x\big.pem`); !errors.Is(err, ErrFileTooLarge) || strings.Join(kinds, ",") != "identify" {
		t.Errorf("too large: %v %q", err, kinds)
	}
	// An answer missing a field is not trusted.
	fr = newTgtFakeInputRunner(func([]string, []byte) tgtResult {
		return tgtResult{stdout: `{"Size":10,"Magic":"2d2d2d2d2d424547","Labels":["CERTIFICATE"],"Flags":{"bad":0}}`}
	})
	if _, err := NewRemoteWindowsTarget(fr).Identify(context.Background(), `C:\x\a.pem`); err == nil {
		t.Error("an incomplete identify answer was accepted")
	}
}

func TestRemoteWindowsReadText(t *testing.T) {
	conf := []byte("[Interface]\r\nPrivateKey = " + strings.Repeat("Q", 44) + "\r\nAddress = 10.0.0.1/24\r\n")
	fr := newTgtFakeInputRunner(tgtWinHost(t, conf, nil))
	out, n, err := NewRemoteWindowsTarget(fr).ReadText(context.Background(), `C:\wg\wg0.conf`)
	want, wn := RedactText(conf)
	if err != nil || string(out) != string(want) || n != wn || n != 1 {
		t.Fatalf("ReadText = %q %d %v", out, n, err)
	}
	// A host that "forgot" to redact is caught.
	fr = newTgtFakeInputRunner(func([]string, []byte) tgtResult {
		b, _ := json.Marshal(map[string]any{"Redactions": 0, "Data": base64.StdEncoding.EncodeToString(conf)})
		return tgtResult{stdout: string(b)}
	})
	if _, _, err := NewRemoteWindowsTarget(fr).ReadText(context.Background(), `C:\wg\wg0.conf`); !errors.Is(err, ErrNotPublic) {
		t.Fatalf("unredacted answer: %v", err)
	}
	for word, want := range map[string]error{"not_public": ErrNotPublic, "too_large": ErrFileTooLarge, "not_found": ErrNotExist} {
		fr = newTgtFakeInputRunner(func([]string, []byte) tgtResult { return tgtResult{stdout: `{"Error":"` + word + `"}`} })
		if _, _, err := NewRemoteWindowsTarget(fr).ReadText(context.Background(), `C:\x`); !errors.Is(err, want) {
			t.Errorf("%s: %v", word, err)
		}
	}
}

func TestPSScriptRefusesUnsafeTemplate(t *testing.T) {
	if _, err := psScript("no argument use", psPathArgs{Path: "x"}); err == nil {
		t.Error("a script that does not read its arguments was accepted")
	}
	for _, s := range []string{psStat, psIdentify, psRead, psReadText, psList} {
		if strings.Contains(s, "%ARGS%") || !strings.Contains(s, "$vistaArgs") {
			t.Fatal("a script does not read $vistaArgs")
		}
	}
	for _, l := range publicPEMLabels {
		if strings.ContainsRune(l, '\'') {
			t.Fatalf("label %q would end a PowerShell literal", l)
		}
	}
}
