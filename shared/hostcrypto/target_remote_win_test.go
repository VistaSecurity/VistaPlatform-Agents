package hostcrypto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// tgtWinIdentify is psIdentify's answer for given markers.
func tgtWinIdentify(magic []byte, private bool, labels ...string) string {
	full := make([]string, 0, len(labels))
	for _, l := range labels {
		full = append(full, "-----BEGIN "+l+"-----")
	}
	b, _ := json.Marshal(map[string]any{"Magic": hex.EncodeToString(magic), "Private": private, "Labels": full})
	return string(b)
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
}

// TestRemoteWindowsArgv: every operation sends the five-element
// -EncodedCommand argv; the path reaches the script only inside the base64
// argument literal, never as script text, whatever it contains.
func TestRemoteWindowsArgv(t *testing.T) {
	for _, p := range tgtWinHostile {
		var kinds []string
		fr := newTgtFakeRunner(func(argv []string) tgtResult {
			script, args := tgtDecodePS(t, argv)
			kinds = append(kinds, tgtPSKind(script))
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
			switch tgtPSKind(script) {
			case "identify":
				return tgtResult{stdout: tgtWinIdentify([]byte("-----BEG"), false, "CERTIFICATE")}
			case "read":
				return tgtResult{stdout: base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\n"))}
			case "list":
				return tgtResult{stdout: `{"Files":[],"Denied":[],"DeniedCount":0,"Truncated":false}`}
			}
			return tgtResult{stdout: `{"Path":"x","Size":1,"Modified":"2026-01-02T03:04:05Z","Owner":"BUILTIN\\Administrators","AclOk":true,"Broad":false}`}
		})
		wt := NewRemoteWindowsTarget(fr)
		ctx := context.Background()
		_, _ = wt.Stat(ctx, p)
		_, _ = wt.List(ctx, p, ListOptions{MaxDepth: 2})
		_, _ = wt.ReadFile(ctx, p)
		if strings.Join(kinds, ",") != "stat,list,identify,read" {
			t.Fatalf("%q: scripts run %q", p, kinds)
		}
		for _, argv := range fr.recordedRuns() {
			for _, w := range argv {
				// What hostinventory's SSH runner would refuse to send.
				if strings.ContainsAny(w, " \t\r\n\"'`$&|<>^%()!;") {
					t.Fatalf("argv element needs quoting: %q", w)
				}
			}
		}
	}
}

func TestRemoteWindowsListArgs(t *testing.T) {
	var got map[string]any
	fr := newTgtFakeRunner(func(argv []string) tgtResult {
		_, got = tgtDecodePS(t, argv)
		return tgtResult{stdout: `{"Files":{"Path":"C:\\r\\a.pem","Size":3,"Modified":"2026-01-02T03:04:05Z","IsLink":false,"Target":""},` +
			`"Denied":"C:\\r\\locked","DeniedCount":1,"Truncated":true}`}
	})
	files, err := NewRemoteWindowsTarget(fr).List(context.Background(), `C:\r`, ListOptions{
		MaxDepth: 3, MaxFiles: 7, MaxSizeBytes: 99, Exclude: []string{`C:\r\skip`}, Names: []string{"*.pem"},
	})
	if got["Root"] != `C:\r` || got["Depth"] != float64(3) || got["Max"] != float64(7) || got["MaxSize"] != float64(99) || got["Cross"] != false {
		t.Fatalf("args = %v", got)
	}
	if ex, _ := got["Exclude"].([]any); len(ex) != 1 || ex[0] != `C:\r\skip` {
		t.Fatalf("exclude = %v", got["Exclude"])
	}
	// PowerShell 5.1's one-element arrays as bare values are accepted.
	var lerr *ListError
	if !errors.As(err, &lerr) || !lerr.Truncated || lerr.DeniedCount != 1 || lerr.Denied[0] != `C:\r\locked` {
		t.Fatalf("err = %v %+v", err, lerr)
	}
	if len(files) != 1 || files[0].Path != `C:\r\a.pem` || files[0].Mode != 0 || files[0].WorldReadable != nil {
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
		fr := newTgtFakeRunner(func([]string) tgtResult { return tgtResult{stdout: tc.out} })
		fi, err := NewRemoteWindowsTarget(fr).Stat(context.Background(), `C:\k\a.pfx`)
		tc.check(t, fi, err)
	}
}

// TestRemoteWindowsReadFileGuard is the Windows half of the guard: for every
// non-public class ReadFile returns ErrNotPublic, the runner's ReadFile is
// never called, and the only script sent is psIdentify. Mutation-checked by
// deleting the Public() test in ReadFile.
func TestRemoteWindowsReadFileGuard(t *testing.T) {
	type answer struct {
		name    string
		path    string
		magic   []byte
		private bool
		labels  []string
	}
	notPublic := []answer{
		{"pkcs8", `C:\k\server.key`, []byte("-----BEG"), true, []string{"PRIVATE KEY"}},
		{"mixed", `C:\k\both.pem`, []byte("-----BEG"), true, []string{"CERTIFICATE", "RSA PRIVATE KEY"}},
		{"key past bound", `C:\k\bundle.pem`, []byte("-----BEG"), true, []string{"CERTIFICATE"}},
		{"pfx", `C:\k\server.pfx`, []byte{0x30, 0x82, 9, 1, 2, 1, 3, 0x30}, false, nil},
		{"jks", `C:\k\a.jks`, magicJKS, false, nil},
		{"putty", `C:\Users\u\key.ppk`, []byte("PuTTY-Us"), false, nil},
		{"bare der", `C:\k\a.cer`, []byte{0x30, 0x82, 9, 1, 2, 1, 3, 0x30}, false, nil},
		{"unknown label", `C:\k\x.key`, []byte("-----BEG"), false, []string{"OpenVPN Static key V1"}},
	}
	for _, a := range notPublic {
		t.Run(a.name, func(t *testing.T) {
			var kinds []string
			fr := newTgtFakeRunner(func(argv []string) tgtResult {
				script, _ := tgtDecodePS(t, argv)
				kinds = append(kinds, tgtPSKind(script))
				return tgtResult{stdout: tgtWinIdentify(a.magic, a.private, a.labels...)}
			})
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

	// The other polarity, and the recheck of what arrives.
	certPEM, keyPEM, _, _ := tgtMaterial(t)
	for _, tc := range []struct {
		name    string
		content []byte
		ok      bool
	}{{"public", certPEM, true}, {"swapped to a key", keyPEM, false}} {
		fr := newTgtFakeRunner(func(argv []string) tgtResult {
			script, args := tgtDecodePS(t, argv)
			if tgtPSKind(script) == "read" {
				if args["Max"] != float64(remoteWindowsReadMax) {
					t.Errorf("read bound = %v", args["Max"])
				}
				return tgtResult{stdout: base64.StdEncoding.EncodeToString(tc.content) + "\r\n"}
			}
			return tgtResult{stdout: tgtWinIdentify(certPEM[:8], false, "CERTIFICATE")}
		})
		b, err := NewRemoteWindowsTarget(fr).ReadFile(context.Background(), `C:\certs\a.pem`)
		if tc.ok && (err != nil || string(b) != string(certPEM)) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrNotPublic) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}

	// A too-large file and an answer without the private flag.
	fr := newTgtFakeRunner(func(argv []string) tgtResult {
		script, _ := tgtDecodePS(t, argv)
		if tgtPSKind(script) == "read" {
			return tgtResult{stdout: `{"Error":"too_large"}`}
		}
		return tgtResult{stdout: tgtWinIdentify([]byte("# conf  "), false)}
	})
	if _, err := NewRemoteWindowsTarget(fr).ReadFile(context.Background(), `C:\x\big.conf`); !errors.Is(err, ErrFileTooLarge) {
		t.Errorf("too large: %v", err)
	}
	fr = newTgtFakeRunner(func([]string) tgtResult {
		return tgtResult{stdout: `{"Magic":"2d2d2d2d2d424547","Labels":["-----BEGIN CERTIFICATE-----"]}`}
	})
	id, err := NewRemoteWindowsTarget(fr).Identify(context.Background(), `C:\x\a.pem`)
	if err != nil || id.Public() {
		t.Errorf("missing private flag: %q %v", id.Class, err)
	}
}

func TestPSArgvRefusesUnsafeTemplate(t *testing.T) {
	if _, err := psArgv("no slot here", psPathArgs{Path: "x"}); err == nil {
		t.Error("a script without an argument slot was accepted")
	}
	if _, err := psArgv("%ARGS% %ARGS%", psPathArgs{Path: "x"}); err == nil {
		t.Error("a script with two slots was accepted")
	}
}
