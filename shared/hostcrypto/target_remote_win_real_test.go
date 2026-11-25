package hostcrypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// These tests run the PowerShell programs for real, through
// RemoteWindowsTarget and hostinventory's LocalRunner, on the machine the
// test binary runs on. They skip unless that machine is Windows, so they are
// meant for a cross-compiled test binary on a Windows host:
//
//	GOOS=windows GOARCH=amd64 go test -c -o hc.test.exe ./shared/hostcrypto/
//	hc.test.exe -test.run 'RemoteWindowsReal|PS' -test.v
//
// The binary needs nothing beside itself: every corpus is generated in the
// test. A failure prints the file, the keep list and the first line that
// differs, in both versions.
//
// HOSTCRYPTO_PWSH, set to a pwsh binary, runs them elsewhere for development.
// That is PowerShell 7 on .NET, not Windows PowerShell 5.1 on .NET Framework:
// it does not stand in for a Windows run.

// fxFull reports HOSTCRYPTO_FULL=1: the per-file real-PowerShell tests then
// run the whole corpus. By default they run a sample (each PowerShell call
// costs about 1.5 s on Windows PowerShell 5.1, and the package must finish
// inside go test's 10-minute default), while the batch tests run every rule
// over the whole corpus in one PowerShell process either way.
func fxFull() bool { return os.Getenv("HOSTCRYPTO_FULL") == "1" }

// fxSample is names, or under the default run every k-th of them (k chosen
// for about n) plus the named ones that exist, in order.
func fxSample(t *testing.T, names []string, n int, always ...string) []string {
	t.Helper()
	keep := map[string]bool{}
	for _, a := range always {
		keep[a] = true
	}
	for _, name := range names {
		delete(keep, name)
	}
	for a := range keep {
		t.Fatalf("sample: %q is not in the corpus", a)
	}
	for _, a := range always {
		keep[a] = true
	}
	if fxFull() || len(names) <= n {
		return names
	}
	k := len(names) / n
	var out []string
	for i, name := range names {
		if i%k == 0 || keep[name] {
			out = append(out, name)
		}
	}
	return out
}

// fxPSRunner is the runner the real tests drive.
func fxPSRunner(t *testing.T) hostinventory.Runner {
	t.Helper()
	if runtime.GOOS == "windows" {
		return hostinventory.NewLocalRunner()
	}
	if p := os.Getenv("HOSTCRYPTO_PWSH"); p != "" {
		return fxPwsh{path: p}
	}
	t.Skip("runs PowerShell: on Windows, or with HOSTCRYPTO_PWSH naming a pwsh binary")
	return nil
}

// fxPwsh runs "powershell" as the pwsh at path.
type fxPwsh struct{ path string }

func (r fxPwsh) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return r.RunInput(ctx, argv, nil)
}

func (r fxPwsh) RunInput(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	if len(argv) > 0 && argv[0] == "powershell" {
		argv = append([]string{r.path}, argv[1:]...)
	}
	out, errb, exit, err := hostinventory.NewLocalRunner().RunInput(ctx, argv, stdin)
	// pwsh on a Unix terminal writes cursor-mode escapes around its output.
	return fxANSI.ReplaceAll(out, nil), errb, exit, err
}

var fxANSI = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func (r fxPwsh) ReadFile(ctx context.Context, p string) ([]byte, error) {
	return hostinventory.NewLocalRunner().ReadFile(ctx, p)
}

// fxPSBatch runs script (with the prelude and its arguments) once and
// returns its JSON answer.
func fxPSBatch(t *testing.T, r hostinventory.Runner, script string, args any) []byte {
	t.Helper()
	full, err := psScript(psBudgetLine(600)+psPrelude+script, args)
	if err != nil {
		t.Fatal(err)
	}
	ir, ok := r.(hostinventory.InputRunner)
	if !ok {
		t.Fatal("the runner takes no stdin")
	}
	out, stderr, exit, err := ir.RunInput(context.Background(), psStdinArgv, psStdin(full))
	if err != nil || exit != 0 {
		t.Fatalf("powershell: exit %d, %v\n%s", exit, err, tgtShort(stderr))
	}
	kind, b, err := psDecode(out)
	if err != nil || kind != 'J' {
		t.Fatalf("unreadable answer (%v): %s %s", err, tgtShort(out), tgtShort(stderr))
	}
	return b
}

// TestRemoteWindowsRealFilterBatch runs vFilter, in ONE PowerShell process,
// over the whole text corpus under every keep set, and compares each answer
// with filterConfig.
func TestRemoteWindowsRealFilterBatch(t *testing.T) {
	r := fxPSRunner(t)
	corpus := fxTextCorpus(t, 400)
	keeps := fxParityKeeps(false)
	type item struct {
		Name string   `json:"Name"`
		B    string   `json:"B"`
		K    []string `json:"K"`
	}
	var items []item
	for _, name := range fxSorted(corpus) {
		if len(corpus[name]) > 64<<10 {
			continue // the large files go through ReadText, one by one
		}
		for _, kn := range fxSorted(keeps) {
			items = append(items, item{Name: name + " with " + kn, B: base64.StdEncoding.EncodeToString(corpus[name]), K: keeps[kn]})
		}
	}
	script := `$bxOut = New-Object 'System.Collections.Generic.List[object]'
foreach ($bxI in $a.Items) {
  $bxB = [Convert]::FromBase64String($bxI.B)
  $bxF = vFilter $bxB $bxB.Length ([string[]]@($bxI.K))
  $bxT = ''; if ($bxF.Status -ceq 'ok') { $bxT = [Convert]::ToBase64String($vL1.GetBytes($bxF.Text)) }
  $bxOut.Add([pscustomobject]@{ S = $bxF.Status; T = $bxT; N = [int]$bxF.N })
}
psOut ([pscustomobject]@{ R = $bxOut.ToArray() })`
	// In pieces, so no answer nears the runner's 8 MiB bound.
	const piece = 600
	fails := 0
	for start := 0; start < len(items); start += piece {
		part := items[start:min(start+piece, len(items))]
		var ans struct {
			R []struct {
				S string `json:"S"`
				T string `json:"T"`
				N int    `json:"N"`
			} `json:"R"`
		}
		if err := json.Unmarshal(fxPSBatch(t, r, script, map[string]any{"Items": part}), &ans); err != nil || len(ans.R) != len(part) {
			t.Fatalf("batch answer: %v (%d of %d)", err, len(ans.R), len(part))
		}
		for i, it := range part {
			b, _ := base64.StdEncoding.DecodeString(it.B)
			got, _ := base64.StdEncoding.DecodeString(ans.R[i].T)
			var err error
			switch ans.R[i].S {
			case "ok":
			case "too_large":
				err = ErrFileTooLarge
			default:
				err = ErrNotPublic
			}
			if msg := fxCheckText(b, it.K, got, ans.R[i].N, err); msg != "" {
				t.Errorf("%s: %s", it.Name, msg)
				if fails++; fails > 30 {
					t.Fatal("too many differences")
				}
			}
		}
	}
	t.Logf("%d filter runs compared", len(items))
}

// TestRemoteWindowsRealPublicBatch runs vPublic and vInspect in one process
// over the file corpus and compares them with publicContent and inspect.
func TestRemoteWindowsRealPublicBatch(t *testing.T) {
	r := fxPSRunner(t)
	corpus := fxFileCorpus(t)
	for i, b := range fxGenerated(200) {
		corpus[fmt.Sprintf("gen/%03d", i)] = b
	}
	names := fxSorted(corpus)
	var items []string
	for _, n := range names {
		items = append(items, base64.StdEncoding.EncodeToString(corpus[n]))
	}
	script := `$bpOut = New-Object 'System.Collections.Generic.List[object]'
foreach ($bpS in $a.Items) {
  $bpB = [Convert]::FromBase64String($bpS)
  $bpP = vPublic $bpB $bpB.Length
  $bpT = ''; $bpOk = $false
  if ($null -ne $bpP) { $bpOk = $true; $bpT = [Convert]::ToBase64String($vL1.GetBytes($bpP)) }
  $bpX = vInspect ($vL1.GetString($bpB, 0, $bpB.Length))
  $bpOut.Add([pscustomobject]@{ Ok = $bpOk; T = $bpT; Labels = $bpX.Labels; Flags = $bpX.Flags })
}
psOut ([pscustomobject]@{ R = $bpOut.ToArray() })`
	var ans struct {
		R []struct {
			Ok     bool            `json:"Ok"`
			T      string          `json:"T"`
			Labels json.RawMessage `json:"Labels"`
			Flags  map[string]int  `json:"Flags"`
		} `json:"R"`
	}
	if err := json.Unmarshal(fxPSBatch(t, r, script, map[string]any{"Items": items}), &ans); err != nil || len(ans.R) != len(items) {
		t.Fatalf("batch answer: %v", err)
	}
	for i, n := range names {
		b := corpus[n]
		want, ok := publicContent(b)
		got, _ := base64.StdEncoding.DecodeString(ans.R[i].T)
		if ok != ans.R[i].Ok || !bytes.Equal(got, want) {
			t.Errorf("%s: public content: host ok=%v, Go ok=%v; %s", n, ans.R[i].Ok, ok, fxFirstDiff(got, want))
		}
		in := inspect(b, int64(len(b)))
		labels, _ := psArray[string](ans.R[i].Labels)
		f := ans.R[i].Flags
		b2i := func(v bool) int {
			if v {
				return 1
			}
			return 0
		}
		wantF := map[string]int{"bad": b2i(in.bad), "nonpub": b2i(in.nonPublic), "unterm": b2i(in.unterminated), "priv": b2i(in.private),
			"orun": b2i(in.outsideRun), "sshbad": b2i(in.sshBad), "sshl": in.sshLines, "nl": in.nLabel}
		if !reflect.DeepEqual(f, wantF) || strings.Join(labels, "|") != strings.Join(in.labels, "|") {
			t.Errorf("%s: inspection: host %v %v, Go %v %v", n, f, labels, wantF, in.labels)
		}
	}
}

// TestRemoteWindowsRealReadText drives RemoteWindowsTarget.ReadText over the
// corpus, file by file, as the collector does.
func TestRemoteWindowsRealReadText(t *testing.T) {
	r := fxPSRunner(t)
	gen := 5
	if fxFull() {
		gen = 30
	}
	corpus := fxTextCorpus(t, gen)
	names := fxSample(t, fxSorted(corpus), 16, "review3/lonecr.conf", "review3/krb5.conf", "review3/nginx_semi.conf",
		"review3/nul.conf", "review3/props.properties", "review3/lines_200001.conf")
	dir := t.TempDir()
	fxWriteCorpus(t, dir, corpus)
	fxSettle()
	keeps := fxParityKeeps(true)
	kn := fxSorted(keeps)
	rt := NewRemoteWindowsTarget(r)
	ctx := context.Background()
	fails := 0
	for i, name := range names {
		b := corpus[name]
		sets := []string{kn[i%len(kn)]}
		if fxFull() {
			sets = []string{"realistic", "gen+statements", kn[i%len(kn)]}
		}
		if len(b) > 1<<20 {
			sets = sets[:1]
		}
		for _, k := range sets {
			start := time.Now()
			got, n, err := rt.ReadText(ctx, filepath.Join(dir, filepath.FromSlash(name)), keeps[k])
			if msg := fxCheckText(b, keeps[k], got, n, err); msg != "" {
				// The host may give up past its time budget, with an answer.
				if errors.Is(err, ErrFileTooLarge) && time.Since(start) > 40*time.Second {
					t.Logf("%s with %s: the host's time budget ran out after %s", name, k, time.Since(start))
					continue
				}
				t.Errorf("%s with %s: %s", name, k, msg)
				if fails++; fails > 20 {
					t.Fatal("too many differences")
				}
			}
			if d := time.Since(start); d > 10*time.Second {
				t.Logf("%s with %s took %s", name, k, d)
			}
		}
	}
}

// TestRemoteWindowsRealSpeed: 200,000 lines (the line bound) within the
// command timeout, and an answer, never a timeout, past the host budget.
func TestRemoteWindowsRealSpeed(t *testing.T) {
	r := fxPSRunner(t)
	dir := t.TempDir()
	text := fxReview3Text()
	fxWriteCorpus(t, dir, map[string][]byte{"l.conf": text["lines_200000.conf"], "long.conf": text["long_line.conf"]})
	fxSettle()
	rt := NewRemoteWindowsTarget(r)
	for _, c := range []struct{ file, name string }{{"l.conf", "realistic"}, {"l.conf", "realistic+statements"}, {"long.conf", "gen+statements"}} {
		keep := fxParityKeeps(true)[c.name]
		start := time.Now()
		got, n, err := rt.ReadText(context.Background(), filepath.Join(dir, c.file), keep)
		d := time.Since(start)
		t.Logf("%s with %s: %s (%d bytes, err %v)", c.file, c.name, d, len(got), err)
		if err != nil && !errors.Is(err, ErrFileTooLarge) {
			t.Errorf("%s with %s: %v after %s: no answer", c.file, c.name, err, d)
			continue
		}
		if err == nil {
			b, _ := os.ReadFile(filepath.Join(dir, c.file))
			if msg := fxCheckText(b, keep, got, n, nil); msg != "" {
				t.Errorf("%s with %s: %s", c.file, c.name, msg)
			}
		}
		if d > 80*time.Second {
			t.Errorf("%s with %s took %s, near the 90-second command timeout", c.file, c.name, d)
		}
	}
}

// TestRemoteWindowsRealReadFile drives ReadFile and Identify over the file
// corpus.
func TestRemoteWindowsRealReadFile(t *testing.T) {
	r := fxPSRunner(t)
	corpus := fxFileCorpus(t)
	dir := t.TempDir()
	fxWriteCorpus(t, dir, corpus)
	fxSettle()
	rt := NewRemoteWindowsTarget(r)
	ctx := context.Background()
	names := fxSample(t, fxSorted(corpus), 14, "cert/certificate_just_under_the_body_bound", "cert/key_between_certificates",
		"cert/envelope_certificate_EC_P-256_fourth_element_raw_under_CERTIFICATE", "cert/trusted_certificate", "ssh/options", "cert/bundle")
	for _, name := range names {
		b := corpus[name]
		p := filepath.Join(dir, filepath.FromSlash(name))
		want, ok := publicContent(b)
		in, err := rt.identify(ctx, p)
		if wantIn := inspect(b, int64(len(b))); err != nil || (!wantIn.nul && !reflect.DeepEqual(in, wantIn)) {
			t.Errorf("%s: inspection differs (%v):\nhost %+v\n  go %+v", name, err, in, wantIn)
		}
		got, err := rt.ReadFile(ctx, p)
		public := identityFrom(p, inspect(b, int64(len(b)))).Public()
		switch {
		case ok && public:
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("%s: ReadFile (%v): %s", name, err, fxFirstDiff(got, want))
			}
		case err == nil:
			t.Errorf("%s: ReadFile returned %d bytes of a file that is not public", name, len(got))
		}
	}
}

// TestRemoteWindowsRealStatListIdentify: the other calls, on a real tree.
func TestRemoteWindowsRealStatListIdentify(t *testing.T) {
	r := fxPSRunner(t)
	dir := t.TempDir()
	certPEM, keyPEM, _, _ := tgtMaterial(t)
	fxWriteCorpus(t, dir, map[string][]byte{"a/cert.pem": certPEM, "a/b/key.pem": keyPEM, "c.txt": []byte("x = 1\n")})
	fxSettle()
	rt := NewRemoteWindowsTarget(r)
	ctx := context.Background()
	fi, err := rt.Stat(ctx, filepath.Join(dir, "a", "cert.pem"))
	if err != nil || fi.Size != int64(len(certPEM)) || fi.IsDir || fi.ModifiedAt == "" {
		t.Errorf("Stat file: %+v %v", fi, err)
	}
	if fi, err := rt.Stat(ctx, filepath.Join(dir, "a")); err != nil || !fi.IsDir {
		t.Errorf("Stat dir: %+v %v", fi, err)
	}
	if _, err := rt.Stat(ctx, filepath.Join(dir, "nosuch")); !errors.Is(err, ErrNotExist) {
		t.Errorf("Stat missing: %v", err)
	}
	files, err := rt.List(ctx, dir, ListOptions{MaxDepth: 5})
	var paths []string
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f.Path)
		paths = append(paths, filepath.ToSlash(rel))
	}
	sort.Strings(paths)
	if err != nil || strings.Join(paths, ",") != "a/b/key.pem,a/cert.pem,c.txt" {
		t.Errorf("List: %v %v", paths, err)
	}
	if files, _ := rt.List(ctx, dir, ListOptions{MaxDepth: 0}); len(files) != 1 {
		t.Errorf("List depth 0: %d files", len(files))
	}
	if id, err := rt.Identify(ctx, filepath.Join(dir, "a", "cert.pem")); err != nil || id.Class != ClassCertificate {
		t.Errorf("Identify cert: %+v %v", id, err)
	}
	if id, err := rt.Identify(ctx, filepath.Join(dir, "a", "b", "key.pem")); err != nil || id.Public() {
		t.Errorf("Identify key: %+v %v", id, err)
	}
	if _, err := rt.ReadFile(ctx, filepath.Join(dir, "a", "b", "key.pem")); !errors.Is(err, ErrNotPublic) {
		t.Errorf("ReadFile key: %v", err)
	}
	if runtime.GOOS != "windows" {
		return
	}
	// A tree deeper than MAX_PATH (260): List must enter it.
	deep := `\\?\` + dir
	for i := 0; i < 6; i++ {
		deep += `\` + strings.Repeat("d", 60)
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatalf("cannot build a deep tree: %v", err)
	}
	if err := os.WriteFile(deep+`\deep.pem`, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	fxSettle()
	files, err = rt.List(ctx, dir, ListOptions{MaxDepth: 20})
	found := false
	for _, f := range files {
		if strings.HasSuffix(f.Path, `deep.pem`) && len(f.Path) > 260 {
			found = true
			if got, err := rt.ReadFile(ctx, f.Path); err != nil || !bytes.Equal(got, certPEM) {
				t.Errorf("ReadFile of the deep file: %v", err)
			}
		}
	}
	if !found {
		t.Errorf("List did not enter a directory past 260 characters (%v): %d files", err, len(files))
	}
}

// TestRemoteWindowsRealTornReads: the in-place rewrite of
// TestRemoteUnixTornReads (bursts and quiet spells), against the PowerShell
// read.
func TestRemoteWindowsRealTornReads(t *testing.T) {
	r := fxPSRunner(t)
	cycles := 1
	if fxFull() {
		cycles = 3
	}
	text := fxReview3Text()
	a, b := text["race_a.conf"], text["race_b.conf"]
	keep := []string{"ssl_ciphers", "ssl_protocols", KeepOptStatements}
	wa, _, _ := FilterConfigText(a, keep)
	wb, _, _ := FilterConfigText(b, keep)
	rt := NewRemoteWindowsTarget(r)
	ok, changed, other, torn, reads := fxTornRun(t, a, b, cycles, func(p string) ([]byte, error) {
		out, _, err := rt.ReadText(context.Background(), p, keep)
		return out, err
	}, func(out []byte) bool { return bytes.Equal(out, wa) || bytes.Equal(out, wb) })
	t.Logf("ok=%d changed=%d other=%d torn=%d of %d", ok, changed, other, torn, reads)
	if torn != 0 {
		t.Fatalf("%d torn reads", torn)
	}
	if ok == 0 {
		t.Fatal("no read succeeded: the test proves nothing")
	}
}

// TestRemoteWindowsRealDeviceNames: names Windows reads as devices or
// rewrites without the \\?\ form (fourth review) are read as the files they
// are.
func TestRemoteWindowsRealDeviceNames(t *testing.T) {
	r := fxPSRunner(t)
	dir := t.TempDir()
	prefix := ""
	if runtime.GOOS == "windows" {
		prefix = `\\?\`
	}
	conf := []byte("ssl_ciphers HIGH;\npassword S3cr3t;\n")
	keep := []string{"ssl_ciphers", KeepOptStatements}
	names := []string{"nul.conf", "con.conf", "aux", "COM1.conf", "prn.txt", "trail.", "trail "}
	for _, n := range names {
		if err := os.WriteFile(prefix+filepath.Join(dir, n), conf, 0o644); err != nil {
			t.Fatalf("%q: %v", n, err)
		}
	}
	fxSettle()
	rt := NewRemoteWindowsTarget(r)
	for _, n := range names {
		got, _, err := rt.ReadText(context.Background(), filepath.Join(dir, n), keep)
		if err != nil || string(got) != "ssl_ciphers HIGH;\n" {
			t.Errorf("%q: %q, %v", n, got, err)
		}
	}
}

// TestRemoteWindowsRealPathForms: the host normalises every path before it
// gives it the \\?\ form (vPath), so "..", forward slashes, a root-relative
// path, a trailing dot and a device name all reach the file they name, and
// Stat answers not-found for a missing path (fifth review: Get-Item on the
// \\?\ form returned null and Stat failed with a null-method error).
func TestRemoteWindowsRealPathForms(t *testing.T) {
	r := fxPSRunner(t)
	if runtime.GOOS != "windows" {
		t.Skip("path forms are Windows paths")
	}
	dir := t.TempDir()
	conf := []byte("ssl_ciphers HIGH;\npassword S3cr3t;\n")
	for _, n := range []string{`m\aux`, `m\nul.conf`, `m\COM1.conf`, `m\trail.`, `m\plain.conf`} {
		p := `\\?\` + filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, conf, 0o644); err != nil {
			t.Fatalf("%q: %v", n, err)
		}
	}
	fxSettle()
	rt := NewRemoteWindowsTarget(r)
	keep := []string{"ssl_ciphers", KeepOptStatements}
	forms := []string{
		dir + `\m\..\m\aux`, dir + `\m\.\nul.conf`, strings.ReplaceAll(dir, `\`, "/") + "/m/COM1.conf",
		dir + `\m\trail.`, dir[2:] + `\m\plain.conf`, dir + `\m\\plain.conf`,
	}
	for _, f := range forms {
		got, _, err := rt.ReadText(context.Background(), f, keep)
		if err != nil || string(got) != "ssl_ciphers HIGH;\n" {
			t.Errorf("ReadText %q: %q, %v", f, got, err)
		}
		fi, err := rt.Stat(context.Background(), f)
		if err != nil || fi.Size != int64(len(conf)) || fi.IsDir {
			t.Errorf("Stat %q: %+v, %v", f, fi, err)
		}
	}
	for _, f := range []string{dir + `\m\missing.conf`, dir + `\nosuch\x`, dir + `\m\..\..\` + filepath.Base(dir) + `\m\none`} {
		if _, err := rt.Stat(context.Background(), f); !errors.Is(err, ErrNotExist) {
			t.Errorf("Stat %q: %v, want not found", f, err)
		}
	}
	if fi, err := rt.Stat(context.Background(), dir+`\m\..`); err != nil || !fi.IsDir {
		t.Errorf("Stat of a directory by ..: %+v, %v", fi, err)
	}
}

// TestRemoteWindowsRealTornReadsTimeReset is the fifth review's writer: it
// rewrites the file in place and sets its last-write time back each time, so
// neither the quiescence rule nor the before/after times can see it (Windows
// has no change time .NET Framework reads). The double read must: two reads
// of one handle that differ refuse the read.
func TestRemoteWindowsRealTornReadsTimeReset(t *testing.T) {
	r := fxPSRunner(t)
	reads := 60
	if fxFull() {
		reads = 200
	}
	text := fxReview3Text()
	a, b := text["race_a.conf"], text["race_b.conf"]
	keep := []string{"ssl_ciphers", "ssl_protocols", KeepOptStatements}
	wa, _, _ := FilterConfigText(a, keep)
	wb, _, _ := FilterConfigText(b, keep)
	dir := t.TempDir()
	p := filepath.Join(dir, "swap.conf")
	tgtWrite(t, dir, "swap.conf", a, 0o644)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	fxSettle()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			f, err := os.OpenFile(p, os.O_WRONLY, 0)
			if err != nil {
				continue
			}
			src := a
			if i%2 == 1 {
				src = b
			}
			for off := 0; off < len(src); off += 4096 {
				_, _ = f.WriteAt(src[off:min(off+4096, len(src))], int64(off))
				time.Sleep(50 * time.Microsecond)
			}
			_ = f.Close()
			_ = os.Chtimes(p, old, old)
			time.Sleep(time.Duration(i%4) * 5 * time.Millisecond) // gaps, so some reads succeed
		}
	}()
	rt := NewRemoteWindowsTarget(r)
	ok, changed, torn := 0, 0, 0
	for i := 0; i < reads; i++ {
		out, _, err := rt.ReadText(context.Background(), p, keep)
		switch {
		case err == nil:
			ok++
			if !bytes.Equal(out, wa) && !bytes.Equal(out, wb) {
				torn++
				t.Errorf("read %d returned neither version: %s", i, fxFirstDiff(out, wa))
			}
		case errors.Is(err, errChanged):
			changed++
		}
	}
	close(stop)
	<-done
	t.Logf("ok=%d changed=%d torn=%d of %d", ok, changed, torn, reads)
	if ok == 0 {
		t.Error("no read succeeded: the test proves nothing")
	}
}

// TestRemoteWindowsRealFutureTime: a file stamped an hour ahead is refused
// (fifth review: the absolute difference let it through), and an hour-old
// one is read.
func TestRemoteWindowsRealFutureTime(t *testing.T) {
	r := fxPSRunner(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "f.conf")
	tgtWrite(t, dir, "f.conf", []byte("ssl_ciphers a;\n"), 0o644)
	ahead := time.Now().Add(time.Hour)
	if err := os.Chtimes(p, ahead, ahead); err != nil {
		t.Fatal(err)
	}
	fxSettle()
	rt := NewRemoteWindowsTarget(r)
	if _, _, err := rt.ReadText(context.Background(), p, []string{"ssl_ciphers"}); !errors.Is(err, errChanged) {
		t.Errorf("a file an hour ahead: %v", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if got, _, err := rt.ReadText(context.Background(), p, []string{"ssl_ciphers"}); err != nil || string(got) != "ssl_ciphers a;\n" {
		t.Errorf("a file an hour old: %q, %v", got, err)
	}
}

// psScripts are the programs a Windows host runs, by name.
func psScripts() map[string]string {
	return map[string]string{"psStat": psStat, "psIdentify": psIdentify, "psRead": psRead, "psReadText": psReadText, "psList": psList}
}

// psAutomatic are PowerShell's automatic variables, which a script must
// never assign ($_ is read in catch blocks only).
var psAutomatic = []string{"args", "input", "matches", "host", "error", "foreach", "switch", "this", "psitem", "home", "pid", "pwd",
	"profile", "shellid", "sender", "event", "eventargs", "eventsubscriber", "lastexitcode", "myinvocation", "executioncontext",
	"stacktrace", "psboundparameters", "pscmdlet", "pscommandpath", "psscriptroot", "psversiontable", "pshome", "psculture",
	"psuiculture", "nestedpromptlevel", "ofs", "consolefilename", "isglobal", "iscoreclr", "islinux", "ismacos", "iswindows"}

var psVarRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)

// TestPSVariableNamesDoNotCollide: two names differing only by case are ONE
// variable to PowerShell. That is how $S (a word set) and $s (a line) were
// one variable and the filter returned unlisted lines.
func TestPSVariableNamesDoNotCollide(t *testing.T) {
	for name, script := range psScripts() {
		if msg := psNameCollisions(script); msg != "" {
			t.Errorf("%s: %s", name, msg)
		}
	}
	// The check can fail: two spellings of one name.
	if psNameCollisions("$fooBar = 1; $foobar = 2") == "" {
		t.Error("the collision check found nothing in a script with a collision")
	}
}

func psNameCollisions(script string) string {
	spellings := map[string]map[string]bool{}
	for _, m := range psVarRe.FindAllStringSubmatch(script, -1) {
		l := strings.ToLower(m[1])
		if spellings[l] == nil {
			spellings[l] = map[string]bool{}
		}
		spellings[l][m[1]] = true
	}
	var bad []string
	for l, s := range spellings {
		if len(s) > 1 {
			bad = append(bad, fmt.Sprintf("%s %v", l, fxSorted(s)))
		}
	}
	sort.Strings(bad)
	return strings.Join(bad, "; ")
}

// TestPSScriptsAvoidTheTraps: no automatic variable, no case-insensitive
// operator, no case-insensitive hashtable, no backtick.
func TestPSScriptsAvoidTheTraps(t *testing.T) {
	for name, script := range psScripts() {
		if msg := psTraps(script); msg != "" {
			t.Errorf("%s: %s", name, msg)
		}
	}
	for _, bad := range []string{"$input = 1", "$Matches[0]", "if ($x -eq 'a') {}", "if ('a' -ne $x) {}", "$y = $x -match 'a'",
		"$y = @($x) -contains 'a'", "$h = @{}", "$y = $x -like 'a*'", "$y = $x -replace 'a', 'b'"} {
		if psTraps(bad) == "" {
			t.Errorf("the trap check passes %q", bad)
		}
	}
	for _, good := range []string{"if ($x -ceq 'a') {}", "if ($n -eq 0) {}", "$y = $x -ilike 'a*'", "[pscustomobject]@{ A = 1 }",
		"try { 1 } catch { psErr $_.Exception }", "$z = [ordered]@{ a = 1 }"} {
		if msg := psTraps(good); msg != "" {
			t.Errorf("the trap check refuses %q: %s", good, msg)
		}
	}
}

var (
	psCaseOps   = regexp.MustCompile(`(?i)\s-(eq|ne)\s*['"]|['"]\s*-(eq|ne)\b`)
	psBareOps   = regexp.MustCompile(`\s-(like|notlike|match|notmatch|contains|notcontains|in|notin|replace|split)\b`)
	psHashtable = regexp.MustCompile(`@\{`)
	psCatchUse  = regexp.MustCompile(`catch\s*\{[^}]*\$_\.`)
)

func psTraps(script string) string {
	var bad []string
	for _, m := range psVarRe.FindAllStringSubmatchIndex(script, -1) {
		name := strings.ToLower(script[m[2]:m[3]])
		for _, a := range psAutomatic {
			if name == a {
				bad = append(bad, "automatic variable $"+script[m[2]:m[3]])
			}
		}
	}
	if strings.Count(script, "$_") != len(psCatchUse.FindAllString(script, -1)) {
		bad = append(bad, "$_ outside a catch block")
	}
	if m := psCaseOps.FindString(script); m != "" {
		bad = append(bad, "case-insensitive comparison with a string: "+m)
	}
	if m := psBareOps.FindString(script); m != "" {
		bad = append(bad, "case-insensitive operator: "+m)
	}
	for _, loc := range psHashtable.FindAllStringIndex(script, -1) {
		before := script[:loc[0]]
		if !strings.HasSuffix(before, "[pscustomobject]") && !strings.HasSuffix(before, "[ordered]") {
			bad = append(bad, "a hashtable literal (its keys ignore case)")
			break
		}
	}
	if strings.Contains(script, "`") {
		bad = append(bad, "a backtick")
	}
	return strings.Join(bad, "; ")
}
