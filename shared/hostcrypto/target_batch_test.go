package hostcrypto

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"golang.org/x/crypto/cryptobyte"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// fxNegativeSerial returns certDER with its serial number made negative:
// a strict envelope that crypto/x509 refuses, as it refuses the EC-ACC root
// of macOS's /etc/ssl/cert.pem (LibreSSL and .NET accept both).
func fxNegativeSerial(t *testing.T, certDER []byte) []byte {
	t.Helper()
	der := append([]byte(nil), certDER...)
	in := cryptobyte.String(der)
	var outer, tbs cryptobyte.String
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) || !outer.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		t.Fatal("certificate envelope")
	}
	tbs.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific())
	var serial cryptobyte.String
	if !tbs.ReadASN1(&serial, cbasn1.INTEGER) || len(serial) == 0 {
		t.Fatal("serial")
	}
	// serial aliases der: its first content byte, made negative and still
	// minimal.
	if serial[0] == 0 {
		serial[0] = 0x80
	} else {
		serial[0] |= 0x80
	}
	if _, err := x509.ParseCertificate(der); err == nil || !certEnvelope(der) {
		t.Fatalf("fixture: parse error %v, envelope %v", err, certEnvelope(der))
	}
	return der
}

// fxLooseEnvelope returns certDER with a fourth element in its outer
// SEQUENCE: not a strict envelope.
func fxLooseEnvelope(t *testing.T, certDER []byte) []byte {
	t.Helper()
	in := cryptobyte.String(certDER)
	var outer cryptobyte.String
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) {
		t.Fatal("envelope")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(outer)
		b.AddBytes([]byte{0x05, 0x00})
	})
	der, err := b.Bytes()
	if err != nil || certEnvelope(der) {
		t.Fatal("fixture")
	}
	return der
}

// Go's recheck of a remote answer: a strict-envelope certificate crypto/x509
// refuses is dropped and counted, the rest of the file crosses; anything
// that is not what the host rule prints refuses the whole answer.
func TestRecheckPublicPerBlock(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	_, _, certDER, _ := tgtMaterial(t)
	good := certificatePEM(certDER)
	neg := certificatePEM(fxNegativeSerial(t, certDER))
	loose := certificatePEM(fxLooseEnvelope(t, certDER))
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
	wide := "-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(certDER) + "\n-----END CERTIFICATE-----\n"
	cases := []struct {
		name, in, out string
		dropped       int
		ok            bool
	}{
		{"good", good, good, 0, true},
		{"negative serial between two good", good + neg + good, good + good, 1, true},
		{"negative serial and a key line", neg + key, key, 1, true},
		{"only a negative serial", neg, "", 1, false},
		{"a loose envelope refuses the answer", good + loose, "", 0, false},
		{"text between blocks refuses", good + "# comment\n" + good, "", 0, false},
		{"another label refuses", good + strings.ReplaceAll(good, "CERTIFICATE", "PUBLIC KEY"), "", 0, false},
		{"a non-canonical line width refuses", wide, "", 0, false},
		{"a block over the body bound refuses", "-----BEGIN CERTIFICATE-----\n" + strings.Repeat(strings.Repeat("A", 64)+"\n", maxCertBody/64+1) + "-----END CERTIFICATE-----\n", "", 0, false},
		{"no final line end refuses", strings.TrimSuffix(good, "\n"), "", 0, false},
		{"an unterminated block refuses", good + "-----BEGIN CERTIFICATE-----\n", "", 0, false},
		{"empty refuses", "", "", 0, false},
	}
	for _, c := range cases {
		b := []byte(c.in)
		out, dropped, err := recheckPublic("/x.pem", b, 1<<30)
		if (err == nil) != c.ok || string(out) != c.out || dropped != c.dropped {
			t.Errorf("%s: err %v, dropped %d, out %q", c.name, err, dropped, out)
		}
		if err != nil && !errors.Is(err, ErrNotPublic) {
			t.Errorf("%s: %v is not ErrNotPublic", c.name, err)
		}
		if len(c.in) > 0 && strings.Trim(string(b), "\x00") != "" {
			t.Errorf("%s: the answer was not cleared", c.name)
		}
	}
}

// fxJunkEnvelope is a strict certificate envelope around a TBS no parser
// takes: it passes every host's envelope check and then the parser refuses
// it.
func fxJunkEnvelope(t *testing.T) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Int64(1) })
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier([]int{1, 2, 840, 10045, 4, 3, 2}) })
		b.AddASN1BitString([]byte{1, 2, 3})
	})
	der, err := b.Bytes()
	if err != nil || !certEnvelope(der) {
		t.Fatal("fixture")
	}
	return der
}

// fxCountingBundle writes a bundle of one good certificate, one junk
// envelope and one negative-serial certificate, with text between them as
// a system bundle has.
func fxCountingBundle(t *testing.T) string {
	t.Helper()
	certPEM, _, certDER, _ := tgtMaterial(t)
	b := "# a bundle\n" + string(certPEM) + "=== junk\n" + certificatePEM(fxJunkEnvelope(t)) + "\nnegative\n" + certificatePEM(fxNegativeSerial(t, certDER))
	p := tgtWrite(t, t.TempDir(), "bundle.pem", []byte(b), 0o644)
	fxSettle()
	return p
}

// fxCheckCounts requires the good certificate to cross and the other two
// to be counted, wherever each was refused (the host's parser or Go).
func fxCheckCounts(t *testing.T, pr PublicReader, p string) {
	t.Helper()
	certPEM, _, _, _ := tgtMaterial(t)
	b, n, err := pr.ReadPublic(context.Background(), p)
	if err != nil || string(b) != string(certPEM) || n != 2 {
		t.Fatalf("read %q, %d unreadable, %v", b, n, err)
	}
}

func TestRemoteUnixRealReadPublicCounts(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	fxCheckCounts(t, NewRemoteUnixTarget(fxLocalRunner(), runtime.GOOS), fxCountingBundle(t))
}

func TestRemoteWindowsRealReadPublicCounts(t *testing.T) {
	fxCheckCounts(t, NewRemoteWindowsTarget(fxPSRunner(t)), fxCountingBundle(t))
}

// fxCountingFake is a remote fake target whose ReadPublic reports
// unreadable certificates.
type fxCountingFake struct {
	*tgtFakeTarget
	n int
}

func (f fxCountingFake) ReadPublic(ctx context.Context, p string) ([]byte, int, error) {
	b, err := f.ReadFile(ctx, p)
	return b, f.n, err
}

// The collector says how many certificates of a file could not be read.
func TestLocReadPublicNote(t *testing.T) {
	rep := locCollect(t, fxCountingFake{tgtFakeTarget: locLinuxTree(t, false), n: 2}, Options{Platform: "linux"})
	j, _ := json.Marshal(rep)
	if !strings.Contains(string(j), "/etc/ssl/certs/ca-certificates.crt: 2 certificates in this file could not be read") {
		t.Errorf("no note: %s", j)
	}
	rep = locCollect(t, fxCountingFake{tgtFakeTarget: locLinuxTree(t, false), n: 1}, Options{Platform: "linux"})
	if j, _ := json.Marshal(rep); !strings.Contains(string(j), "ca-certificates.crt: 1 certificate in this file could not be read") {
		t.Errorf("no singular note: %s", j)
	}
	rep = locCollect(t, fxCountingFake{tgtFakeTarget: locLinuxTree(t, false)}, Options{Platform: "linux"})
	if j, _ := json.Marshal(rep); strings.Contains(string(j), "in this file could not be read") {
		t.Errorf("a note with nothing unreadable")
	}
}

// fxSystemBundle names this machine's system CA bundle (or the one
// HOSTCRYPTO_BUNDLE names), or "" when it has none.
func fxSystemBundle() string {
	if p := os.Getenv("HOSTCRYPTO_BUNDLE"); p != "" {
		return p
	}
	for _, p := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// fxCheckBundle requires most of a system bundle to cross a remote read,
// and every certificate block of it to be either read or counted.
func fxCheckBundle(t *testing.T, pr PublicReader, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blocks := strings.Count(string(raw), "-----BEGIN CERTIFICATE-----") + strings.Count(string(raw), "-----BEGIN TRUSTED CERTIFICATE-----")
	if blocks == 0 {
		t.Skip("the bundle holds no certificate blocks")
	}
	b, unreadable, err := pr.ReadPublic(context.Background(), path)
	if err != nil {
		t.Fatalf("%s: %v (%d unreadable)", path, err, unreadable)
	}
	read := strings.Count(string(b), "-----BEGIN CERTIFICATE-----")
	t.Logf("%s: %d certificate blocks, %d read, %d could not be read", path, blocks, read, unreadable)
	if read+unreadable != blocks {
		t.Errorf("read %d + unreadable %d != %d blocks", read, unreadable, blocks)
	}
	if read*10 < blocks*9 {
		t.Errorf("only %d of %d certificates crossed", read, blocks)
	}
}

// TestRemoteUnixRealSystemBundle reads this machine's own system CA bundle
// through the remote Unix target's real host programs (sh, awk, openssl):
// most of it must cross, the rest counted.
func TestRemoteUnixRealSystemBundle(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	p := fxSystemBundle()
	if p == "" {
		t.Skip("no system CA bundle")
	}
	fxCheckBundle(t, NewRemoteUnixTarget(fxLocalRunner(), runtime.GOOS), p)
}

// TestRemoteWindowsRealSystemBundle reads a system CA bundle (this
// machine's, or HOSTCRYPTO_BUNDLE on a Windows host, which has no PEM
// bundle of its own) through the PowerShell host program.
func TestRemoteWindowsRealSystemBundle(t *testing.T) {
	r := fxPSRunner(t)
	p := fxSystemBundle()
	if p == "" {
		t.Skip("no CA bundle: set HOSTCRYPTO_BUNDLE")
	}
	fxCheckBundle(t, NewRemoteWindowsTarget(r), p)
}

// The secret the batch fixtures hold past their first MagicBytes bytes.
const fxBatchSecret = "S3cr3tBatchMarker"

// fxBatchTree writes files of every kind a batch must answer for and
// returns the paths to ask about (missing ones included).
func fxBatchTree(t *testing.T, unixOnly bool) []string {
	t.Helper()
	certPEM, keyPEM, certDER, _ := tgtMaterial(t)
	dir := t.TempDir()
	files := map[string][]byte{
		"cert.pem":     certPEM,
		"key.pem":      append(append([]byte(nil), keyPEM...), []byte("# "+fxBatchSecret+"\n")...),
		"both.pem":     append(append([]byte(nil), certPEM...), keyPEM...),
		"c.der":        certDER,
		"secret.txt":   []byte("password=" + fxBatchSecret + "\n"),
		"empty":        nil,
		"nul.bin":      []byte("abc\x00" + fxBatchSecret),
		"utf16.txt":    {0xff, 0xfe, 'a', 0, 'b', 0},
		"has space.pm": certPEM,
		"-dash.pem":    certPEM,
	}
	if unixOnly {
		files["new\nline.pem"] = certPEM
	}
	var paths []string
	for n, b := range files {
		paths = append(paths, tgtWrite(t, dir, n, b, 0o644))
	}
	paths = append(paths, dir, filepath.Join(dir, "missing.pem"), filepath.Join(dir, "no", "such", "dir.pem"))
	if unixOnly {
		for _, l := range [][2]string{{"key.pem", "link.pem"}, {"nowhere", "dangling.pem"}} {
			if err := os.Symlink(l[0], filepath.Join(dir, l[1])); err != nil {
				t.Fatal(err)
			}
			paths = append(paths, filepath.Join(dir, l[1]))
		}
		locked := tgtWrite(t, dir, "locked.pem", keyPEM, 0o000)
		paths = append(paths, locked)
	}
	fxSettle()
	return paths
}

// fxErrText is an error's text, or "" for nil.
func fxErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// fxBatchParity requires StatIdentifyMany to answer every path exactly as
// Stat and Identify do.
func fxBatchParity(t *testing.T, tg interface {
	Target
	BatchTarget
}, paths []string) {
	t.Helper()
	ctx := context.Background()
	got, err := tg.StatIdentifyMany(ctx, paths)
	if err != nil || len(got) != len(paths) {
		t.Fatalf("batch: %v, %d answers for %d paths", err, len(got), len(paths))
	}
	for i, p := range paths {
		g := got[i]
		fi, serr := tg.Stat(ctx, p)
		id, ierr := tg.Identify(ctx, p)
		if g.Path != p || !reflect.DeepEqual(g.Info, fi) || fxErrText(g.StatErr) != fxErrText(serr) {
			t.Errorf("%q stat: batch %+v %v, single %+v %v", p, g.Info, g.StatErr, fi, serr)
		}
		if !reflect.DeepEqual(g.Identity, id) || fxErrText(g.IdentifyErr) != fxErrText(ierr) {
			t.Errorf("%q identify: batch %+v %v, single %+v %v", p, g.Identity, g.IdentifyErr, id, ierr)
		}
		if len(g.Identity.Magic) > MagicBytes {
			t.Errorf("%q: %d magic bytes", p, len(g.Identity.Magic))
		}
	}
}

func TestStatIdentifyManyRealUnix(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	paths := fxBatchTree(t, true)
	rr := &tgtRecordingRunner{inner: fxLocalRunner()}
	rt := NewRemoteUnixTarget(rr, runtime.GOOS)
	fxBatchParity(t, rt, paths)
	if n := len(rr.runs); n != 1+2*len(paths) {
		t.Errorf("%d commands: the batch was not one", n)
	}
	// Past one batch's bound: still one answer per path, in order.
	var many []string
	for i := 0; i < 3*maxBatchPaths; i++ {
		many = append(many, paths[i%len(paths)])
	}
	got, err := rt.StatIdentifyMany(context.Background(), many)
	if err != nil || len(got) != len(many) {
		t.Fatalf("%d answers, %v", len(got), err)
	}
	for i := range many {
		if got[i].Path != many[i] {
			t.Fatalf("answer %d is for %q", i, got[i].Path)
		}
	}
}

func TestStatIdentifyManyRealWindows(t *testing.T) {
	r := fxPSRunner(t)
	paths := fxBatchTree(t, false)
	var calls atomic.Int64
	fxBatchParity(t, NewRemoteWindowsTarget(fxCountingRunner{inner: r, n: &calls}), paths)
	if n := calls.Load(); n != 1+2*int64(len(paths)) {
		t.Errorf("%d commands: the batch was not one", n)
	}
}

func TestStatIdentifyManyLocal(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	fxBatchParity(t, NewLocalTarget(), fxBatchTree(t, runtime.GOOS != "windows"))
}

// fxCountingRunner counts commands, keeping stdin.
type fxCountingRunner struct {
	inner hostinventory.Runner
	n     *atomic.Int64
}

func (r fxCountingRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	r.n.Add(1)
	return r.inner.Run(ctx, argv)
}

func (r fxCountingRunner) RunInput(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	r.n.Add(1)
	if ir, ok := r.inner.(hostinventory.InputRunner); ok {
		return ir.RunInput(ctx, argv, stdin)
	}
	return nil, nil, -1, errors.New("no stdin")
}

func (r fxCountingRunner) ReadFile(ctx context.Context, p string) ([]byte, error) {
	return r.inner.ReadFile(ctx, p)
}

// fxNoSecret fails when s holds the batch secret, as text or in hex.
func fxNoSecret(t *testing.T, where, s string) {
	t.Helper()
	for _, form := range []string{fxBatchSecret, hex.EncodeToString([]byte(fxBatchSecret)), base64.StdEncoding.EncodeToString([]byte(fxBatchSecret))[:16]} {
		if strings.Contains(s, form) {
			t.Errorf("%s: the secret crossed (%q)", where, form)
		}
	}
}

// No byte of a file beyond Identify's markers crosses in a batch answer:
// the host's raw answer, decoded, holds no secret the files hold past their
// first MagicBytes bytes.
func TestStatIdentifyManySecrecyUnix(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	paths := fxBatchTree(t, true)
	rt := NewRemoteUnixTarget(fxLocalRunner(), runtime.GOOS)
	out, _, exit, err := fxLocalRunner().Run(context.Background(), rt.batchArgv(paths))
	if err != nil || exit != 0 {
		t.Fatalf("exit %d %v", exit, err)
	}
	var decoded strings.Builder
	for _, line := range strings.Split(string(out), "\n") {
		for _, f := range strings.Fields(line) {
			if _, v, ok := strings.Cut(f, ":"); ok {
				b, _ := hex.DecodeString(v)
				decoded.Write(b)
				decoded.WriteByte('\n')
			}
		}
	}
	if !strings.Contains(decoded.String(), "flags:") {
		t.Fatalf("the answer did not decode: %q", out)
	}
	fxNoSecret(t, "unix batch", string(out)+decoded.String())
}

func TestStatIdentifyManySecrecyWindows(t *testing.T) {
	r := fxPSRunner(t)
	paths := fxBatchTree(t, false)
	rt := NewRemoteWindowsTarget(r)
	b, err := rt.psJSON(context.Background(), psBatch, psBatchArgs{Paths: paths, Max: rt.maxBytes})
	if err != nil || !json.Valid(b) || !strings.Contains(string(b), `"Flags"`) {
		t.Fatalf("batch answer: %v %q", err, b)
	}
	fxNoSecret(t, "windows batch", string(b))
}

// fxBatchFake is a fake target with StatIdentifyMany as a loop of its own
// single calls, counting batches.
type fxBatchFake struct {
	*tgtFakeTarget
	batches *atomic.Int64
}

func (f fxBatchFake) StatIdentifyMany(ctx context.Context, paths []string) ([]PathInfo, error) {
	f.batches.Add(1)
	out := make([]PathInfo, 0, len(paths))
	for _, p := range paths {
		out = append(out, statIdentifySingle(ctx, f.tgtFakeTarget, p))
	}
	return out, nil
}

// Pass 1 over a remote target with the batch interface makes the same
// Report as without it, and uses the batch.
func TestLocBatchParity(t *testing.T) {
	opts := Options{Platform: "linux", HomeDirectories: true}
	plain := locCollect(t, locLinuxTree(t, false), opts)
	var n atomic.Int64
	ft := locLinuxTree(t, false)
	batched := locCollect(t, fxBatchFake{tgtFakeTarget: ft, batches: &n}, opts)
	a, _ := json.MarshalIndent(plain, "", " ")
	b, _ := json.MarshalIndent(batched, "", " ")
	if string(a) != string(b) {
		t.Errorf("the Reports differ:\n%s", fxFirstDiff(b, a))
	}
	if n.Load() == 0 {
		t.Error("pass 1 did not use the batch")
	}
	// A directory the batch found missing is not listed; one it found is.
	plainFT := locLinuxTree(t, false)
	locCollect(t, plainFT, opts)
	lists := func(calls []string) (all, missing int) {
		for _, c := range calls {
			if root, ok := strings.CutPrefix(c, "list "); ok {
				all++
				if _, err := plainFT.Stat(context.Background(), root); errors.Is(err, ErrNotExist) {
					missing++
				}
			}
		}
		return
	}
	pa, pm := lists(plainFT.recorded())
	ba, bm := lists(ft.recorded())
	if pm == 0 || bm != 0 || ba != pa-pm {
		t.Errorf("lists: %d (%d of missing roots) without the batch, %d (%d) with it", pa, pm, ba, bm)
	}
	// A local target is not batched.
	n.Store(0)
	locCollect(t, fxBatchFake{tgtFakeTarget: locLinuxTree(t, true), batches: &n}, opts)
	if n.Load() != 0 {
		t.Error("a local target was batched")
	}
}
