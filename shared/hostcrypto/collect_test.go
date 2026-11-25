package hostcrypto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

func tgtNow() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) }

func TestOptionsDefaults(t *testing.T) {
	var o Options
	if o.maxFiles() != 200000 || o.maxFileBytes() != 10<<20 || o.maxRecordsPerSection() != 2000 || o.maxDuration() != 15*time.Minute {
		t.Fatalf("defaults: %d %d %d %s", o.maxFiles(), o.maxFileBytes(), o.maxRecordsPerSection(), o.maxDuration())
	}
	o = Options{MaxFiles: 5, MaxFileBytes: 6, MaxRecordsPerSection: 7, MaxDuration: time.Second, Now: tgtNow}
	if o.maxFiles() != 5 || o.maxFileBytes() != 6 || o.maxRecordsPerSection() != 7 || o.maxDuration() != time.Second || !o.now().Equal(tgtNow()) {
		t.Fatal("overrides not honoured")
	}
}

// TestMarkPrecedence pins the outcome rule: failed > partial > ok >
// unsupported = skipped, the first of equals standing.
func TestMarkPrecedence(t *testing.T) {
	cases := []struct {
		seq  []string
		want string
	}{
		{[]string{SectionOK}, SectionOK},
		{[]string{SectionFailed, SectionOK}, SectionFailed},
		{[]string{SectionOK, SectionFailed}, SectionFailed},
		{[]string{SectionPartial, SectionOK}, SectionPartial},
		{[]string{SectionOK, SectionPartial, SectionOK}, SectionPartial},
		{[]string{SectionPartial, SectionFailed, SectionPartial}, SectionFailed},
		{[]string{SectionSkipped, SectionOK}, SectionOK},
		{[]string{SectionOK, SectionSkipped}, SectionOK},
		{[]string{SectionUnsupported, SectionSkipped}, SectionUnsupported},
		{[]string{SectionSkipped, SectionUnsupported}, SectionSkipped},
		{[]string{SectionFailed, SectionSkipped}, SectionFailed},
	}
	for _, tc := range cases {
		r := &Report{}
		for _, o := range tc.seq {
			r.mark("s", o)
		}
		if got := r.SectionState("s"); got != tc.want {
			t.Errorf("%q -> %q, want %q", tc.seq, got, tc.want)
		}
	}
	var nilRep *Report
	if nilRep.SectionState("x") != "" || nilRep.SectionOK("x") {
		t.Error("nil report")
	}
}

func TestReportHelpers(t *testing.T) {
	r := &Report{}
	r.fail(SectionCertificates, errors.New("boom"))
	r.partial(SectionKeystores, errors.New("half\nof it\x00"))
	r.skip(SectionHomeDirectories)
	r.limit(SectionSweep, "max_files", "stopped after 3 files")
	r.limit(SectionSweep, "max_files", "again")
	r.limit(SectionSweep, "max_duration", "stopped after 1s")
	r.fail(SectionConfigs, errors.New(strings.Repeat("é", 400)))

	if r.SectionOK(SectionCertificates) || r.SectionState(SectionCertificates) != SectionFailed {
		t.Error("fail")
	}
	if r.SectionState(SectionKeystores) != SectionPartial || r.SectionState(SectionHomeDirectories) != SectionSkipped || r.SectionState(SectionSweep) != SectionPartial {
		t.Errorf("sections: %v", r.Sections)
	}
	if len(r.Limits) != 2 {
		t.Fatalf("limits not de-duplicated: %+v", r.Limits)
	}
	for _, e := range r.Errors {
		if strings.ContainsAny(e.Message, "\n\x00") {
			t.Errorf("message not folded: %q", e.Message)
		}
		if len(e.Message) > maxErrorMessage+len("…(truncated)") {
			t.Errorf("message not bounded: %d bytes", len(e.Message))
		}
	}
	last := r.Errors[len(r.Errors)-1].Message
	if !strings.HasSuffix(last, "…(truncated)") || !strings.HasPrefix(last, "é") {
		t.Errorf("long message: %q", last)
	}
	if strings.ContainsRune(strings.TrimSuffix(last, "…(truncated)"), '�') {
		t.Error("message cut inside a rune")
	}
}

func TestBudget(t *testing.T) {
	now := tgtNow()
	b := newBudget(10, now.Add(time.Minute), func() time.Time { return now })
	if got := b.take(4); got != 4 || b.remaining() != 6 {
		t.Fatalf("take 4: %d, %d left", got, b.remaining())
	}
	if got := b.take(10); got != 6 || b.remaining() != 0 {
		t.Fatalf("take past the end: %d", got)
	}
	if b.take(1) != 0 {
		t.Fatal("granted beyond the allowance")
	}
	if b.expired() {
		t.Fatal("expired early")
	}
	now = now.Add(time.Minute)
	if !b.expired() {
		t.Fatal("did not expire")
	}

	// Concurrent takers never over-spend.
	cb := newBudget(1000, time.Time{}, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				n := cb.take(1)
				mu.Lock()
				total += n
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if total != 1000 || cb.expired() {
		t.Fatalf("granted %d of 1000", total)
	}
}

func TestCollectionLimitsOncePerSection(t *testing.T) {
	c := &collection{
		opts:   Options{MaxFiles: 2},
		report: newReport(Options{Now: tgtNow}),
		budget: newBudget(2, time.Time{}, nil),
	}
	c.files(SectionSweep, 1)
	c.files(SectionSweep, 5)
	c.files(SectionSweep, 5)
	c.files(SectionCertificates, 1)
	if len(c.report.Limits) != 2 {
		t.Fatalf("limits: %+v", c.report.Limits)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 2; i++ {
		if !c.timeUp(ctx, SectionSweep) {
			t.Fatal("timeUp")
		}
	}
	n := 0
	for _, l := range c.report.Limits {
		if l.Limit == "max_duration" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("max_duration recorded %d times", n)
	}
}

func TestRegistryDedupAndMerge(t *testing.T) {
	r := newRegistry(0)
	cfgUse := Usage{Kind: "config", ConfigPath: "/etc/nginx/nginx.conf", Directive: "ssl_certificate"}
	procUse := Usage{Kind: "process", Process: "nginx"}
	r.addCertificate(Certificate{Location: Location{Path: "/etc/ssl/a.pem", FoundBy: FoundBySweep}, FingerprintSHA256: "aa"})
	r.addCertificate(Certificate{Location: Location{Path: "/etc/ssl/a.pem", FoundBy: FoundByConfig, UsedBy: []Usage{cfgUse}}, FingerprintSHA256: "aa"})
	r.addCertificate(Certificate{Location: Location{Path: "/etc/ssl/a.pem", FoundBy: FoundByKnownLocation, UsedBy: []Usage{cfgUse, procUse}}, FingerprintSHA256: "aa"})
	// Same file, another member of the bundle: a distinct item.
	r.addCertificate(Certificate{Location: Location{Path: "/etc/ssl/a.pem", FoundBy: FoundBySweep}, FingerprintSHA256: "bb"})
	// A store item: distinct by store and fingerprint.
	r.addCertificate(Certificate{Location: Location{Store: `Cert:\LocalMachine\My`, FoundBy: FoundByPlatformStore}, FingerprintSHA256: "aa"})
	r.addPrivateKey(PrivateKey{Location: Location{Path: "/k", FoundBy: FoundBySweep}, PublicKeySHA256: "p"})
	r.addPrivateKey(PrivateKey{Location: Location{Path: "/k", FoundBy: FoundByProcess, UsedBy: []Usage{procUse}}, PublicKeySHA256: "p"})
	r.addLibrary(CryptoLibrary{Name: "openssl", Path: "/lib/libssl.so.3", Source: "file", LoadedBy: []string{"sshd"}})
	r.addLibrary(CryptoLibrary{Name: "openssl", Path: "/lib/libssl.so.3", Source: "process", LoadedBy: []string{"nginx", "sshd"}})

	rep := &Report{}
	r.finish(rep)
	if len(rep.Certificates) != 3 {
		t.Fatalf("certificates: %+v", rep.Certificates)
	}
	a := rep.Certificates[1] // sorted: store item ("" path) first, then a.pem aa, a.pem bb
	if a.Location.Path != "/etc/ssl/a.pem" || a.FingerprintSHA256 != "aa" {
		t.Fatalf("order: %+v", rep.Certificates)
	}
	if a.Location.FoundBy != FoundByConfig {
		t.Errorf("FoundBy = %q, want the strongest (config)", a.Location.FoundBy)
	}
	if len(a.Location.UsedBy) != 2 || a.Location.UsedBy[0] != cfgUse || a.Location.UsedBy[1] != procUse {
		t.Errorf("UsedBy = %+v", a.Location.UsedBy)
	}
	if len(rep.PrivateKeys) != 1 || rep.PrivateKeys[0].Location.FoundBy != FoundByProcess {
		t.Errorf("keys: %+v", rep.PrivateKeys)
	}
	if len(rep.Libraries) != 1 || strings.Join(rep.Libraries[0].LoadedBy, ",") != "nginx,sshd" || rep.Libraries[0].Source != "process" {
		t.Errorf("libraries: %+v", rep.Libraries)
	}
}

func TestRegistryMaxRecords(t *testing.T) {
	r := newRegistry(2)
	for i := 0; i < 5; i++ {
		r.addCertificate(Certificate{Location: Location{Path: fmt.Sprintf("/c%d", i), FoundBy: FoundBySweep}, FingerprintSHA256: "f"})
	}
	// Merging into an item already held still works at the bound.
	if !r.addCertificate(Certificate{Location: Location{Path: "/c0", FoundBy: FoundByConfig}, FingerprintSHA256: "f"}) {
		t.Fatal("merge refused at the bound")
	}
	// SSH shares one bound across its three lists.
	r.addAuthorizedKeys(AuthorizedKeysFile{Location: Location{Path: "/a"}})
	r.addKnownHosts(KnownHostsFile{Location: Location{Path: "/k"}})
	if r.addHostPublicKey(SSHPublicKey{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:x"}) {
		t.Fatal("ssh bound not shared")
	}
	r.addKeystore(Keystore{Location: Location{Path: "/s"}})
	r.addConfig(CryptoConfig{Location: Location{Path: "/n"}, Product: "nginx"})

	rep := &Report{Sections: map[string]string{}}
	r.finish(rep)
	if len(rep.Certificates) != 2 || rep.Certificates[0].Location.FoundBy != FoundByConfig {
		t.Fatalf("certs: %+v", rep.Certificates)
	}
	got := map[string]bool{}
	for _, l := range rep.Limits {
		if l.Limit != "max_records" {
			t.Errorf("limit %+v", l)
		}
		got[l.Section] = true
	}
	if !got[SectionCertificates] || !got[SectionSSH] || got[SectionKeystores] || got[SectionConfigs] || len(rep.Limits) != 2 {
		t.Fatalf("limits: %+v", rep.Limits)
	}
	if rep.SectionState(SectionCertificates) != SectionPartial {
		t.Error("a section cut by max_records must be partial")
	}
}

// TestRegistryDeterministic: the same items added in any order produce
// byte-identical JSON.
func TestRegistryDeterministic(t *testing.T) {
	items := []func(r *registry){
		func(r *registry) {
			r.addCertificate(Certificate{Location: Location{Path: "/b", FoundBy: FoundBySweep, UsedBy: []Usage{{Kind: "process", Process: "z"}}}, FingerprintSHA256: "2"})
		},
		func(r *registry) {
			r.addCertificate(Certificate{Location: Location{Path: "/b", FoundBy: FoundBySweep, UsedBy: []Usage{{Kind: "config", ConfigPath: "/c"}}}, FingerprintSHA256: "2"})
		},
		func(r *registry) {
			r.addCertificate(Certificate{Location: Location{Path: "/a", FoundBy: FoundBySweep}, FingerprintSHA256: "9"})
		},
		func(r *registry) { r.addKeystore(Keystore{Location: Location{Path: "/z.jks"}, Type: KeystoreJKS}) },
		func(r *registry) { r.addKeystore(Keystore{Location: Location{Path: "/a.p12"}, Type: KeystorePKCS12}) },
		func(r *registry) {
			r.addConfig(CryptoConfig{Location: Location{Path: "/n"}, Product: "nginx", Context: "b"})
		},
		func(r *registry) {
			r.addConfig(CryptoConfig{Location: Location{Path: "/n"}, Product: "nginx", Context: "a"})
		},
		func(r *registry) { r.addHostPublicKey(SSHPublicKey{Algorithm: "ssh-rsa", Fingerprint: "SHA256:b"}) },
		func(r *registry) { r.addHostPublicKey(SSHPublicKey{Algorithm: "ssh-ed25519", Fingerprint: "SHA256:a"}) },
		func(r *registry) { r.addPrivateKey(PrivateKey{Location: Location{Path: "/k2"}, PublicKeySHA256: "x"}) },
		func(r *registry) { r.addPrivateKey(PrivateKey{Location: Location{Path: "/k1"}, PublicKeySHA256: "y"}) },
	}
	render := func(order []int) string {
		r := newRegistry(0)
		for _, i := range order {
			items[i](r)
		}
		rep := newReport(Options{Now: tgtNow, Mode: hostinventory.ModeLocal, Platform: "linux"})
		r.finish(rep)
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	fwd := make([]int, len(items))
	rev := make([]int, len(items))
	for i := range items {
		fwd[i] = i
		rev[i] = len(items) - 1 - i
	}
	if a, b := render(fwd), render(rev); a != b {
		t.Fatalf("order-dependent output:\n%s\n%s", a, b)
	}
}

func TestCollectEmpty(t *testing.T) {
	// The header and scope, with no pass registered (the passes register in
	// their own files and are tested there).
	saved := passes
	t.Cleanup(func() { passes = saved })
	passes = nil
	ft := newTgtFakeTarget(true)
	rep, err := Collect(context.Background(), ft, Options{
		Platform: "linux", AgentID: "agent-1", Now: tgtNow,
		ExcludePaths: []string{"/z", "/a"}, SweepRoots: []string{"/srv"}, HomeDirectories: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode != hostinventory.ModeLocal || rep.Platform != "linux" || rep.AgentID != "agent-1" || !rep.Collected.Equal(tgtNow()) {
		t.Fatalf("header: %+v", rep)
	}
	if len(rep.Sections) != 1 || rep.Sections[SectionPlatform] != SectionOK {
		t.Fatalf("sections = %v; with no passes only platform is claimed", rep.Sections)
	}
	if strings.Join(rep.Scope.ExcludedPaths, ",") != "/a,/z" || !rep.Scope.HomeDirectories || rep.Scope.SweepRoots[0] != "/srv" {
		t.Fatalf("scope: %+v", rep.Scope)
	}
	if _, err := json.Marshal(rep); err != nil {
		t.Fatal(err)
	}
}

func TestCollectModeAndPlatform(t *testing.T) {
	ctx := context.Background()
	if _, err := Collect(ctx, nil, Options{}); err == nil {
		t.Error("nil target accepted")
	}
	remote := newTgtFakeTarget(false)
	if _, err := Collect(ctx, remote, Options{Mode: hostinventory.ModeLocal, Platform: "linux"}); err == nil {
		t.Error("local mode over a remote target accepted")
	}
	if _, err := Collect(ctx, newTgtFakeTarget(true), Options{Mode: hostinventory.ModeRemote, Platform: "linux"}); err == nil {
		t.Error("remote mode over a local target accepted")
	}
	if _, err := Collect(ctx, remote, Options{Mode: "sideways", Platform: "linux"}); err == nil {
		t.Error("unknown mode accepted")
	}

	// Remote: mode inferred, AgentID never stamped, platform detected.
	remote.script([]string{"uname", "-s"}, tgtResult{stdout: "Darwin\n"})
	rep, err := Collect(ctx, remote, Options{AgentID: "agent-1", Now: tgtNow})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode != hostinventory.ModeRemote || rep.AgentID != "" || rep.Platform != "darwin" {
		t.Fatalf("remote report: %+v", rep)
	}

	// Detection failing is an error with the platform section failed.
	rep, err = Collect(ctx, newTgtFakeTarget(false), Options{Now: tgtNow})
	if err == nil || rep == nil || rep.SectionState(SectionPlatform) != SectionFailed || len(rep.Errors) != 1 {
		t.Fatalf("undetectable platform: %+v %v", rep, err)
	}
	if _, err := Collect(ctx, newTgtFakeTarget(false), Options{Platform: "plan9"}); err == nil {
		t.Error("unknown platform accepted")
	}
}

// TestCollectRunsPasses registers a pass for the length of the test, to prove
// Collect calls passes with a working collection and finishes the registry.
func TestCollectRunsPasses(t *testing.T) {
	saved := passes
	t.Cleanup(func() { passes = saved })
	passes = []pass{func(ctx context.Context, c *collection) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("pass context has no deadline")
		}
		c.registry.addCertificate(Certificate{Location: Location{Path: "/x", FoundBy: FoundByKnownLocation}, FingerprintSHA256: "f"})
		c.mark(SectionCertificates, SectionOK)
	}}
	rep, err := Collect(context.Background(), newTgtFakeTarget(true), Options{Platform: "linux", Now: tgtNow, MaxDuration: time.Hour})
	if err != nil || len(rep.Certificates) != 1 || !rep.SectionOK(SectionCertificates) {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

// TestCollectionWrappers: the locked wrappers the passes call reach the
// report, concurrently.
func TestCollectionWrappers(t *testing.T) {
	c := &collection{report: newReport(Options{Now: tgtNow})}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				c.fail(SectionCertificates, errors.New("f"))
			case 1:
				c.partial(SectionKeystores, errors.New("p"))
			case 2:
				c.note(SectionKeystores, errors.New("n"))
			default:
				c.mark(SectionCertificates, SectionOK)
			}
		}(i)
	}
	wg.Wait()
	if c.report.SectionState(SectionCertificates) != SectionFailed || c.report.SectionState(SectionKeystores) != SectionPartial || len(c.report.Errors) != 15 {
		t.Fatalf("sections %v, %d errors", c.report.Sections, len(c.report.Errors))
	}
}

// TestRegistryRealPath (review item 12): one file reached by a link and by its
// own path is one item, recorded under the shorter path.
func TestRegistryRealPath(t *testing.T) {
	// Remote: links learnt from listings.
	r := newRegistry(0)
	r.addLink("/etc/ssl/certs/abcd1234.0", "../../pki/tls/certs/ca-bundle.crt")
	r.addLink("/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt")
	for _, p := range []string{"/etc/ssl/certs/abcd1234.0", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"} {
		r.addCertificate(Certificate{Location: Location{Path: p, FoundBy: FoundByKnownLocation}, FingerprintSHA256: "f"})
	}
	rep := &Report{}
	r.finish(rep)
	if len(rep.Certificates) != 1 || rep.Certificates[0].Location.Path != "/etc/ssl/cert.pem" {
		t.Fatalf("remote: %+v", rep.Certificates)
	}
	if got := joinLinkTarget(`C:\certs\link.pem`, "real.pem"); got != `C:\certs\real.pem` {
		t.Fatalf("windows relative target: %q", got)
	}

	// Local: resolved through the filesystem.
	if runtime.GOOS == "windows" {
		return
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "deep", "real-bundle.pem")
	tgtWrite(t, dir, "deep/real-bundle.pem", []byte("x"), 0o644)
	link := filepath.Join(dir, "c.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	lr := newRegistry(0)
	lr.resolve = localRealPath
	lr.addCertificate(Certificate{Location: Location{Path: real, FoundBy: FoundBySweep}, FingerprintSHA256: "f"})
	lr.addCertificate(Certificate{Location: Location{Path: link, FoundBy: FoundByConfig}, FingerprintSHA256: "f"})
	rep = &Report{}
	lr.finish(rep)
	if len(rep.Certificates) != 1 || rep.Certificates[0].Location.Path != link || rep.Certificates[0].Location.FoundBy != FoundByConfig {
		t.Fatalf("local: %+v", rep.Certificates)
	}
}

// TestCollectThreadsMaxFileBytes: Options.MaxFileBytes reaches the target.
func TestCollectThreadsMaxFileBytes(t *testing.T) {
	ft := newTgtFakeTarget(true).file("/x.conf", make([]byte, 100))
	if _, err := Collect(context.Background(), ft, Options{Platform: "linux", MaxFileBytes: 50}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ft.ReadText(context.Background(), "/x.conf", []string{"a"}); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("bound not threaded: %v", err)
	}
}

// TestLocalRunnerRunInput: the InputRunner the Windows target relies on.
func TestLocalRunnerRunInput(t *testing.T) {
	if _, err := exec.LookPath("cat"); err != nil {
		t.Skip("no cat")
	}
	var ir hostinventory.InputRunner = hostinventory.NewLocalRunner()
	out, _, exit, err := ir.RunInput(context.Background(), []string{"cat"}, []byte("line one\nline two\n"))
	if err != nil || exit != 0 || string(out) != "line one\nline two\n" {
		t.Fatalf("RunInput: %q %d %v", out, exit, err)
	}
	var _ hostinventory.InputRunner = (*hostinventory.SSHRunner)(nil)
}

// TestReadConfigIsTheOnlyPath (review item F): readConfig asks the target
// for exactly the product's keep words and refuses a product without them
// before the target is asked anything; the sweep reads no file at all, so a
// sweep hit is never read as text and a non-public file never as a file.
func TestReadConfigIsTheOnlyPath(t *testing.T) {
	saved := configKeepWords
	t.Cleanup(func() { configKeepWords = saved })
	configKeepWords = map[string][]string{"wireguard": {"address", "interface", "listenport", KeepOptSections}}

	conf := []byte("[Interface]\nPrivateKey = " + strings.Repeat("Q", 44) + "\nAddress = 10.0.0.1/24\npassword = hunter2\n")
	ft := newTgtFakeTarget(false).file("/etc/wireguard/wg0.conf", conf)
	c := tgtCollection(ft, Options{})
	got, err := c.readConfig(context.Background(), "/etc/wireguard/wg0.conf", "wireguard")
	if err != nil || string(got) != "[Interface]\nAddress = 10.0.0.1/24\n" {
		t.Fatalf("readConfig = %q, %v", got, err)
	}
	if len(ft.keeps) != 1 || strings.Join(ft.keeps[0], ",") != "address,interface,listenport,"+KeepOptSections {
		t.Fatalf("keep words sent: %q", ft.keeps)
	}
	before := len(ft.recorded())
	if _, err := c.readConfig(context.Background(), "/etc/wireguard/wg0.conf", "unknown-product"); !errors.Is(err, ErrNotPublic) {
		t.Fatalf("product without keep words: %v", err)
	}
	if len(ft.recorded()) != before {
		t.Fatal("the target was asked for a product without keep words")
	}

	// The sweep over a tree of text secrets, keys and certificates.
	_, keyPEM, _, _ := tgtMaterial(t)
	certPEM, _, _, _ := tgtMaterial(t)
	tree := newTgtFakeTarget(false).
		file("/srv/wg0.conf", conf).
		file("/srv/app/.env", []byte("DB_PASSWORD=hunter2\nAPI_TOKEN="+strings.Repeat("Z", 44)+"\n")).
		file("/srv/app/server.key", keyPEM).
		file("/srv/app/server.crt", certPEM).
		file("/srv/app/id_ed25519", keyPEM)
	sc := tgtCollection(tree, Options{})
	hits := sweep(context.Background(), sc, []string{"/srv"})
	if len(hits) == 0 {
		t.Fatal("no hits; the test proves nothing")
	}
	for _, call := range tree.recorded() {
		if strings.HasPrefix(call, "readtext ") || strings.HasPrefix(call, "read ") || strings.HasPrefix(call, "read-refused ") {
			t.Fatalf("the sweep read a file: %s", call)
		}
	}
}
