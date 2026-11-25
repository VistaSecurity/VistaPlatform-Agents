package hostcrypto

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func covIsCovered(rep *Report, dir string) bool {
	for _, d := range rep.Coverage.Directories {
		if d == dir {
			return true
		}
	}
	return false
}

func covSkipped(rep *Report, p string) string {
	for _, s := range rep.Coverage.SkippedFiles {
		if s.Path == p {
			return s.Reason
		}
	}
	return ""
}

// covItemAt reports whether the Report holds a file-based item at p.
func covItemAt(rep *Report, p string) bool {
	var locs []Location
	for _, x := range rep.Certificates {
		locs = append(locs, x.Location)
	}
	for _, x := range rep.PrivateKeys {
		locs = append(locs, x.Location)
	}
	for _, x := range rep.Keystores {
		locs = append(locs, x.Location)
	}
	for _, x := range rep.SSH.AuthorizedKeys {
		locs = append(locs, x.Location)
	}
	for _, x := range rep.SSH.KnownHosts {
		locs = append(locs, x.Location)
	}
	for _, l := range locs {
		if l.Path == p || l.Container == p {
			return true
		}
	}
	return false
}

// covInvariant is the removal precondition, checked against the fake host
// itself: in every covered directory, every regular file whose content is
// something the Report records is in the Report or in SkippedFiles. toFake
// maps a Report path to the fake's path (Windows fixtures store "/C:/...").
func covInvariant(t *testing.T, ft *tgtFakeTarget, rep *Report, toFake func(string) string, fromFake func(string) string) {
	t.Helper()
	ft.mu.Lock()
	type file struct {
		path string
		b    []byte
	}
	var all []file
	for p, n := range ft.nodes {
		if !n.dir && n.link == "" && !n.fifo {
			all = append(all, file{p, n.content})
		}
	}
	ft.mu.Unlock()
	for _, d := range rep.Coverage.Directories {
		fd := toFake(d)
		for _, f := range all {
			if filepathDir(f.path) != fd {
				continue
			}
			id := identityFrom(f.path, inspect(f.b, int64(len(f.b))))
			rec := id.Class == ClassCertificate || id.Class == ClassMixed || id.Class == ClassPrivateKey || id.Class == ClassKeystore
			rp := fromFake(f.path)
			if rec && !covItemAt(rep, rp) && covSkipped(rep, rp) == "" {
				t.Fatalf("%s is covered but %s (%s) is not in the Report", d, rp, id.Class)
			}
		}
	}
}

func filepathDir(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func covIdentity(p string) string { return p }

func covDER(b []byte) []byte {
	blk, _ := pem.Decode(b)
	return blk.Bytes
}

// covTree is a host with crypto directories of each kind of interest.
func covTree(t *testing.T, local bool) *tgtFakeTarget {
	m := locTestMaterial(t)
	big := append(append([]byte(nil), m.leafPEM...), []byte(strings.Repeat("# padding\n", 400))...)
	return locLinuxTree(t, local).
		// A name-filtered row (letsencrypt keeps *.pem): the .key beside
		// them is only found if coverage identifies everything.
		file("/etc/letsencrypt/live/site/cert.pem", m.leafPEM).
		fileMode("/etc/letsencrypt/live/site/privkey.pem", m.ecPEM, 0o600).
		fileMode("/etc/letsencrypt/live/site/extra.key", m.rsaPEM, 0o600).
		// An over-size file in a crypto directory.
		file("/etc/nginx/certs/a.crt", m.leafPEM).
		file("/etc/nginx/certs/huge.crt", big).
		// A remote-unplaceable binary.
		file("/etc/pki/CA/blob.der", covDER(m.leafPEM)).
		// A denied directory.
		file("/etc/haproxy/certs/x.pem", m.leafPEM).
		deny("/etc/haproxy/certs")
}

func TestCoverageKnownLocations(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(fmt.Sprintf("local=%v", local), func(t *testing.T) {
			ft := covTree(t, local)
			rep := locCollect(t, ft, Options{Platform: "linux", MaxFileBytes: 2048})
			covInvariant(t, ft, rep, covIdentity, covIdentity)
			// Covered: a crypto directory whose every file was handled.
			for _, d := range []string{"/etc/ssl/private", "/etc/letsencrypt/live/site", "/etc/nginx/certs", "/etc/ssh"} {
				if !covIsCovered(rep, d) {
					t.Errorf("%s not covered: %v", d, rep.Coverage.Directories)
				}
			}
			if !covItemAt(rep, "/etc/letsencrypt/live/site/extra.key") {
				t.Error("coverage did not identify the file outside the row's name filter")
			}
			if r := covSkipped(rep, "/etc/nginx/certs/huge.crt"); !strings.Contains(r, "read bound") {
				t.Errorf("the over-size file is not listed as skipped: %q", r)
			}
			// Never covered: denied, top-level, configuration directories.
			for _, d := range []string{"/etc/haproxy/certs", "/etc", "/etc/nginx", "/etc/elasticsearch"} {
				if covIsCovered(rep, d) {
					t.Errorf("%s covered", d)
				}
			}
			// The DER file is placed locally (parsed), not remotely.
			if covIsCovered(rep, "/etc/pki/CA") != local {
				t.Errorf("/etc/pki/CA covered=%v with local=%v", covIsCovered(rep, "/etc/pki/CA"), local)
			}
			// Home directories only with the opt-in.
			if covIsCovered(rep, "/home/alice/.ssh") {
				t.Error("a home directory covered without the opt-in")
			}
			rep = locCollect(t, covTree(t, local), Options{Platform: "linux", HomeDirectories: true, MaxFileBytes: 2048})
			if !covIsCovered(rep, "/home/alice/.ssh") {
				t.Errorf("the opted-in home .ssh not covered: %v", rep.Coverage.Directories)
			}
		})
	}
}

// TestCoverageMutation: a directory claimed covered without identifying its
// files is caught by the invariant.
func TestCoverageMutation(t *testing.T) {
	ft := covTree(t, true)
	rep := locCollect(t, ft, Options{Platform: "linux"})
	// Claim the denied directory too, as a careless rule would.
	rep.Coverage.Directories = append(rep.Coverage.Directories, "/etc/haproxy/certs")
	failed := false
	func() {
		defer func() { failed = recover() != nil }()
		covInvariantPanics(ft, rep)
	}()
	if !failed {
		t.Fatal("the invariant passes a directory whose files are not in the Report")
	}
}

// covInvariantPanics is covInvariant without a *testing.T, for the mutation
// test: it panics where covInvariant fails.
func covInvariantPanics(ft *tgtFakeTarget, rep *Report) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	for _, d := range rep.Coverage.Directories {
		for p, n := range ft.nodes {
			if n.dir || n.link != "" || filepathDir(p) != d {
				continue
			}
			id := identityFrom(p, inspect(n.content, int64(len(n.content))))
			if (id.Class == ClassCertificate || id.Class == ClassPrivateKey) && !covItemAt(rep, p) && covSkipped(rep, p) == "" {
				panic(p)
			}
		}
	}
}

func TestCoverageExclusions(t *testing.T) {
	ft := covTree(t, true)
	rep := locCollect(t, ft, Options{Platform: "linux", ExcludePaths: []string{"/etc/ssl/private/legacy.key", "/etc/nginx/certs"}})
	if covIsCovered(rep, "/etc/ssl/private") || covIsCovered(rep, "/etc/nginx/certs") {
		t.Fatalf("an excluded file or directory, covered: %v", rep.Coverage.Directories)
	}
}

func TestCoverageDroppedRecords(t *testing.T) {
	rep := locCollect(t, covTree(t, true), Options{Platform: "linux", MaxRecordsPerSection: 1})
	if len(rep.Coverage.Directories) != 0 || !platHasLimit(rep, covLimitSection, "max_records") {
		t.Fatalf("coverage with dropped records: %v %+v", rep.Coverage.Directories, rep.Limits)
	}
}

// TestCoverageNeighbours: the directory of a file a configuration names is
// covered when small, its other files recorded as neighbours; a big one is
// not.
func TestCoverageNeighbours(t *testing.T) {
	m := locTestMaterial(t)
	for _, local := range []bool{true, false} {
		ft := locLinuxTree(t, local).
			file("/etc/haproxy/haproxy.cfg", []byte("frontend f\n bind :443 ssl crt /srv/tls/site.pem\n")).
			file("/srv/tls/site.pem", m.leafPEM).
			fileMode("/srv/tls/old.key", m.rsaPEM, 0o600)
		ft.file("/etc/nginx/nginx.conf", []byte("http { server { listen 443 ssl; ssl_certificate /srv/big/a.crt; } }\n"))
		for i := 0; i < covMaxEntriesNeighbour+1; i++ {
			ft.file(fmt.Sprintf("/srv/big/f%04d.txt", i), []byte("x\n"))
		}
		ft.file("/srv/big/a.crt", m.leafPEM)
		rep := locCollect(t, ft, Options{Platform: "linux"})
		covInvariant(t, ft, rep, covIdentity, covIdentity)
		if !covIsCovered(rep, "/srv/tls") {
			t.Fatalf("local=%v: /srv/tls not covered: %v", local, rep.Coverage.Directories)
		}
		k := locKeyAt(rep, "/srv/tls/old.key")
		if k == nil || k.Location.FoundBy != FoundByNeighbour {
			t.Fatalf("the neighbour key: %+v", k)
		}
		if covIsCovered(rep, "/srv/big") {
			t.Fatal("a directory over the neighbour bound was covered")
		}
	}
}

func TestCoverageSweep(t *testing.T) {
	for _, local := range []bool{true, false} {
		m := locTestMaterial(t)
		ft := tgtSweepTree(t, local).
			file("/srv/web/tls/site.crt", m.leafPEM).
			fileMode("/srv/web/tls/backup.txt", m.ecPEM, 0o600).
			file("/srv/web/tls/notes.md", []byte("# notes\n"))
		c := tgtCollection(ft, Options{Platform: "linux", SweepRoots: []string{"/srv"}})
		passSweep(context.Background(), c)
		c.registry.finish(c.report)
		if covIsCovered(c.report, "/srv/web/tls") != local {
			t.Fatalf("local=%v: /srv/web/tls covered=%v %v", local, covIsCovered(c.report, "/srv/web/tls"), c.report.Coverage.Directories)
		}
		// The fixture's JKS is a stub that does not parse in full: its
		// directory is not covered.
		if covIsCovered(c.report, "/srv/app") {
			t.Fatal("a directory with a keystore read in part was covered")
		}
		if local {
			covInvariant(t, ft, c.report, covIdentity, covIdentity)
		}
	}
}

// TestCoverageRealFilesystem is the platform's removal precondition on this
// machine, as the unprivileged test user: a directory held by a listener
// this test starts is covered, with the key and its sibling; the key is
// deleted and the next collection still covers the directory without the
// key. A directory the user may not list is never covered, and one with an
// over-size file is covered with that file skipped.
func TestCoverageRealFilesystem(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pass 3 on this machine reads /proc")
	}
	if os.Geteuid() == 0 {
		t.Skip("must run unprivileged: root can list the denied directory")
	}
	k := platNewKey(t, "localhost")
	base := t.TempDir()
	dir, denied, sized := filepath.Join(base, "tls"), filepath.Join(base, "locked"), filepath.Join(base, "sized")
	for _, d := range []string{dir, denied, sized} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string, b []byte, mode os.FileMode) {
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatal(err)
		}
	}
	keyPath, certPath := filepath.Join(dir, "server.key"), filepath.Join(dir, "server.crt")
	write(keyPath, k.keyPEM, 0o600)
	write(certPath, k.certPEM, 0o644)
	write(filepath.Join(dir, "README"), []byte("hello\n"), 0o644)
	write(filepath.Join(denied, "a.crt"), k.certPEM, 0o644)
	write(filepath.Join(sized, "a.crt"), k.certPEM, 0o644)
	write(filepath.Join(sized, "huge.pem"), append(append([]byte(nil), k.certPEM...), []byte(strings.Repeat("# padding\n", 7000))...), 0o644)
	open := func(p string) *os.File {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	keyF, certF, deniedF, sizedF := open(keyPath), open(certPath), open(filepath.Join(denied, "a.crt")), open(filepath.Join(sized, "a.crt"))
	defer func() { _ = certF.Close(); _ = deniedF.Close(); _ = sizedF.Close() }()
	if err := os.Chmod(denied, 0o311); err != nil { // traversable, not listable
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(denied, 0o755) }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	collect := func() *Report {
		c := tgtCollection(NewLocalTarget(), Options{Platform: "linux", MaxFileBytes: 16 << 10})
		c.registry.resolve = localRealPath
		platRunningPass(context.Background(), c)
		c.registry.finish(c.report)
		return c.report
	}
	real := func(p string) string { r, _ := filepath.EvalSymlinks(p); return r }
	covered := func(rep *Report, d string) bool {
		for _, x := range rep.Coverage.Directories {
			if real(x) == real(d) {
				return true
			}
		}
		return false
	}
	has := func(rep *Report, p string) bool {
		for _, c := range rep.Certificates {
			if real(c.Location.Path) == real(p) {
				return true
			}
		}
		for _, x := range rep.PrivateKeys {
			if real(x.Location.Path) == real(p) {
				return true
			}
		}
		return false
	}
	rep := collect()
	if !covered(rep, dir) || !has(rep, keyPath) || !has(rep, certPath) {
		t.Fatalf("collection 1: covered=%v key=%v cert=%v %v", covered(rep, dir), has(rep, keyPath), has(rep, certPath), rep.Coverage.Directories)
	}
	if covered(rep, denied) {
		t.Fatal("a directory the user may not list was covered")
	}
	if !covered(rep, sized) {
		t.Fatalf("the directory with an over-size file is not covered: %v", rep.Coverage.Directories)
	}
	skippedOK := false
	for _, s := range rep.Coverage.SkippedFiles {
		skippedOK = skippedOK || real(s.Path) == real(filepath.Join(sized, "huge.pem"))
	}
	if !skippedOK {
		t.Fatalf("the over-size file is not in skipped_files: %+v", rep.Coverage.SkippedFiles)
	}
	t.Logf("collection 1: processes %q, %d directories covered", rep.Sections[SectionProcesses], len(rep.Coverage.Directories))

	_ = keyF.Close()
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	rep = collect()
	if !covered(rep, dir) || has(rep, keyPath) || !has(rep, certPath) {
		t.Fatalf("collection 2: covered=%v key=%v cert=%v", covered(rep, dir), has(rep, keyPath), has(rep, certPath))
	}
	if rep.Sections[SectionProcesses] == SectionOK {
		t.Log("processes read ok (no other users' processes on this machine)")
	}
}

// covReadDenied is a host where some files can be stat'ed but not read, as
// root's 0600 host keys are for an unprivileged agent.
type covReadDenied struct {
	*tgtFakeTarget
	denied map[string]bool
}

func (d covReadDenied) Identify(ctx context.Context, p string) (Identity, error) {
	if d.denied[p] {
		return Identity{}, fmt.Errorf("%s: %w", p, ErrPermission)
	}
	return d.tgtFakeTarget.Identify(ctx, p)
}

func (d covReadDenied) ReadFile(ctx context.Context, p string) ([]byte, error) {
	if d.denied[p] {
		return nil, fmt.Errorf("%s: %w", p, ErrPermission)
	}
	return d.tgtFakeTarget.ReadFile(ctx, p)
}

// TestCoverageUnreadableFileIsSkipped: the first real run found /etc/ssh
// covered with its host keys absent, because they could be stat'ed but not
// read. Such a file is now in SkippedFiles, so the platform keeps its item.
func TestCoverageUnreadableFileIsSkipped(t *testing.T) {
	ft := locLinuxTree(t, true)
	key := "/etc/ssh/ssh_host_ed25519_key"
	rep := locCollect(t, covReadDenied{ft, map[string]bool{key: true}}, Options{Platform: "linux"})
	if !covIsCovered(rep, "/etc/ssh") || covSkipped(rep, key) != "permission denied" {
		t.Fatalf("covered=%v skipped=%q", covIsCovered(rep, "/etc/ssh"), covSkipped(rep, key))
	}
	covInvariant(t, ft, rep, covIdentity, covIdentity)
}
