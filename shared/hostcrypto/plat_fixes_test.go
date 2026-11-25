package hostcrypto

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Finding 1: a deadline never leaves a section ok with an incomplete list.
// ---------------------------------------------------------------------------

// platSectionCounts counts each pass-1/2 section's items.
func platSectionCounts(rep *Report) map[string]int {
	return map[string]int{
		SectionCertificates: len(rep.Certificates),
		SectionPrivateKeys:  len(rep.PrivateKeys),
		SectionKeystores:    len(rep.Keystores),
		SectionSSH:          len(rep.SSH.AuthorizedKeys) + len(rep.SSH.KnownHosts) + len(rep.SSH.HostPublicKeys),
		SectionConfigs:      len(rep.Configs),
	}
}

// platRunStopping runs passes 1 and 2 on target with a clock that reads
// "before the deadline" for the first n checks and "past it" after; n < 0
// never expires. It returns the report and whether the clock ever expired.
func platRunStopping(t *testing.T, target Target, opts Options, n int) (*Report, bool) {
	t.Helper()
	c := tgtCollection(target, opts)
	deadline := tgtNow().Add(time.Hour)
	calls, expired := 0, false
	c.budget = newBudget(opts.maxFiles(), deadline, func() time.Time {
		calls++
		if n >= 0 && calls > n {
			expired = true
			return deadline
		}
		return deadline.Add(-time.Minute)
	})
	ctx := context.Background()
	passKnownLocations(ctx, c)
	passFollowConfiguration(ctx, c)
	c.registry.finish(c.report)
	return c.report, expired
}

func platHasLimit(rep *Report, section, limit string) bool {
	for _, l := range rep.Limits {
		if l.Section == section && l.Limit == limit {
			return true
		}
	}
	return false
}

// TestStopAtEveryBoundary stops passes 1 and 2 at every clock check in
// turn, on a Linux and a Windows fixture, local and remote: a section may
// read ok only when it holds everything the unbounded run found; any
// other section is partial with the time limit; none is failed.
func TestStopAtEveryBoundary(t *testing.T) {
	type fixture struct {
		name     string
		platform string
		make     func(bool) Target
	}
	fixtures := []fixture{
		{"linux", "linux", func(l bool) Target { return covTree(t, l) }},
		{"windows", "windows", func(l bool) Target { return locWindowsTree(t, l) }},
	}
	for _, fx := range fixtures {
		for _, local := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/local=%v", fx.name, local), func(t *testing.T) {
				opts := Options{Platform: fx.platform, HomeDirectories: true}
				full, _ := platRunStopping(t, fx.make(local), opts, -1)
				want := platSectionCounts(full)
				boundaries := 0
				for n := 0; n < 5000; n++ {
					target := fx.make(local)
					rep, expired := platRunStopping(t, target, opts, n)
					if !expired {
						break
					}
					boundaries++
					// No directory is covered unless all its files were
					// handled, wherever the run stopped.
					switch ft := target.(type) {
					case *tgtFakeTarget:
						covInvariant(t, ft, rep, covIdentity, covIdentity)
					case *locWinFake:
						covInvariant(t, ft.tgtFakeTarget, rep, locW2S, locS2W)
					}
					got := platSectionCounts(rep)
					for s, w := range want {
						state := rep.Sections[s]
						switch {
						case state == SectionFailed:
							t.Fatalf("stopped at check %d: %s failed", n, s)
						case state == SectionOK && got[s] != w:
							t.Fatalf("stopped at check %d: %s ok with %d of %d items", n, s, got[s], w)
						case state != SectionOK && state != SectionUnsupported && !platHasLimit(rep, s, "max_duration"):
							if state == SectionPartial && full.Sections[s] == SectionPartial {
								continue // partial for its own reasons in the full run too
							}
							t.Fatalf("stopped at check %d: %s is %q without the time limit", n, s, state)
						}
					}
				}
				if boundaries < 10 {
					t.Fatalf("only %d boundaries: the clock is not consulted where it should be", boundaries)
				}
			})
		}
	}
}

// TestStopDetailNamesTheBound: a caller's deadline earlier than MaxDuration
// is the bound named, a caller's cancellation says so, and neither leaves a
// section failed or ok.
func TestStopDetailNamesTheBound(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want string
	}{
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}, "caller's deadline"},
		{"cancelled", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, "cancelled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctx()
			defer cancel()
			rep, err := Collect(ctx, locLinuxTree(t, true), Options{Platform: "linux", Now: tgtNow, SweepRoots: []string{"/srv"}})
			if err != nil {
				t.Fatal(err)
			}
			for s, st := range rep.Sections {
				if s == SectionPlatform {
					continue
				}
				if st == SectionFailed || st == SectionOK {
					t.Errorf("%s: %s", s, st)
				}
			}
			found := false
			for _, l := range rep.Limits {
				if l.Limit == "max_duration" {
					found = true
					if !strings.Contains(l.Detail, tc.want) || strings.Contains(l.Detail, "15m0s") {
						t.Errorf("%s: detail %q", l.Section, l.Detail)
					}
				}
			}
			if !found {
				t.Fatal("no time limit recorded")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Finding 2: a visit uses the fullest description of a file.
// ---------------------------------------------------------------------------

// platACLWin is a remote Windows host as the real one answers: a listing
// carries no owner and no ACL; Stat (and the batch) carry both.
type platACLWin struct {
	*locWinFake
	statPerms bool
}

func (w platACLWin) List(ctx context.Context, root string, opts ListOptions) ([]FileInfo, error) {
	files, err := w.locWinFake.List(ctx, root, opts)
	for i := range files {
		files[i].Mode, files[i].Owner, files[i].WorldReadable, files[i].GroupReadable = 0, "", nil, nil
	}
	return files, err
}

func (w platACLWin) Stat(ctx context.Context, p string) (FileInfo, error) {
	fi, err := w.locWinFake.Stat(ctx, p)
	fi.Mode, fi.GroupReadable = 0, nil
	if w.statPerms {
		f := false
		fi.Owner, fi.WorldReadable = `NT AUTHORITY\SYSTEM`, &f
	} else {
		fi.Owner, fi.WorldReadable = "", nil
	}
	return fi, err
}

func (w platACLWin) StatIdentifyMany(ctx context.Context, paths []string) ([]PathInfo, error) {
	out := make([]PathInfo, 0, len(paths))
	for _, p := range paths {
		out = append(out, statIdentifySingle(ctx, w, p))
	}
	return out, nil
}

func TestVisitUsesTheFullestInfo(t *testing.T) {
	hostKey := `C:\ProgramData\ssh\ssh_host_ed25519_key`
	w := platACLWin{locWinFake: locWindowsTree(t, false), statPerms: true}
	rep := locCollect(t, w, Options{Platform: "windows"})
	k := locKeyAt(rep, hostKey)
	if k == nil || k.Location.Owner != `NT AUTHORITY\SYSTEM` || k.Location.WorldReadable == nil {
		t.Fatalf("host key visited without the ACL the host gave: %+v", k)
	}
	// When the host says nothing of permissions at all, the section says so.
	w = platACLWin{locWinFake: locWindowsTree(t, false), statPerms: false}
	rep = locCollect(t, w, Options{Platform: "windows"})
	if rep.Sections[SectionSSH] != SectionPartial || !locErrorsContain(rep, "permissions of") {
		t.Fatalf("unknown permissions: %v %+v", rep.Sections, rep.Errors)
	}
}

// ---------------------------------------------------------------------------
// Finding 3: a remote known_hosts file is never read as key lines.
// ---------------------------------------------------------------------------

// platPublicReader answers ReadPublic as a real remote target does for a
// known_hosts file: its key blobs alone, the host field gone.
type platPublicReader struct{ *tgtFakeTarget }

func (p platPublicReader) ReadPublic(ctx context.Context, path string) ([]byte, int, error) {
	return []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"), 0, nil
}

func TestRemoteKnownHostsNotMisread(t *testing.T) {
	ft := locLinuxTree(t, false)
	rep := locCollect(t, platPublicReader{ft}, Options{Platform: "linux", HomeDirectories: true})
	for _, kh := range rep.SSH.KnownHosts {
		if kh.Hashed != nil || kh.Entries != nil {
			t.Fatalf("remote known_hosts %s: entries %v hashed %v", kh.Location.Path, kh.Entries, kh.Hashed)
		}
	}
	if rep.Sections[SectionSSH] != SectionPartial || !locErrorsContain(rep, "known_hosts files are not read") {
		t.Fatalf("%v %+v", rep.Sections, rep.Errors)
	}
	// Locally the hashed file says hashed.
	rep = locCollect(t, locLinuxTree(t, true), Options{Platform: "linux"})
	for _, kh := range rep.SSH.KnownHosts {
		if kh.Location.Path == "/etc/ssh/ssh_known_hosts" && (kh.Hashed == nil || !*kh.Hashed || kh.Entries == nil || *kh.Entries != 1) {
			t.Fatalf("local: %+v", kh)
		}
	}
}

// ---------------------------------------------------------------------------
// Finding 5: the sweep records what it listed, at the file bound.
// ---------------------------------------------------------------------------

func TestSweepAtMaxFilesRecords(t *testing.T) {
	k := platNewKey(t, "sweep-bound")
	ft := newTgtFakeTarget(true)
	for i := 0; i < 5000; i++ {
		if i%10 == 0 {
			ft.file(fmt.Sprintf("/srv/d%02d/c%04d.crt", i%50, i), k.certPEM)
		} else {
			ft.file(fmt.Sprintf("/srv/d%02d/f%04d.txt", i%50, i), []byte("text\n"))
		}
	}
	c := tgtCollection(ft, Options{Platform: "linux", SweepRoots: []string{"/srv"}, MaxFiles: 3000})
	passSweep(context.Background(), c)
	c.registry.finish(c.report)
	if n := len(c.report.Certificates); n < 200 || n > 350 {
		t.Fatalf("recorded %d certificates of the ~300 the listed 3000 hold", n)
	}
	if c.report.Sections[SectionSweep] != SectionPartial || !platHasLimit(c.report, SectionSweep, "max_files") {
		t.Fatalf("%v %+v", c.report.Sections, c.report.Limits)
	}
}

// ---------------------------------------------------------------------------
// Finding 6: one file, however its path is spelled.
// ---------------------------------------------------------------------------

func TestRegistryNormalisesPaths(t *testing.T) {
	k := platNewKey(t, "paths")
	cert, err := ParseCertificateDER(k.certDER)
	if err != nil {
		t.Fatal(err)
	}
	r := newRegistry(100)
	for _, d := range []string{"/var", "/tmp", "/etc"} {
		r.addLink(d, "/private"+d)
	}
	for _, p := range []string{"/private/var/folders/x/k.pem", "/var/folders/x//k.pem", "/var/folders/./x/k.pem", "/var/folders/x/k.pem"} {
		c := cert
		c.Location = Location{Path: p, FoundBy: FoundBySweep}
		r.addCertificate(c)
	}
	rep := &Report{}
	r.finish(rep)
	if len(rep.Certificates) != 1 || rep.Certificates[0].Location.Path != "/var/folders/x/k.pem" {
		t.Fatalf("%+v", rep.Certificates)
	}
	// Without the links (Linux), /var and /private/var are two places.
	r = newRegistry(100)
	for _, p := range []string{"/private/var/k.pem", "/var//k.pem"} {
		c := cert
		c.Location = Location{Path: p}
		r.addCertificate(c)
	}
	rep = &Report{}
	r.finish(rep)
	if len(rep.Certificates) != 2 {
		t.Fatalf("%+v", rep.Certificates)
	}
}

// ---------------------------------------------------------------------------
// Finding 8: trust does not depend on which sighting came first.
// ---------------------------------------------------------------------------

func TestTrustAnchorIndependentOfOrder(t *testing.T) {
	k := platNewKey(t, "anchor")
	cert, err := ParseCertificateDER(k.certDER)
	if err != nil {
		t.Fatal(err)
	}
	// Registry: a plain sighting first, an anchor second.
	r := newRegistry(10)
	plain, anchor := cert, ksTrustAnchor(cert)
	plain.Location = Location{Path: "/etc/ssl/ca/a.pem", FoundBy: FoundByKnownLocation}
	anchor.Location = Location{Path: "/etc/ssl/ca/a.pem", FoundBy: FoundByConfig}
	r.addCertificate(plain)
	r.addCertificate(anchor)
	rep := &Report{}
	r.finish(rep)
	if len(rep.Certificates) != 1 || !rep.Certificates[0].TrustAnchor || rep.Certificates[0].CertificatePEM != "" {
		t.Fatalf("registry: %+v", rep.Certificates)
	}
	// locTouch: a file seen first plainly, then as a trust store.
	prod := &locProduced{certs: []Certificate{plain}}
	locTouch(prod, locVisit{Trust: true, FoundBy: FoundByConfig})
	if !prod.certs[0].TrustAnchor {
		t.Fatal("a later trust-store sighting did not make the certificate an anchor")
	}
	// A trust store's private-key entry's certificate is not an anchor.
	c := tgtCollection(newTgtFakeTarget(true), Options{Platform: "linux"})
	leaf, trusted := cert, cert
	leaf.Location.Alias, trusted.Location.Alias = "server", "ca"
	trusted.FingerprintSHA256 = "other"
	kc := KeystoreContents{
		Keystore: Keystore{Type: KeystoreJKS, Entries: []KeystoreEntry{
			{Alias: "server", Kind: "private_key", CertificateFingerprint: cert.FingerprintSHA256},
			{Alias: "ca", Kind: "certificate", CertificateFingerprint: "other"},
		}},
		Certificates: []Certificate{leaf, trusted},
	}
	f := &locFile{v: locVisit{Path: "/etc/app/trust.jks", Trust: true}, prod: &locProduced{}}
	c.locAddKeystore(f, kc)
	for _, got := range f.prod.certs {
		if got.Location.Alias == "server" && got.TrustAnchor {
			t.Fatal("the private-key entry's certificate became an anchor")
		}
		if got.Location.Alias == "ca" && !got.TrustAnchor {
			t.Fatal("the trusted entry is not an anchor")
		}
	}
}
