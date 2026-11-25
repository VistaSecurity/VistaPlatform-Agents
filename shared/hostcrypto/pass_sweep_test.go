package hostcrypto

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// tgtCollection builds a collection over a fake target, as Collect would.
func tgtCollection(t Target, opts Options) *collection {
	opts.Now = tgtNow
	return &collection{
		target:   t,
		opts:     opts,
		report:   newReport(opts),
		registry: newRegistry(opts.maxRecordsPerSection()),
		budget:   newBudget(opts.maxFiles(), time.Time{}, nil),
	}
}

// tgtSweepTree is one tree for both modes: a key hiding as backup.txt, a
// certificate, a DER certificate named .der, a keystore, text, a link.
func tgtSweepTree(t *testing.T, local bool) *tgtFakeTarget {
	certPEM, keyPEM, certDER, _ := tgtMaterial(t)
	return newTgtFakeTarget(local).
		file("/srv/app/backup.txt", keyPEM).
		file("/srv/app/server.crt", certPEM).
		file("/srv/app/ca.der", certDER).
		file("/srv/app/blob.bin", certDER).
		file("/srv/app/store.jks", append(append([]byte(nil), magicJKS...), 0, 0, 0, 2)).
		file("/srv/app/readme.md", []byte("# readme\n")).
		file("/srv/app/nssdb/cert9.db", []byte("SQLite format 3\x00")).
		symlink("/srv/app/current.crt", "/srv/app/server.crt")
}

func tgtHitPaths(hits []sweepHit) string {
	var p []string
	for _, h := range hits {
		p = append(p, h.Info.Path+"="+string(h.Identity.Class))
	}
	return strings.Join(p, ",")
}

func TestSweepLocalByContent(t *testing.T) {
	ft := tgtSweepTree(t, true)
	c := tgtCollection(ft, Options{})
	hits := sweep(context.Background(), c, []string{"/srv"})
	want := "/srv/app/backup.txt=private_key,/srv/app/ca.der=,/srv/app/nssdb/cert9.db=keystore," +
		"/srv/app/server.crt=certificate,/srv/app/store.jks=keystore"
	if got := tgtHitPaths(hits); got != want {
		t.Fatalf("hits:\n got %s\nwant %s", got, want)
	}
	if c.report.SectionState(SectionSweep) != SectionOK {
		t.Fatalf("sweep = %q", c.report.SectionState(SectionSweep))
	}
	// Every file was identified by content, the link was not.
	for _, p := range []string{"/srv/app/readme.md", "/srv/app/blob.bin", "/srv/app/backup.txt"} {
		if !ft.called("identify", p) {
			t.Errorf("%s not identified", p)
		}
	}
	if ft.called("identify", "/srv/app/current.crt") {
		t.Error("a link was followed")
	}
}

// TestSweepRemoteByName: remotely the key called backup.txt is NOT found,
// only named candidates are identified, and nothing is read.
func TestSweepRemoteByName(t *testing.T) {
	ft := tgtSweepTree(t, false)
	c := tgtCollection(ft, Options{})
	hits := sweep(context.Background(), c, []string{"/srv"})
	want := "/srv/app/ca.der=,/srv/app/nssdb/cert9.db=keystore,/srv/app/server.crt=certificate,/srv/app/store.jks=keystore"
	if got := tgtHitPaths(hits); got != want {
		t.Fatalf("hits:\n got %s\nwant %s", got, want)
	}
	for _, p := range []string{"/srv/app/backup.txt", "/srv/app/readme.md", "/srv/app/blob.bin"} {
		if ft.called("identify", p) {
			t.Errorf("%s identified remotely; only named candidates should be", p)
		}
	}
	for _, call := range ft.recorded() {
		if strings.HasPrefix(call, "read") {
			t.Fatalf("the sweep read a file: %s", call)
		}
	}
	// By name is not by content: partial, and the limit says so.
	if c.report.SectionState(SectionSweep) != SectionPartial {
		t.Fatalf("sweep = %q", c.report.SectionState(SectionSweep))
	}
	found := false
	for _, l := range c.report.Limits {
		found = found || (l.Section == SectionSweep && l.Limit == "remote_by_name")
	}
	if !found {
		t.Fatalf("limits: %+v", c.report.Limits)
	}
}

func TestSweepOutcomes(t *testing.T) {
	ctx := context.Background()

	// No roots: skipped.
	c := tgtCollection(newTgtFakeTarget(true), Options{})
	if sweep(ctx, c, nil) != nil || c.report.SectionState(SectionSweep) != SectionSkipped {
		t.Fatalf("no roots: %q", c.report.SectionState(SectionSweep))
	}

	// A root that does not exist holds nothing: ok.
	c = tgtCollection(newTgtFakeTarget(true), Options{})
	sweep(ctx, c, []string{"/nowhere"})
	if c.report.SectionState(SectionSweep) != SectionOK || len(c.report.Errors) != 0 {
		t.Fatalf("missing root: %q %+v", c.report.SectionState(SectionSweep), c.report.Errors)
	}

	// Every root unreadable: failed. One of two: partial.
	ft := tgtSweepTree(t, true).dir("/locked").deny("/locked")
	c = tgtCollection(ft, Options{})
	sweep(ctx, c, []string{"/locked"})
	if c.report.SectionState(SectionSweep) != SectionFailed || len(c.report.Errors) != 1 {
		t.Fatalf("all failed: %q %+v", c.report.SectionState(SectionSweep), c.report.Errors)
	}
	c = tgtCollection(ft, Options{})
	if hits := sweep(ctx, c, []string{"/locked", "/srv"}); len(hits) == 0 {
		t.Fatal("the readable root was not swept")
	}
	if c.report.SectionState(SectionSweep) != SectionPartial {
		t.Fatalf("one failed: %q", c.report.SectionState(SectionSweep))
	}

	// A denied subdirectory: partial with a counted error.
	ft = tgtSweepTree(t, true).dir("/srv/secret").deny("/srv/secret")
	c = tgtCollection(ft, Options{})
	sweep(ctx, c, []string{"/srv"})
	if c.report.SectionState(SectionSweep) != SectionPartial || len(c.report.Errors) != 1 ||
		!strings.Contains(c.report.Errors[0].Message, "1 directories") {
		t.Fatalf("denied subdir: %q %+v", c.report.SectionState(SectionSweep), c.report.Errors)
	}

	// An unreadable file: partial, counted.
	ft = tgtSweepTree(t, true).deny("/srv/app/readme.md")
	c = tgtCollection(ft, Options{})
	sweep(ctx, c, []string{"/srv"})
	if c.report.SectionState(SectionSweep) != SectionPartial ||
		!strings.Contains(c.report.Errors[0].Message, "1 files could not be identified") {
		t.Fatalf("unreadable file: %q %+v", c.report.SectionState(SectionSweep), c.report.Errors)
	}
}

func TestSweepBudget(t *testing.T) {
	ctx := context.Background()
	ft := tgtSweepTree(t, true)

	// The file budget truncates the listing and is recorded once.
	c := tgtCollection(ft, Options{MaxFiles: 3})
	sweep(ctx, c, []string{"/srv", "/srv/app"})
	if c.report.SectionState(SectionSweep) != SectionPartial {
		t.Fatalf("budget: %q", c.report.SectionState(SectionSweep))
	}
	n := 0
	for _, l := range c.report.Limits {
		if l.Section == SectionSweep && l.Limit == "max_files" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("max_files recorded %d times: %+v", n, c.report.Limits)
	}
	identified := 0
	for _, call := range ft.recorded() {
		if strings.HasPrefix(call, "identify ") {
			identified++
		}
	}
	if identified > 3 {
		t.Fatalf("identified %d files on a budget of 3", identified)
	}

	// An expired deadline stops before listing anything.
	ft = tgtSweepTree(t, true)
	c = tgtCollection(ft, Options{})
	c.budget = newBudget(100, tgtNow(), tgtNow)
	if hits := sweep(ctx, c, []string{"/srv"}); hits != nil || ft.called("list", "/srv") {
		t.Fatal("swept after the deadline")
	}
	if c.report.SectionState(SectionSweep) != SectionPartial || c.report.Limits[0].Limit != "max_duration" {
		t.Fatalf("deadline: %q %+v", c.report.SectionState(SectionSweep), c.report.Limits)
	}

	// Exclusions reach the listing.
	ft = tgtSweepTree(t, true)
	c = tgtCollection(ft, Options{ExcludePaths: []string{"/srv/app/nssdb"}})
	for _, h := range sweep(ctx, c, []string{"/srv"}) {
		if strings.HasPrefix(h.Info.Path, "/srv/app/nssdb") {
			t.Fatalf("excluded path swept: %s", h.Info.Path)
		}
	}
}

// TestSweepCountsWhatItSkips: files over the size bound and unreadable
// entries make the sweep partial with a LimitHit each (review item 7).
func TestSweepCountsWhatItSkips(t *testing.T) {
	certPEM, _, _, _ := tgtMaterial(t)
	ft := newTgtFakeTarget(true).
		file("/srv/a.pem", certPEM).
		file("/srv/huge.pem", make([]byte, 2048)).
		file("/srv/odd.pem", certPEM).unreadable("/srv/odd.pem").
		fifo("/srv/pipe.pem")
	c := tgtCollection(ft, Options{MaxFileBytes: 1024})
	hits := sweep(context.Background(), c, []string{"/srv"})
	if len(hits) != 1 || c.report.SectionState(SectionSweep) != SectionPartial {
		t.Fatalf("hits %d, sweep %q", len(hits), c.report.SectionState(SectionSweep))
	}
	got := map[string]bool{}
	for _, l := range c.report.Limits {
		got[l.Limit] = l.Section == SectionSweep
	}
	// The fake refuses a FIFO as the real targets do.
	if _, err := ft.Identify(context.Background(), "/srv/pipe.pem"); !errors.Is(err, errNotRegular) {
		t.Fatalf("fake FIFO: %v", err)
	}
	if !got["max_file_bytes"] || !got["unreadable"] {
		t.Fatalf("limits: %+v", c.report.Limits)
	}
}

// TestSweepRemoteNamesAndHitStat (review item 11): a remote sweep identifies
// the default SSH key names, which have no extension, and Stats each hit
// whose listing carried no permissions (remote Windows) — each hit, not each
// file.
func TestSweepRemoteNamesAndHitStat(t *testing.T) {
	_, keyPEM, _, _ := tgtMaterial(t)
	ft := newTgtFakeTarget(false).
		file("/home/u/.ssh/id_ed25519", keyPEM).
		file("/etc/ssh/ssh_host_rsa_key", keyPEM).
		file("/home/u/.ssh/config", []byte("Host x\n")).
		file("/home/u/notes", keyPEM)
	c := tgtCollection(ft, Options{})
	hits := sweep(context.Background(), c, []string{"/home", "/etc"})
	var paths []string
	for _, h := range hits {
		paths = append(paths, h.Info.Path)
	}
	if strings.Join(paths, ",") != "/etc/ssh/ssh_host_rsa_key,/home/u/.ssh/id_ed25519" {
		t.Fatalf("hits %q", paths)
	}
	if ft.called("identify", "/home/u/notes") || ft.called("identify", "/home/u/.ssh/config") {
		t.Fatal("a remote sweep identified a file by content")
	}

	// A listing without WorldReadable: the hit is Stat'ed, the rest are not.
	nl := &tgtNoACLTarget{tgtFakeTarget: newTgtFakeTarget(false).file("/c/a.pfx", []byte{0x30, 0x82, 1, 2}).file("/c/readme.txt", []byte("x"))}
	c = tgtCollection(nl, Options{})
	hits = sweep(context.Background(), c, []string{"/c"})
	if len(hits) != 1 || hits[0].Info.WorldReadable == nil {
		t.Fatalf("hits %+v", hits)
	}
	if !nl.called("stat", "/c/a.pfx") || nl.called("stat", "/c/readme.txt") {
		t.Fatalf("stat calls: %q", nl.recorded())
	}
}

// tgtNoACLTarget lists like the remote Windows target: no permissions.
type tgtNoACLTarget struct{ *tgtFakeTarget }

func (t *tgtNoACLTarget) List(ctx context.Context, root string, opts ListOptions) ([]FileInfo, error) {
	files, err := t.tgtFakeTarget.List(ctx, root, opts)
	for i := range files {
		files[i].WorldReadable, files[i].GroupReadable = nil, nil
	}
	return files, err
}
