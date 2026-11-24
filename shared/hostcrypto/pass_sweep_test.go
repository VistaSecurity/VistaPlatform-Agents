package hostcrypto

import (
	"context"
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
	if c.report.SectionState(SectionSweep) != SectionOK {
		t.Fatalf("sweep = %q", c.report.SectionState(SectionSweep))
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
