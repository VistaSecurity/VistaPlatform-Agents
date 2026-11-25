package hostcrypto

import (
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// TestPassOrder pins the one list that orders the passes (collect.go).
func TestPassOrder(t *testing.T) {
	var names []string
	for _, p := range passes {
		n := runtime.FuncForPC(reflect.ValueOf(p).Pointer()).Name()
		names = append(names, n[strings.LastIndexByte(n, '.')+1:])
	}
	want := "passKnownLocations,platPass,passFollowConfiguration,platRunningPass,passSweep"
	if got := strings.Join(names, ","); got != want {
		t.Fatalf("pass order:\n got %s\nwant %s", got, want)
	}
}

// TestPlatProcessRecordIsPassOnes: a file found through a process gets the
// record pass 1's dispatcher gives it, whatever the mode, with FoundBy
// process and the process's usages.
func TestPlatProcessRecordIsPassOnes(t *testing.T) {
	k := platNewKey(t, "same")
	for _, local := range []bool{true, false} {
		_, c := platRunningFake(t, local, k)
		platRunningPass(t.Context(), c)
		c.registry.finish(c.report)
		got := c.report.PrivateKeys

		ft := newTgtFakeTarget(local)
		ft.fileMode("/etc/ssl/server.key", k.keyPEM, 0o600)
		c2 := tgtCollection(ft, Options{Platform: "linux"})
		c2.locVisit(t.Context(), locVisit{Path: "/etc/ssl/server.key", Kind: locMaterial, FoundBy: FoundByProcess, Section: SectionProcesses})
		c2.locFlushRecords()
		c2.registry.finish(c2.report)
		want := c2.report.PrivateKeys
		if len(got) != 1 || len(want) != 1 {
			t.Fatalf("local=%v: %d %d", local, len(got), len(want))
		}
		g := got[0]
		g.Location.UsedBy = nil
		if !reflect.DeepEqual(g, want[0]) {
			t.Fatalf("local=%v:\n pass 3 %+v\n pass 1 %+v", local, g, want[0])
		}
	}
}

// TestPassSweepDispatches: a sweep hit is recorded through the dispatcher.
func TestPassSweepDispatches(t *testing.T) {
	k := platNewKey(t, "swept")
	ft := newTgtFakeTarget(true).fileMode("/srv/app/backup.txt", k.keyPEM, 0o600)
	c := tgtCollection(ft, Options{Platform: "linux", SweepRoots: []string{"/srv"}})
	passSweep(t.Context(), c)
	c.registry.finish(c.report)
	if len(c.report.PrivateKeys) != 1 || c.report.PrivateKeys[0].Location.FoundBy != FoundBySweep || c.report.Sections[SectionSweep] != SectionOK {
		t.Fatalf("%v %+v", c.report.Sections, c.report.PrivateKeys)
	}
	keyAssertNoLeak(t, "sweep", c.report, k.secret())
}

// TestProtectionAbsentWhenNotRead: an unread Protection is absent from the
// JSON, not an empty object.
func TestProtectionAbsentWhenNotRead(t *testing.T) {
	b, _ := json.Marshal(Report{})
	if strings.Contains(string(b), `"protection"`) {
		t.Fatalf("%s", b)
	}
	b, _ = json.Marshal(Report{Protection: Protection{FIPSMode: platBoolPtr(false)}})
	if !strings.Contains(string(b), `"protection":{"fips_mode":false}`) {
		t.Fatalf("%s", b)
	}
}
