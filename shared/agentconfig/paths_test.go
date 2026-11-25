package agentconfig

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestParsePathListCases(t *testing.T) {
	cases := []struct {
		in       string
		want     []string
		problems int
	}{
		{"", nil, 0},
		{"\n \n", nil, 0},
		{"/var/lib/docker", []string{"/var/lib/docker"}, 0},
		{" /b \r\n/a\n/b\n", []string{"/a", "/b"}, 0},
		{`C:\Windows\WinSxS`, []string{`C:\Windows\WinSxS`}, 0},
		{`c:/data`, []string{`c:/data`}, 0},
		{`\\fileserver\share`, []string{`\\fileserver\share`}, 0},
		{"/path with spaces, and commas", []string{"/path with spaces, and commas"}, 0},
		{"relative/path", nil, 1},
		{"C:relative", nil, 1},
		{"~/keys", nil, 1},
		{"/a/../etc", nil, 1},
		{`C:\a\..\b`, nil, 1},
		{"/ok\nnot-ok\n/also\tbad", []string{"/ok"}, 2},
		{"/" + strings.Repeat("a", MaxPathLength), nil, 1},
	}
	for _, c := range cases {
		got, problems := ParsePathList(c.in)
		if fmt.Sprint(got) != fmt.Sprint(c.want) || len(problems) != c.problems {
			t.Errorf("ParsePathList(%q) = %q, %q; want %q and %d problem(s)", c.in, got, problems, c.want, c.problems)
		}
	}
}

func TestParsePathListCeiling(t *testing.T) {
	var lines []string
	for i := 0; i <= MaxPathListEntries; i++ {
		lines = append(lines, fmt.Sprintf("/p%03d", i))
	}
	if _, problems := ParsePathList(strings.Join(lines, "\n")); len(problems) != 1 {
		t.Fatalf("%d paths: problems %q, want one", len(lines), problems)
	}
	if _, problems := ParsePathList(strings.Join(lines[:MaxPathListEntries], "\n")); len(problems) != 0 {
		t.Fatalf("%d paths refused: %q", MaxPathListEntries, problems)
	}
}

// One set of paths is one string, however it was typed, so a converged agent
// never shows as pending.
func TestFormatPathListIsCanonical(t *testing.T) {
	a := FormatPathList([]string{"/b", " /a", "/b", "rel", ""})
	b := FormatPathList([]string{"/a", "/b"})
	if a != b || a != "/a\n/b" {
		t.Fatalf("FormatPathList = %q and %q, want both %q", a, b, "/a\n/b")
	}
}

func TestHostCryptoSettings(t *testing.T) {
	for _, k := range []Key{KeyHostCryptoEnabled, KeyHostCryptoHomeDirectories, KeyHostCryptoDefaultKeystorePasswords} {
		f := Registry[k]
		if f.Kind != KindBool || f.Default.B == nil || *f.Default.B {
			t.Errorf("%s must be a bool that defaults OFF", k)
		}
		if !AppliesTo(k, RuntimeAgent) || AppliesTo(k, RuntimeSensor) {
			t.Errorf("%s must apply to the agent only", k)
		}
	}
	// The two opt-ins are consents: turning one on needs a confirmation, and
	// a device can never grant itself one (BootstrapValues skips them).
	for _, k := range []Key{KeyHostCryptoHomeDirectories, KeyHostCryptoDefaultKeystorePasswords} {
		if Registry[k].Confirm == "" {
			t.Errorf("%s needs a confirmation to turn on", k)
		}
		if got := BootstrapValues(RuntimeAgent, nil, nil, Values{k: Bool(true)}); len(got) != 0 {
			t.Errorf("a device reporting %s=true bootstrapped %v", k, got)
		}
	}
	iv := Registry[KeyHostCryptoInterval]
	if iv.Floor != 3600 || iv.Default.I == nil || *iv.Default.I != 86400 {
		t.Errorf("interval: floor %d default %v, want 3600 and 86400", iv.Floor, iv.Default)
	}
	if f := Registry[KeyHostCryptoExcludePaths]; f.Kind != KindPathList {
		t.Errorf("exclude paths kind %q", f.Kind)
	}
}

func TestValidateAndNormalizePathList(t *testing.T) {
	if err := Validate(RuntimeAgent, Values{KeyHostCryptoExcludePaths: Text("/ok\nrelative")}); err == nil {
		t.Fatal("a relative path was accepted")
	}
	if err := Validate(RuntimeAgent, Values{KeyHostCryptoExcludePaths: Int(3)}); err == nil {
		t.Fatal("a number was accepted as a path list")
	}
	if err := Validate(RuntimeAgent, Values{KeyHostCryptoExcludePaths: Text("/b\n/a")}); err != nil {
		t.Fatal(err)
	}
	out, _ := Normalize(RuntimeAgent, Values{KeyHostCryptoExcludePaths: Text(" /b\n/a\n/b ")})
	if got := *out[KeyHostCryptoExcludePaths].S; got != "/a\n/b" {
		t.Fatalf("normalized %q", got)
	}
	// A path list travels as a string, so an older agent decoding the whole
	// answer through Value does not lose every other setting.
	b, _ := json.Marshal(Values{KeyHostCryptoExcludePaths: Text("/a\n/b")})
	if string(b) != `{"host_crypto_exclude_paths":"/a\n/b"}` {
		t.Fatalf("wire form %s", b)
	}
	if c := (Change{Key: KeyHostCryptoExcludePaths, From: Text(""), To: Text("/a")}).String(); !strings.Contains(c, "none") {
		t.Fatalf("change %q does not say none for the empty list", c)
	}
}
