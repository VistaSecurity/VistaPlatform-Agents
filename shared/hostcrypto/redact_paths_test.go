package hostcrypto

import (
	mrand "math/rand/v2"
	"strings"
	"testing"
)

// fxPathRuns is the generated corpus's share of path-shaped and
// near-path-shaped runs: the edges of the exemption (a segment of 39 and of 40
// characters, an empty segment, one slash, a slash after = and after other
// characters) and random runs over an alphabet heavy in / and =.
func fxPathRuns() []string {
	a := func(n int) string { return strings.Repeat("A", n) }
	out := []string{
		"-Djavax.net.ssl.trustStore=/etc/elasticsearch/certs/truststore.jks",
		"ssl_certificate /etc/letsencrypt/live/www.example.internal/fullchain.pem",
		"SSLCertificateFile /etc/pki/tls/certs/localhostCombinedChainFile/serverchain",
		"key=" + strings.Repeat("QUJD", 11), "/" + strings.Repeat("QUJD", 20), "/a/b/" + a(60),
		"/" + a(39) + "/" + a(39), "/" + a(40) + "/" + a(39), "/" + a(39) + "/" + a(40), "//" + a(45),
		"/a//b/" + a(40), "=/a/b" + a(40), a(41) + "=/x/y", "x/y/" + a(45), a(20) + "=/" + a(30) + "/" + a(30),
		a(40) + "/a/b/" + a(40), "/a/b/c=/" + a(39) + "/d" + a(42), strings.Repeat("0123456789abcdef", 4),
	}
	rnd := mrand.New(mrand.NewPCG(2026, 1124))
	alpha := "AAAAAAAAAAzz09+==//////"
	for i := 0; i < 60; i++ {
		var b strings.Builder
		for n := 30 + rnd.IntN(90); n > 0; n-- {
			if rnd.IntN(8) == 0 {
				b.WriteString(a(rnd.IntN(45)))
				continue
			}
			b.WriteByte(alpha[rnd.IntN(len(alpha))])
		}
		out = append(out, b.String())
	}
	return out
}

// The path-shaped exemption: a long dotless path survives whole, while every
// secret shape the redaction exists for still goes.
func TestRedactPathShapedRuns(t *testing.T) {
	q := func(n int) string { return strings.Repeat("Q", n) }
	b64 := strings.Repeat("QUJD", 11) // 44 characters of base64
	hex := strings.Repeat("0123456789abcdef", 4)
	cases := []struct {
		name, in, out string
		n             int
	}{
		// Survive whole.
		{"jvm trust store path", "-Djavax.net.ssl.trustStore=/etc/elasticsearch/certs/truststore.jks", "", 0},
		{"nginx certificate path", "ssl_certificate /etc/letsencrypt/live/www.example.internal/fullchain.pem", "", 0},
		{"long dotless path", "SSLCertificateFile /etc/pki/tls/certs/localhostCombinedChainFile/serverchain", "", 0},
		{"39-character segments", "x /" + q(39) + "/" + q(39), "", 0},
		{"path after a short plain part", "x " + q(20) + "=/" + q(30) + "/" + q(30), "", 0},

		// Still redacted.
		{"base64 key after =", "key=" + b64, "[redacted]", 1},
		{"64-hex digest", "digest " + hex, "digest [redacted]", 1},
		{"one slash and 80 base64", "file /" + strings.Repeat("QUJD", 20), "file [redacted]", 1},
		{"a 60-character segment ends the path", "file /a/b/" + q(60), "file /a/b[redacted]", 1},
		{"a 40-character segment is not a path segment", "x /" + q(40) + "/" + q(39), "x [redacted]", 1},
		{"an empty segment ends the path", "x //" + q(45), "x [redacted]", 1},
		{"a slash inside the run is not a path start", "x " + q(41) + "/a/b", "x [redacted]", 1},
		{"a long plain part before = goes", "x " + q(41) + "=/a/b", "x [redacted]/a/b", 1},
		{"the remainder after a breaking segment is judged on its own", "x /a/b/c=/" + q(39) + "/d" + q(42), "x /a/b/c=/" + q(39) + "[redacted]", 1},
		{"a long remainder goes", "x /a/b/" + q(45) + "/c", "x /a/b[redacted]", 1},
		{"a short remainder after an empty segment stays", "x " + q(35) + "=/a/b//cc", "", 0},
		{"a path between two long plain parts", "x " + q(40) + "=/a/b/" + q(40), "x [redacted]/a/b[redacted]", 2},
	}
	for _, c := range cases {
		want := c.out
		if want == "" {
			want = c.in
		}
		got, n := redactRuns(c.in)
		if got != want || n != c.n {
			t.Errorf("%s:\n in   %q\n got  %q (%d)\n want %q (%d)", c.name, c.in, got, n, want, c.n)
		}
		// The same through the whole rule, as a kept line.
		word := strings.Fields(c.in)[0]
		if i := strings.IndexByte(word, '='); i > 0 {
			word = word[:i]
		}
		word = strings.TrimPrefix(word, "-D")
		out, red, ok := FilterConfigText([]byte(c.in+"\n"), []string{word})
		if !ok || string(out) != want+"\n" || red != c.n {
			t.Errorf("%s through FilterConfigText (keep %q): ok %v, got %q (%d)", c.name, word, ok, out, red)
		}
	}
}

// checkFiltered refuses a line redactRuns would still change, so redaction
// must be a fixed point.
func TestRedactRunsIsIdempotent(t *testing.T) {
	for _, s := range fxPathRuns() {
		once, _ := redactRuns(s)
		if twice, n := redactRuns(once); twice != once || n != 0 {
			t.Errorf("not a fixed point:\n in    %q\n once  %q\n twice %q", s, once, twice)
		}
	}
	for _, v := range fxGenerated(300) {
		for _, line := range strings.Split(string(v), "\n") {
			once, _ := redactRuns(line)
			if twice, _ := redactRuns(once); twice != once {
				t.Errorf("not a fixed point: %q", line)
			}
		}
	}
}

// The Go backstop on a remote host's filtered text accepts a path the host
// rightly left alone and still refuses a run the host should have redacted.
func TestCheckFilteredPathShapedRuns(t *testing.T) {
	paths := "-Djavax.net.ssl.trustStore=/etc/elasticsearch/certs/truststore.jks\n" +
		"SSLCertificateFile /etc/pki/tls/certs/localhostCombinedChainFile/serverchain\n"
	if out, _, err := checkFiltered("/etc/x.conf", []byte(paths), 0); err != nil || string(out) != paths {
		t.Errorf("path lines refused: %v, %q", err, out)
	}
	for _, bad := range []string{"key=" + strings.Repeat("QUJD", 11) + "\n", "file /a/b/" + strings.Repeat("Q", 60) + "\n"} {
		if _, _, err := checkFiltered("/etc/x.conf", []byte(bad), 0); err == nil {
			t.Errorf("unredacted run accepted: %q", bad)
		}
	}
}
