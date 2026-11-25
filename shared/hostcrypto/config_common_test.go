package hostcrypto

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// cfgJSON marshals for comparison and for the secret checks.
func cfgJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// cfgWantEqual compares two configurations field by field through their JSON,
// so a failure prints both.
func cfgWantEqual(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		g, w := strings.Split(cfgJSON(t, got), "\n"), strings.Split(cfgJSON(t, want), "\n")
		var d []string
		have := map[string]int{}
		for _, l := range w {
			have[l]++
		}
		for _, l := range g {
			if have[l] > 0 {
				have[l]--
			} else {
				d = append(d, "+ "+strings.TrimSpace(l))
			}
		}
		have = map[string]int{}
		for _, l := range g {
			have[l]++
		}
		for _, l := range w {
			if have[l] > 0 {
				have[l]--
			} else {
				d = append(d, "- "+strings.TrimSpace(l))
			}
		}
		t.Errorf("mismatch (+ got only, - want only):\n%s", strings.Join(d, "\n"))
	}
}

// cfgFind returns the configuration with the given Context, failing the test
// when there is none.
func cfgFind(t *testing.T, cfgs []CryptoConfig, context string) CryptoConfig {
	t.Helper()
	for _, c := range cfgs {
		if c.Context == context {
			return c
		}
	}
	var have []string
	for _, c := range cfgs {
		have = append(have, c.Context)
	}
	t.Fatalf("no config with context %q; have %q", context, have)
	return CryptoConfig{}
}

// cfgNoSecrets fails when a secret value appears anywhere in the marshalled
// result, and when the result is empty (an empty result would pass vacuously).
func cfgNoSecrets(t *testing.T, cfgs []CryptoConfig, secrets ...string) {
	t.Helper()
	if len(cfgs) == 0 {
		t.Fatal("no configs parsed: the secret check would be vacuous")
	}
	out := cfgJSON(t, cfgs)
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("secret %q reached the report:\n%s", s, out)
		}
	}
}

func cfgCheckString(t *testing.T, what, s string) {
	t.Helper()
	if len(s) > cfgMaxValue {
		t.Errorf("%s is %d bytes, over the %d bound", what, len(s), cfgMaxValue)
	}
	if !utf8.ValidString(s) {
		t.Errorf("%s is not valid UTF-8", what)
	}
}

func cfgCheckList(t *testing.T, what string, l []string) {
	t.Helper()
	if len(l) > cfgMaxList {
		t.Errorf("%s has %d items, over the %d bound", what, len(l), cfgMaxList)
	}
	for _, s := range l {
		cfgCheckString(t, what, s)
	}
}

// cfgCheckBounds holds every value, list, map and reference to its bound.
func cfgCheckBounds(t *testing.T, cfgs []CryptoConfig) {
	t.Helper()
	for _, c := range cfgs {
		for _, s := range []string{c.Product, c.Context, c.MinProtocol, c.MaxProtocol, c.CipherString, c.Policy} {
			cfgCheckString(t, "field", s)
		}
		cfgCheckList(t, "Protocols", c.Protocols)
		cfgCheckList(t, "CipherSuites", c.CipherSuites)
		cfgCheckList(t, "KeyExchanges", c.KeyExchanges)
		cfgCheckList(t, "Groups", c.Groups)
		cfgCheckList(t, "MACs", c.MACs)
		cfgCheckList(t, "SignatureAlgorithms", c.SignatureAlgorithms)
		cfgCheckList(t, "HostKeyAlgorithms", c.HostKeyAlgorithms)
		cfgCheckList(t, "DisabledAlgorithms", c.DisabledAlgorithms)
		if len(c.Settings) > cfgMaxSettings {
			t.Errorf("%d settings, over the bound", len(c.Settings))
		}
		for k, v := range c.Settings {
			cfgCheckString(t, "setting name", k)
			cfgCheckString(t, "setting "+k, v)
		}
		if len(c.References) > cfgMaxRefs {
			t.Errorf("%d references, over the bound", len(c.References))
		}
		for _, r := range c.References {
			cfgCheckString(t, "reference", r.Path)
			cfgCheckString(t, "reference", r.Directive)
		}
	}
}

func TestConfigRegistry(t *testing.T) {
	want := []string{"apache", "crypto-policies", "gnutls", "haproxy", "java", "java-options",
		"krb5", "nginx", "openssl", "postfix", "ssh", "sshd"}
	cfgWantEqual(t, ConfigProducts(), want)
	for _, p := range want {
		if ConfigParserFor(p) == nil {
			t.Errorf("no parser for %q", p)
		}
	}
	if ConfigParserFor("nosuch") != nil || ConfigParserFor("") != nil {
		t.Error("an unknown product must have no parser")
	}
}

func TestCfgNormaliseProtocol(t *testing.T) {
	for in, want := range map[string]string{
		"SSLv3": "SSLv3", "sslv2": "SSLv2", "TLSv1": "TLSv1.0", "TLSv1.0": "TLSv1.0",
		"TLSv1_1": "TLSv1.1", "tls1.2": "TLSv1.2", " TLS 1.3 ": "TLSv1.3", "TLSv1.2": "TLSv1.2",
		"DTLSv1": "DTLSv1.0", "dtls1.2": "DTLSv1.2", "SSHv2": "SSHv2", "ssh1": "SSHv1",
	} {
		got, ok := cfgNormaliseProtocol(in)
		if !ok || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "SSLv2Hello", "ALL", "TLSv1.4", "2", "TLSv"} {
		if got, ok := cfgNormaliseProtocol(in); ok {
			t.Errorf("%q must not normalise, got %q", in, got)
		}
	}
}

func TestCfgLogicalLines(t *testing.T) {
	in := "\xef\xbb\xbfa \\\r\n   b\r\n# note \\\r\nc\r\n\x00d\\\\\r\ne"
	got := cfgLogicalLines([]byte(in), "#", true)
	var texts []string
	for _, l := range got {
		texts = append(texts, l.text)
	}
	// "a b" joined (leading blanks of the continuation dropped), the comment
	// does not swallow "c", NULs vanish, an even number of backslashes is not
	// a continuation.
	cfgWantEqual(t, texts, []string{"a b", "# note \\", "c", `d\\`, "e"})
	if got[0].n != 1 || got[2].n != 4 {
		t.Errorf("line numbers: %+v", got)
	}
	// Without continuation a trailing backslash is just text.
	off := cfgLogicalLines([]byte("a \\\nb"), "#", false)
	if len(off) != 2 {
		t.Errorf("continuation off: %+v", off)
	}
}

func TestCfgFields(t *testing.T) {
	cfgWantEqual(t, cfgFields(`a "b c" 'd e' f"g h"i # tail`, true), []string{"a", "b c", "d e", "fg hi"})
	cfgWantEqual(t, cfgFields(`a #b`, false), []string{"a", "#b"})
	cfgWantEqual(t, cfgFields(`say "he said \"hi\""`, false), []string{"say", `he said "hi"`})
	cfgWantEqual(t, cfgFields(`open "never closed`, false), []string{"open", "never closed"})
	cfgWantEqual(t, cfgFields(`"" x`, false), []string{"", "x"})
}

// cfgHostile builds the inputs that hurt parsers: unterminated quotes and
// braces, one enormous line, NULs, CRLF, a byte order mark, too many lines,
// endless continuations, nesting, expansion bombs.
func cfgHostile() map[string][]byte {
	big := strings.Repeat("A", 1<<20)
	prefixes := []string{
		"ssl_protocols ", "ssl_ciphers ", "Ciphers ", "MACs ", "CipherString = ", "Ciphersuites=",
		"SSLProtocol ", "SSLCipherSuite ", "jdk.tls.disabledAlgorithms=", "security.provider.1=",
		"bind :443 ssl ciphers ", "ssl-default-bind-ciphers ", "permitted_enctypes = ",
		"smtpd_tls_protocols = ", "SYSTEM=", "config=", "CRYPTO_POLICY=", "-Dhttps.protocols=",
		"Include ", "include ", ".include ", "HostKey ", "ssl_certificate ",
	}
	in := map[string][]byte{
		"empty":                 nil,
		"only-bom":              []byte("\xef\xbb\xbf"),
		"unterminated-dquote":   []byte(`ssl_protocols "TLSv1.2 TLSv1.3;` + "\nCiphers \"a,b\nSSLProtocol \"all"),
		"unterminated-squote":   []byte("ssl_ciphers 'HIGH;\nbind :443 ssl crt 'x"),
		"unbalanced-open":       []byte("http { server { listen 443 ssl; ssl_protocols TLSv1.3; "),
		"unbalanced-close":      []byte("} } } ssl_protocols TLSv1.2; }"),
		"unbalanced-vhost":      []byte("<VirtualHost *:443>\nSSLProtocol TLSv1.2\n</IfModule></Directory>\n<IfModule\n<"),
		"deep-braces":           []byte(strings.Repeat("a {", 100000) + "ssl_protocols TLSv1.3;"),
		"deep-sections":         []byte(strings.Repeat("<IfModule mod_ssl.c>\n", 100000) + "SSLProtocol TLSv1.2\n"),
		"nul-bytes":             []byte("Ciphers a\x00b\x00\x00\nssl_protocols\x00TLSv1.2;\n[\x00sec\x00]\nk\x00=\x00v"),
		"crlf":                  []byte("Ciphers aes256-ctr\r\nMACs hmac-sha2-256\r\nMatch User x\r\nCiphers a\r\n"),
		"bom-and-crlf":          []byte("\xef\xbb\xbfssl_protocols TLSv1.2;\r\nCiphers aes\r\n"),
		"many-lines":            []byte(strings.Repeat("Ciphers a\n", 250000)),
		"many-semicolons":       []byte(strings.Repeat(";", 5<<20)),
		"endless-continuation":  []byte(strings.Repeat("a \\\n", 250000)),
		"expansion-bomb":        []byte("a=$b$b\nb=$c$c\nc=$d$d\nd=$a$a\n[s]\nCipherString=$a\nopenssl_conf=s\nsmtpd_tls_ciphers=$a\n"),
		"binary":                []byte("\xff\xfe\x00\x01\x80\x81" + strings.Repeat("\xc3", 5000)),
		"huge-section-names":    []byte(strings.Repeat("[x]\n[y]\n", 100000)),
		"one-big-token":         []byte(big),
		"one-big-quoted":        []byte(`"` + big + `"`),
		"many-distinct-keys":    nil,
		"many-distinct-section": nil,
	}
	var keys, secs strings.Builder
	for i := 0; i < 20000; i++ {
		keys.WriteString("jdk.tls.keyLimits=")
		keys.WriteString(strings.Repeat("k", i%7+1))
		keys.WriteString("\nfips.p")
		keys.WriteString(strings.Repeat("x", i%50))
		keys.WriteString("=1\n")
		secs.WriteString("[s")
		secs.WriteString(strings.Repeat("y", i%40))
		secs.WriteString("]\nCipherString=")
		secs.WriteString(strings.Repeat("z", i%90))
		secs.WriteString("\n")
	}
	in["many-distinct-keys"] = []byte(keys.String())
	in["many-distinct-section"] = []byte(secs.String())
	for _, p := range prefixes {
		in["big-value:"+p] = []byte(p + big + "\n" + p + big + ";")
		in["big-list:"+p] = []byte(p + strings.Repeat("a,", 100000) + "\n")
	}
	return in
}

func TestConfigHostileInputs(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	inputs := cfgHostile()
	for _, product := range ConfigProducts() {
		parse := ConfigParserFor(product)
		for name, in := range inputs {
			start := time.Now()
			out := parse(in, nil)
			if d := time.Since(start); d > 10*time.Second {
				t.Errorf("%s on %s took %v", product, name, d)
			}
			cfgCheckBounds(t, out)
			if _, err := json.Marshal(out); err != nil {
				t.Errorf("%s on %s: result does not marshal: %v", product, name, err)
			}
		}
	}
	// The other exported entry points take the same input.
	for name, in := range inputs {
		for _, be := range []string{"opensslcnf", "openssh", "opensshserver", "gnutls", "java", "nss", "krb5"} {
			cfgCheckBounds(t, ParseCryptoPolicyBackend(be, in))
		}
		_ = name
	}
}

func TestParseCryptoPolicyBackendUnknown(t *testing.T) {
	if ParseCryptoPolicyBackend("nosuch.config", []byte("x=y")) != nil {
		t.Error("an unknown back-end must return nil")
	}
}

// cfgT parses b with no resolver. It also hands b to keepRecord, so the
// keep-word parity test (config_keep_test.go) sees every fixture.
func cfgT(p ConfigParser, b []byte) []CryptoConfig { keepRecord(p, "", b); return p(b, nil) }
