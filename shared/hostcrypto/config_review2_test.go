package hostcrypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reproductions from the second review of hc/configs, checked there against
// the real programs.

func TestJavaLoneCarriageReturnEndsALine(t *testing.T) {
	// java.util.Properties ends a line at \r, \n or \r\n, so the second
	// property is its own (unlisted) property, not part of the first's value.
	cfgs := cfgT(cfgParseJava, []byte("jdk.tls.disabledAlgorithms=SSLv3\rjavax.net.ssl.keyStorePassword=SECRETCR\rkeystore.type=pkcs12\r"))
	cfgNoSecrets(t, cfgs, "SECRETCR")
	cfgWantEqual(t, cfgs[0].DisabledAlgorithms, []string{"SSLv3"})
	cfgWantEqual(t, cfgs[0].Settings["keystore.type"], "pkcs12")
	// A \r\n pair is one line end, and a continuation may end in either.
	cfgs = cfgT(cfgParseJava, []byte("jdk.tls.disabledAlgorithms=SSLv3,\\\r\n  RC4\r\nkeystore.type=jks\r"))
	cfgWantEqual(t, cfgs[0].DisabledAlgorithms, []string{"SSLv3", "RC4"})
}

// What every parser does with a lone \r: a \r is blank space inside a line
// (cfgFields and TrimSpace treat it so; nginx's tokenizer too), never a line
// end, except in a properties file where it is one. Either way a secret on
// the far side of one cannot be kept, because no allowlisted directive can
// start after it.
func TestLoneCarriageReturnNeverLeaks(t *testing.T) {
	for product, in := range map[string]string{
		"sshd":            "Ciphers aes128-ctr\rMACs SECRETLONECR\rPasswordAuthentication SECRETLONECR\n",
		"ssh":             "Ciphers aes128-ctr\rIdentityFile SECRETLONECR\n",
		"nginx":           "http{ssl_protocols TLSv1.2;\rssl_certificate_key engine:SECRETLONECR;\r}",
		"apache":          "SSLProtocol TLSv1.2\rSSLCertificateKeyFile pkcs11:SECRETLONECR\n",
		"haproxy":         "global\n ssl-default-bind-ciphers HIGH\rssl-default-bind-ciphersuites SECRETLONECR\n",
		"openssl":         "openssl_conf=i\r[i]\rssl_conf=s\r[s]\rsystem_default=d\r[d]\rCipherString=HIGH\rPIN=SECRETLONECR\n",
		"krb5":            "[libdefaults]\rpermitted_enctypes = aes256-cts-hmac-sha1-96\rpkinit_identities = PKCS12:SECRETLONECR\n",
		"postfix":         "smtpd_tls_ciphers = high\rsmtpd_tls_key_file = store:SECRETLONECR\n",
		"gnutls":          "[overrides]\rinsecure-hash = md5\rSECRETLONECR = x\n",
		"java-options":    "-Dhttps.protocols=TLSv1.2\r-Djavax.net.ssl.keyStorePassword=SECRETLONECR\n",
		"crypto-policies": "DEFAULT\rSECRETLONECR\n",
	} {
		out := cfgT(ConfigParserFor(product), []byte(in))
		if strings.Contains(cfgJSON(t, out), "SECRETLONECR") {
			t.Errorf("%s: %s", product, cfgJSON(t, out))
		}
	}
}

func TestApacheDepthPastLimitIsCountedNotPushed(t *testing.T) {
	// 70 opens (6 past the limit) and 70 closes: the skipped body is skipped,
	// and afterwards the server level is current again.
	in := strings.Repeat("<IfModule x>\n", 70) + "SSLProtocol SSLv3\n" + strings.Repeat("</IfModule>\n", 70) + "SSLProtocol TLSv1.3\n"
	got := cfgT(cfgParseApache, []byte(in))
	cfgWantEqual(t, got[0].Protocols, []string{"TLSv1.3"})
	// A stray close tag changes nothing.
	got = cfgT(cfgParseApache, []byte("<IfModule mod_ssl.c>\n</Directory>\nSSLProtocol TLSv1.2\n</IfModule>\n"))
	cfgWantEqual(t, got[0].Protocols, []string{"TLSv1.2"})
}

func TestOpenSSLFIPSBackendNeverSetsFIPS(t *testing.T) {
	got := keepCPBackend("openssl_fips.config", []byte("[fips_sect]\nactivate = 1\n"))
	if got[0].FIPS != nil {
		t.Errorf("must not set FIPS: %s", cfgJSON(t, got))
	}
	cfgWantEqual(t, got[0].Settings["fips_sect activate"], "1")
}

func TestNginxRepeatedProtocolsAreUnited(t *testing.T) {
	got := cfgT(cfgParseNginx, []byte("server{listen 443 ssl; ssl_protocols TLSv1.2; ssl_protocols TLSv1.3 TLSv1.2; proxy_ssl_protocols TLSv1.1; proxy_ssl_protocols TLSv1.2;}"))
	cfgWantEqual(t, got[0].Protocols, []string{"TLSv1.2", "TLSv1.3"})
	cfgWantEqual(t, got[0].Settings["proxy_ssl_protocols"], "TLSv1.1 TLSv1.2")
}

func TestHAProxyProtocolFlagsBesideABoundAreIgnored(t *testing.T) {
	got := cfgT(cfgParseHAProxy, []byte("global\n ssl-default-bind-options ssl-min-ver TLSv1.2\nfrontend f\n bind :443 ssl no-tlsv13 no-sslv3\n bind :444 ssl ssl-max-ver TLSv1.2 no-tlsv10\n bind :445 ssl no-sslv3\n"))
	a := cfgFind(t, got, "frontend f bind :443")
	cfgWantEqual(t, a.DisabledProtocols, []string(nil))
	cfgWantEqual(t, a.Protocols, []string(nil))
	cfgWantEqual(t, a.MinProtocol, "TLSv1.2")
	cfgWantEqual(t, a.Settings["bind ssl-options"], "no-tlsv13 no-sslv3") // kept as written
	b := cfgFind(t, got, "frontend f bind :444")
	cfgWantEqual(t, b.Protocols, []string{"TLSv1.2"})
	cfgWantEqual(t, b.DisabledProtocols, []string(nil))
	// Under the inherited minimum even a lone no-* is ignored.
	cfgWantEqual(t, cfgFind(t, got, "frontend f bind :445").DisabledProtocols, []string(nil))
	// With no bound anywhere the exclusions count.
	got = cfgT(cfgParseHAProxy, []byte("frontend f\n bind :443 ssl no-sslv3\n"))
	cfgWantEqual(t, got[0].DisabledProtocols, []string{"SSLv3"})
}

func TestOpenSSLIncludeLeavesItsSectionCurrent(t *testing.T) {
	files := map[string][]byte{"/inc.cnf": []byte("[later]\nMinProtocol = TLSv1.2\n")}
	in := "openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = later\n.include /inc.cnf\nignored = x\n"
	// "ignored" lands in [later], where the included file left off, not in [s].
	f := cfgOSSLLoad([]byte(in), newCfgIncl(cfgMapResolver(files, "/")))
	if f.secs["later"].vals["ignored"] != "x" || f.secs["s"].vals["ignored"] != "" {
		t.Errorf("section after include: later=%v s=%v", f.secs["later"].vals, f.secs["s"].vals)
	}
	got := cfgParseOpenSSL([]byte(in), cfgMapResolver(files, "/"))
	cfgWantEqual(t, got[0].MinProtocol, "TLSv1.2")
}

func TestOpenSSLExplicitDefaultSection(t *testing.T) {
	for _, hdr := range []string{"[default]", "[ default ]", "[DEFAULT]"} {
		got := cfgT(cfgParseOpenSSL, []byte("[x]\na = b\n"+hdr+"\nopenssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nMinProtocol = TLSv1.3\n"))
		if len(got) != 1 || got[0].MinProtocol != "TLSv1.3" {
			t.Errorf("%s: %s", hdr, cfgJSON(t, got))
		}
	}
}

func TestKrb5IncludedirNameFilter(t *testing.T) {
	enc := func(n string) []byte { return []byte("[libdefaults]\npermitted_enctypes = " + n + "\n") }
	files := map[string][]byte{
		"/etc/krb5.conf.d/crypto-policies": enc("e1"), "/etc/krb5.conf.d/a_b-1": enc("e2"),
		"/etc/krb5.conf.d/site.conf": enc("e3"), "/etc/krb5.conf.d/.hidden.conf": enc("SECRETX"),
		"/etc/krb5.conf.d/x.rpmsave": enc("SECRETX"), "/etc/krb5.conf.d/ba$d": enc("SECRETX"),
		"/etc/krb5.conf.d/.dot": enc("SECRETX"),
	}
	for name, want := range map[string]bool{"crypto-policies": true, "a_b-1": true, "site.conf": true, ".hidden.conf": false, "x.rpmsave": false, "ba$d": false, ".dot": false} {
		res := func(string, int64) []IncludedFile {
			return []IncludedFile{{Path: "/etc/krb5.conf.d/" + name, Text: files["/etc/krb5.conf.d/"+name]}}
		}
		got := cfgParseKrb5([]byte("includedir /etc/krb5.conf.d\n"), res)
		read := len(got) == 1 && len(got[0].CipherSuites) == 1
		if read != want {
			t.Errorf("%s: read=%v want %v", name, read, want)
		}
	}
	// A plain "include" of a file is not filtered by name.
	got := cfgParseKrb5([]byte("include /x/.odd\n"), func(string, int64) []IncludedFile {
		return []IncludedFile{{Path: "/x/.odd", Text: enc("e9")}}
	})
	if len(got) != 1 || len(got[0].CipherSuites) != 1 {
		t.Errorf("include: %s", cfgJSON(t, got))
	}
}

func TestPostfixBlankAndCommentLinesDoNotEndAContinuation(t *testing.T) {
	got := cfgT(cfgParsePostfix, []byte("smtpd_tls_mandatory_ciphers = high\n\n# note\n   , medium\nsmtpd_tls_security_level = encrypt\n"))
	cfgWantEqual(t, got[0].Settings["smtpd_tls_mandatory_ciphers"], "high , medium")
	cfgWantEqual(t, got[0].Settings["smtpd_tls_security_level"], "encrypt")
}

func TestIncludeBudgetIsCheckedBeforeTheResolver(t *testing.T) {
	var asked []int64
	res := func(p string, max int64) []IncludedFile {
		asked = append(asked, max)
		return []IncludedFile{{Path: "/f" + strings.Repeat("x", len(asked)), Text: make([]byte, 5<<20)}}
	}
	in := newCfgIncl(res)
	for i := 0; i < 5; i++ {
		in.get("*", 0)
	}
	// 16 MiB / 5 MiB files: three are taken; the fourth is cut (its bytes do
	// not fit), after which the budget is under 5 MiB but not spent; the
	// resolver was told the remaining bytes each time.
	if len(asked) < 3 || asked[0] != cfgMaxIncludeBytes || asked[1] != cfgMaxIncludeBytes-5<<20 || asked[2] != cfgMaxIncludeBytes-10<<20 {
		t.Errorf("maxBytes told to the resolver: %v", asked)
	}
	// Depth: the resolver is not called at all at the limit.
	calls := 0
	inc := newCfgIncl(func(string, int64) []IncludedFile { calls++; return nil })
	inc.get("x", cfgMaxIncludeDepth)
	// File count: not called once 256 files were taken.
	inc.files = cfgMaxIncludeFiles
	inc.get("x", 0)
	// Bytes: not called once the budget is spent.
	inc.files, inc.bytes = 0, cfgMaxIncludeBytes
	inc.get("x", 0)
	if calls != 0 {
		t.Errorf("resolver called %d times with the budget spent", calls)
	}
	// A resolver that ignores maxBytes still cannot make the parser hold more.
	huge := newCfgIncl(func(string, int64) []IncludedFile {
		return []IncludedFile{{Path: "/a", Text: make([]byte, 20<<20)}}
	})
	if got := huge.get("x", 0); len(got) != 0 {
		t.Errorf("oversized file taken: %d", len(got))
	}
}

func TestHAProxyKeysAndDirectivesNeverComeFromFileText(t *testing.T) {
	got := cfgT(cfgParseHAProxy, []byte("backend b\n server pin=SECRETNAME 1.2.3.4:443 ssl send-proxy-v2-ssl crt /c.pem verify required\n server-template evil-key-name 2 h:1 ssl ca-file /ca.pem\n"))
	b := cfgFind(t, got, "backend b")
	for k := range b.Settings {
		if strings.Contains(k, "SECRETNAME") || strings.Contains(k, "evil-key-name") {
			t.Errorf("file text in a Settings key: %q", k)
		}
	}
	for _, r := range b.References {
		if strings.Contains(r.Directive, "SECRETNAME") || strings.Contains(r.Directive, "evil") {
			t.Errorf("file text in a directive: %q", r.Directive)
		}
	}
	// A zero-argument flag the parser does not know does not hide the crt.
	cfgWantEqual(t, b.References[0], ConfigReference{Kind: "certificate", Directive: "server crt", Path: "/c.pem"})
	cfgWantEqual(t, b.Settings["server.1 verify"], "required")
}

func TestHAProxyHasNoBackslashContinuation(t *testing.T) {
	got := cfgT(cfgParseHAProxy, []byte("global\n ssl-default-bind-ciphers HIGH\\\n ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256\n"))
	// The first line ends at its newline: the second directive is its own.
	cfgWantEqual(t, got[0].CipherString, "HIGH\\")
	cfgWantEqual(t, got[0].CipherSuites, []string{"TLS_AES_128_GCM_SHA256"})
}

func TestSSHDMatchKeywordsAreRestricted(t *testing.T) {
	got := cfgT(cfgParseSSHD, []byte("Match User bob\nCiphers aes128-ctr\nMACs hmac-sha2-256\nKexAlgorithms curve25519-sha256\nHostKeyAlgorithms ssh-ed25519\nHostKey /k\nPermitRootLogin no\n"))
	if len(got) != 1 || len(got[0].CipherSuites)+len(got[0].MACs)+len(got[0].KeyExchanges)+len(got[0].HostKeyAlgorithms)+len(got[0].References) != 0 {
		t.Errorf("global-only keywords kept in Match: %s", cfgJSON(t, got))
	}
	cfgWantEqual(t, got[0].Settings["PermitRootLogin"], "no")
	// The client's Match all takes everything.
	cl := cfgT(cfgParseSSHClient, []byte("Match all\nCiphers aes128-ctr\n"))
	cfgWantEqual(t, cl[0].CipherSuites, []string{"aes128-ctr"})
}

func TestJavaIncludeIsFollowed(t *testing.T) {
	files := map[string][]byte{"/more.security": []byte("jdk.tls.disabledAlgorithms=SSLv3, RC4\nkeystore.type=jks\n")}
	in := "include /more.security\nkeystore.type=pkcs12\n"
	plain := cfgT(cfgParseJava, []byte(in))
	cfgWantEqual(t, plain[0].DisabledAlgorithms, []string(nil))
	cfgWantEqual(t, plain[0].References, []ConfigReference{{Kind: "include", Directive: "include", Path: "/more.security"}})
	got := cfgParseJava([]byte(in), cfgMapResolver(files, "/"))
	cfgWantEqual(t, got[0].DisabledAlgorithms, []string{"SSLv3", "RC4"})
	cfgWantEqual(t, got[0].Settings["keystore.type"], "pkcs12") // the later definition wins
}

func TestNoCopiedCommentLinesInTests(t *testing.T) {
	files, _ := filepath.Glob("config_*_test.go")
	for _, f := range files {
		if f == "config_review2_test.go" {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, bad := range []string{"OpenSSL example configuration file", "To opt out of the system crypto-policies", "master security properties file", "Dropping SSLv3, ref: POODLE", "system-wide configuration file", "Mozilla \"intermediate\""} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
	}
}

func TestNoCopiedCommentLinesInFixtures(t *testing.T) {
	// The fixtures are written here: none carries a comment line from a
	// distribution's own file.
	for _, bad := range []string{"OpenSSL example configuration file", "To opt out of the system crypto-policies", "master security properties file", "Dropping SSLv3, ref: POODLE", "system-wide configuration file", "Mozilla \"intermediate\""} {
		for dir, files := range cfgOwn {
			for name, text := range files {
				if strings.Contains(text, bad) {
					t.Errorf("%s/%s contains %q", dir, name, bad)
				}
			}
		}
	}
}
