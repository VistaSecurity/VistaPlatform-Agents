package hostcrypto

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Reproductions from the review of hc/configs: each case below leaked, hung
// or reported something the file does not say.

func TestReviewLeaks(t *testing.T) {
	cases := []struct{ name, product, in string }{
		{"openssl-expand-req-password", "openssl", "openssl_conf=i\n[i]\nssl_conf=s\n[s]\nsystem_default=d\n[d]\nCipherString=HIGH:${req::input_password}\n[req]\ninput_password=SECRETPW1\n"},
		{"openssl-expand-global", "openssl", "pw=SECRETPW2\nopenssl_conf=i\n[i]\nssl_conf=s\n[s]\nsystem_default=d\n[d]\nOptions=$pw\n"},
		{"openssl-include-expand", "openssl", "pw=SECRETPW3\n.include /etc/$pw\n"},
		{"openssl-provider-name", "openssl", "openssl_conf=i\n[i]\nproviders=p\n[p]\nSECRETPW4=x\n[x]\nactivate=1\n"},
		{"openssl-engines-keys", "openssl", "openssl_conf=i\n[i]\nengines=e\n[e]\nSECRETPW5=pk\npkcs11=pk\n[pk]\nPIN=SECRETPW5\n"},
		{"java-fips-prefix", "java", "fips.keystore.password=SECRETPW6\nfips.provider.1=SUN\n"},
		{"java-provider-inline", "java", "security.provider.1=SunPKCS11 --name=x\\nlibrary=/l.so\\nSECRETPW7\nsecurity.provider.2=SUN\n"},
		{"nginx-store-pin", "nginx", "http{server{listen 443 ssl; ssl_certificate_key \"store:pkcs11:token=t;pin-value=SECRETPW8\";}}"},
		{"nginx-pkcs11-bare", "nginx", "http{server{listen 443 ssl; ssl_certificate_key \"pkcs11:token=t?pin-value=SECRETPW9\";}}"},
		{"nginx-cert-store", "nginx", "http{server{listen 443 ssl; ssl_certificate \"store:pkcs11:pin-value=SECRETPWA\";}}"},
		{"nginx-proxy-pass-url", "nginx", "http{server{listen 443 ssl; proxy_ssl_server_name https://u:SECRETPWB@h;}}"},
		{"nginx-server-name-url", "nginx", "http{server{listen 443 ssl; server_name https://u:SECRETPWB2@h; ssl_protocols TLSv1.2;}}"},
		{"apache-key-quoted-space", "apache", "SSLCertificateKeyFile \" pkcs11:pin-value=SECRETPWC\"\nSSLEngine on\n"},
		{"apache-pkcs11-case", "apache", "<VirtualHost *:443>\nSSLCertificateKeyFile PKCS11:pin-value=SECRETPWD\nSSLEngine on\n</VirtualHost>\n"},
		{"apache-ssl-proxy-cert", "apache", "SSLProxyMachineCertificateFile pkcs11:pin-value=SECRETPWE\nSSLProtocol TLSv1.2\n"},
		{"apache-vhost-args", "apache", "<VirtualHost *:443 SECRETPWF>\nSSLEngine on\n</VirtualHost>\n"},
		{"apache-servername-url", "apache", "<VirtualHost *:443>\nServerName https://u:SECRETPWF2@h\nSSLEngine on\n</VirtualHost>\n"},
		{"ssh-match-negexec", "ssh", "Match !exec \"curl -H 'Authorization: Bearer SECRETPWG' x\"\nCiphers aes128-ctr\n"},
		{"ssh-match-exec-eq", "ssh", "Match exec=\"SECRETPWH\"\nCiphers aes128-ctr\n"},
		{"ssh-match-unknown-criterion", "ssh", "Match Frobnicate SECRETPWH2 user bob\nCiphers aes128-ctr\n"},
		{"ssh-host-url", "ssh", "Host https://u:SECRETPWI@h\nCiphers aes128-ctr\n"},
		{"ssh-identity-url", "ssh", "IdentityFile pkcs11:pin-value=SECRETPWI2\nCiphers aes128-ctr\n"},
		{"haproxy-unknown-opt", "haproxy", "frontend f\n bind :443 ssl crt /c.pem quic-cc-algo ciphers SECRETPWJ\n"},
		{"haproxy-global-server-options", "haproxy", "global\n ssl-default-server-options ca-sign-pass SECRETPWK\n ssl-default-bind-ciphers HIGH\n"},
		{"haproxy-server-sni", "haproxy", "backend b\n server s 1.2.3.4:443 ssl verify none sni str(SECRETPWL) alpn h2 check\n"},
		{"haproxy-server-unknown", "haproxy", "backend b\n server s 1.2.3.4:443 ssl pool-conn-name SECRETPWM\n"},
		{"haproxy-bind-url", "haproxy", "frontend f\n bind https://u:SECRETPWM2@h ssl crt /c.pem\n"},
		{"postfix-expand", "postfix", "pw = SECRETPWN\nsmtpd_tls_ciphers = $pw\nsmtpd_tls_security_level = may\n"},
		{"postfix-key-url", "postfix", "smtpd_tls_key_file = store:pin-value=SECRETPWN2\nsmtpd_tls_security_level = may\n"},
		{"krb5-ccache", "krb5", "[libdefaults]\ndefault_ccache_name = FILE:/tmp/SECRETPWO\nallow_weak_crypto = false\n"},
		{"krb5-pkcs12-pin", "krb5", "[libdefaults]\npkinit_identities = PKCS12:/x.p12?pin=SECRETPWP\nallow_weak_crypto = false\n"},
		{"krb5-keytab", "krb5", "[libdefaults]\ndefault_keytab_name = https://u:SECRETPWP2@h/k\nallow_weak_crypto = false\n"},
		{"gnutls", "gnutls", "[overrides]\nSECRETPWQ = x\ninsecure-hash = sha1\n"},
		{"java-options-store", "java-options", "-Djavax.net.ssl.keyStore=store:pkcs11:pin-value=SECRETPWR -Dhttps.protocols=TLSv1.2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := cfgT(ConfigParserFor(c.product), []byte(c.in))
			if strings.Contains(cfgJSON(t, out), "SECRETPW") {
				t.Errorf("secret reached the report: %s", cfgJSON(t, out))
			}
			cfgCheckBounds(t, out)
		})
	}
}

func TestCfgRefSchemes(t *testing.T) {
	for _, tc := range []struct {
		in        string
		source    string // Settings "<directive>_source", empty when none
		path      string // the reference kept, empty when none
		isInclude bool
	}{
		{"/etc/ssl/key.pem", "", "/etc/ssl/key.pem", false},
		{"relative/key.pem", "", "relative/key.pem", false},
		{`C:\ssl\key.pem`, "", `C:\ssl\key.pem`, false},
		{"C:/ssl/key.pem", "", "C:/ssl/key.pem", false},
		{"store:pkcs11:token=t;pin-value=S", "store", "", false},
		{"ENGINE:pkcs11:id", "engine", "", false},
		{"data:abc", "data", "", false},
		{"pkcs11:token=t?pin-value=S", "pkcs11", "", false},
		{"https://u:p@h/x", "https", "", false},
		{"file:///etc/x", "file", "", false},
		{"/etc/x;y", "", "", false},
		{"/etc/x=y", "", "", false},
		{"/etc/a:b", "", "", false},
		{"/etc/x?query", "", "", false},
		{"/etc/conf.d/??-*.conf", "", "/etc/conf.d/??-*.conf", true},
		{"/etc/x\x01y", "", "", false},
		{"fe80::1", "", "", false}, // an IPv6 group is not a scheme; and not a path either
	} {
		kind := "private_key"
		if tc.isInclude {
			kind = "include"
		}
		var c CryptoConfig
		cfgRef(&c, kind, "d", tc.in)
		gotPath := ""
		if len(c.References) == 1 {
			gotPath = c.References[0].Path
		}
		if gotPath != tc.path || c.Settings["d_source"] != tc.source {
			t.Errorf("%q: path %q source %q; want path %q source %q", tc.in, gotPath, c.Settings["d_source"], tc.path, tc.source)
		}
	}
	for in, want := range map[string]bool{"www.example.com:443": false, "localhost:8080": false, "pkcs11:x": true, "C:\\x": false, "ab:cd": false} {
		if _, got := cfgURIScheme(in); got != want {
			t.Errorf("cfgURIScheme(%q) = %v", in, got)
		}
	}
}

// Nothing is admitted by a prefix, suffix or substring: a near-miss name is
// dropped.
func TestNoPrefixAdmission(t *testing.T) {
	java := cfgT(cfgParseJava, []byte("fips.keystore.type=PKCS11\nfips.keystore.password=SECRETPWX\nfips.provider.1=SUN\nfips.provider.1000=SECRETPWX\nfips.provider.x=SECRETPWX\nfips.providers=SECRETPWX\nsecurity.provider.1=SunJSSE\nsecurity.providerX=SECRETPWX\nsecurity.provider.1a=SECRETPWX\nsecurity.provider.=SECRETPWX\n"))
	cfgWantEqual(t, java[0].Settings, map[string]string{
		"fips.keystore.type": "PKCS11", "fips.providers": "SUN", "providers": "SunJSSE",
	})
	cfgNoSecrets(t, java, "SECRETPWX")

	ngx := cfgT(cfgParseNginx, []byte("server{listen 443 ssl; proxy_ssl_certificate_keyX /SECRETPWX; proxy_ssl_password_file /SECRETPWX; xproxy_ssl_verify SECRETPWX; proxy_ssl_verify on;}"))
	cfgWantEqual(t, ngx[0].Settings, map[string]string{"proxy_ssl_verify": "on"})

	ha := cfgT(cfgParseHAProxy, []byte("frontend f\n bind :443 ssl no-tlsv14 no-tlsv1x no-tlsv10-secret force-tlsv1 ssl-min-ver-x TLSv1.3 no-tlsv11\n"))
	cfgWantEqual(t, ha[0].DisabledProtocols, []string{"TLSv1.1"})
	cfgWantEqual(t, ha[0].Protocols, []string(nil))
}

func TestContextIsBoundedAndSanitised(t *testing.T) {
	long := strings.Repeat("a", 1000)
	for name, c := range map[string]CryptoConfig{
		"nginx":   cfgT(cfgParseNginx, []byte("server{listen 443 ssl; server_name "+long+" https://u:SECRETPWY@h;}"))[0],
		"apache":  cfgT(cfgParseApache, []byte("<VirtualHost *:443>\nServerName "+long+"\nSSLEngine on\n</VirtualHost>"))[0],
		"ssh":     cfgT(cfgParseSSHClient, []byte("Host "+long+" https://u:SECRETPWY@h\nCiphers aes128-ctr\n"))[0],
		"haproxy": cfgT(cfgParseHAProxy, []byte("frontend "+long+"\n bind :443 ssl\n"))[0],
		"openssl": cfgT(cfgParseOpenSSL, []byte("openssl_conf=i\n[i]\nssl_conf=s\n[s]\nsystem_default="+long+"\n["+long+"]\nMinProtocol=TLSv1.2\n"))[0],
	} {
		if len(c.Context) > 256 || strings.Contains(c.Context, "SECRETPWY") {
			t.Errorf("%s context: %d bytes %.80q", name, len(c.Context), c.Context)
		}
	}
	ng := cfgT(cfgParseNginx, []byte("server{listen 443 ssl; server_name https://u:p@h www.example.com;}"))[0]
	cfgWantEqual(t, ng.Context, "server_name https: www.example.com; listen 443 ssl")
}

func TestSSHMatchCriteriaAllowlist(t *testing.T) {
	for in, want := range map[string]string{
		"Match User bob Group staff":            "Match User bob Group staff",
		"Match Address 10.0.0.0/8,!10.1.0.0/16": "Match Address 10.0.0.0/8,!10.1.0.0/16",
		"Match Address fe80::/10":               "Match Address fe80::/10",
		"Match !User bob":                       "Match !User bob",
		"Match LocalPort 22 RDomain red":        "Match LocalPort 22 RDomain red",
		"Match Host *.corp final":               "Match Host *.corp final",
		"Match canonical all":                   "Match canonical all",
		"Match exec \"test -f /x\" User bob":    "Match exec User bob",
		"Match !exec \"test -f /x\" User bob":   "Match !exec User bob",
		"Match exec=\"test\" User bob":          "Match exec User bob",
		"Match Frobnicate SECRETARG User bob":   "Match (unrecognised criterion) User bob",
		"Match tagged secret-tag":               "Match tagged secret-tag",
	} {
		got := cfgT(cfgParseSSHClient, []byte(in+"\nCiphers aes128-ctr\n"))
		if len(got) != 1 || got[0].Context != want {
			t.Errorf("%q: context %q, want %q", in, got[0].Context, want)
		}
	}
}

func TestProtocolsAreNeverInvented(t *testing.T) {
	// HAProxy: exclusions only.
	ha := cfgT(cfgParseHAProxy, []byte("global\n ssl-default-bind-options no-sslv3\nfrontend f\n bind :443 ssl crt /c.pem no-tlsv10\n"))
	cfgWantEqual(t, cfgFind(t, ha, "global").DisabledProtocols, []string{"SSLv3"})
	cfgWantEqual(t, cfgFind(t, ha, "global").Protocols, []string(nil))
	b := cfgFind(t, ha, "frontend f bind :443")
	cfgWantEqual(t, b.DisabledProtocols, []string{"SSLv3", "TLSv1.0"})
	cfgWantEqual(t, b.Protocols, []string(nil))
	// Both bounds, or a force: stated.
	ha = cfgT(cfgParseHAProxy, []byte("frontend f\n bind :443 ssl ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.3\n bind :444 ssl force-tlsv12\n"))
	cfgWantEqual(t, cfgFind(t, ha, "frontend f bind :443").Protocols, []string{"TLSv1.2", "TLSv1.3"})
	cfgWantEqual(t, cfgFind(t, ha, "frontend f bind :444").Protocols, []string{"TLSv1.2"})
	// Apache.
	ap := cfgT(cfgParseApache, []byte("SSLProtocol all -SSLv3 -TLSv1\n"))
	cfgWantEqual(t, ap[0].Protocols, []string(nil))
	cfgWantEqual(t, ap[0].DisabledProtocols, []string{"SSLv3", "TLSv1.0"})
	cfgWantEqual(t, ap[0].Settings["SSLProtocol"], "all -SSLv3 -TLSv1")
	ap = cfgT(cfgParseApache, []byte("SSLProtocol -all +TLSv1.2 +TLSv1.3\n"))
	cfgWantEqual(t, ap[0].Protocols, []string{"TLSv1.2", "TLSv1.3"})
	// Postfix: exclusions are not an allowed set; a bound is a bound.
	pf := cfgT(cfgParsePostfix, []byte("smtpd_tls_protocols = !SSLv2, !SSLv3\nsmtp_tls_protocols = >=TLSv1.2\n"))
	cfgWantEqual(t, pf[0].DisabledProtocols, []string{"SSLv2", "SSLv3"})
	cfgWantEqual(t, pf[0].Protocols, []string(nil))
	cfgWantEqual(t, pf[1].MinProtocol, "TLSv1.2")
	// A virtual host that states its own protocols drops the server level's
	// exclusions, and vice versa.
	ap = cfgT(cfgParseApache, []byte("SSLProtocol all -SSLv3\n<VirtualHost *:443>\nSSLProtocol TLSv1.3\n</VirtualHost>\n<VirtualHost *:444>\nSSLEngine on\n</VirtualHost>\n"))
	cfgWantEqual(t, cfgFind(t, ap, "VirtualHost *:443").Protocols, []string{"TLSv1.3"})
	cfgWantEqual(t, cfgFind(t, ap, "VirtualHost *:443").DisabledProtocols, []string(nil))
	cfgWantEqual(t, cfgFind(t, ap, "VirtualHost *:444").DisabledProtocols, []string{"SSLv3"})
}

func TestJavaOnlyTLSListIsDisabled(t *testing.T) {
	c := cfgT(cfgParseJava, []byte(`jdk.tls.disabledAlgorithms=SSLv3, include jdk.disabled.namedCurves, RC4
jdk.disabled.namedCurves=secp112r1, secp112r2
jdk.certpath.disabledAlgorithms=MD2
jdk.jar.disabledAlgorithms=MD5
jdk.security.legacyAlgorithms=DES
jdk.tls.legacyAlgorithms=NULL
`))[0]
	cfgWantEqual(t, c.DisabledAlgorithms, []string{"SSLv3", "secp112r1", "secp112r2", "RC4"})
	for k, v := range map[string]string{
		"jdk.certpath.disabledAlgorithms": "MD2", "jdk.jar.disabledAlgorithms": "MD5",
		"jdk.security.legacyAlgorithms": "DES", "jdk.tls.legacyAlgorithms": "NULL",
		"jdk.disabled.namedCurves": "secp112r1, secp112r2",
	} {
		if c.Settings[k] != v {
			t.Errorf("%s = %q", k, c.Settings[k])
		}
	}
}

func TestOpenSSLOnlySystemDefaultIsHostWide(t *testing.T) {
	in := `openssl_conf = i
[i]
ssl_conf = s
providers = p
[s]
myapp = app
[app]
MinProtocol = TLSv1
CipherString = ALL
[p]
fips = f
default = d
[f]
activate = 1
[d]
activate = 1
`
	c := cfgT(cfgParseOpenSSL, []byte(in))[0]
	if c.MinProtocol != "" || c.CipherString != "" || c.Context != "" {
		t.Errorf("an application's own section is not the host's policy: %s", cfgJSON(t, c))
	}
	if c.FIPS == nil || !*c.FIPS || c.Settings["providers"] != "fips,default" {
		t.Errorf("providers and FIPS are still reported: %s", cfgJSON(t, c))
	}
	// system_default naming a section that does not exist is no policy either.
	if got := cfgT(cfgParseOpenSSL, []byte("openssl_conf=i\n[i]\nssl_conf=s\n[s]\nsystem_default=nope\n[x]\nMinProtocol=TLSv1\n")); got != nil {
		t.Errorf("got %s", cfgJSON(t, got))
	}
}

func TestKrb5RealmSubsectionAndDuplicates(t *testing.T) {
	c := cfgT(cfgParseKrb5, []byte(`[libdefaults]
 allow_weak_crypto = false
 EXAMPLE.COM = {
  permitted_enctypes = des-cbc-crc
  allow_weak_crypto = true
  inner = {
   permitted_enctypes = rc4-hmac
  }
 }
 permitted_enctypes = aes256-cts-hmac-sha1-96
 allow_weak_crypto = true
 permitted_enctypes = aes128-cts-hmac-sha1-96
`))[0]
	cfgWantEqual(t, c.CipherSuites, []string{"aes256-cts-hmac-sha1-96"})
	cfgWantEqual(t, c.Settings, map[string]string{"allow_weak_crypto": "false", "permitted_enctypes": "aes256-cts-hmac-sha1-96"})
}

func TestNginxConfCommandReplacesInherited(t *testing.T) {
	cfgs := cfgT(cfgParseNginx, []byte(`http {
	ssl_conf_command Options PrioritizeChaCha;
	ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256;
	ssl_conf_command MinProtocol TLSv1.2;
	server { listen 443 ssl; server_name a; }
	server { listen 444 ssl; server_name b; ssl_conf_command Options ServerPreference; }
}`))
	a := cfgFind(t, cfgs, "server_name a; listen 443 ssl")
	cfgWantEqual(t, a.CipherSuites, []string{"TLS_AES_128_GCM_SHA256"})
	cfgWantEqual(t, a.MinProtocol, "TLSv1.2")
	b := cfgFind(t, cfgs, "server_name b; listen 444 ssl")
	// Any ssl_conf_command at this level replaces the whole inherited set.
	cfgWantEqual(t, b.Settings, map[string]string{"ssl_conf_command Options": "ServerPreference"})
	cfgWantEqual(t, b.CipherSuites, []string(nil))
	cfgWantEqual(t, b.MinProtocol, "")
}

func TestGnuTLSLayouts(t *testing.T) {
	r8 := cfgT(cfgParseGnuTLS, []byte("SYSTEM=NONE:+VERS-TLS1.2\n"))
	cfgWantEqual(t, r8[0].Policy, "NONE:+VERS-TLS1.2")
	r9 := cfgT(cfgParseGnuTLS, []byte("[global]\noverride-mode = allowlist\n[overrides]\nenabled-version = tls1.3\nenabled-version = tls1.2\ntls-enabled-cipher = AES-256-GCM\ntls-enabled-kx = ECDHE-RSA\nenabled-curve = secp256r1\nsecure-sig = RSA-SHA256\nsecure-hash = SHA256\ntls-disabled-mac = SHA1\n"))[0]
	cfgWantEqual(t, r9.Protocols, []string{"TLSv1.3", "TLSv1.2"})
	cfgWantEqual(t, r9.CipherSuites, []string{"AES-256-GCM"})
	cfgWantEqual(t, r9.KeyExchanges, []string{"ECDHE-RSA"})
	cfgWantEqual(t, r9.Groups, []string{"secp256r1"})
	cfgWantEqual(t, r9.SignatureAlgorithms, []string{"RSA-SHA256"})
	cfgWantEqual(t, r9.DisabledAlgorithms, []string{"SHA1"})
	cfgWantEqual(t, r9.Settings["enabled-version"], "tls1.3,tls1.2")
	cfgWantEqual(t, r9.Settings["override-mode"], "allowlist")
}

// cfgLinear checks that doubling the input does not much more than double the
// work: it times n and 4n (the best of three each) and fails when 4n costs
// more than 9 times n, where a quadratic parser costs 16 times and a linear
// one 4. n grows until the first measurement is long enough to read.
func cfgLinear(t *testing.T, name string, p ConfigParser, gen func(n int) string) {
	t.Helper()
	n, t1, t4, ok := cfgGrowth(p, gen)
	if ok && t4 > 9*t1 {
		t.Errorf("%s: n=%d took %v, 4n took %v (%.1fx): not linear", name, n, t1, t4, float64(t4)/float64(t1))
	}
}

// cfgGrowth times a parser at n and 4n; ok is false when it is too fast to
// measure.
func cfgGrowth(p ConfigParser, gen func(n int) string) (n int, t1, t4 time.Duration, ok bool) {
	best := func(in []byte) time.Duration {
		var m time.Duration
		for i := 0; i < 3; i++ {
			st := time.Now()
			p(in, nil)
			if d := time.Since(st); i == 0 || d < m {
				m = d
			}
		}
		return m
	}
	p(nil, nil) // warm up
	for n = 500; n <= 60000; n *= 2 {
		in := []byte(gen(n))
		p(in, nil)
		t1 = best(in)
		if t1 >= 10*time.Millisecond {
			return n, t1, best([]byte(gen(4 * n))), true
		}
	}
	return n, t1, 0, false
}

// The linearity check must be able to fail: a deliberately quadratic parser
// is caught, a linear one is not.
func TestLinearityCheckCanFail(t *testing.T) {
	sink := 0
	quad := func(b []byte, _ IncludeResolver) []CryptoConfig {
		n := bytes.Count(b, []byte("\n"))
		for i := 0; i < n; i++ { // rescans the whole input once per line
			sink += bytes.Count(b, []byte("x"))
		}
		return nil
	}
	lin := func(b []byte, _ IncludeResolver) []CryptoConfig {
		for i := 0; i < 40; i++ {
			sink += strings.Count(string(b), "\n")
		}
		return nil
	}
	gen := func(n int) string { return strings.Repeat("x\n", n) }
	// Timing on a loaded machine is noisy in both directions, so each
	// polarity gets three tries and must hold in at least one: a quadratic
	// parser cannot look linear three times running, nor a linear one
	// quadratic, except on a machine too busy to measure anything.
	caught, flagged := false, true
	var last string
	for try := 0; try < 3 && (!caught || flagged); try++ {
		if !caught {
			n, t1, t4, ok := cfgGrowth(quad, gen)
			caught = ok && t4 > 9*t1
			last = fmt.Sprintf("quadratic n=%d %v %v ok=%v", n, t1, t4, ok)
		}
		if flagged {
			n, t1, t4, ok := cfgGrowth(lin, gen)
			flagged = ok && t4 > 9*t1
			if flagged {
				last = fmt.Sprintf("linear n=%d %v %v", n, t1, t4)
			}
		}
	}
	if !caught {
		t.Errorf("a quadratic parser was not caught: %s", last)
	}
	if flagged {
		t.Errorf("a linear parser was flagged: %s", last)
	}
	_ = sink
}

func TestParsersAreLinear(t *testing.T) {
	rep := func(s string, n int) string { return strings.Repeat(s, n) }
	each := func(n int, f func(i int) string) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			sb.WriteString(f(i))
		}
		return sb.String()
	}
	long := rep("x", 60)
	for _, tc := range []struct {
		name string
		p    ConfigParser
		gen  func(n int) string
	}{
		{"haproxy default-server", cfgParseHAProxy, func(n int) string {
			return "backend b\n" + rep(" default-server ssl verify none alpn h2 ciphers HIGH ssl-min-ver TLSv1.2\n", n) + rep(" server s 1.1.1.1:443\n", n)
		}},
		{"haproxy distinct default-server", cfgParseHAProxy, func(n int) string {
			return "backend b\n" + each(n, func(i int) string { return fmt.Sprintf(" default-server ssl verify none ca-file /c%d.pem\n", i) }) + rep(" server s 1.1.1.1:443\n", n)
		}},
		{"haproxy servers", cfgParseHAProxy, func(n int) string {
			return "backend b\n" + each(n, func(i int) string { return fmt.Sprintf(" server s%d 1.1.1.1:443 ssl verify none crt /c%d.pem\n", i, i) })
		}},
		{"haproxy binds", cfgParseHAProxy, func(n int) string { return "frontend f\n" + rep(" bind :443 ssl crt /a.pem\n", n) }},
		{"haproxy long lines", cfgParseHAProxy, func(n int) string {
			return "global\n" + rep(" ssl-default-bind-options "+rep("no-sslv3 ", 5000)+"\n", n/20+1)
		}},
		{"java continuation", cfgParseJava, func(n int) string { return "jdk.tls.disabledAlgorithms=" + rep("a,\\\n", n) + "\n" }},
		{"java many properties", cfgParseJava, func(n int) string {
			return each(n, func(i int) string {
				return fmt.Sprintf("security.provider.%d=P%d\nfips.provider.%d=Q\n", i%1000, i, i%1000)
			})
		}},
		{"java options", cfgParseJavaOptions, func(n int) string { return rep("-Dhttps.protocols=TLSv1.2 -Djavax.net.ssl.trustStore=/t ", n) }},
		{"postfix continuation", cfgParsePostfix, func(n int) string { return "smtpd_tls_ciphers = a\n" + rep(" b\n", n) }},
		{"postfix many keys", cfgParsePostfix, func(n int) string {
			return each(n, func(i int) string { return fmt.Sprintf("k%d = %s\n", i, long) }) + "smtpd_tls_ciphers = x\n"
		}},
		{"gnutls repeated", cfgParseGnuTLS, func(n int) string { return "[overrides]\n" + rep("insecure-hash = "+rep("x", 3000)+"\n", n) }},
		{"gnutls many lists", cfgParseGnuTLS, func(n int) string { return "[overrides]\n" + rep("tls-enabled-mac = SHA1\n", n) }},
		{"krb5 lines", cfgParseKrb5, func(n int) string {
			return "[libdefaults]\n" + rep("permitted_enctypes = aes256-cts-hmac-sha1-96\n", n)
		}},
		{"krb5 subsections", cfgParseKrb5, func(n int) string { return "[libdefaults]\n" + rep("R = {\n a = b\n}\n", n) }},
		{"nginx includes", cfgParseNginx, func(n int) string { return rep("include a;", n) }},
		{"nginx servers", cfgParseNginx, func(n int) string {
			return "http{ssl_protocols TLSv1.2;" + rep("server{listen 443 ssl;ssl_ciphers HIGH;}", n) + "}"
		}},
		{"nginx deep braces", cfgParseNginx, func(n int) string { return rep("http{", n) }},
		{"apache closes", cfgParseApache, func(n int) string { return rep("<IfModule x>\n", 63) + rep("</Nope>\n", n) }},
		{"apache vhosts", cfgParseApache, func(n int) string {
			return rep("<VirtualHost *:443>\nSSLEngine on\nSSLCipherSuite HIGH\n</VirtualHost>\n", n)
		}},
		{"apache opens then bad closes", cfgParseApache, func(n int) string { return rep("<IfModule x>\n", n) + rep("</Nope>\n", n) }},
		{"apache deep", cfgParseApache, func(n int) string { return rep("<IfModule x>\n", n) + "SSLProtocol all\n" }},
		{"ssh matches", cfgParseSSHD, func(n int) string { return rep("Match User a\nCiphers aes\n", n) }},
		{"ssh hostkeys", cfgParseSSHD, func(n int) string { return each(n, func(i int) string { return fmt.Sprintf("HostKey /a%d\n", i) }) }},
		{"openssl sections", cfgParseOpenSSL, func(n int) string {
			return "openssl_conf=i\n[i]\nssl_conf=s\nproviders=p\n[s]\nsystem_default=d\n[p]\n" +
				each(n, func(i int) string { return fmt.Sprintf("p%d = sec%d\n", i%1000, i) }) +
				each(n, func(i int) string { return fmt.Sprintf("[sec%d]\nz = 1\n", i) })
		}},
		{"openssl self reference", cfgParseOpenSSL, func(n int) string { return "a = $b$b\nb = $a$a\n" + rep("[s]\nCipherString = $a\n", n) }},
	} {
		t.Run(tc.name, func(t *testing.T) { cfgLinear(t, tc.name, tc.p, tc.gen) })
	}
	// The same shape in the crypto-policy back-ends.
	cfgLinear(t, "backend ssh", func(b []byte, _ IncludeResolver) []CryptoConfig {
		return ParseCryptoPolicyBackend("openssh", b)
	}, func(n int) string { return rep("CRYPTO_POLICY='-oCiphers=a -oMACs=b'\nCiphers x\n", n) })
}

func FuzzConfigHAProxy(f *testing.F) {
	f.Add([]byte(cfgHAProxyStock))
	f.Add([]byte("defaults\n default-server ssl verify none\nbackend b\n default-server ca-file x\n server-template w 3 a:1 ssl crt \"x\n bind\n"))
	f.Add([]byte("global\n ssl-default-bind-options ssl-min-ver\nlisten l\n bind :1 ssl force-tlsv12 no-tlsv12 ssl-max-ver\n"))
	f.Fuzz(func(t *testing.T, b []byte) { cfgCheckBounds(t, cfgT(cfgParseHAProxy, b)) })
}

func FuzzConfigJava(f *testing.F) {
	f.Add([]byte(cfgJDK17))
	f.Add([]byte("jdk.tls.disabledAlgorithms=a, include jdk.disabled.namedCurves\njdk.disabled.namedCurves=\\\n"))
	f.Add([]byte("JAVA_OPTS=\"-Dhttps.protocols=TLSv1.2 -Djavax.net.ssl.keyStore=store:x -D\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		cfgCheckBounds(t, cfgT(cfgParseJava, b))
		cfgCheckBounds(t, cfgT(cfgParseJavaOptions, b))
	})
}

func FuzzConfigPostfix(f *testing.F) {
	f.Add([]byte(cfgPostfixMain))
	f.Add([]byte("a = $a\n smtpd_tls_protocols = !SSLv2,>=TLSv1.2\n\n continued\n"))
	f.Fuzz(func(t *testing.T, b []byte) { cfgCheckBounds(t, cfgT(cfgParsePostfix, b)) })
}

func FuzzConfigKrb5(f *testing.F) {
	f.Add([]byte("[libdefaults]\n permitted_enctypes = a b\n R = {\n x = y\n }\npkinit_identities = FILE:a,b\ninclude /x\nincludedir /y/\n"))
	f.Add([]byte("[libdefaults]\n }\n }\n R = {\n R = {\n"))
	f.Fuzz(func(t *testing.T, b []byte) { cfgCheckBounds(t, cfgT(cfgParseKrb5, b)) })
}

func FuzzConfigGnuTLS(f *testing.F) {
	f.Add([]byte("SYSTEM=NONE:+VERS-TLS1.2\n[global]\noverride-mode = allowlist\n[overrides]\ntls-enabled-mac = SHA1\ninsecure-hash = md5\nenabled-version = tls1.2\n"))
	f.Add([]byte("[\n[overrides\nx==\n"))
	f.Fuzz(func(t *testing.T, b []byte) { cfgCheckBounds(t, cfgT(cfgParseGnuTLS, b)) })
}

func FuzzConfigCryptoPolicyBackends(f *testing.F) {
	f.Add([]byte("CRYPTO_POLICY='-oCiphers=a -oMACs=b'\n"), "openssh")
	f.Add([]byte("@SECLEVEL=2:kEECDH\n"), "openssl")
	f.Add([]byte("[fips_sect]\nactivate = 1\n"), "openssl_fips")
	f.Add([]byte("config=\"disallow=ALL allow=a:tls-version-min=tls1.2\"\n"), "nss")
	f.Add([]byte("[libdefaults]\npermitted_enctypes = a\n"), "krb5.config")
	f.Fuzz(func(t *testing.T, b []byte, name string) {
		cfgCheckBounds(t, ParseCryptoPolicyBackend(name, b))
		cfgCheckBounds(t, cfgT(cfgParseCryptoPoliciesConfig, b))
	})
}
