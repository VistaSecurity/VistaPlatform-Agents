// Fixtures are written for this repository (config_fixtures_data_test.go) and
// model the file layouts of the distributions the tests name (Rocky Linux 8 and
// 9, Debian, the official nginx and httpd images, Temurin); no distribution
// file is copied.
package hostcrypto

import (
	"path"
	"sort"
	"strings"
	"testing"
)

// cfgFixtureTree returns the own fixtures of dir as a map keyed by the file's
// real path: prefix + the path under dir.
func cfgFixtureTree(t *testing.T, dir, prefix string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for rel, text := range cfgOwn[dir] {
		files[path.Join(prefix, rel)] = []byte(text)
	}
	if len(files) == 0 {
		t.Fatalf("no fixtures for %s", dir)
	}
	return files
}

// cfgMapResolver is the map-backed resolver the tests use: a pattern is
// matched against the keys with path.Match, relative patterns against base,
// and the result is sorted, as a glob is.
func cfgMapResolver(files map[string][]byte, base string) IncludeResolver {
	return func(pattern string, _ int64) []IncludedFile {
		if !strings.HasPrefix(pattern, "/") {
			pattern = path.Join(base, pattern)
		}
		if strings.HasSuffix(pattern, "/") {
			pattern += "*"
		}
		var keys []string
		for k := range files {
			if ok, _ := path.Match(pattern, k); ok {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var out []IncludedFile
		for _, k := range keys {
			out = append(out, IncludedFile{Path: k, Text: files[k]})
		}
		return out
	}
}

func TestFixtureRocky9SSHDThroughIncludes(t *testing.T) {
	files := cfgFixtureTree(t, "rocky9", "/")
	// Without a resolver the include is only recorded.
	plain := cfgParseSSHD(files["/etc/ssh/sshd_config"], nil)
	if len(plain) != 1 || len(plain[0].CipherSuites) != 0 || len(plain[0].References) != 1 {
		t.Fatalf("nil resolver: %s", cfgJSON(t, plain))
	}
	cfgs := cfgParseSSHD(files["/etc/ssh/sshd_config"], cfgMapResolver(files, "/etc/ssh"))
	if len(cfgs) != 1 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	g := cfgs[0]
	// `sshd -T` on this host reports the crypto-policy lists, because
	// 50-redhat.conf includes opensshserver.config before anything else sets
	// them, and the usual first-value-wins applies.
	if len(g.CipherSuites) != 5 || g.CipherSuites[0] != "aes256-gcm@openssh.com" || g.CipherSuites[4] != "aes128-ctr" {
		t.Errorf("ciphers: %v", g.CipherSuites)
	}
	if len(g.MACs) != 8 || len(g.KeyExchanges) != 9 || len(g.HostKeyAlgorithms) == 0 || len(g.SignatureAlgorithms) == 0 {
		t.Errorf("lists: macs=%d kex=%d hostkeys=%d sigs=%d", len(g.MACs), len(g.KeyExchanges), len(g.HostKeyAlgorithms), len(g.SignatureAlgorithms))
	}
	for k, want := range map[string]string{
		"RequiredRSASize": "2048", "GSSAPIAuthentication": "yes", "ChallengeResponseAuthentication": "no",
		"AuthorizedKeysFile": ".ssh/authorized_keys", "GSSAPIKexAlgorithms": "gss-curve25519-sha256-,gss-nistp256-sha256-,gss-group14-sha256-,gss-group16-sha512-",
	} {
		if g.Settings[k] != want {
			t.Errorf("%s = %q, want %q", k, g.Settings[k], want)
		}
	}
	// Every include is also still recorded.
	var incs []string
	for _, r := range g.References {
		if r.Kind == "include" {
			incs = append(incs, r.Path)
		}
	}
	cfgWantEqual(t, incs, []string{"/etc/ssh/sshd_config.d/*.conf", "/etc/crypto-policies/back-ends/opensshserver.config"})
}

func TestSSHFirstValueWinsAcrossIncludes(t *testing.T) {
	files := map[string][]byte{
		"/etc/ssh/sshd_config.d/10-mine.conf":   []byte("Ciphers aes128-ctr\nPermitRootLogin no\n"),
		"/etc/ssh/sshd_config.d/50-redhat.conf": []byte("Ciphers aes256-ctr\nPermitRootLogin yes\nMACs hmac-sha2-256\n"),
	}
	res := cfgMapResolver(files, "/etc/ssh")
	// Include first: the included Ciphers wins over the one after it.
	got := cfgParseSSHD([]byte("Include sshd_config.d/*.conf\nCiphers 3des-cbc\n"), res)
	cfgWantEqual(t, got[0].CipherSuites, []string{"aes128-ctr"})
	cfgWantEqual(t, got[0].MACs, []string{"hmac-sha2-256"})
	cfgWantEqual(t, got[0].Settings["PermitRootLogin"], "no")
	// Include last: the earlier line wins.
	got = cfgParseSSHD([]byte("Ciphers 3des-cbc\nInclude sshd_config.d/*.conf\n"), res)
	cfgWantEqual(t, got[0].CipherSuites, []string{"3des-cbc"})
}

func TestSSHIncludeInsideMatchIsScoped(t *testing.T) {
	files := map[string][]byte{
		"/etc/ssh/m.conf": []byte("PasswordAuthentication yes\nMatch User inner\nPermitRootLogin no\n"),
	}
	got := cfgParseSSHD([]byte("PasswordAuthentication no\nMatch User bob\nInclude m.conf\nPermitRootLogin prohibit-password\nCiphers aes256-ctr\nMatch all\nRekeyLimit default\n"), cfgMapResolver(files, "/etc/ssh"))
	// global; Match User bob (with the included PasswordAuthentication and, after
	// the include, its own PermitRootLogin); the block the included file opened,
	// which applies only inside bob's; Match all.
	byCtx := map[string]CryptoConfig{}
	for _, c := range got {
		byCtx[c.Context] = c
	}
	cfgWantEqual(t, byCtx["Match User bob"].Settings["PasswordAuthentication"], "yes")
	cfgWantEqual(t, byCtx["Match User bob"].Settings["PermitRootLogin"], "prohibit-password")
	cfgWantEqual(t, byCtx["Match User bob"].CipherSuites, []string(nil)) // not allowed in Match
	cfgWantEqual(t, byCtx["Match User bob > Match User inner"].Settings["PermitRootLogin"], "no")
	cfgWantEqual(t, byCtx[""].Settings["PasswordAuthentication"], "no")
	cfgWantEqual(t, byCtx["Match all"].Settings["RekeyLimit"], "default")
}

func TestIncludeBudgetsAndCycles(t *testing.T) {
	// A file that includes itself is read once.
	reads := 0
	self := func(pattern string, _ int64) []IncludedFile {
		reads++
		return []IncludedFile{{Path: "/a", Text: []byte("Include /a\nCiphers aes128-ctr\n")}}
	}
	got := cfgParseSSHD([]byte("Include /a\n"), self)
	if reads > 3 || len(got) != 1 || len(got[0].CipherSuites) != 1 {
		t.Errorf("cycle: %d resolver calls, %s", reads, cfgJSON(t, got))
	}
	// A resolver that returns 1000 files is cut at 256.
	n := 0
	many := func(pattern string, _ int64) []IncludedFile {
		var out []IncludedFile
		for i := 0; i < 1000; i++ {
			out = append(out, IncludedFile{Path: "/f" + string(rune('A'+i%26)) + strings.Repeat("x", i), Text: []byte("HostKey /k\n")})
		}
		n = len(out)
		return out
	}
	inc := newCfgIncl(many)
	if got := inc.get("*", 0); len(got) != cfgMaxIncludeFiles || n != 1000 {
		t.Errorf("file budget: got %d files", len(got))
	}
	// The byte budget: 4 MiB files, at most 4 of them.
	big := func(pattern string, _ int64) []IncludedFile {
		var out []IncludedFile
		for i := 0; i < 10; i++ {
			out = append(out, IncludedFile{Path: "/b" + strings.Repeat("y", i), Text: make([]byte, 4<<20)})
		}
		return out
	}
	if got := newCfgIncl(big).get("*", 0); len(got) != 4 {
		t.Errorf("byte budget: got %d files", len(got))
	}
	// Depth: a chain of includes stops at 8.
	depth := 0
	chain := func(pattern string, _ int64) []IncludedFile {
		depth++
		return []IncludedFile{{Path: "/c" + strings.Repeat("z", depth), Text: []byte("Include next\nHostKey /k\n")}}
	}
	cfgParseSSHD([]byte("Include next\n"), chain)
	if depth != cfgMaxIncludeDepth {
		t.Errorf("depth: resolver called %d times, want %d", depth, cfgMaxIncludeDepth)
	}
}

func TestFixtureDebianNginxInheritsThroughIncludes(t *testing.T) {
	files := cfgFixtureTree(t, "debian", "/")
	site := files["/etc/nginx/sites-available/default"]
	files["/etc/nginx/sites-enabled/default"] = site
	files["/etc/nginx/sites-enabled/tls"] = []byte(`server {
	listen 443 ssl;
	server_name secure.example.com;
	ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
	ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
}
`)
	res := cfgMapResolver(files, "/etc/nginx")
	nilRes := cfgParseNginx(files["/etc/nginx/nginx.conf"], nil)
	for _, c := range nilRes {
		if strings.HasPrefix(c.Context, "server_name") {
			t.Fatalf("with no resolver no server is seen: %s", cfgJSON(t, c))
		}
	}
	cfgs := cfgParseNginx(files["/etc/nginx/nginx.conf"], res)
	c := cfgFind(t, cfgs, "server_name secure.example.com; listen 443 ssl")
	// The included server carries the http level's policy of the file that
	// includes it.
	cfgWantEqual(t, c.Protocols, []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"})
	cfgWantEqual(t, c.Settings["ssl_prefer_server_ciphers"], "on")
	cfgWantEqual(t, c.References, []ConfigReference{
		{Kind: "certificate", Directive: "ssl_certificate", Path: "/etc/ssl/certs/ssl-cert-snakeoil.pem"},
		{Kind: "private_key", Directive: "ssl_certificate_key", Path: "/etc/ssl/private/ssl-cert-snakeoil.key"},
	})
	for _, c := range cfgs { // the plain HTTP default site is not reported
		if strings.Contains(c.Context, "default_server") {
			t.Errorf("a server with no TLS is not reported: %s", c.Context)
		}
	}
}

func TestFixtureDebianApacheInheritsThroughIncludes(t *testing.T) {
	files := cfgFixtureTree(t, "debian", "/")
	files["/etc/apache2/mods-enabled/ssl.conf"] = files["/etc/apache2/mods-available/ssl.conf"]
	files["/etc/apache2/sites-enabled/default-ssl.conf"] = files["/etc/apache2/sites-available/default-ssl.conf"]
	root := []byte("IncludeOptional mods-enabled/*.load\nIncludeOptional mods-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n")
	cfgs := cfgParseApache(root, cfgMapResolver(files, "/etc/apache2"))
	v := cfgFind(t, cfgs, "VirtualHost *:443")
	// Debian's ssl.conf is "SSLProtocol all -SSLv3": the file does not say what
	// "all" covers, so only the exclusion is reported.
	if len(v.Protocols) != 0 {
		t.Errorf("Protocols must stay empty: %v", v.Protocols)
	}
	cfgWantEqual(t, v.DisabledProtocols, []string{"SSLv3"})
	cfgWantEqual(t, v.CipherString, "HIGH:!aNULL")
	cfgWantEqual(t, v.Settings["SSLProtocol"], "all -SSLv3")
	cfgWantEqual(t, v.Settings["SSLSessionTickets"], "off")
	cfgWantEqual(t, v.References, []ConfigReference{
		{Kind: "certificate", Directive: "SSLCertificateFile", Path: "/etc/ssl/certs/ssl-cert-snakeoil.pem"},
		{Kind: "private_key", Directive: "SSLCertificateKeyFile", Path: "/etc/ssl/private/ssl-cert-snakeoil.key"},
	})
	cfgNoSecrets(t, cfgs, "ask-for-passphrase", "shmcb")
}

func TestFixtureRocky9OpenSSLIncludesTheBackend(t *testing.T) {
	files := cfgFixtureTree(t, "rocky9", "/")
	for k, v := range cfgFixtureTree(t, "rocky", "/") {
		files[k] = v
	}
	cnf := files["/etc/pki/tls/openssl.cnf"]
	plain := cfgParseOpenSSL(cnf, nil)
	if len(plain) != 1 || plain[0].Context != "crypto_policy" || plain[0].CipherString != "" {
		t.Fatalf("nil resolver reports the section and no policy: %s", cfgJSON(t, plain))
	}
	cfgs := cfgParseOpenSSL(cnf, cfgMapResolver(files, "/etc/pki/tls"))
	if len(cfgs) != 1 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	c := cfgs[0]
	if c.MinProtocol != "TLSv1.2" || c.MaxProtocol != "TLSv1.3" || c.Policy != "SECLEVEL=2" || len(c.CipherSuites) != 4 {
		t.Errorf("the included back-end must give the policy: %s", cfgJSON(t, c))
	}
	cfgWantEqual(t, c.Settings["providers"], "default")
	var paths []string
	for _, r := range c.References {
		paths = append(paths, r.Path)
	}
	cfgWantEqual(t, paths, []string{"/etc/pki/tls/openssl.d", "/etc/crypto-policies/back-ends/opensslcnf.config"})
}

func TestFixtureRocky9Krb5ThroughIncludedir(t *testing.T) {
	files := cfgFixtureTree(t, "rocky9", "/")
	conf := files["/etc/krb5.conf"]
	plain := cfgParseKrb5(conf, nil)
	if len(plain) != 1 || len(plain[0].CipherSuites) != 0 {
		t.Fatalf("nil resolver: %s", cfgJSON(t, plain))
	}
	cfgs := cfgParseKrb5(conf, cfgMapResolver(files, "/etc"))
	c := cfgs[0]
	cfgWantEqual(t, c.CipherSuites, []string{"aes256-cts-hmac-sha384-192", "aes128-cts-hmac-sha256-128", "aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"})
	cfgWantEqual(t, c.Groups, []string{"edwards25519"})
	cfgWantEqual(t, c.Settings["default_ccache_name"], "keyring")
	cfgWantEqual(t, c.References, []ConfigReference{
		{Kind: "include", Directive: "includedir", Path: "/etc/krb5.conf.d/"},
		{Kind: "trust_store", Directive: "pkinit_anchors", Path: "/etc/pki/tls/certs/ca-bundle.crt"},
	})
}

func TestFixtureBackendsRocky8And9(t *testing.T) {
	be := func(distro, name string) []CryptoConfig {
		b, ok := cfgOwn[distro]["etc/crypto-policies/back-ends/"+name]
		if !ok {
			t.Fatalf("no fixture %s/%s", distro, name)
		}
		return ParseCryptoPolicyBackend(name, []byte(b))
	}
	one := func(distro, name string) CryptoConfig {
		t.Helper()
		got := be(distro, name)
		if len(got) != 1 {
			t.Fatalf("%s/%s: %s", distro, name, cfgJSON(t, got))
		}
		if got[0].Product != "crypto-policies" || got[0].Context == "" {
			t.Errorf("%s/%s: product/context %q %q", distro, name, got[0].Product, got[0].Context)
		}
		return got[0]
	}

	// RHEL 8: a bare SYSTEM= line with no section header.
	g8 := one("rocky8", "gnutls.config")
	if !strings.HasPrefix(g8.Policy, "NONE:+MAC-ALL:-MD5") {
		t.Errorf("rocky8 gnutls policy: %q", g8.Policy)
	}
	// RHEL 9: allowlist mode with the enabled lists.
	g9 := one("rocky9", "gnutls.config")
	if g9.Settings["override-mode"] != "allowlist" || len(g9.MACs) == 0 || len(g9.Groups) == 0 || len(g9.SignatureAlgorithms) == 0 {
		t.Errorf("rocky9 gnutls: %s", cfgJSON(t, g9))
	}
	cfgWantEqual(t, g9.MACs[:2], []string{"AEAD", "SHA1"})
	cfgWantEqual(t, g9.Groups[:2], []string{"GROUP-X25519", "GROUP-SECP256R1"})
	if g9.Settings["secure-hash"] == "" {
		t.Error("secure-hash is kept in Settings")
	}

	ls := one("rocky9", "libssh.config")
	if len(ls.CipherSuites) != 5 || len(ls.KeyExchanges) == 0 || len(ls.HostKeyAlgorithms) == 0 || len(ls.SignatureAlgorithms) == 0 {
		t.Errorf("libssh: %s", cfgJSON(t, ls))
	}
	fips := one("rocky9", "openssl_fips.config")
	// The file exists on every host and is read only in FIPS mode: it never
	// sets FIPS, it is kept as written.
	if fips.FIPS != nil || fips.Settings["fips_sect activate"] != "1" {
		t.Errorf("openssl_fips: %s", cfgJSON(t, fips))
	}
	o := one("rocky9", "openssl.config")
	if o.Policy != "SECLEVEL=2" || !strings.HasPrefix(o.CipherString, "@SECLEVEL=2:kEECDH") {
		t.Errorf("openssl.config: %s", cfgJSON(t, o))
	}
	oc := one("rocky9", "opensslcnf.config")
	if oc.MinProtocol != "TLSv1.2" || oc.Policy != "SECLEVEL=2" {
		t.Errorf("opensslcnf: %s", cfgJSON(t, oc))
	}
	j := one("rocky9", "java.config")
	if len(j.DisabledAlgorithms) == 0 || j.Settings["jdk.certpath.disabledAlgorithms"] == "" || j.Settings["jdk.disabled.namedCurves"] == "" {
		t.Errorf("java: %d disabled", len(j.DisabledAlgorithms))
	}
	for _, d := range j.DisabledAlgorithms {
		if d == "include jdk.disabled.namedCurves" {
			t.Error("the namedCurves include must be resolved")
		}
	}
	js := one("rocky9", "javasystem.config")
	if len(js.Groups) == 0 || js.Settings["jdk.tls.ephemeralDHKeySize"] != "2048" {
		t.Errorf("javasystem: %s", cfgJSON(t, js))
	}
	nss := one("rocky9", "nss.config")
	if nss.MinProtocol != "TLSv1.2" {
		t.Errorf("nss: %s", cfgJSON(t, nss))
	}
	for _, n := range []string{"openssh.config", "opensshserver.config"} {
		if c := one("rocky9", n); len(c.CipherSuites) != 5 {
			t.Errorf("%s: %s", n, cfgJSON(t, c))
		}
	}
	if c := one("rocky9", "krb5.config"); len(c.CipherSuites) != 4 {
		t.Errorf("krb5: %s", cfgJSON(t, c))
	}
	// Rocky 8's openssh back-end uses the CRYPTO_POLICY= spelling.
	if c := one("rocky8", "openssh.config"); len(c.CipherSuites) == 0 {
		t.Errorf("rocky8 openssh: %s", cfgJSON(t, c))
	}
	for _, n := range []string{"opensslcnf.config", "opensshserver.config", "java.config", "nss.config", "krb5.config", "libssh.config"} {
		if len(be("rocky8", n)) != 1 {
			t.Errorf("rocky8 %s parsed to nothing", n)
		}
	}
}

func TestFixtureJavaSecurityTemurin(t *testing.T) {
	for _, d := range []string{"temurin8", "temurin21"} {
		cfgs := cfgParseJava([]byte(cfgOwn[d]["java.security"]), nil)
		if len(cfgs) != 1 {
			t.Fatalf("%s: %s", d, cfgJSON(t, cfgs))
		}
		c := cfgs[0]
		if len(c.DisabledAlgorithms) == 0 || c.Settings["providers"] == "" {
			t.Errorf("%s: %s", d, cfgJSON(t, c))
		}
		// Only the TLS list is a deny list; the certificate-path list is a
		// Setting, and no entry of it leaks into DisabledAlgorithms by name.
		if c.Settings["jdk.certpath.disabledAlgorithms"] == "" {
			t.Errorf("%s: certpath list missing from Settings", d)
		}
		cfgNoSecrets(t, cfgs, "KeyRep", "SecretKeySpec")
	}
	// On JDK 21 the curve deny list is shipped as its own property and
	// included by name; the include is resolved.
	c := cfgParseJava([]byte(cfgOwn["temurin21"]["java.security"]), nil)[0]
	for _, d := range c.DisabledAlgorithms {
		if strings.HasPrefix(d, "include ") {
			t.Errorf("unresolved include %q", d)
		}
	}
}

func TestFixtureStockProductFiles(t *testing.T) {
	// Every stock file parses without a panic and within bounds; the ones
	// that carry TLS policy report some.
	nginx := cfgFixtureTree(t, "nginx", "/etc")
	cfgs := cfgParseNginx(nginx["/etc/nginx/nginx.conf"], cfgMapResolver(nginx, "/etc/nginx"))
	cfgCheckBounds(t, cfgs)
	httpd := cfgFixtureTree(t, "httpd", "/usr/local/apache2")
	cfgs = cfgParseApache(httpd["/usr/local/apache2/conf/httpd.conf"], cfgMapResolver(httpd, "/usr/local/apache2"))
	cfgCheckBounds(t, cfgs)
	ssl := cfgParseApache(httpd["/usr/local/apache2/conf/extra/httpd-ssl.conf"], nil)
	v := cfgFind(t, ssl, "VirtualHost _default_:443 ServerName www.example.com:443")
	cfgWantEqual(t, v.Settings["SSLEngine"], "on")
	if v.CipherString == "" && len(ssl) < 2 {
		t.Errorf("httpd-ssl.conf: %s", cfgJSON(t, ssl))
	}
	cfgNoSecrets(t, ssl, "builtin")
	deb := cfgFixtureTree(t, "debian", "/")
	ha := cfgParseHAProxy(deb["/etc/haproxy/haproxy.cfg"], nil)
	g := cfgFind(t, ha, "global")
	if g.CipherString == "" || g.MinProtocol != "TLSv1.2" {
		t.Errorf("debian haproxy global: %s", cfgJSON(t, g))
	}
	if len(g.Protocols) != 0 {
		t.Errorf("exclusions and a minimum state no allowed list: %v", g.Protocols)
	}
	pf := cfgParsePostfix(deb["/etc/postfix/main.cf"], nil)
	cfgCheckBounds(t, pf)
}
