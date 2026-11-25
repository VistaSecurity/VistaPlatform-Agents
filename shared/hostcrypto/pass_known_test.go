package hostcrypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Fixtures: every key is generated here, at test time.
// ---------------------------------------------------------------------------

type locMat struct {
	caPEM, leafPEM []byte
	ecPEM          []byte // PKCS#8 "PRIVATE KEY"
	rsaPEM         []byte // PKCS#1 "RSA PRIVATE KEY"
	edPEM          []byte // "OPENSSH PRIVATE KEY"
	edPub          []byte // the .pub line
	authorized     []byte // an authorized_keys file with options
	jks            []byte // an empty JKS
	keytab         []byte // an empty keytab
	secrets        [][]byte
}

var (
	locMatOnce sync.Once
	locMatVal  locMat
	locMatErr  error
)

func locTestMaterial(t *testing.T) locMat {
	t.Helper()
	locMatOnce.Do(func() { locMatVal, locMatErr = locBuildMaterial(t) })
	if locMatErr != nil {
		t.Fatalf("generate test material: %v", locMatErr)
	}
	return locMatVal
}

func locBuildMaterial(t *testing.T) (locMat, error) {
	var m locMat
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return m, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "loc test CA"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return m, err
	}
	m.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return m, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &ecKey.PublicKey, caKey)
	if err != nil {
		return m, err
	}
	m.leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	p8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		return m, err
	}
	m.ecPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return m, err
	}
	m.rsaPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return m, err
	}
	blk, err := ssh.MarshalPrivateKey(edKey, "")
	if err != nil {
		return m, err
	}
	m.edPEM = pem.EncodeToMemory(blk)
	sp, err := ssh.NewPublicKey(edKey.Public())
	if err != nil {
		return m, err
	}
	m.edPub = ssh.MarshalAuthorizedKey(sp)
	m.authorized = append([]byte(`from="10.0.0.0/8",no-pty `), m.edPub...)

	m.jks = append(append([]byte(nil), magicJKS...), 0, 0, 0, 2, 0, 0, 0, 0)
	m.jks = append(m.jks, make([]byte, 20)...)
	m.keytab = []byte{0x05, 0x02}

	for _, k := range []crypto.Signer{ecKey, rsaKey, edKey} {
		m.secrets = append(m.secrets, keyTestSecrets(t, k)...)
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// A Linux host on the fake target
// ---------------------------------------------------------------------------

const locNginxConf = `user www-data;
events {}
http {
    include /etc/nginx/conf.d/*.conf;
}
`

const locNginxSite = `server {
    listen 443 ssl;
    server_name a.example;
    ssl_certificate /etc/nginx/ssl/site.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_trusted_certificate /etc/nginx/missing-chain.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
}
`

const locSSHDConf = "HostKey /etc/ssh/ssh_host_ed25519_key\nCiphers aes256-gcm@openssh.com\nPasswordAuthentication no\n"

// locLinuxTree is a small Linux host: a trust bundle and its per-anchor
// links, nginx naming a certificate and a key, sshd naming its host key, a
// JDK, Elasticsearch's JVM options naming a trust store and a security file,
// a keytab, a home directory.
func locLinuxTree(t *testing.T, local bool) *tgtFakeTarget {
	m := locTestMaterial(t)
	return newTgtFakeTarget(local).
		file("/etc/ssl/certs/ca-certificates.crt", m.caPEM).
		file("/usr/share/ca-certificates/loc/ca.crt", m.caPEM).
		symlink("/etc/ssl/certs/0a1b2c3d.0", "/usr/share/ca-certificates/loc/ca.crt").
		fileMode("/etc/ssl/private/server.key", m.ecPEM, 0o600).
		fileMode("/etc/ssl/private/legacy.key", m.rsaPEM, 0o640).
		file("/etc/ssl/private/README", []byte("keys live here\n")).
		file("/etc/nginx/nginx.conf", []byte(locNginxConf)).
		file("/etc/nginx/conf.d/site.conf", []byte(locNginxSite)).
		file("/etc/nginx/ssl/site.crt", m.leafPEM).
		file("/etc/ssh/sshd_config", []byte(locSSHDConf)).
		fileMode("/etc/ssh/ssh_host_ed25519_key", m.edPEM, 0o600).
		file("/etc/ssh/ssh_host_ed25519_key.pub", m.edPub).
		file("/etc/ssh/ssh_known_hosts", []byte("|1|abc=|def= ssh-ed25519 AAAA\n")).
		file("/usr/lib/jvm/java-17/lib/security/cacerts", m.jks).
		file("/usr/lib/jvm/java-17/conf/security/java.security", []byte("jdk.tls.disabledAlgorithms=SSLv3, TLSv1, RC4\nkeystore.password=hunter2\n")).
		file("/etc/elasticsearch/jvm.options", []byte("-Djavax.net.ssl.trustStore=/etc/es/ts.jks\n-Djava.security.properties=/etc/elasticsearch/extra.security\n-Djavax.net.ssl.trustStorePassword=hunter2\n")).
		file("/etc/es/ts.jks", m.jks).
		file("/etc/elasticsearch/extra.security", []byte("jdk.tls.disabledAlgorithms=SSLv3\n")).
		fileMode("/etc/krb5.keytab", m.keytab, 0o600).
		file("/home/alice/.ssh/authorized_keys", m.authorized).
		fileMode("/home/alice/.ssh/id_ed25519", m.edPEM, 0o600).
		file("/home/alice/.ssh/known_hosts", []byte("host.example ssh-ed25519 AAAA\n"))
}

func locCollect(t *testing.T, tgt Target, opts Options) *Report {
	t.Helper()
	if opts.Now == nil {
		opts.Now = tgtNow
	}
	rep, err := Collect(context.Background(), tgt, opts)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rep
}

func locCertAt(rep *Report, p string) *Certificate {
	for i := range rep.Certificates {
		if rep.Certificates[i].Location.Path == p {
			return &rep.Certificates[i]
		}
	}
	return nil
}

func locKeyAt(rep *Report, p string) *PrivateKey {
	for i := range rep.PrivateKeys {
		if rep.PrivateKeys[i].Location.Path == p {
			return &rep.PrivateKeys[i]
		}
	}
	return nil
}

func locStoreAt(rep *Report, p string) *Keystore {
	for i := range rep.Keystores {
		if rep.Keystores[i].Location.Path == p {
			return &rep.Keystores[i]
		}
	}
	return nil
}

func locConfigOf(rep *Report, p, product string) *CryptoConfig {
	for i := range rep.Configs {
		if rep.Configs[i].Location.Path == p && rep.Configs[i].Product == product {
			return &rep.Configs[i]
		}
	}
	return nil
}

func locHasUsage(l Location, configPath, directive string) bool {
	return locUsage(l, configPath, directive) != nil
}

func locUsage(l Location, configPath, directive string) *Usage {
	for i, u := range l.UsedBy {
		if u.Kind == "config" && u.ConfigPath == configPath && u.Directive == directive {
			return &l.UsedBy[i]
		}
	}
	return nil
}

// locRefStatus is the Status of the reference with this directive and path
// among a report's configurations, or "?" when there is none.
func locRefStatus(rep *Report, directive, path string) string {
	for _, c := range rep.Configs {
		for _, r := range c.References {
			if r.Directive == directive && r.Path == path {
				return r.Status
			}
		}
	}
	return "?"
}

func locErrorsContain(rep *Report, parts ...string) bool {
	for _, e := range rep.Errors {
		all := true
		for _, p := range parts {
			if !strings.Contains(e.Message, p) {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}

// locPrivatePaths are the files of locLinuxTree whose bytes must never be
// asked for over a remote connection.
var locPrivatePaths = []string{
	"/etc/ssl/private/server.key", "/etc/ssl/private/legacy.key", "/etc/ssh/ssh_host_ed25519_key",
	"/home/alice/.ssh/id_ed25519", "/usr/lib/jvm/java-17/lib/security/cacerts",
	"/etc/es/ts.jks", "/etc/krb5.keytab",
}

// locPrivateReads returns an error naming the first call that asked a remote
// target for a private file's bytes, or that the target refused.
func locPrivateReads(calls []string, private []string) error {
	for _, call := range calls {
		if strings.HasPrefix(call, "read-refused ") {
			return fmt.Errorf("a refused read reached the target: %s", call)
		}
		for _, p := range private {
			if call == "read "+p {
				return fmt.Errorf("a private file's bytes were asked for: %s", call)
			}
		}
	}
	return nil
}

func TestLocLinuxLocalAndRemote(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(fmt.Sprintf("local=%v", local), func(t *testing.T) {
			ft := locLinuxTree(t, local)
			rep := locCollect(t, ft, Options{Platform: "linux", HomeDirectories: true})

			// The trust bundle: anchors, no PEM; its link in /etc/ssl/certs
			// skipped, not a second copy.
			ca := locCertAt(rep, "/etc/ssl/certs/ca-certificates.crt")
			if ca == nil || !ca.TrustAnchor || ca.CertificatePEM != "" || ca.Location.FoundBy != FoundByKnownLocation {
				t.Fatalf("trust bundle certificate: %+v", ca)
			}
			if locCertAt(rep, "/etc/ssl/certs/0a1b2c3d.0") != nil || ft.called("identify", "/etc/ssl/certs/0a1b2c3d.0") {
				t.Error("a per-anchor link in /etc/ssl/certs was visited")
			}

			// nginx: the included server block names the certificate and the
			// key; both carry the configuration as UsedBy and FoundBy config.
			// The directive is in the included file: the usage names it, the
			// root that includes it, the product and the server block.
			leaf := locCertAt(rep, "/etc/nginx/ssl/site.crt")
			if leaf == nil || leaf.Location.FoundBy != FoundByConfig || leaf.TrustAnchor {
				t.Fatalf("nginx certificate: %+v", leaf)
			}
			u := locUsage(leaf.Location, "/etc/nginx/conf.d/site.conf", "ssl_certificate")
			if u == nil || u.RootConfigPath != "/etc/nginx/nginx.conf" || u.Product != "nginx" || !strings.Contains(u.Context, "a.example") {
				t.Fatalf("nginx certificate usage: %+v", leaf.Location.UsedBy)
			}
			key := locKeyAt(rep, "/etc/ssl/private/server.key")
			if key == nil || key.Location.FoundBy != FoundByConfig || key.Role != "tls" ||
				!locHasUsage(key.Location, "/etc/nginx/conf.d/site.conf", "ssl_certificate_key") ||
				key.Location.Mode != "0600" || key.Location.WorldReadable == nil || *key.Location.WorldReadable {
				t.Fatalf("nginx key: %+v", key)
			}
			if locConfigOf(rep, "/etc/nginx/nginx.conf", "nginx") == nil {
				t.Error("no nginx configuration record")
			}
			// A missing file is on its reference, not in Errors.
			if st := locRefStatus(rep, "ssl_trusted_certificate", "/etc/nginx/missing-chain.pem"); st != RefMissing {
				t.Errorf("missing reference status %q", st)
			}
			if locErrorsContain(rep, "missing-chain.pem") {
				t.Errorf("a missing reference reached Errors: %+v", rep.Errors)
			}
			for _, ref := range []struct{ d, p string }{
				{"ssl_certificate", "/etc/nginx/ssl/site.crt"}, {"ssl_certificate_key", "/etc/ssl/private/server.key"},
				{"include", "/etc/nginx/conf.d/*.conf"}, {"HostKey", "/etc/ssh/ssh_host_ed25519_key"},
			} {
				if st := locRefStatus(rep, ref.d, ref.p); st != RefFound {
					t.Errorf("%s %s: status %q", ref.d, ref.p, st)
				}
			}
			if u := locUsage(hkUsageLoc(rep), "/etc/ssh/sshd_config", "HostKey"); u == nil || u.RootConfigPath != "" || u.Product != "sshd" {
				t.Errorf("sshd usage from the root file: %+v", u)
			}

			// sshd: the host key, role and usage; its public half.
			hk := locKeyAt(rep, "/etc/ssh/ssh_host_ed25519_key")
			if hk == nil || hk.Role != "ssh_host_key" || hk.Format != KeyFormatOpenSSH ||
				!locHasUsage(hk.Location, "/etc/ssh/sshd_config", "HostKey") {
				t.Fatalf("host key: %+v", hk)
			}
			if len(rep.SSH.HostPublicKeys) != 1 || rep.SSH.HostPublicKeys[0].Algorithm != "ssh-ed25519" {
				t.Errorf("host public keys: %+v", rep.SSH.HostPublicKeys)
			}
			if locConfigOf(rep, "/etc/ssh/sshd_config", "sshd") == nil {
				t.Error("no sshd configuration record")
			}

			// Java: cacerts is a keystore, java.security a configuration, the
			// JVM options name a trust store and a security file, which
			// becomes a java configuration found by configuration.
			if ks := locStoreAt(rep, "/usr/lib/jvm/java-17/lib/security/cacerts"); ks == nil || ks.Type != KeystoreJKS {
				t.Errorf("cacerts: %+v", ks)
			}
			if locConfigOf(rep, "/usr/lib/jvm/java-17/conf/security/java.security", "java") == nil {
				t.Error("no java.security record")
			}
			ts := locStoreAt(rep, "/etc/es/ts.jks")
			if ts == nil || ts.Location.FoundBy != FoundByConfig ||
				!locHasUsage(ts.Location, "/etc/elasticsearch/jvm.options", "-Djavax.net.ssl.trustStore") {
				t.Errorf("trust store named by jvm.options: %+v", ts)
			}
			extra := locConfigOf(rep, "/etc/elasticsearch/extra.security", "java")
			if extra == nil || extra.Location.FoundBy != FoundByConfig {
				t.Errorf("security properties named by jvm.options: %+v", extra)
			}
			if ks := locStoreAt(rep, "/etc/krb5.keytab"); ks == nil || ks.Type != KeystoreKeytab {
				t.Errorf("keytab: %+v", ks)
			}

			// Home directory material, opted in.
			if len(rep.SSH.AuthorizedKeys) != 1 || rep.SSH.AuthorizedKeys[0].Account != "alice" ||
				len(rep.SSH.AuthorizedKeys[0].Keys) != 1 {
				t.Fatalf("authorized keys: %+v", rep.SSH.AuthorizedKeys)
			}
			ak := rep.SSH.AuthorizedKeys[0].Keys[0]
			if local && (ak.Restricted == nil || !*ak.Restricted || ak.CertificateAuthority == nil || *ak.CertificateAuthority) {
				t.Errorf("local: options not read: restricted %v, cert-authority %v", ak.Restricted, ak.CertificateAuthority)
			}
			if !local && (ak.Restricted != nil || ak.CertificateAuthority != nil) {
				t.Errorf("remote: options do not cross, both must be unknown: %v %v", ak.Restricted, ak.CertificateAuthority)
			}
			if len(rep.SSH.KnownHosts) != 2 {
				t.Fatalf("known hosts files: %+v", rep.SSH.KnownHosts)
			}
			for _, kh := range rep.SSH.KnownHosts {
				if local != (kh.Entries != nil && kh.Hashed != nil) {
					t.Errorf("local=%v: known_hosts %s counts %v %v", local, kh.Location.Path, kh.Entries, kh.Hashed)
				}
				if kh.Location.Mode == "" {
					t.Errorf("known_hosts without its location: %+v", kh.Location)
				}
			}
			uk := locKeyAt(rep, "/home/alice/.ssh/id_ed25519")
			if uk == nil || uk.Role != "ssh_user_key" {
				t.Errorf("user key: %+v", uk)
			}

			// No secret of a configuration file reaches the report.
			blob, _ := json.Marshal(rep)
			if strings.Contains(string(blob), "hunter2") {
				t.Error("a configuration secret reached the report")
			}

			if local {
				if key.Algorithm != "ECDSA" || key.PublicKeySHA256 == "" || key.PublicKeySHA256 != leaf.PublicKeySHA256 {
					t.Errorf("local key not parsed or not paired with its certificate: %+v", key)
				}
				for _, s := range []string{SectionCertificates, SectionPrivateKeys, SectionKeystores, SectionSSH, SectionConfigs, SectionHomeDirectories} {
					if rep.Sections[s] != SectionOK {
						t.Errorf("section %s = %q, errors %+v", s, rep.Sections[s], rep.Errors)
					}
				}
				return
			}

			// REMOTE: no private byte was asked for; keys are described from
			// their markers and say why the rest is empty.
			if err := locPrivateReads(ft.recorded(), locPrivatePaths); err != nil {
				t.Fatal(err)
			}
			if key.Format != KeyFormatPKCS8 || key.Encrypted == nil || *key.Encrypted || key.Unknown == "" || key.PublicKeySHA256 != "" {
				t.Errorf("remote PKCS#8 key from its label: %+v", key)
			}
			if ks := locStoreAt(rep, "/usr/lib/jvm/java-17/lib/security/cacerts"); ks == nil || ks.Unknown == "" || ks.EntryCount != nil {
				t.Errorf("remote keystore must say why it is empty: %+v", ks)
			}
			if lk := locKeyAt(rep, "/etc/ssl/private/legacy.key"); lk == nil || lk.Format != KeyFormatPKCS1 ||
				lk.Algorithm != "RSA" || lk.Encrypted != nil {
				t.Errorf("remote PKCS#1 key from its label: %+v", lk)
			}
			for _, call := range ft.recorded() {
				if call == "read /etc/nginx/nginx.conf" || call == "read /etc/ssh/sshd_config" {
					t.Errorf("configuration read as a file: %s", call)
				}
			}
			if !ft.called("readtext", "/etc/nginx/conf.d/site.conf") {
				t.Error("the include was not read through ReadText")
			}
			if rep.Sections[SectionSSH] != SectionPartial || !locErrorsContain(rep, "known_hosts") {
				t.Errorf("remote known_hosts must leave ssh partial with a reason: %q %+v", rep.Sections[SectionSSH], rep.Errors)
			}
			if rep.Sections[SectionConfigs] != SectionOK || rep.Sections[SectionCertificates] != SectionOK {
				t.Errorf("remote sections: %+v", rep.Sections)
			}
		})
	}
}

// TestLocRemoteNeverAsksForPrivateBytes: the guard both ways. On the real
// remote collection it finds nothing; fed a recording with a private read in
// it, or with a refused read, it fails.
func TestLocRemoteNeverAsksForPrivateBytes(t *testing.T) {
	ft := locLinuxTree(t, false)
	locCollect(t, ft, Options{Platform: "linux", HomeDirectories: true})
	calls := ft.recorded()
	if err := locPrivateReads(calls, locPrivatePaths); err != nil {
		t.Fatal(err)
	}
	if err := locPrivateReads(append(calls, "read /etc/ssl/private/server.key"), locPrivatePaths); err == nil {
		t.Fatal("the guard missed a private read")
	}
	if err := locPrivateReads(append(calls, "read-refused /x"), locPrivatePaths); err == nil {
		t.Fatal("the guard missed a refused read")
	}
	// And the fake itself refuses, so a pass that asked would be caught even
	// for a path the list above forgot.
	if _, err := ft.ReadFile(context.Background(), "/etc/ssl/private/server.key"); err == nil {
		t.Fatal("the remote fake returned a private key")
	}
}

// TestLocProjection: the whole report of a local collection, which parsed
// every generated key in memory, holds no window of any private component.
// The detector is shown to fire on a report that does.
func TestLocProjection(t *testing.T) {
	m := locTestMaterial(t)
	ft := locLinuxTree(t, true)
	rep := locCollect(t, ft, Options{Platform: "linux", HomeDirectories: true})
	if len(rep.PrivateKeys) < 4 {
		t.Fatalf("expected the generated keys to be described, got %d", len(rep.PrivateKeys))
	}
	keyAssertNoLeak(t, "local report", rep, m.secrets...)

	blob, _ := json.Marshal(rep)
	leaky := append(blob, []byte(fmt.Sprintf("%x", m.secrets[0]))...)
	if keyLeakIn(leaky, m.secrets...) == "" {
		t.Fatal("the leak detector cannot see a hex-encoded secret")
	}
}

// TestLocHomeOptIn: per-user locations are visited only when asked for.
func TestLocHomeOptIn(t *testing.T) {
	for _, on := range []bool{false, true} {
		ft := locLinuxTree(t, true)
		rep := locCollect(t, ft, Options{Platform: "linux", HomeDirectories: on})
		touched := false
		for _, call := range ft.recorded() {
			if strings.Contains(call, "/home/") {
				touched = true
			}
		}
		if touched != on {
			t.Errorf("HomeDirectories=%v but /home touched=%v", on, touched)
		}
		want := SectionSkipped
		if on {
			want = SectionOK
		}
		if rep.Sections[SectionHomeDirectories] != want {
			t.Errorf("HomeDirectories=%v: section %q", on, rep.Sections[SectionHomeDirectories])
		}
	}
}

// TestLocExcludePaths: an excluded path is not entered by either pass, even
// when a configuration names it.
func TestLocExcludePaths(t *testing.T) {
	for _, exclude := range []bool{false, true} {
		ft := locLinuxTree(t, true)
		opts := Options{Platform: "linux"}
		if exclude {
			opts.ExcludePaths = []string{"/etc/ssl/private"}
		}
		rep := locCollect(t, ft, opts)
		visited := ft.called("identify", "/etc/ssl/private/server.key")
		if visited == exclude || (locKeyAt(rep, "/etc/ssl/private/server.key") != nil) == exclude {
			t.Errorf("exclude=%v: visited=%v", exclude, visited)
		}
	}
}

// TestLocDeniedAndBounds: a file the account may not read makes its section
// partial and says which; the file bound and the record bound are recorded.
func TestLocDeniedAndBounds(t *testing.T) {
	ft := locLinuxTree(t, true).deny("/etc/ssl/private/legacy.key")
	rep := locCollect(t, ft, Options{Platform: "linux"})
	if rep.Sections[SectionPrivateKeys] != SectionPartial || !locErrorsContain(rep, "legacy.key", "permission denied") {
		t.Errorf("denied key: %q %+v", rep.Sections[SectionPrivateKeys], rep.Errors)
	}

	ft = locLinuxTree(t, true)
	rep = locCollect(t, ft, Options{Platform: "linux", MaxFiles: 3})
	found := false
	for _, l := range rep.Limits {
		if l.Limit == "max_files" {
			found = true
		}
	}
	if !found {
		t.Errorf("max_files not recorded: %+v", rep.Limits)
	}

	ft = locLinuxTree(t, true)
	rep = locCollect(t, ft, Options{Platform: "linux", MaxRecordsPerSection: 1})
	if len(rep.PrivateKeys) != 1 || rep.Sections[SectionPrivateKeys] != SectionPartial {
		t.Errorf("max_records: %d keys, section %q", len(rep.PrivateKeys), rep.Sections[SectionPrivateKeys])
	}
}

// TestLocOneFileTwoWays: a key reached through a link and through the
// configuration that names it is one record carrying both usages and the
// strongest FoundBy; without the link it is still one record.
func TestLocOneFileTwoWays(t *testing.T) {
	m := locTestMaterial(t)
	ft := locLinuxTree(t, false).
		symlink("/etc/nginx/ssl/current.key", "/etc/ssl/private/server.key").
		file("/etc/nginx/conf.d/two.conf", []byte("server {\n listen 8443 ssl;\n ssl_certificate /etc/nginx/ssl/site.crt;\n ssl_certificate_key /etc/nginx/ssl/current.key;\n}\n"))
	_ = m
	rep := locCollect(t, ft, Options{Platform: "linux"})
	n := 0
	var k PrivateKey
	for _, x := range rep.PrivateKeys {
		if strings.HasSuffix(x.Location.Path, "server.key") || strings.HasSuffix(x.Location.Path, "current.key") {
			n++
			k = x
		}
	}
	if n != 1 {
		t.Fatalf("one key reached two ways became %d records", n)
	}
	// Two server blocks in two included files name it: two usages, each
	// crediting its own file, on one record.
	if k.Location.FoundBy != FoundByConfig || len(k.Location.UsedBy) != 2 ||
		!locHasUsage(k.Location, "/etc/nginx/conf.d/site.conf", "ssl_certificate_key") ||
		!locHasUsage(k.Location, "/etc/nginx/conf.d/two.conf", "ssl_certificate_key") {
		t.Errorf("merged key: %+v", k.Location)
	}
	if ft.called("identify", "/etc/nginx/ssl/current.key") && ft.called("identify", "/etc/ssl/private/server.key") {
		t.Error("the same file was identified twice")
	}
}

func hkUsageLoc(rep *Report) Location {
	if k := locKeyAt(rep, "/etc/ssh/ssh_host_ed25519_key"); k != nil {
		return k.Location
	}
	return Location{}
}
