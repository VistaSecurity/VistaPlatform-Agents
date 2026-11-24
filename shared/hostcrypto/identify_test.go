package hostcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// tgtPEMHeader builds a PEM header line at run time, so no private key
// header appears as a literal in the source for a secret scanner to trip on.
func tgtPEMHeader(label string) string { return "-----BEGIN " + label + "-----\n" }

var (
	tgtMaterialOnce sync.Once
	tgtCertPEM      []byte
	tgtKeyPEM       []byte
	tgtKeyDER       []byte
	tgtCertDER      []byte
)

// tgtMaterial returns a certificate and its private key, generated once per
// test binary in memory. Nothing of it is committed.
func tgtMaterial(t *testing.T) (certPEM, keyPEM, certDER, keyDER []byte) {
	t.Helper()
	var genErr error
	tgtMaterialOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			genErr = err
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(7),
			Subject:      pkix.Name{CommonName: "hostcrypto test"},
			NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			genErr = err
			return
		}
		kder, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			genErr = err
			return
		}
		tgtCertDER, tgtKeyDER = der, kder
		tgtCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		tgtKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	})
	if genErr != nil || tgtCertPEM == nil {
		t.Fatalf("generate test material: %v", genErr)
	}
	return tgtCertPEM, tgtKeyPEM, tgtCertDER, tgtKeyDER
}

func TestClassifyLabels(t *testing.T) {
	cases := []struct {
		labels []string
		want   Class
	}{
		{[]string{"CERTIFICATE"}, ClassCertificate},
		{[]string{"TRUSTED CERTIFICATE"}, ClassCertificate},
		{[]string{"X509 CERTIFICATE"}, ClassCertificate},
		{[]string{"CERTIFICATE", "CERTIFICATE", "CERTIFICATE"}, ClassCertificate},
		{[]string{"RSA PRIVATE KEY"}, ClassPrivateKey},
		{[]string{"EC PRIVATE KEY"}, ClassPrivateKey},
		{[]string{"DSA PRIVATE KEY"}, ClassPrivateKey},
		{[]string{"OPENSSH PRIVATE KEY"}, ClassPrivateKey},
		{[]string{"ENCRYPTED PRIVATE KEY"}, ClassPrivateKey},
		{[]string{"PRIVATE KEY"}, ClassPrivateKey},
		{[]string{"SSH2 ENCRYPTED PRIVATE KEY"}, ClassPrivateKey},
		{[]string{"Some Odd private Key"}, ClassPrivateKey},
		{[]string{"EC PARAMETERS", "EC PRIVATE KEY"}, ClassPrivateKey},
		{[]string{"PUBLIC KEY"}, ClassPublicKey},
		{[]string{"RSA PUBLIC KEY"}, ClassPublicKey},
		{[]string{"SSH2 PUBLIC KEY"}, ClassPublicKey},
		{[]string{"CERTIFICATE REQUEST"}, ClassCSR},
		{[]string{"NEW CERTIFICATE REQUEST"}, ClassCSR},
		{[]string{"X509 CRL"}, ClassCRL},
		{[]string{"DH PARAMETERS"}, ClassDHParams},
		{[]string{"PGP PRIVATE KEY BLOCK"}, ClassPGP},
		{[]string{"PGP PUBLIC KEY BLOCK"}, ClassPGP},
		// Mixed: a certificate and its key in one file.
		{[]string{"CERTIFICATE", "PRIVATE KEY"}, ClassMixed},
		{[]string{"RSA PRIVATE KEY", "CERTIFICATE", "CERTIFICATE"}, ClassMixed},
		// Public classes together stay public, the strongest named.
		{[]string{"CERTIFICATE", "X509 CRL"}, ClassCertificate},
		// An unrecognised label is not public, even beside a certificate.
		{[]string{"OpenVPN Static key V1"}, ClassPrivateKey}, // says KEY, not on the allowlist
		{[]string{"PKCS7"}, ClassUnknown},
		{[]string{"CERTIFICATE", "PKCS7"}, ClassUnknown},
		{[]string{"EC PARAMETERS"}, ClassUnknown},
	}
	for _, tc := range cases {
		got := Classify([]byte("-----BEG"), tc.labels)
		if got.Class != tc.want {
			t.Errorf("Classify(labels %q) = %q, want %q", tc.labels, got.Class, tc.want)
		}
	}
}

// TestClassifyPublicPolarity is the guard in both directions: a file of
// public labels is public, and adding any private label makes it not.
func TestClassifyPublicPolarity(t *testing.T) {
	public := [][]string{
		{"CERTIFICATE"}, {"PUBLIC KEY"}, {"CERTIFICATE REQUEST"}, {"X509 CRL"},
		{"DH PARAMETERS"}, {"CERTIFICATE", "CERTIFICATE"},
	}
	private := []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
		"OPENSSH PRIVATE KEY", "DSA PRIVATE KEY", "PGP PRIVATE KEY BLOCK", "UNHEARD OF THING"}
	for _, labels := range public {
		if id := Classify(nil, labels); !id.Public() {
			t.Errorf("labels %q: want public, got %q", labels, id.Class)
		}
		for _, p := range private {
			with := append(append([]string(nil), labels...), p)
			if id := Classify(nil, with); id.Public() {
				t.Errorf("labels %q: want NOT public, got %q", with, id.Class)
			}
		}
	}
}

func TestClassifyMagic(t *testing.T) {
	cases := []struct {
		name  string
		magic []byte
		class Class
		ks    string
	}{
		{"jks", []byte{0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2}, ClassKeystore, KeystoreJKS},
		{"jceks", []byte{0xCE, 0xCE, 0xCE, 0xCE, 0, 0, 0, 2}, ClassKeystore, KeystoreJCEKS},
		{"keytab v2", []byte{0x05, 0x02, 0, 0, 0, 0x40}, ClassKeystore, KeystoreKeytab},
		{"keytab v1", []byte{0x05, 0x01, 0, 0}, ClassKeystore, KeystoreKeytab},
		{"putty", []byte("PuTTY-User-Key-File-3: ssh-ed25519")[:8], ClassPrivateKey, ""},
		{"ssh1", []byte("SSH PRIVATE KEY FILE")[:8], ClassPrivateKey, ""},
		{"sqlite unnamed", []byte("SQLite format 3\x00")[:8], ClassUnknown, ""},
		{"der 0x82", []byte{0x30, 0x82, 0x03, 0x01, 0x30, 0x82}, ClassUnknown, ""},
		{"der 0x80", []byte{0x30, 0x80, 0x02, 0x01}, ClassUnknown, ""},
		{"der 0x83", []byte{0x30, 0x83, 0x01, 0x00, 0x00}, ClassUnknown, ""},
		{"text", []byte("ssl_prot"), ClassText, ""},
		{"text cut rune", []byte("abcdef\xc3"), ClassText, ""},
		{"text bom", []byte("\xEF\xBB\xBF[sect"), ClassText, ""},
		{"binary", []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, ClassUnknown, ""},
		{"nul", []byte{'a', 0, 'b'}, ClassUnknown, ""},
		{"empty", nil, ClassUnknown, ""},
	}
	for _, tc := range cases {
		got := Classify(tc.magic, nil)
		if got.Class != tc.class || got.KeystoreType != tc.ks {
			t.Errorf("%s: Classify = (%q, %q), want (%q, %q)", tc.name, got.Class, got.KeystoreType, tc.class, tc.ks)
		}
	}
	// A keystore's magic wins over PEM-looking text inside it.
	if got := Classify(magicJKS, []string{"CERTIFICATE"}); got.Class != ClassKeystore {
		t.Errorf("JKS with a label: got %q", got.Class)
	}
	// Identity carries at most MagicBytes, copied.
	long := []byte("0123456789abcdef")
	got := Classify(long, nil)
	if len(got.Magic) != MagicBytes {
		t.Fatalf("Magic len = %d", len(got.Magic))
	}
	long[0] = 'X'
	if got.Magic[0] != '0' {
		t.Error("Identity.Magic aliases the caller's slice")
	}
}

func TestClassifyNamed(t *testing.T) {
	der := []byte{0x30, 0x82, 0x0a, 0x01, 0x02, 0x01, 0x03, 0x30}
	sqlite := []byte("SQLite f")
	cases := []struct {
		name   string
		magic  []byte
		labels []string
		class  Class
		ks     string
	}{
		{"/etc/pki/nssdb/cert9.db", sqlite, nil, ClassKeystore, KeystoreNSS},
		{"/home/u/.pki/nssdb/key4.db", sqlite, nil, ClassKeystore, KeystoreNSS},
		{"/x/cert9.db", nil, nil, ClassKeystore, KeystoreNSS},
		{"/x/other.db", sqlite, nil, ClassUnknown, ""},
		{"/x/cert8.db", []byte{0, 0, 0, 0, 0x61, 0x15, 0x06, 0}, nil, ClassKeystore, KeystoreNSS},
		{"/x/key3.db", nil, nil, ClassKeystore, KeystoreNSS},
		{"/home/u/.gnupg/pubring.kbx", nil, nil, ClassPGP, ""},
		{"/x/keys.kbx", nil, nil, ClassPGP, ""},
		{"/home/u/.gnupg/pubring.gpg", nil, nil, ClassPGP, ""},
		{"/home/u/.gnupg/secring.gpg", nil, nil, ClassPGP, ""},
		{"/Library/Keychains/System.keychain", nil, nil, ClassKeystore, KeystoreKeychain},
		{"/Users/u/Library/Keychains/login.keychain-db", nil, nil, ClassKeystore, KeystoreKeychain},
		{"/x/server.p12", der, nil, ClassKeystore, KeystorePKCS12},
		{`C:\certs\server.PFX`, der, nil, ClassKeystore, KeystorePKCS12},
		{"/x/a.bcfks", der, nil, ClassKeystore, KeystoreBCFKS},
		{"/x/a.bks", nil, nil, ClassKeystore, KeystoreBKS},
		{"/x/server.der", der, nil, ClassUnknown, ""},
		{"/x/server.crt", der, nil, ClassUnknown, ""},
		{"/x/id_ed25519.pub", []byte("ssh-ed25"), nil, ClassPublicKey, ""},
		{"/x/id_ecdsa.pub", []byte("ecdsa-sh"), nil, ClassPublicKey, ""},
		{"/x/id_sk.pub", []byte("sk-ssh-e"), nil, ClassPublicKey, ""},
		{"/x/notes.pub", []byte("hello wo"), nil, ClassText, ""},
		{"/x/id.pub", nil, nil, ClassUnknown, ""},
		// A name never makes content MORE public, and content that says
		// something definite stands.
		{"/x/server.p12", []byte("-----BEG"), []string{"CERTIFICATE"}, ClassCertificate, ""},
		{"/x/readme.txt", []byte("-----BEG"), []string{"PRIVATE KEY"}, ClassPrivateKey, ""},
		{"/x/settings.jks", []byte("text her"), nil, ClassKeystore, KeystoreJKS},
		{"/x/a.ppk", nil, nil, ClassPrivateKey, ""},
	}
	for _, tc := range cases {
		got := ClassifyNamed(tc.name, tc.magic, tc.labels)
		if got.Class != tc.class || got.KeystoreType != tc.ks {
			t.Errorf("ClassifyNamed(%q) = (%q, %q), want (%q, %q)", tc.name, got.Class, got.KeystoreType, tc.class, tc.ks)
		}
	}
}

// TestClassifyNamedNeverMorePublic: for every name the table knows, a file
// whose content is unknown or absent is never classified public by its name.
func TestClassifyNamedNeverMorePublic(t *testing.T) {
	names := []string{"a.p12", "a.pfx", "a.jks", "a.jceks", "a.bks", "a.bcfks", "a.keytab", "a.kbx",
		"a.keychain", "a.keychain-db", "cert9.db", "key4.db", "cert8.db", "key3.db", "pubring.gpg",
		"secring.gpg", "a.pub", "a.pem", "a.key", "a.crt", "a.der", "a.ppk", "plain"}
	for _, n := range names {
		for _, magic := range [][]byte{nil, {0x30, 0x82, 1, 2}, {0x01, 0x02, 0x03}} {
			if id := ClassifyNamed("/d/"+n, magic, nil); id.Public() {
				t.Errorf("%s with magic %x: public (%q)", n, magic, id.Class)
			}
		}
	}
}

func TestScanPEMLabels(t *testing.T) {
	certPEM, keyPEM, _, _ := tgtMaterial(t)
	bundle := append(append([]byte("Bag Attributes\n"), certPEM...), keyPEM...)
	got := ScanPEMLabels(bundle, 0)
	if strings.Join(got, ",") != "CERTIFICATE,PRIVATE KEY" {
		t.Fatalf("labels = %q", got)
	}
	ssh2 := []byte("---- BEGIN SSH2 PUBLIC KEY ----\nComment: x\nAAAA\n---- END SSH2 PUBLIC KEY ----\n")
	if got := ScanPEMLabels(ssh2, 0); len(got) != 1 || got[0] != "SSH2 PUBLIC KEY" {
		t.Fatalf("ssh2 labels = %q", got)
	}
	// The bound holds.
	var many []byte
	for i := 0; i < 100; i++ {
		many = append(many, certPEM...)
	}
	if got := ScanPEMLabels(many, 0); len(got) != maxPEMLabels {
		t.Fatalf("bound: %d labels", len(got))
	}
	if got := ScanPEMLabels(many, 3); len(got) != 3 {
		t.Fatalf("max 3: %d labels", len(got))
	}
	// Malformed headers are not labels.
	for _, s := range []string{
		"-----BEGIN -----",
		"-----BEGIN CERT\nIFICATE-----",
		"-----BEGIN " + strings.Repeat("A", 90) + "-----",
		"-----BEGIN CERTIFICATE",
	} {
		if got := ScanPEMLabels([]byte(s), 0); len(got) != 0 {
			t.Errorf("%q: labels %q", s, got)
		}
	}
	// A malformed header does not hide a following good one.
	if got := ScanPEMLabels([]byte("-----BEGIN broken\n"+tgtPEMHeader("CERTIFICATE")), 0); len(got) != 1 || got[0] != "CERTIFICATE" {
		t.Errorf("after malformed: %q", got)
	}
}

// tgtID classifies whole-file content as every target does.
func tgtID(name string, b []byte) Identity {
	return identityFrom(name, inspect(b, int64(len(b))))
}

// TestPublicIsAnAllowlist: items 2 and 13 of the review. Public is decided by
// exact labels; anything else, however it is spelled, is not public, and a
// malformed label is never returned.
func TestPublicIsAnAllowlist(t *testing.T) {
	certPEM, keyPEM, _, _ := tgtMaterial(t)
	body := "MIIBkTCB+wIJAKHHIG...\n"
	block := func(label string) string {
		return "-----BEGIN " + label + "-----\n" + body + "-----END " + label + "-----\n"
	}
	cases := []struct {
		name    string
		content string
		public  bool
		class   Class
		labels  string
	}{
		{"certificate", string(certPEM), true, ClassCertificate, "CERTIFICATE"},
		{"dashed private label", block("X-PRIVATE KEY"), false, ClassPrivateKey, "X-PRIVATE KEY"},
		{"secret label", block("MY SECRET"), false, ClassPrivateKey, "MY SECRET"},
		{"key label", block("HMAC KEY"), false, ClassPrivateKey, "HMAC KEY"},
		{"unlisted public-sounding key", block("EC PUBLIC KEY"), false, ClassPrivateKey, "EC PUBLIC KEY"},
		{"lowercase label", "-----BEGIN OpenVPN Static key V1-----\n0123\n-----END OpenVPN Static key V1-----\n", false, ClassPrivateKey, ""},
		{"lowercase begin word", string(certPEM) + "-----begin private key-----\n", true, ClassCertificate, "CERTIFICATE"},
		{"dotted label", block("X9.42 DH PARAMETERS"), false, ClassText, ""},
		{"base64 label", "-----BEGIN YY99uuY1gWotaYup510A3QVEZh0RN8YzrOkWD0reoNvzXMhgs5UEoQn1CmXQ-----\n", false, ClassText, ""},
		{"label over 64", block(strings.Repeat("A", 65)), false, ClassText, ""},
		{"text after the dashes", "-----BEGIN CERTIFICATE----- x\n" + body + "-----END CERTIFICATE-----\n", false, ClassText, ""},
		{"cert then pasted secret", string(certPEM) + "PrivateKey: " + strings.Repeat("Q", 44) + "\n", false, ClassUnknown, "CERTIFICATE"},
		{"unterminated cert", "-----BEGIN CERTIFICATE-----\n" + body, false, ClassUnknown, "CERTIFICATE"},
		{"cert with nested key, no END", "-----BEGIN CERTIFICATE-----\n" + body + string(keyPEM), false, ClassMixed, "CERTIFICATE,PRIVATE KEY"},
		{"cert with NUL", string(certPEM) + "\x00", false, ClassUnknown, "CERTIFICATE"},
		{"unknown label beside cert", string(certPEM) + block("PKCS7"), false, ClassUnknown, "CERTIFICATE,PKCS7"},
		{"crlf certificate", strings.ReplaceAll(string(certPEM), "\n", "\r\n"), true, ClassCertificate, "CERTIFICATE"},
		{"bag attributes before cert", "Bag Attributes\n    friendlyName: web\nsubject=/CN=x\n" + string(certPEM), true, ClassCertificate, "CERTIFICATE"},
		{"ssh2 public key", "---- BEGIN SSH2 PUBLIC KEY ----\nComment: x\nAAAA\n---- END SSH2 PUBLIC KEY ----\n", true, ClassPublicKey, "SSH2 PUBLIC KEY"},
	}
	for _, tc := range cases {
		id := tgtID("/x/f.pem", []byte(tc.content))
		if id.Public() != tc.public || id.Class != tc.class || strings.Join(id.PEMLabels, ",") != tc.labels {
			t.Errorf("%s: public=%v class=%q labels=%q, want %v %q %q", tc.name, id.Public(), id.Class, id.PEMLabels, tc.public, tc.class, tc.labels)
		}
		for _, l := range id.PEMLabels {
			if len(l) > 64 || strings.Trim(l, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -") != "" {
				t.Errorf("%s: returned label %q", tc.name, l)
			}
		}
	}

	// Past the 64-label bound a private key still makes the file not public.
	var b []byte
	for i := 0; i < maxPEMLabels+6; i++ {
		b = append(b, certPEM...)
	}
	b = append(b, keyPEM...)
	id := tgtID("/x/bundle.pem", b)
	if id.Public() || id.Class != ClassMixed || len(id.PEMLabels) != maxPEMLabels {
		t.Fatalf("bundle: %q, %d labels", id.Class, len(id.PEMLabels))
	}
}

// TestSSHPublicKeyFileRule: an OpenSSH .pub file is public only when every
// line is a public key line.
func TestSSHPublicKeyFileRule(t *testing.T) {
	line := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC3x9g5sQ1oB7g5rQ8a8d7a3r0C2bWq3pXvJb2bq9N7a user@host\n"
	cases := []struct {
		content string
		public  bool
	}{
		{line, true},
		{"# comment\n\n" + line, false}, // public by content, but the magic is not a key type: Go is stricter than the host here
		{line + line, true},
		{line + "PrivateKey: " + strings.Repeat("Q", 44) + "\n", false},
		{"ssh-ed25519 AAAA " + strings.Repeat("Q", 44) + "\n", false},
		{"ssh-ed25519  AAAA\n", false},
		{"ssh-rsa AAAA==x\n", false},
	}
	for _, tc := range cases {
		if got := tgtID("/home/u/.ssh/id.pub", []byte(tc.content)).Public(); got != tc.public {
			t.Errorf("%q: public=%v", tc.content, got)
		}
	}
	if tgtID("/x/id.txt", []byte(line)).Public() {
		t.Error("an SSH key line in a non-.pub file is public")
	}
}
