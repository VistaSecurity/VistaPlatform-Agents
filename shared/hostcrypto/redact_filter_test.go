package hostcrypto

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"golang.org/x/crypto/ssh"
)

// The ReadText rule (FilterConfigText), case by case: every rule of the
// function's comment, and the inputs of the third review.
func TestFilterConfigRuleTable(t *testing.T) {
	q := strings.Repeat("Q", RedactRunLength)
	secretLines := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "secret_line_%d S3cr3t-%d\n", i, i)
		}
		return b.String()
	}
	nested := func(n int) string {
		return strings.Repeat("http {\n", n) + "ssl_ciphers deep;\n" + strings.Repeat("}\n", n)
	}
	st := KeepOptStatements
	bs, ind, cr := KeepOptBackslash, KeepOptIndent, KeepOptCR
	cases := []struct {
		name string
		in   string
		keep []string
		out  string
		n    int
		ok   bool
	}{
		// Refusals and keep validation.
		{"empty keep refused", "a 1\n", nil, "", 0, false},
		{"only options refused", "a 1\n", []string{st, bs}, "", 0, false},
		{"unknown option refused", "a 1\n", []string{"a", "@nosuch"}, "", 0, false},
		{"a ; in a word refused", "a 1\n", []string{"a;"}, "", 0, false},
		{"a blank in a word refused", "a 1\n", []string{"a b"}, "", 0, false},
		{"NUL refused", "a 1\n\x00", []string{"a"}, "", 0, false},
		{"0x01 refused", "a \x01\n", []string{"a"}, "", 0, false},
		{"keystore magic refused", "\xfe\xed\xfe\xedtext\n", []string{"text"}, "", 0, false},
		{"keystore magic after a UTF-8 BOM refused", "\xef\xbb\xbf\xfe\xed\xfe\xedssl_ciphers a;\n", []string{"ssl_ciphers"}, "", 0, false},
		{"UTF-16 LE BOM refused", "\xff\xfessl_ciphers a\n", []string{"ssl_ciphers"}, "", 0, false},
		{"UTF-16 BE BOM refused", "\xfe\xffssl_ciphers a\n", []string{"ssl_ciphers"}, "", 0, false},

		// Byte-order mark and line ends.
		{"BOM stripped", "\xef\xbb\xbfa 1\n", []string{"a"}, "a 1\n", 0, true},
		{"a file that is only a BOM yields nothing", "\xef\xbb\xbf", []string{"a"}, "", 0, true},
		{"a BOM and a line end is one blank line", "\xef\xbb\xbf\n", []string{"a"}, "\n", 0, true},
		{"empty file", "", []string{"a"}, "", 0, true},
		{"one line end", "\n", []string{"a"}, "\n", 0, true},
		{"CRLF", "a 1\r\nb 2\r\n", []string{"a", "b"}, "a 1\nb 2\n", 0, true},
		{"no final line end", "a 1\nb 2", []string{"a", "b"}, "a 1\nb 2\n", 0, true},
		{"lone CR cuts the line", "a 1\rpassword S3cr3t\nb 2\n", []string{"a", "b", "password"}, "a 1\nb 2\n", 0, true},
		{"lone CR cuts a dropped line too", "password S3cr3t\ra 1\n", []string{"a"}, "", 0, true},
		{"lone CR ends a line with @cr", "a=1\rb=S3cr3t\rc=2\n", []string{"a", "c", cr}, "a=1\nc=2\n", 0, true},
		{"CR CR LF with @cr", "a=1\r\r\nc=2\n", []string{"a", "c", cr}, "a=1\n\nc=2\n", 0, true},
		{"lone CR at the end", "a 1\r", []string{"a"}, "a 1\n", 0, true},

		// Comments.
		{"comments dropped even with a keep word", "# Ciphers x\n; Ciphers y\n! Ciphers z\n// Ciphers w\n  # Ciphers u\nCiphers v\n", []string{"ciphers"}, "Ciphers v\n", 0, true},

		// Words.
		{"kept and dropped", "Ciphers aes256-gcm@openssh.com\npassword = hunter2-Secret!\n", []string{"ciphers"}, "Ciphers aes256-gcm@openssh.com\n", 0, true},
		{"keep compared without ASCII case", "SSLProtocol all\nsslPROTOCOL x\n", []string{"SSLProtocol"}, "SSLProtocol all\nsslPROTOCOL x\n", 0, true},
		{"no non-ASCII case folding", "\xc4ssl_ciphers S3cr3t\nSſl_ciphers x\n", []string{"ssl_ciphers"}, "", 0, true},
		{"first word stops at = : ; { }", "ssl=1\nssl:2\nssl;3\nssl{4\nssl}5\nssl_password S3cr3t\n", []string{"ssl"}, "ssl=1\nssl:2\nssl;3\nssl{4\nssl}5\n", 0, true},
		{"jvm option", "-Djavax.net.ssl.keyStore=/a.jks\n-Djavax.net.ssl.keyStorePassword=changeit\n", []string{"javax.net.ssl.keystore"}, "-Djavax.net.ssl.keyStore=/a.jks\n", 0, true},
		{"@SECLEVEL is the word seclevel", "@SECLEVEL=2:kEECDH:HIGH\n", []string{"seclevel"}, "@SECLEVEL=2:kEECDH:HIGH\n", 0, true},
		{"yaml colon", "client-key-data: " + q + "x\nserver: https://k\n", []string{"server"}, "server: https://k\n", 0, true},

		// Structure is strict.
		{"structure", "[Interface]\n\n  \n};\n</VirtualHost>\n}\nPrivateKey = x\n", []string{"address"}, "[Interface]\n\n  \n};\n</VirtualHost>\n}\n", 0, true},
		{"reviewer: a header that is not one", "[S3cr3t-section!]\n[ \"S3cr3t\", \"tok\" ]\n[ok section.1:/x-y_z]\n", []string{"a"}, "[ok section.1:/x-y_z]\n", 0, true},
		{"reviewer: text after a closing tag", "</VirtualHost> S3cr3t\n</VirtualHost>\n", []string{"a"}, "</VirtualHost>\n", 0, true},
		{"a header over 128 bytes is not one", "[" + strings.Repeat("a.", 64) + "a]\n[" + strings.Repeat("a.", 64) + "]\n", []string{"x"}, "[" + strings.Repeat("a.", 64) + "]\n", 0, true},
		{"{ after a kept line is structure", "server\n\n# c\n{\nlisten 1\n}\n", []string{"server", "listen"}, "server\n\n{\nlisten 1\n}\n", 0, true},
		{"{ after a dropped line drops its block", "password\n{\nlisten S3cr3t\n}\nlisten 2\n", []string{"listen"}, "listen 2\n", 0, true},
		{"{ after structure drops its block", "[s]\n{\nlisten S3cr3t\n}\n", []string{"listen"}, "[s]\n", 0, true},

		// Dropped blocks.
		{"reviewer: krb5 REALM = { inside [libdefaults]",
			"[libdefaults]\n permitted_enctypes = aes256\n EXAMPLE.COM = {\n  permitted_enctypes = des\n  pkinit_identities = PKCS11:S3cr3t\n }\n default_tkt_enctypes = x\n",
			[]string{"permitted_enctypes", "default_tkt_enctypes", "pkinit_identities"},
			"[libdefaults]\n permitted_enctypes = aes256\n default_tkt_enctypes = x\n", 0, true},
		{"nested dropped braces", "a {\n b {\n  c 1\n }\n # }\n c S3cr3t\n} else {\n c S3cr3t2\n}\nc ok\n", []string{"c"}, "c ok\n", 0, true},
		{"an unclosed dropped block drops the rest", "x {\nc S3cr3t\n", []string{"c"}, "", 0, true},
		{"a dropped tag drops through its match", "<Directory />\n  AuthPass S3cr3t\n  <directory /x>\n  </Directory>\n  SSLProtocol S3cr3t\n</DIRECTORY>\nSSLProtocol y\n",
			[]string{"sslprotocol"}, "SSLProtocol y\n", 0, true},
		{"a kept tag is a word", "<VirtualHost *:443>\nSSLCertificateFile /a\nSSLPassPhraseDialog exec:/x\n</VirtualHost>\n", []string{"virtualhost", "sslcertificatefile"},
			"<VirtualHost *:443>\nSSLCertificateFile /a\n</VirtualHost>\n", 0, true},
		{"reviewer: apache", "<VirtualHost *:443>\n  SSLEngine on\n  SSLCertificateKeyFile /k\n  SSLCipherSuite HIGH\n  SetEnv DB_PASS S3cr3t-1\n</VirtualHost> S3cr3t-2\n</IfModule>\n<Directory />\n  AuthPass S3cr3t-3\n</Directory>\n",
			[]string{"virtualhost", "sslengine", "sslcertificatekeyfile", "sslciphersuite", "ifmodule"},
			"<VirtualHost *:443>\n  SSLEngine on\n  SSLCertificateKeyFile /k\n  SSLCipherSuite HIGH\n</IfModule>\n", 0, true},

		// No continuation without an option.
		{"reviewer: win.ini CertPath=C:\\certs\\ without @backslash", "[Certs]\nCertPath=C:\\certs\\\nPassword=S3cr3t-1\nCipherList=HIGH\n", []string{"certpath", "cipherlist"},
			"[Certs]\nCertPath=C:\\certs\\\nCipherList=HIGH\n", 0, true},
		{"reviewer: a kept word without ; and 5,000 secret lines, line mode", "ssl_protocols TLSv1.2\n" + secretLines(5000), []string{"ssl_protocols"}, "ssl_protocols TLSv1.2\n", 0, true},

		// @backslash.
		{"backslash continues", "Ciphers a,\\\n  b,\\\n  c\nPasswordX y\n", []string{"ciphers", bs}, "Ciphers a,\\\n  b,\\\n  c\n", 0, true},
		{"backslash without the option", "Ciphers a,\\\n  b\n", []string{"ciphers"}, "Ciphers a,\\\n", 0, true},
		{"reviewer: trustStore=C:\\\\certs\\\\ (even) does not continue", "javax.net.ssl.trustStore=C:\\\\certs\\\\\njavax.net.ssl.trustStorePassword=S3cr3t-2\n",
			[]string{"javax.net.ssl.truststore", bs, cr}, "javax.net.ssl.trustStore=C:\\\\certs\\\\\n", 0, true},
		{"three backslashes continue", "a x\\\\\\\nb\n", []string{"a", bs}, "a x\\\\\\\nb\n", 0, true},
		{"a blank after the backslash ends it", "a x\\ \nS3cr3t\n", []string{"a", bs}, "a x\\ \n", 0, true},
		{"a dropped line does not continue", "password = \\\nciphers x\n", []string{"ciphers", bs}, "ciphers x\n", 0, true},
		{"a # line inside a continuation is dropped", "a 1\\\n# S3cr3t \\\nb 2\nc 3\n", []string{"a", bs}, "a 1\\\nb 2\n", 0, true},
		{"a ! line inside a continuation is data", "a 1\\\n  !b\n", []string{"a", bs}, "a 1\\\n  !b\n", 0, true},
		{"at most 32 continuation lines", "a 0\\\n" + strings.Repeat("x\\\n", 40) + "end\nb 1\n", []string{"a", "b", bs},
			"a 0\\\n" + strings.Repeat("x\\\n", 32) + "b 1\n", 0, true},
		{"PEM on kept lines dropped", "cert = \\\n-----BEGIN CERTIFICATE-----\\\nMIIB\\\n-----END CERTIFICATE-----\\\nx\n", []string{"cert", bs}, "cert = \\\nx\n", 1, true},

		// @indent.
		{"Postfix continuation", "smtpd_tls_ciphers = high\n  !aNULL\n\n# c\n  # c2\n\t!MD5\nrelay_password = S3cr3t\n  S3cr3t2\nsmtpd_tls_protocols = !SSLv2\n",
			[]string{"smtpd_tls_ciphers", "smtpd_tls_protocols", ind}, "smtpd_tls_ciphers = high\n  !aNULL\n\n\t!MD5\nsmtpd_tls_protocols = !SSLv2\n", 0, true},
		{"an indented first line is a line", "  smtpd_tls_ciphers = x\n  more\n", []string{"smtpd_tls_ciphers", ind}, "  smtpd_tls_ciphers = x\n  more\n", 0, true},
		{"indent without the option", "a = 1\n  more\n", []string{"a"}, "a = 1\n", 0, true},
		{"at most 32 indented continuation lines", "a = 0\n" + strings.Repeat("  x\n", 40) + "b = 1\n", []string{"a", "b", ind}, "a = 0\n" + strings.Repeat("  x\n", 32) + "b = 1\n", 0, true},

		// @statements.
		{"reviewer: a one-line nginx block", "server { listen 443 ssl; ssl_password_file /x; }\n", []string{"server", "listen", st}, "server {\nlisten 443 ssl;\n}\n", 0, true},
		{"statements across lines and comments", "ssl_ciphers A # c S3cr3t\n   B;\n", []string{"ssl_ciphers", st}, "ssl_ciphers A B;\n", 0, true},
		{"quotes hold ; { } #", "add_header X \"a;b{c}#d\";\n", []string{"add_header", st}, "add_header X \"a;b{c}#d\";\n", 0, true},
		{"escaped quote", "ssl_ciphers 'a\\'b' c;\n", []string{"ssl_ciphers", st}, "ssl_ciphers 'a\\'b' c;\n", 0, true},
		{"a line end inside quotes is a blank", "ssl_ciphers \"a\nb\";\n", []string{"ssl_ciphers", st}, "ssl_ciphers \"a b\";\n", 0, true},
		{"a dropped opener drops its block", "location / { ssl_ciphers x; proxy_set_header A S3cr3t; }\nssl_ciphers y;\n", []string{"ssl_ciphers", st}, "ssl_ciphers y;\n", 0, true},
		{"nested kept and dropped", "http {\n server {\n  listen 1;\n  location / {\n   ssl_ciphers S3cr3t;\n   if ($x) { ssl_ciphers S3cr3t2; }\n  }\n }\n}\n",
			[]string{"http", "server", "listen", "ssl_ciphers", st}, "http {\nserver {\nlisten 1;\n}\n}\n", 0, true},
		{"a stray } at the top", "}\nssl_ciphers a;\n", []string{"ssl_ciphers", st}, "}\nssl_ciphers a;\n", 0, true},
		{"} } server {", "http { server { listen 1; } } server { listen 2; }\n", []string{"http", "server", "listen", st}, "http {\nserver {\nlisten 1;\n}\n}\nserver {\nlisten 2;\n}\n", 0, true},
		{"${var}", "set $x ${y}z;\nssl_ciphers a;\n", []string{"set", "ssl_ciphers", st}, "set $x ${y}z;\nssl_ciphers a;\n", 0, true},
		{"# inside a word", "ssl_ciphers a#b;\n", []string{"ssl_ciphers", st}, "ssl_ciphers a#b;\n", 0, true},
		{"# after a quote", "ssl_ciphers \"a\"#c S3cr3t\n b;\n", []string{"ssl_ciphers", st}, "ssl_ciphers \"a\" b;\n", 0, true},
		{"a quote after a word", "ssl_ciphers \"a\"b c\"d\";\n", []string{"ssl_ciphers", st}, "ssl_ciphers \"a\"b c\"d\";\n", 0, true},
		{"an unterminated quote drops the rest", "ssl_ciphers \"abc\nssl_protocols x;\n", []string{"ssl_ciphers", "ssl_protocols", st}, "", 0, true},
		{"reviewer: a kept word without ; and 5,000 secret lines", "ssl_protocols TLSv1.2\n" + secretLines(5000) + "ssl_ciphers a;\nssl_ciphers b;\n",
			[]string{"ssl_protocols", "ssl_ciphers", st}, "ssl_ciphers b;\n", 0, true},
		{"64 lines is the bound", "ssl_ciphers a\n" + strings.Repeat("b\n", 62) + ";\nssl_ciphers x\n" + strings.Repeat("b\n", 63) + ";\n",
			[]string{"ssl_ciphers", st}, "ssl_ciphers a" + strings.Repeat(" b", 62) + ";\n", 0, true},
		{"16 KiB is the bound", "ssl_ciphers " + strings.Repeat("A-", 8180) + ";\nssl_ciphers " + strings.Repeat("A-", 8200) + ";\nssl_protocols x;\n",
			[]string{"ssl_ciphers", "ssl_protocols", st}, "ssl_ciphers " + strings.Repeat("A-", 8180) + ";\nssl_protocols x;\n", 0, true},
		{"an over-long opener drops its block", "server " + strings.Repeat("x ", 9000) + "{ listen S3cr3t; }\nlisten 2;\n", []string{"server", "listen", st}, "listen 2;\n", 0, true},
		{"depth past 64 is dropped", nested(70), []string{"http", "ssl_ciphers", st}, strings.Repeat("http {\n", 64) + strings.Repeat("}\n", 64), 0, true},
		{"a lone CR is a blank in statements", "ssl_ciphers a\rb;\n", []string{"ssl_ciphers", st}, "ssl_ciphers a b;\n", 0, true},
		{"PEM inside a kept statement", "ssl_certificate -----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----;\nssl_ciphers a;\n", []string{"ssl_certificate", "ssl_ciphers", st}, "ssl_ciphers a;\n", 1, true},
		{"a run in a statement", "ssl_ciphers " + q + ";\n", []string{"ssl_ciphers", st}, "ssl_ciphers " + RedactedMarker + ";\n", 1, true},
		{"empty statements", ";;{}\nssl_ciphers a;\n", []string{"ssl_ciphers", st}, "ssl_ciphers a;\n", 0, true},

		// Redaction.
		{"run at 39 kept, 40 redacted", "a " + q[:39] + "\na " + q + "\n", []string{"a"}, "a " + q[:39] + "\na " + RedactedMarker + "\n", 1, true},
		{"latin-1 bytes", "a caf\xe9 \xff\n", []string{"a"}, "a caf\xe9 \xff\n", 0, true},
	}
	for _, tc := range cases {
		out, n, ok := FilterConfigText([]byte(tc.in), tc.keep)
		if ok != tc.ok || (ok && (string(out) != tc.out || n != tc.n)) {
			t.Errorf("%s: got %q (%d, %v), want %q (%d, %v)", tc.name, tgtShort(out), n, ok, tgtShort([]byte(tc.out)), tc.n, tc.ok)
		}
	}
	many := strings.Repeat("a\n", maxConfigLines+1)
	if _, _, st := filterConfig([]byte(many), []string{"a"}); st != configTooManyLines {
		t.Fatalf("line bound: %v", st)
	}
	if _, _, st := filterConfig([]byte(strings.Repeat("a\n", maxConfigLines)), []string{"a"}); st != configOK {
		t.Fatalf("at the line bound: %v", st)
	}
	if _, _, st := filterConfig([]byte(strings.Repeat("a\r", maxConfigLines+1)), []string{"a", KeepOptCR}); st != configTooManyLines {
		t.Fatalf("line bound counts @cr lines: %v", st)
	}
}

// TestPrivateUnderPublicLabel holds the deny rule to real objects of every
// kind and size this test can make: every private key encoding must be
// refused under a public label, every public object must pass, and the rule
// must refuse the whole file.
func TestPrivateUnderPublicLabel(t *testing.T) {
	private, public := fxDenyObjects(t)
	for name, der := range private {
		for _, label := range []string{"CERTIFICATE", "PUBLIC KEY", "EC PARAMETERS", "X509 CRL"} {
			block := pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
			first := strings.Split(string(block), "\n")[1]
			if !privateUnderPublicLabel(first) {
				t.Errorf("%s under %s passes: %.24s", name, label, first)
			}
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: public["certificate tiny"]})
			if out, ok := publicContent(append(cert, block...)); ok {
				t.Errorf("%s under %s: the file was not refused: %q", name, label, tgtShort(out))
			}
		}
	}
	for name, der := range public {
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		first := strings.Split(string(block), "\n")[1]
		if privateUnderPublicLabel(first) {
			t.Errorf("%s refused: %.24s", name, first)
		}
	}
	// OpenSSH under a public label.
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	op, err := ssh.MarshalPrivateKey(edPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	op.Type = "PUBLIC KEY"
	if _, ok := publicContent(pem.EncodeToMemory(op)); ok {
		t.Error("an OpenSSH private key under PUBLIC KEY passes")
	}
	// What still passes, stated: an encrypted PKCS#8 key is SEQUENCE
	// SEQUENCE, like a certificate.
	enc := []byte{0x30, 0x82, 0x01, 0x00, 0x30, 0x57, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d}
	if privateUnderPublicLabel(base64.StdEncoding.EncodeToString(append(enc, make([]byte, 60)...))[:64]) {
		t.Error("the encrypted PKCS#8 prefix is refused; update the comment that says it passes")
	}
}

// fxDenyObjects builds DER of every private key encoding and every public
// object kind, in the sizes that move the outer length form (short, 0x81,
// 0x82).
func fxDenyObjects(t *testing.T) (private, public map[string][]byte) {
	t.Helper()
	fxDenyOnce.Do(func() { fxDenyPriv, fxDenyPub = fxBuildDenyObjects(t) })
	if fxDenyPriv == nil {
		t.Fatal("object generation failed")
	}
	return fxDenyPriv, fxDenyPub
}

var (
	fxDenyOnce            sync.Once
	fxDenyPriv, fxDenyPub map[string][]byte
)

func fxBuildDenyObjects(t *testing.T) (private, public map[string][]byte) {
	private, public = map[string][]byte{}, map[string][]byte{}
	// PKCS#1 of a 512-bit key, built by hand (Go no longer generates one):
	// its outer length is in the one-byte (0x81) form.
	{
		r := func(n int) *big.Int {
			b := make([]byte, n)
			_, _ = rand.Read(b)
			b[0] |= 0x80
			return new(big.Int).SetBytes(b)
		}
		p1, _ := asn1.Marshal([]*big.Int{big.NewInt(0), r(64), big.NewInt(65537), r(64), r(32), r(32), r(32), r(32), r(32)})
		private["PKCS#1 RSA 512"] = p1
	}
	for _, bits := range []int{1024, 2048, 4096} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		private[fmt.Sprintf("PKCS#1 RSA %d", bits)] = x509.MarshalPKCS1PrivateKey(k)
		p8, _ := x509.MarshalPKCS8PrivateKey(k)
		private[fmt.Sprintf("PKCS#8 RSA %d", bits)] = p8
		public[fmt.Sprintf("RSA PUBLIC KEY %d", bits)] = x509.MarshalPKCS1PublicKey(&k.PublicKey)
		spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		public[fmt.Sprintf("SPKI RSA %d", bits)] = spki
		if bits == 4096 {
			public["certificate RSA 4096"] = fxSelfSigned(t, k, &k.PublicKey, 300)
			csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "r"}}, k)
			public["CSR RSA"] = csr
			crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)},
				fxCA(t, k), k)
			if err != nil {
				t.Fatal(err)
			}
			public["CRL"] = crl
		}
	}
	for _, c := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		n := c.Params().Name
		sec1, _ := x509.MarshalECPrivateKey(k)
		private["SEC1 "+n] = sec1
		p8, _ := x509.MarshalPKCS8PrivateKey(k)
		private["PKCS#8 EC "+n] = p8
		spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		public["SPKI EC "+n] = spki
		public["certificate EC "+n] = fxSelfSigned(t, k, &k.PublicKey, 0)
	}
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	p8, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	private["PKCS#8 Ed25519"] = p8
	spki, _ := x509.MarshalPKIXPublicKey(edPub)
	public["SPKI Ed25519"] = spki
	public["certificate tiny"] = fxSelfSigned(t, edPriv, edPub, 0)
	public["certificate huge"] = fxSelfSigned(t, edPriv, edPub, 3000)
	// X25519 PKCS#8, by hand: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING { OCTET STRING key } }.
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := asn1.Marshal(xkey.Bytes())
	x25519, _ := asn1.Marshal(struct {
		V   int
		Alg struct{ OID asn1.ObjectIdentifier }
		Key []byte
	}{0, struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 101, 110}}, inner})
	private["PKCS#8 X25519"] = x25519
	xs, _ := x509.MarshalPKIXPublicKey(xkey.PublicKey())
	public["SPKI X25519"] = xs
	// RFC 5958 v2 (version 1) Ed25519 with its public key.
	v2, _ := asn1.Marshal(struct {
		V   int
		Alg struct{ OID asn1.ObjectIdentifier }
		Key []byte
		Pub asn1.BitString `asn1:"tag:1,optional"`
	}{1, struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 101, 112}}, inner, asn1.BitString{Bytes: edPub, BitLength: 256}})
	private["RFC 5958 v2 Ed25519"] = v2
	// DSA private (OpenSSL's "DSA PRIVATE KEY"): SEQUENCE of six INTEGERs, version 0.
	for _, size := range []int{128, 256, 384} {
		r := func(n int) *big.Int {
			b := make([]byte, n)
			_, _ = rand.Read(b)
			b[0] |= 0x80
			return new(big.Int).SetBytes(b)
		}
		dsa, _ := asn1.Marshal([]*big.Int{big.NewInt(0), r(size), r(20), r(size), r(size), r(20)})
		private[fmt.Sprintf("DSA %d", size*8)] = dsa
	}
	// PKCS#12 (version 3) begins like a private key and is one.
	p12, _ := asn1.Marshal(struct {
		V    int
		Data struct{ OID asn1.ObjectIdentifier }
	}{3, struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}}})
	private["PKCS#12 header"] = append(p12, make([]byte, 40)...)
	// DH parameters (p, g), and EC parameters named and explicit, in each
	// outer length form.
	for _, size := range []int{64, 128, 256} {
		p := make([]byte, size)
		_, _ = rand.Read(p)
		p[0] |= 0x80
		dh, _ := asn1.Marshal(struct{ P, G *big.Int }{new(big.Int).SetBytes(p), big.NewInt(2)})
		public[fmt.Sprintf("DH PARAMETERS %d", size*8)] = dh
	}
	named, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	public["EC PARAMETERS named"] = named
	for _, fieldLen := range []int{14, 32, 66, 200} {
		public[fmt.Sprintf("EC PARAMETERS explicit %d", fieldLen)] = fxExplicitECParams(fieldLen)
	}
	return private, public
}

// fxExplicitECParams is SEC1 ECParameters with an explicit prime field of
// fieldLen bytes: SEQUENCE { INTEGER 1, SEQUENCE { OID prime-field, INTEGER
// p }, SEQUENCE { a, b }, base, order }.
func fxExplicitECParams(fieldLen int) []byte {
	n := func() []byte { b := make([]byte, fieldLen); _, _ = rand.Read(b); return b }
	p := new(big.Int).SetBytes(n())
	der, _ := asn1.Marshal(struct {
		V     int
		Field struct {
			OID asn1.ObjectIdentifier
			P   *big.Int
		}
		Curve struct{ A, B []byte }
		Base  []byte
		Order *big.Int
	}{1, struct {
		OID asn1.ObjectIdentifier
		P   *big.Int
	}{asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}, p}, struct{ A, B []byte }{n(), n()}, append([]byte{4}, append(n(), n()...)...), p})
	return der
}

func fxCA(t *testing.T, k *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCRLSign | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// fxSelfSigned is a certificate with sans DNS names (0 for the smallest).
func fxSelfSigned(t *testing.T, priv, pub any, sans int) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	for i := 0; i < sans; i++ {
		tmpl.DNSNames = append(tmpl.DNSNames, fmt.Sprintf("h%d.example.com", i))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestSSHPublicKeyLines: section E of the third review.
func TestSSHPublicKeyLines(t *testing.T) {
	line := func(k any) string {
		p, err := ssh.NewPublicKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	edLine := line(ed.Public())
	// An 8192-bit modulus (1,025 bytes with its sign byte) fits the bound;
	// generating a real one takes too long for a unit test.
	if _, ok := sshKeyLine("ssh-rsa " + fxRSABlob(1025)); !ok {
		t.Error("an 8192-bit RSA blob is refused")
	}
	for _, bits := range []int{1024, 2048, 4096} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := sshKeyLine(line(&k.PublicKey)); !ok {
			t.Errorf("RSA %d refused", bits)
		}
	}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, _ := ecdsa.GenerateKey(c, rand.Reader)
		if _, ok := sshKeyLine(line(&k.PublicKey)); !ok {
			t.Errorf("ECDSA %s refused", c.Params().Name)
		}
	}
	blob := strings.Fields(edLine)[1]
	rsaBlob := fxRSABlob
	for name, tc := range map[string]struct {
		in, out string
		ok      bool
	}{
		".pub":           {edLine + " alice@example.com", "ssh-ed25519 " + blob, true},
		"tabs":           {"ssh-ed25519\t" + blob + "\tc", "ssh-ed25519 " + blob, true},
		"leading blanks": {"  ssh-ed25519 " + blob, "ssh-ed25519 " + blob, true},
		"options":        {"from=\"10.0.0.1\",no-pty " + edLine + " c", "ssh-ed25519 " + blob, true},
		"options with a quoted blank and an escaped quote": {"command=\"echo \\\"a b\\\" S3cr3t\",from=\"x\" " + edLine, "ssh-ed25519 " + blob, true},
		"a key type inside an option is not the key":       {"command=\"ssh-ed25519 " + blob + "\" garbage", "", false},
		"unterminated quote":                               {"command=\"x " + edLine, "", false},
		"two option fields":                                {"a b " + edLine, "", false},
		"upper-case type":                                  {strings.Replace(edLine, "ssh-ed25519", "SSH-ED25519", 1), "", false},
		"ssh-dss is not listed":                            {"ssh-dss " + rsaBlob(128), "", false},
		"ed25519 one character long":                       {"ssh-ed25519 " + blob + "A", "", false},
		"rsa past 1,400":                                   {"ssh-rsa " + rsaBlob(1100), "", false},
	} {
		got, ok := sshKeyLine(tc.in)
		if ok != tc.ok || got != tc.out {
			t.Errorf("%s: %q %v", name, got, ok)
		}
	}
	for _, kt := range sshKeyTypes {
		if kt.name == "ssh-dss" {
			t.Error("ssh-dss is in the table")
		}
		switch {
		case strings.HasPrefix(kt.name, "sk-") && !strings.Contains(kt.name, "-cert-"):
			if kt.maxLen > 300 {
				t.Errorf("%s: %d", kt.name, kt.maxLen)
			}
		case strings.Contains(kt.name, "-cert-v01@"):
			if kt.maxLen > 4096 {
				t.Errorf("%s: %d", kt.name, kt.maxLen)
			}
		case kt.name == "ssh-rsa":
			if kt.maxLen > 1400 {
				t.Errorf("%s: %d", kt.name, kt.maxLen)
			}
		default:
			if kt.minLen != kt.maxLen {
				t.Errorf("%s: not exact", kt.name)
			}
		}
	}
}

// fxRSABlob is the base64 of an ssh-rsa blob with a modulus of modBytes.
func fxRSABlob(modBytes int) string {
	sstr := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	m := make([]byte, modBytes)
	_, _ = rand.Read(m)
	m[0] = 0x7f
	return base64.StdEncoding.EncodeToString(append(append(sstr([]byte("ssh-rsa")), sstr([]byte{1, 0, 1})...), sstr(m)...))
}

// fxTextCorpus is every configuration text the parity tests run: the
// reviewers' corpora (rebuilt here), the rule table's inputs, and a
// deterministic generated corpus that mixes every construct the rule knows
// about. Nothing is read from disk.
func fxTextCorpus(t *testing.T, generated int) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for k, v := range tgtReviewCorpus(t).text {
		if len(v) < 2<<20 {
			out["review2/"+k] = v
		}
	}
	for k, v := range fxReview3Text() {
		out["review3/"+k] = v
	}
	for i, v := range fxGenerated(generated) {
		out[fmt.Sprintf("gen/%03d", i)] = v
	}
	return out
}

// fxReview3Text is the third review's text corpus (gen3.py), rebuilt.
func fxReview3Text() map[string][]byte {
	S := "S3cr3tMarker"
	rnd := mrand.New(mrand.NewPCG(11, 3))
	rb := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rnd.IntN(256))
		}
		return b
	}
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	var secrets strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&secrets, "secret_line_%d %s-%d\n", i, S, i)
	}
	high := []byte("ssl_ciphers ")
	for c := 2; c < 256; c++ {
		if c != '\n' && c != '\r' {
			high = append(high, byte(c))
		}
	}
	high = append(high, ";\n"...)
	// The race files differ in one line of equal length, which straddles
	// byte 4,096, so a read that takes one page from each version joins a
	// kept word of one to the secret of the other.
	race := func(secret bool) []byte {
		var b strings.Builder
		for b.Len() < 4000 {
			b.WriteString(strings.Repeat("#", 60) + "\n")
		}
		b.WriteString(strings.Repeat("#", 4076-b.Len()-1) + "\n")
		if secret {
			b.WriteString("password    " + S + "-zz-qq-ww-xxxxxxxxxxxx;\n")
		} else {
			b.WriteString("ssl_ciphers HIGH-HIGH-HIGH-aaaaaaaaaaaaaaaaaaa;\n")
		}
		for b.Len() < 8700 {
			b.WriteString("ssl_protocols TLSv1.3;\n")
		}
		return []byte(b.String())
	}
	return map[string][]byte{
		"sshd_config": []byte("# comment " + S + "\nPort 22\nHostKey /etc/ssh/ssh_host_ed25519_key\nCiphers aes256-gcm@openssh.com\nciphers lower-case-ok\nCIPHERSX not-a-keep-word-" + S +
			"\nKexAlgorithms sntrup761x25519-sha512\nMatch User bob\n  PasswordAuthentication yes\n  Ciphers aes128-ctr\nAuthorizedKeysCommandUser x" + S + "\n"),
		"nginx_semi.conf": []byte("server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.2\n     TLSv1.3;\n  ssl_ciphers HIGH:!aNULL\n  auth_basic_user_file /x/" + S + "-1\n  proxy_set_header Authorization \"Basic " + S +
			"-2\"\n  ssl_ecdh_curve X25519;\n  ssl_password_file /etc/p;\n  ssl_ciphers 'A'   # forgot the semicolon\n  password1 " + S + "-3\n  password2 " + S + "-4\n  more " + S + "-5\n}\n"),
		"nginx_unterminated.conf": []byte("ssl_protocols TLSv1.2\n" + secrets.String()),
		"props.properties": []byte("-Djavax.net.ssl.keyStore=/etc/ks.jks\n-Djavax.net.ssl.keyStorePassword=" + S + "-1\njavax.net.ssl.trustStore=C:\\\\certs\\\\\njavax.net.ssl.trustStorePassword=" + S +
			"-2\njdk.tls.disabledAlgorithms=SSLv3, \\\n   RC4, \\\n   " + S + "-3\nkeystore.dir=C:\\\\ks\\\\ \\\\\nkeystore.password=" + S + "-4\n"),
		"win.ini":             []byte("[Certs]\nCertPath=C:\\certs\\\nPassword=" + S + "-1\n[" + S + "-section]\n[ \"" + S + "-2\", \"tok\" ]\nCipherList=HIGH\n"),
		"apache.conf":         []byte("<VirtualHost *:443>\n  SSLEngine on\n  SSLCertificateKeyFile /k\n  SSLCipherSuite HIGH\n  SetEnv DB_PASS " + S + "-1\n</VirtualHost> " + S + "-2\n</IfModule>\n<Directory />\n  AuthPass " + S + "-3\n</Directory>\n"),
		"brace.conf":          []byte("ssl_ciphers HIGH;\n} " + S + "-1\n{ " + S + "-2\n}; " + S + "-3\n};\n  }  \n"),
		"prefix.conf":         []byte("ssl HIGH\nssl_password " + S + "-1\nssl.password=" + S + "-2\nssl:" + S + "-3\nssl=ok\nssl;ok\nSSL{ok\n<ssl>ok\n<ssl_password>" + S + "-4\n-Dssl=ok\n-D ssl " + S + "-5\n"),
		"mixedcase.conf":      []byte("SsL_PrOtOcOlS TLSv1.2;\nSSL_CIPHERS HIGH;\nssl_Ciphers LOW;\n\xef\xac\x80ssl_ciphers " + S + "-1;\nS\xc5\xbfl_ciphers " + S + "-2;\n\xc4\xb0ssl_ciphers " + S + "-3;\n"),
		"nonascii_first.conf": []byte("\xc4ssl_ciphers " + S + "-1;\nssl_ciphers\xa0" + S + "-2;\n\xa0ssl_ciphers ok;\nssl_ciphers\x85" + S + "-3;\nssl_ciphers\x0bok;\nssl_ciphers\x0cok;\n"),
		"crlf.conf":           []byte("ssl_protocols TLSv1.2;\r\npassword " + S + ";\r\nssl_ciphers HIGH\r\n  :LOW;\r\n\r\n"),
		"lonecr.conf":         []byte("ssl_protocols TLSv1.2;\rpassword " + S + ";\rssl_ciphers HIGH\r  :LOW;\r\r"),
		"mixed_eol.conf":      []byte("ssl_protocols a;\r\r\npassword " + S + "\n\rssl_ciphers b;\r\n\n\r\r\nssl_ciphers \\\r\n" + S + "-2 \\\r" + S + "-3\nend\n"),
		"bom.conf":            []byte("\xef\xbb\xbfssl_protocols TLSv1.2;\n\xef\xbb\xbfssl_ciphers x;\npassword " + S + "\n"),
		"bom_only.conf":       []byte("\xef\xbb\xbf"),
		"nonl.conf":           []byte("ssl_protocols TLSv1.2;\nssl_ciphers HIGH"),
		"empty.conf":          {},
		"only_nl.conf":        []byte("\n"),
		"long_line.conf":      []byte("ssl_ciphers " + strings.Repeat("A-B:", 262144) + ";\nssl_protocols " + b64(rb(786432)) + ";\nnext\n"),
		"long_nonkept.conf":   []byte("password " + strings.Repeat("x", 1048576) + "\nssl_ciphers ok;\n"),
		"awk_hostile.conf": []byte("ssl_ciphers back\\slash \\n \\\\ \\0 & && \\& %s %d %n %% %x %*s %1$s;\nssl_ciphers $1 $0 ${x} `id` \"q\" 'sq';\nssl_ciphers &" + b64(rb(45)) +
			"&\\\nssl_ciphers printf(\"%s\\n\", x) sub(/a/,\"&\");\nssl_ciphers \x1b[31m \x7f \x02 \x03;\n"),
		"pem_in_kept.conf": []byte("ssl_ciphers HIGH;\nssl_certificate -----BEGIN CERTIFICATE-----\n" + b64(rb(48)) + "\n-----END CERTIFICATE-----\nssl_ciphers after;\nssl_ciphers -----BEGIN X-----\nssl_ciphers " + S +
			"-1\nssl_ciphers -----END X-----\nssl_ciphers tail;\n"),
		"runs.conf": []byte("ssl_ciphers " + strings.Repeat("A", 39) + ";\nssl_ciphers " + strings.Repeat("A", 40) + ";\nssl_ciphers x=" + b64(rb(45)) + ";\nssl_ciphers " +
			fmt.Sprintf("%x", rb(32)) + ";\nssl_ciphers " + strings.TrimRight(base64.URLEncoding.EncodeToString(rb(32)), "=") + "-_;\n"),
		"nul.conf":             []byte("ssl_ciphers a;\x00\n"),
		"ctl01.conf":           []byte("ssl_ciphers a;\x01\n"),
		"jks_magic.conf":       []byte("\xfe\xed\xfe\xedssl_ciphers a;\n"),
		"sqlite_magic.conf":    []byte("SQLite format 3\x00ssl_ciphers a;\n"),
		"keytab_magic_nl.conf": []byte("\x05\x02\nssl_ciphers a;\n"),
		"keytab_split.conf":    []byte("\x05\nssl_ciphers a;\n"),
		"bom_then_jks.conf":    []byte("\xef\xbb\xbf\xfe\xed\xfe\xedssl_ciphers a;\n"),
		"utf16_nonul.conf":     []byte("\xff\xfessl_ciphers a;\r\n"),
		"comments.conf": []byte("  # ssl_ciphers " + S + "-1\n\t; ssl_ciphers " + S + "-2\n!ssl_ciphers " + S + "-3\n// ssl_ciphers " + S + "-4\n/ ssl_ciphers ok\nssl_ciphers \\\n# " + S +
			"-5 continued comment\n"),
		"ws_only.conf":            []byte("   \n\t\t\n \t \nssl_ciphers a;   \n"),
		"trailing_ws_bslash.conf": []byte("ssl_ciphers a \\ \t\n" + S + "-1\nssl_ciphers b \\\\\n" + S + "-2\n"),
		"kubeconfig":              []byte("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: " + b64(rb(600)) + "\n    server: https://k:6443\nusers:\n- name: a\n  user:\n    client-key-data: " + b64(rb(200)) + "\n    token: " + S + "\n"),
		"highbytes.conf":          high,
		"krb5.conf":               []byte("[libdefaults]\n default_tkt_enctypes = aes256\n EXAMPLE.COM = {\n  default_tkt_enctypes = des " + S + "\n }\n[realms]\n R = {\n  kdc = k\n }\n"),
		"race_a.conf":             race(false),
		"race_b.conf":             race(true),
		"lines_200000.conf":       bytes.Repeat([]byte("ssl_ciphers a;\n"), 200000),
		"lines_200001.conf":       bytes.Repeat([]byte("ssl_ciphers a;\n"), 200001),
		"lines_200000_blank.conf": append(bytes.Repeat([]byte("ssl_ciphers a;\n"), 200000), '\n'),
	}
}

// fxGenerated builds n configuration texts from fragments of every construct
// the rule distinguishes, deterministically.
func fxGenerated(n int) [][]byte {
	frags := []string{"ssl_ciphers HIGH", "SSL_Protocols TLSv1.2", "server", "listen 443 ssl", "password S3cr3t", "location / ", "<VirtualHost *:443>",
		"</VirtualHost>", "<Directory /x>", "</directory>", "<Location>", "[section]", "[bad!]", "{", "}", "};", ";", "# comment", "! bang",
		"// slash", "; semi", "\"quoted ; { } # x\"", "'single \\' q'", "\"esc \\\\\" x", "a\\", "b\\\\", "c\\\\\\", "-Djavax.net.ssl.keyStore=/k",
		"@SECLEVEL=2:HIGH", "${var}", "$x{y}", "$z{", "#hash", "\t", "  ", "\r", "\f", "\v", "kept = value", "smtpd_tls_ciphers = high",
		"  !aNULL", "EXAMPLE.COM = {", "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", "-----BEGIN X-----", strings.Repeat("QUJD", 11),
		"\xe9\xff", "=", ":", "ssl_ciphers", "\\", "\"", "'", "{x}", "<", ">", "</", "kept", "KEPT=1", "secret", "if ($a) {", "} else {",
		"ssl_ciphers \"a\nb\";", "\xef\xbb\xbf", "[ok]", "  [ok]  ", "<IfModule x>", "</IfModule>"}
	seps := []string{" ", "", "\t", ";", "{", "}", " # ", "\"", "\\"}
	ends := []string{"\n", "\n", "\n", "\n", "\r\n", "\r", "\r\r\n", "\\\n", "\\\\\n"}
	rnd := mrand.New(mrand.NewPCG(2026, 11))
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		var b strings.Builder
		if rnd.IntN(10) == 0 {
			b.WriteString("\xef\xbb\xbf")
		}
		lines := rnd.IntN(30)
		if rnd.IntN(25) == 0 {
			lines = 70 + rnd.IntN(10) // a statement past the line bound
		}
		for l := 0; l < lines; l++ {
			if rnd.IntN(4) == 0 {
				b.WriteString(strings.Repeat(" ", rnd.IntN(3)) + strings.Repeat("\t", rnd.IntN(2)))
			}
			for f, nf := 0, rnd.IntN(5); f < nf; f++ {
				if f > 0 {
					b.WriteString(seps[rnd.IntN(len(seps))])
				}
				b.WriteString(frags[rnd.IntN(len(frags))])
			}
			if l < lines-1 || rnd.IntN(3) > 0 {
				b.WriteString(ends[rnd.IntN(len(ends))])
			}
		}
		if rnd.IntN(30) == 0 {
			b.WriteString(strings.Repeat("http {\n", 66) + "ssl_ciphers deep;\n" + strings.Repeat("}\n", 66))
		}
		out = append(out, []byte(b.String()))
	}
	return out
}

// fxKeepGen is the keep list of the generated corpus.
var fxKeepGen = []string{"ssl_ciphers", "ssl_protocols", "server", "listen", "kept", "smtpd_tls_ciphers", "virtualhost", "ifmodule", "seclevel",
	"javax.net.ssl.keystore", "a", "b", "c", "x", "http", "if", "location"}

// fxParityKeeps are the keep lists the host programs are compared under:
// each option a product declares, with the realistic, broad and generated
// word lists.
func fxParityKeeps(short bool) map[string][]string {
	opts := map[string][]string{"": nil, "+statements": {KeepOptStatements}, "+java": {KeepOptCR, KeepOptBackslash},
		"+backslash": {KeepOptBackslash}, "+indent": {KeepOptIndent}}
	bases := map[string][]string{"gen": fxKeepGen, "realistic": tgtRealisticKeep}
	if !short {
		bases["broad"] = tgtBroadKeep
	}
	out := map[string][]string{}
	for bn, b := range bases {
		for on, o := range opts {
			out[bn+on] = append(append([]string(nil), b...), o...)
		}
	}
	return out
}

// fxFirstDiff renders the first line where two outputs differ, both
// versions, so a failure on a host nobody is watching explains itself.
func fxFirstDiff(got, want []byte) string {
	g, w := strings.SplitAfter(string(got), "\n"), strings.SplitAfter(string(want), "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("first difference at line %d of %d/%d:\n  host %q\n  go   %q", i+1, len(g), len(w), tgtShort([]byte(gl)), tgtShort([]byte(wl)))
		}
	}
	return "no line differs (the counts or the status do)"
}

// fxSorted returns the keys of m in order.
func fxSorted[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// fxWriteCorpus writes a corpus under dir.
func fxWriteCorpus(t *testing.T, dir string, corpus map[string][]byte) {
	t.Helper()
	for name, b := range corpus {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// fxCheckText compares one host ReadText answer with filterConfig and
// returns a self-explanatory complaint, or "".
func fxCheckText(b []byte, keep []string, got []byte, n int, err error) string {
	want, wn, st := filterConfig(b, keep)
	switch st {
	case configOK:
		if err != nil {
			return fmt.Sprintf("host refused (%v), Go returned %d bytes", err, len(want))
		}
		if !bytes.Equal(got, want) || n != wn {
			return fmt.Sprintf("host %d bytes, %d redactions; Go %d bytes, %d redactions; %s", len(got), n, len(want), wn, fxFirstDiff(got, want))
		}
	case configTooManyLines:
		if !errors.Is(err, ErrFileTooLarge) {
			return fmt.Sprintf("Go: too many lines; host: %v (%d bytes)", err, len(got))
		}
	default:
		if !errors.Is(err, ErrNotPublic) {
			return fmt.Sprintf("Go refused (%v); host: %v (%d bytes)", st, err, len(got))
		}
	}
	return ""
}

// TestFilterAwkParity runs the text corpus through the real readTextScript
// under every awk installed, with every option set, and requires the host's
// answer to equal filterConfig's byte for byte.
func TestFilterAwkParity(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	gen := 400
	if testing.Short() {
		gen = 60
	}
	corpus := fxTextCorpus(t, gen)
	dir := t.TempDir()
	fxWriteCorpus(t, dir, corpus)
	keeps := fxParityKeeps(testing.Short())
	ctx := context.Background()
	for impl, runner := range tgtAwks(t) {
		t.Run(impl, func(t *testing.T) {
			t.Parallel()
			rt := NewRemoteUnixTarget(runner, runtime.GOOS)
			fails := 0
			for _, name := range fxSorted(corpus) {
				b := corpus[name]
				// The big files once, with one option set each, under the slow awks.
				for _, kn := range fxSorted(keeps) {
					if len(b) > 1<<20 && kn != "gen" && kn != "gen+statements" {
						continue
					}
					if testing.Short() && impl == "busybox" && len(b) > 256<<10 {
						continue // busybox awk takes seconds per megabyte
					}
					got, n, err := rt.ReadText(ctx, filepath.Join(dir, filepath.FromSlash(name)), keeps[kn])
					if msg := fxCheckText(b, keeps[kn], got, n, err); msg != "" {
						t.Errorf("%s with %s: %s", name, kn, msg)
						if fails++; fails > 20 {
							t.Fatal("too many differences")
						}
					}
				}
			}
		})
	}
}

// fxFileCorpus is every file the public-content parity tests run: the
// second review's files, the deny objects under public labels, and SSH key
// lines of every type, form and bound.
func fxFileCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	r := tgtReviewCorpus(t)
	for k, v := range r.files {
		out["review2/"+k] = v
	}
	private, public := fxDenyObjects(t)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: public["certificate tiny"]})
	for name, der := range private {
		out["deny/"+strings.ReplaceAll(name, " ", "_")] = append(append([]byte(nil), cert...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	for name, der := range public {
		label := "CERTIFICATE"
		switch {
		case strings.HasPrefix(name, "SPKI"):
			label = "PUBLIC KEY"
		case strings.HasPrefix(name, "RSA PUBLIC"):
			label = "RSA PUBLIC KEY"
		case strings.HasPrefix(name, "DH"):
			label = "DH PARAMETERS"
		case strings.HasPrefix(name, "EC PARAMETERS"):
			label = "EC PARAMETERS"
		case name == "CRL":
			label = "X509 CRL"
		case name == "CSR RSA":
			label = "CERTIFICATE REQUEST"
		}
		out["pass/"+strings.ReplaceAll(name, " ", "_")] = pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	p, _ := ssh.NewPublicKey(ed.Public())
	edLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rp, _ := ssh.NewPublicKey(&rk.PublicKey)
	rsaLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(rp)))
	for name, s := range map[string]string{
		"pub":            edLine + " c\n" + rsaLine + "\n",
		"options":        "from=\"10.0.0.1\",command=\"echo \\\"S3cr3t a\\\"\" " + edLine + " S3cr3t\n",
		"option_payload": "command=\"" + edLine + "\" garbage\n",
		"unterminated":   "command=\"x " + edLine + "\n",
		"crlf_bom":       "\xef\xbb\xbf" + edLine + "\r\n" + rsaLine + "\r\n",
		"upper":          strings.ToUpper(edLine[:11]) + edLine[11:] + "\n",
		"tabs":           strings.ReplaceAll(edLine, " ", "\t") + "\n",
	} {
		out["ssh/"+name] = []byte(s)
	}
	return out
}

// TestPublicAwkParity runs the file corpus through the real readScript and
// identifyScript under every awk installed.
func TestPublicAwkParity(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	corpus := fxFileCorpus(t)
	dir := t.TempDir()
	fxWriteCorpus(t, dir, corpus)
	ctx := context.Background()
	for impl, runner := range tgtAwks(t) {
		t.Run(impl, func(t *testing.T) {
			rt := NewRemoteUnixTarget(runner, runtime.GOOS)
			for _, name := range fxSorted(corpus) {
				b := corpus[name]
				p := filepath.Join(dir, filepath.FromSlash(name))
				want, ok := publicContent(b)
				out, _, exit, _ := runner.Run(ctx, rt.scriptArgv(readScript, p, remoteUnixReadMax))
				if ok != (exit == 0) || (ok && !bytes.Equal(out, want)) {
					t.Errorf("%s: host exit %d, Go ok=%v; %s", name, exit, ok, fxFirstDiff(out, want))
				}
				if strings.HasPrefix(name, "deny/") && (ok || exit == 0) {
					t.Errorf("%s: a private key under a public label was not refused", name)
				}
				in, err := rt.identify(ctx, p)
				if wantIn := inspect(b, int64(len(b))); err != nil || (!wantIn.nul && !reflect.DeepEqual(in, wantIn)) {
					t.Errorf("%s: inspection differs (%v):\nhost %+v\n  go %+v", name, err, in, wantIn)
				}
			}
		})
	}
}

// TestRemoteUnixTornReads is the third review's in-place rewrite: two files
// of the same size, one with a kept line where the other has a secret, written
// over each other in 4,096-byte pieces (dd conv=notrunc) while the host reads.
// Every answer must be exactly the filter of one version or a refusal: never
// a line of one joined to the other. The same for ReadFile with a
// certificate and a same-size private key.
func TestRemoteUnixTornReads(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	reads := 2000
	if testing.Short() {
		reads = 200
	}
	text := fxReview3Text()
	a, b := text["race_a.conf"], text["race_b.conf"]
	certPEM, keyPEM, _, _ := tgtMaterial(t)
	same := append([]byte(nil), keyPEM...)
	for len(same) < len(certPEM) {
		same = append(same, '\n')
	}
	same = same[:len(certPEM)]
	keep := []string{"ssl_ciphers", "ssl_protocols", KeepOptStatements}
	for _, c := range []struct {
		name   string
		x, y   []byte
		accept func([]byte) bool
		read   func(rt *RemoteUnixTarget, p string) ([]byte, error)
	}{
		{"text", a, b, func(out []byte) bool {
			wa, _, _ := FilterConfigText(a, keep)
			wb, _, _ := FilterConfigText(b, keep)
			return bytes.Equal(out, wa) || bytes.Equal(out, wb)
		}, func(rt *RemoteUnixTarget, p string) ([]byte, error) {
			out, _, err := rt.ReadText(context.Background(), p, keep)
			return out, err
		}},
		{"public", certPEM, same, func(out []byte) bool { return bytes.Equal(out, certPEM) },
			func(rt *RemoteUnixTarget, p string) ([]byte, error) { return rt.ReadFile(context.Background(), p) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "swap")
			tgtWrite(t, dir, "swap", c.x, 0o644)
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				f, err := os.OpenFile(p, os.O_WRONLY, 0)
				if err != nil {
					return
				}
				defer func() { _ = f.Close() }()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					src := c.x
					if i%2 == 1 {
						src = c.y
					}
					for off := 0; off < len(src); off += 4096 {
						_, _ = f.WriteAt(src[off:min(off+4096, len(src))], int64(off))
						// dd's gap between its two writes, which is what
						// lets a read take one page of each version.
						time.Sleep(50 * time.Microsecond)
					}
					// Every fifth rewrite pauses, so some reads fall between
					// rewrites and succeed: if every read were refused the
					// test would prove nothing.
					if i%5 == 4 {
						time.Sleep(15 * time.Millisecond)
					}
				}
			}()
			rt := NewRemoteUnixTarget(hostinventory.NewLocalRunner(), runtime.GOOS)
			ok, changed, other, torn := 0, 0, 0, 0
			for i := 0; i < reads; i++ {
				out, err := c.read(rt, p)
				switch {
				case err == nil:
					ok++
					if !c.accept(out) {
						torn++
						if torn <= 3 {
							t.Errorf("read %d returned neither version: %q", i, tgtShort(out))
						}
					}
				case errors.Is(err, errChanged):
					changed++
				default:
					other++
				}
			}
			close(stop)
			wg.Wait()
			t.Logf("%s: ok=%d changed=%d other=%d torn=%d of %d", c.name, ok, changed, other, torn, reads)
			if torn != 0 {
				t.Fatalf("%d torn reads", torn)
			}
			if ok == 0 {
				t.Fatal("no read succeeded: the test proves nothing")
			}
		})
	}
}

// TestReadTextCalledOnlyByReadConfig: configuration reaches a parser only
// through readConfig, so every read carries the parser's own keep list. A
// call of ReadText anywhere else in the package's source fails, except inside
// a Target implementation's own ReadText (a wrapper delegating).
func TestReadTextCalledOnlyByReadConfig(t *testing.T) {
	calls := fxCallersOf(t, "ReadText")
	if len(calls) == 0 {
		t.Fatal("no call of ReadText found: the scan proves nothing")
	}
	for _, c := range calls {
		if c != "collection.readConfig" && !strings.HasSuffix(c, ".ReadText") {
			t.Errorf("ReadText is called from %s", c)
		}
	}
}

// fxCallersOf returns, for every call in the package's non-test source of a
// function or method named name, the function it is made from ("Recv.Func"
// or "Func"; "" outside any function).
func fxCallersOf(t *testing.T, name string) []string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []string
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var cur string
		ast.Inspect(f, func(n ast.Node) bool {
			if fd, ok := n.(*ast.FuncDecl); ok {
				cur = fd.Name.Name
				if fd.Recv != nil && len(fd.Recv.List) == 1 {
					rt := fd.Recv.List[0].Type
					if st, ok := rt.(*ast.StarExpr); ok {
						rt = st.X
					}
					cur = types.ExprString(rt) + "." + cur
				}
			}
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := ""
			switch f := c.Fun.(type) {
			case *ast.Ident:
				callee = f.Name
			case *ast.SelectorExpr:
				callee = f.Sel.Name
			}
			if callee == name {
				out = append(out, cur)
			}
			return true
		})
	}
	return out
}
