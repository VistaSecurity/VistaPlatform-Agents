package hostcrypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"golang.org/x/crypto/ssh"
)

// tgtReview is the reviewer's corpus (review-core-2/gen.py), regenerated in
// the test with fresh keys: nothing of it is committed.
type tgtReview struct {
	text    map[string][]byte
	files   map[string][]byte
	markers [][]byte // strings that must never cross
	secrets [][]byte // raw secrets for the 16-byte projection check
	certPEM []byte
	pubLine []byte
}

var (
	tgtReviewOnce sync.Once
	tgtReviewData tgtReview
)

func tgtReviewCorpus(t *testing.T) tgtReview {
	t.Helper()
	tgtReviewOnce.Do(func() { tgtReviewData = tgtBuildReview(t) })
	if tgtReviewData.text == nil {
		t.Fatal("corpus generation failed")
	}
	return tgtReviewData
}

func tgtBuildReview(t *testing.T) tgtReview {
	rb := func(n int) []byte { return tgtRandom(t, n) }
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(rb(n)) }
	b64u := func(n int) string { return strings.TrimRight(base64.URLEncoding.EncodeToString(rb(n)), "=") }
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "review"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ec.PublicKey, ec)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	rk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshBlock, err := ssh.MarshalPrivateKey(edPriv, "review")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(edPriv.Public())
	spki, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)

	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	rsaKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	idEd := pem.EncodeToMemory(sshBlock)
	idPub := ssh.MarshalAuthorizedKey(sshPub)
	wgpriv := b64(32)
	wrap := func(s string, n int) []byte {
		var parts []string
		for len(s) > n {
			parts = append(parts, s[:n])
			s = s[n:]
		}
		return []byte(strings.Join(append(parts, s), "\n") + "\n")
	}
	hexColon := func(n int) string {
		h := make([]string, n)
		for i, c := range rb(n) {
			h[i] = fmt.Sprintf("%02x", c)
		}
		return strings.Join(h, ":")
	}
	cat := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	S := func(s string) []byte { return []byte(s) }

	odd := "x\n-----BEGIN EC-PRIVATE-KEY-----\n" + b64(48) + "\nshort\n-----END EC-PRIVATE-KEY-----\ny\n" +
		"-----BEGIN private key-----\n" + b64(48) + "\nshrt2\n-----END private key-----\nz\n" +
		"--- BEGIN THREE DASH ---\nshrt3\n" +
		"  -----BEGIN PRIVATE KEY-----  \nindented-short\n-----END PRIVATE KEY-----\nw\n" +
		"inline -----BEGIN OPENSSH PRIVATE KEY----- here\nhidden\n-----END X-----\nv\n" +
		"-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----\nafter-oneline\n" +
		"-----BEGIN CERTIFICATE-----\n" + strings.Repeat("QUJD", 16) + "\nSHORTTAILINSIDECERT\n-----END CERTIFICATE-----\n"
	big := []byte("line " + strings.Repeat("a b c\n", 200000))
	big[len(big)-100] = 0
	high := make([]byte, 0, 512)
	for c := 1; c < 256; c++ {
		if c != '\n' {
			high = append(high, byte(c))
		}
	}
	high = append(high, '\n')
	for i := 0; i < 2; i++ {
		for c := 128; c < 256; c++ {
			high = append(high, byte(c))
		}
	}
	high = append(high, '\n')
	runs := ""
	for _, n := range []int{39, 40, 41} {
		runs += strings.Repeat("A", n) + "\nx=" + b64(60)[:n] + ";\n"
	}
	utf16 := []byte{0xff, 0xfe}
	for _, c := range "\ufeffkey = value\r\n" {
		utf16 = append(utf16, byte(c), byte(c>>8))
	}
	r := tgtReview{
		certPEM: cert,
		pubLine: idPub,
		text: map[string][]byte{
			"wg0.conf":              S("[Interface]\nPrivateKey = " + wgpriv + "\nAddress = 10.0.0.1/24\nListenPort = 51820\n\n[Peer]\nPublicKey = " + b64(32) + "\nPresharedKey = " + b64(32) + "\nAllowedIPs = 0.0.0.0/0\n"),
			"kubeconfig":            S("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: " + base64.StdEncoding.EncodeToString(cert) + "\n    server: https://k:6443\nusers:\n- name: a\n  user:\n    client-certificate-data: " + base64.StdEncoding.EncodeToString(cert) + "\n    client-key-data: " + base64.StdEncoding.EncodeToString(key) + "\n    token: " + b64u(24) + "\n"),
			"pem_priv_plain.conf":   cat(S("before\n"), key, S("after\n"), rsaKey, S("tail\n")),
			"odd_labels.conf":       S(odd),
			"unterminated.conf":     S("keep\n-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\nlast-short\n"),
			"cert_then_secret.conf": cat(cert, S(b64(48)+"\npw = "+hex.EncodeToString(rb(8))+"\n")),
			"crlf.conf":             cat(S("a = 1\r\nkey = "+b64(48)+"\r\n"), []byte(strings.ReplaceAll(string(key), "\n", "\r\n")), S("tail\r\n\r\n")),
			"nonl.conf":             S("line1\nsecret=" + b64(48)),
			"nonl_cr.conf":          S("line1\nlast\r"),
			"only_nl.conf":          S("\n"),
			"empty.conf":            {},
			"cr_mid.conf":           S("a\rb\r\r\n\r\nc\r" + b64(48) + "\rd\n"),
			"long_b64.conf":         S("x=" + b64(786432) + "\nnext\n"),
			"long_nonrun.conf":      S("y=" + strings.Repeat("ab cd-", 180000) + "\n"),
			"long_nonl.conf":        S("z=" + strings.Repeat("Q,w%", 262144)),
			"run_39_40_41.conf":     S(runs),
			"b64url.conf": S("token = " + b64u(20) + "." + b64u(60) + "." + b64u(32) + "\nwg_url = " + b64u(32)[:43] +
				"\nghp = ghp_" + strings.Repeat("Ab9", 12) + "\nstripe = sk_live_" + b64u(18) + "\ndashed = " +
				b64(30)[:30] + "-" + b64(30)[:30] + "-" + b64(30)[:30] + "\n"),
			"hex.conf":         S("k = " + hex.EncodeToString(rb(32)) + "\napi = " + hex.EncodeToString(rb(16)) + "\nmac = " + hexColon(32) + "\nH=" + strings.ToUpper(hex.EncodeToString(rb(20))) + "\n"),
			"utf8.conf":        cat(S("naïve = café ✓ 日本語\né"+b64(45)+"é\nemoji=😀"+b64(45)+"\n"), S("latin1=\xe9\xff\xfe"+b64(45)+"\xa0end\n")),
			"nul_late.conf":    big,
			"tabs.conf":        S("\tkey\t=\t" + b64(48) + "\t\n\t\t\n \t \n"),
			"awk_hostile.conf": S("back\\slash \\n \\\\ \\0 & && \\& %s %d %n %% %x %*s %1$s\n$1 $0 ${x} `id` \"q\" 'sq'\n&" + b64(45) + "&\\\nprintf(\"%s\\n\", x)\nsub(/a/,\"&\")\n"),
			"ssh_like.conf":    cat(idPub, idEd),
			"highbytes.conf":   high,
			"begin_variants.conf": S("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: x\nAAAA\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\nok\n---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"r\"\n" + b64(60)[:60] +
				"\n---- END SSH2 PUBLIC KEY ----\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxx\n-----END PGP PRIVATE KEY BLOCK-----\nend\n"),
			"putty.ppk.conf": S("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: r\nPublic-Lines: 2\n" + b64(48) + "\n" + b64(15) + "\nPrivate-Lines: 1\n" + b64(24) + "\nPrivate-MAC: " + hex.EncodeToString(rb(32)) + "\n"),
			"short_secrets.conf": S("password = hunter2-Secret!\napi_key = " + hex.EncodeToString(rb(16)) + "\naws_access_key_id = AKIA" + strings.Repeat("Q7", 8) +
				"\nwrapped =\n" + string(wrap(b64(96), 32)) + "openssl_text priv:\n    " + hexColon(15) + ":\n    " + hexColon(15) + "\n"),
			"utf16le_bom.conf": utf16,
			"jks_magic.conf":   S("\xfe\xed\xfe\xedtext after magic\n"),
		},
		files: map[string][]byte{
			"cert.pem":                 cert,
			"pub.pem":                  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}),
			"csr.pem":                  tgtCSR(t, ec),
			"id_ed25519.pub":           idPub,
			"cert.der":                 certDER,
			"key.pem":                  key,
			"rsa.key":                  rsaKey,
			"id_ed25519":               idEd,
			"key.der":                  keyDER,
			"mixed.pem":                cat(cert, key),
			"text.conf":                S("hello = world\n"),
			"jks.jks":                  cat(magicJKS, rb(200)),
			"unident.bin":              rb(300),
			"cert_short_secrets.pem":   cat(cert, S("password = hunter2\napi_key = "+hex.EncodeToString(rb(16))+"\n"), wrap(b64(96), 32)),
			"cert_raw_bytes.pem":       cat(cert, []byte(strings.ReplaceAll(string(rb(64)), "\x00", "\x01")), S("\n")),
			"cert_key_b64_wrapped.pem": cat(cert, wrap(base64.StdEncoding.EncodeToString(key), 36)),
			"two_certs.pem":            cat(cert, cert),
			"fake.pub":                 S("ssh-ed25519 " + b64(51) + " c\n"),
			"pub_then_priv.pub":        cat(idPub, S("ssh-ed25519 "+base64.StdEncoding.EncodeToString(idEd)+"\n")),
		},
	}
	r.markers = append(r.markers, []byte(wgpriv))
	for _, k := range [][]byte{key, rsaKey, idEd} {
		for _, l := range strings.Split(string(k), "\n") {
			if !strings.Contains(l, "-----") && len(l) >= 16 {
				r.markers = append(r.markers, []byte(l))
			}
		}
	}
	r.markers = append(r.markers, []byte(base64.StdEncoding.EncodeToString(keyDER)[:40]), []byte(base64.StdEncoding.EncodeToString(key)[8:60]))
	// The private halves only: a PKCS#8 encoding also holds the public point,
	// which the certificate rightly carries.
	ecRaw, err := ec.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	r.secrets = [][]byte{ecRaw, x509.MarshalPKCS1PrivateKey(rk)[len(x509.MarshalPKCS1PrivateKey(rk))-64:], edPriv.Seed()}
	return r
}

func tgtCSR(t *testing.T, k *ecdsa.PrivateKey) []byte {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "r"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func tgtRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// tgtRealisticKeep is what configuration parsers list: names, paths and
// policy, never credentials.
var tgtRealisticKeep = []string{"address", "listenport", "allowedips", "server", "apiversion", "kind",
	"ssl_protocols", "ssl_ciphers", "ciphers", "kexalgorithms", "macs", "hostkey", "protocol", "minprotocol",
	"cipherstring", "jdk.tls.disabledalgorithms", "javax.net.ssl.keystore", "sslprotocol", "sslciphersuite"}

// tgtBroadKeep keeps the secret-bearing lines too, to exercise kept-line
// redaction and continuation in the parity test.
var tgtBroadKeep = append(append([]string(nil), tgtRealisticKeep...), "privatekey", "publickey", "presharedkey", "key",
	"secret", "token", "x", "y", "z", "a", "c", "d", "line1", "last", "keep", "before", "after", "tail", "api", "mac", "h", "k",
	"wrapped", "password", "client-key-data", "certificate-authority-data", "back", "printf", "sub", "emoji", "latin1", "ok", "end", "next", "pw")

// tgtLeaks reports whether any 16-byte window of secret appears in out raw,
// hex-encoded or base64-encoded.
func tgtLeaks(out, secret []byte) bool {
	s := string(out)
	for i := 0; i+16 <= len(secret); i++ {
		w := secret[i : i+16]
		if strings.Contains(s, string(w)) || strings.Contains(strings.ToLower(s), hex.EncodeToString(w)) {
			return true
		}
		for off := 0; off < 3 && i+off+15 <= len(secret); off++ {
			if strings.Contains(s, base64.StdEncoding.EncodeToString(secret[i+off:i+off+15])) {
				return true
			}
		}
	}
	return false
}

func tgtCrossed(out []byte, r tgtReview) string {
	for _, m := range r.markers {
		if strings.Contains(string(out), string(m)) {
			return "marker " + string(m[:8])
		}
	}
	for i, s := range r.secrets {
		if tgtLeaks(out, s) {
			return fmt.Sprintf("secret %d", i)
		}
	}
	return ""
}

// TestFilterConfigTextProjection: with a realistic keep list, nothing of the
// reviewer's secrets corpus survives.
func TestFilterConfigTextProjection(t *testing.T) {
	r := tgtReviewCorpus(t)
	for name, b := range r.text {
		out, _, ok := FilterConfigText(b, tgtRealisticKeep)
		if !ok {
			continue
		}
		if what := tgtCrossed(out, r); what != "" {
			t.Errorf("%s: %s crossed", name, what)
		}
		for _, s := range []string{"hunter2", "PrivateKey", "client-key-data", "ghp_", "sk_live_", "AKIA"} {
			if strings.Contains(string(out), s) {
				t.Errorf("%s: %q survived", name, s)
			}
		}
	}
}

// TestPublicContentRules: the remote ReadFile rule on the reviewer's files.
func TestPublicContentRules(t *testing.T) {
	r := tgtReviewCorpus(t)
	want := map[string]string{
		"cert.pem":                 string(r.certPEM),
		"cert_key_b64_wrapped.pem": string(r.certPEM),
		"cert_raw_bytes.pem":       string(r.certPEM),
		"cert_short_secrets.pem":   string(r.certPEM),
		"two_certs.pem":            string(r.certPEM) + string(r.certPEM),
		"id_ed25519.pub":           strings.Join(strings.Fields(string(r.pubLine))[:2], " ") + "\n",
		"pub_then_priv.pub":        strings.Join(strings.Fields(string(r.pubLine))[:2], " ") + "\n",
	}
	for name, b := range r.files {
		out, ok := publicContent(b)
		w, public := want[name]
		if ok != public || (ok && string(out) != w) {
			t.Errorf("%s: ok=%v out=%q", name, ok, tgtShort(out))
		}
		if what := tgtCrossed(out, r); what != "" {
			t.Errorf("%s: %s in public content", name, what)
		}
	}
	// Body and frame rules.
	cert := string(r.certPEM)
	for name, tc := range map[string]struct {
		in, out string
		ok      bool
	}{
		"bom":             {"\xef\xbb\xbf" + cert, cert, true},
		"crlf":            {strings.ReplaceAll(cert, "\n", "\r\n"), cert, true},
		"long body line":  {"-----BEGIN CERTIFICATE-----\n" + strings.Repeat("Q", 77) + "\n-----END CERTIFICATE-----\n" + cert, cert, true},
		"header in body":  {"-----BEGIN CERTIFICATE-----\nProc-Type: 4\nQQQQ\n-----END CERTIFICATE-----\n", "", false},
		"wrong end":       {"-----BEGIN CERTIFICATE-----\nQQQQ\n-----END X509 CRL-----\n", "", false},
		"unterminated":    {"-----BEGIN CERTIFICATE-----\nQQQQ\n", "", false},
		"private poisons": {cert + "-----BEGIN PRIVATE KEY-----\nQQQQ\n-----END PRIVATE KEY-----\n", "", false},
		"bad begin":       {cert + "-----BEGIN private key-----\n", "", false},
		"nul poisons":     {cert + "\x00", "", false},
		"options and comment dropped": {"from=\"10.0.0.1\" " + strings.TrimSpace(string(r.pubLine)) + " alice@example.com\n",
			strings.Join(strings.Fields(string(r.pubLine))[:2], " ") + "\n", true},
		"blob wrong length": {"ssh-ed25519 " + strings.Fields(string(r.pubLine))[1] + "AAAA\n", "", false},
		"type mismatch":     {"ssh-rsa " + strings.Fields(string(r.pubLine))[1] + "\n", "", false},
	} {
		out, ok := publicContent([]byte(tc.in))
		if ok != tc.ok || string(out) != tc.out {
			t.Errorf("%s: ok=%v out=%q", name, ok, tgtShort(out))
		}
	}
	// The SSH key table's lengths and prefixes are those of real keys.
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, _ := ecdsa.GenerateKey(curve, rand.Reader)
		p, _ := ssh.NewPublicKey(&k.PublicKey)
		if _, ok := sshKeyLine(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))); !ok {
			t.Errorf("genuine %s key line refused", p.Type())
		}
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	p, _ := ssh.NewPublicKey(&rk.PublicKey)
	if _, ok := sshKeyLine(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))); !ok {
		t.Error("genuine RSA key line refused")
	}
}

// tgtPathRunner runs a real runner with a PATH that puts dir first, so the
// awk program can be run by another awk implementation.
type tgtPathRunner struct {
	inner hostinventory.Runner
	path  string
}

func (r tgtPathRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	if len(argv) > 1 && argv[0] == "env" {
		argv = append([]string{"env", "PATH=" + r.path}, argv[1:]...)
	}
	return r.inner.Run(ctx, argv)
}

func (r tgtPathRunner) ReadFile(ctx context.Context, p string) ([]byte, error) {
	return r.inner.ReadFile(ctx, p)
}

// tgtAwks returns the runners to run the parity corpus through: the
// system's awk, and every other awk installed (busybox standing in for the
// BWK awk of macOS when that is absent).
func tgtAwks(t *testing.T) map[string]hostinventory.Runner {
	runners := map[string]hostinventory.Runner{"system awk": hostinventory.NewLocalRunner()}
	// The same binary under several names (nawk and awk are often mawk) is
	// run once.
	seen := map[string]bool{}
	if sys, err := exec.LookPath("awk"); err == nil {
		if r, err := filepath.EvalSymlinks(sys); err == nil {
			seen[r] = true
		}
	}
	for _, impl := range []string{"busybox", "original-awk", "nawk", "gawk", "mawk"} {
		bin, err := exec.LookPath(impl)
		if err != nil {
			continue
		}
		if r, err := filepath.EvalSymlinks(bin); err == nil {
			if seen[r] {
				continue
			}
			seen[r] = true
		}
		dir := t.TempDir()
		if impl == "busybox" {
			if err := os.WriteFile(filepath.Join(dir, "awk"), []byte("#!/bin/sh\nexec "+bin+" awk \"$@\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Symlink(bin, filepath.Join(dir, "awk")); err != nil {
			t.Fatal(err)
		}
		runners[impl] = tgtPathRunner{inner: hostinventory.NewLocalRunner(), path: dir + string(os.PathListSeparator) + os.Getenv("PATH")}
	}
	return runners
}

func tgtShort(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}

// TestRemoteParity runs the real host scripts through LocalRunner, under
// every awk installed, over the reviewer's corpus, and requires the host's
// answers to equal the Go rules byte for byte: ReadText (two keep lists),
// the public read, and the inspection.
func TestRemoteParity(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	r := tgtReviewCorpus(t)
	dir := t.TempDir()
	for name, b := range r.text {
		tgtWrite(t, dir, "text/"+name, b, 0o644)
	}
	for name, b := range r.files {
		tgtWrite(t, dir, "files/"+name, b, 0o644)
	}
	fxSettle()
	ctx := context.Background()
	lt := NewLocalTarget()
	for impl, runner := range tgtAwks(t) {
		rt := NewRemoteUnixTarget(runner, runtime.GOOS)
		t.Run(impl, func(t *testing.T) {
			for name, b := range r.text {
				p := filepath.Join(dir, "text", name)
				for kname, keep := range map[string][]string{"realistic": tgtRealisticKeep, "broad": tgtBroadKeep} {
					got, n, err := rt.ReadText(ctx, p, keep)
					lgot, ln, lerr := lt.ReadText(ctx, p, keep)
					if msg := fxCheckText(b, keep, got, n, err); msg != "" {
						t.Errorf("%s/%s: remote: %s", name, kname, msg)
					}
					if msg := fxCheckText(b, keep, lgot, ln, lerr); msg != "" {
						t.Errorf("%s/%s: local: %s", name, kname, msg)
					}
					if kname == "realistic" {
						if what := tgtCrossed(got, r); what != "" {
							t.Errorf("%s: %s crossed in ReadText", name, what)
						}
					}
				}
			}
			for name, b := range r.files {
				p := filepath.Join(dir, "files", name)
				want, ok := publicContent(b)
				out, _, exit, _ := runner.Run(ctx, rt.scriptArgv(readScript, p, remoteUnixReadMax))
				if ok != (exit == 0) || (ok && string(out) != string(want)) {
					t.Errorf("%s: host public read exit %d %q, Go ok=%v %q", name, exit, tgtShort(out), ok, tgtShort(want))
				}
				if what := tgtCrossed(out, r); what != "" {
					t.Errorf("%s: %s crossed in a public read", name, what)
				}
				got, err := rt.ReadFile(ctx, p)
				if ok && identityFrom(p, inspect(b, int64(len(b)))).Public() {
					if err != nil || string(got) != string(want) {
						t.Errorf("%s: ReadFile = %v %q", name, err, tgtShort(got))
					}
				} else if err == nil {
					t.Errorf("%s: ReadFile succeeded on a file that is not public", name)
				}
				in, err := rt.identify(ctx, p)
				if wantIn := inspect(b, int64(len(b))); err != nil || (!wantIn.nul && !reflect.DeepEqual(in, wantIn)) {
					t.Errorf("%s: inspection differs (%v):\nremote %+v\n    go %+v", name, err, in, wantIn)
				}
			}
		})
	}
}

// TestRemoteReadStructure asserts structurally what the race loops measure:
// the public read and the text read each read the file exactly once, from fd
// 3, into awk, and nothing but awk prints.
func TestRemoteReadStructure(t *testing.T) {
	for name, script := range map[string]string{"read": readScript, "text": readTextScript} {
		body := strings.TrimPrefix(script, readPrelude)
		if strings.Count(body, `head -c "$size" <&3`) != 1 || strings.Count(script, "head -c") != 2 {
			t.Errorf("%s: fd 3 is read other than once", name)
		}
		for _, w := range []string{"cat ", "$F", "\"$p\"", "tail", "repin"} {
			if strings.Contains(body, w) {
				t.Errorf("%s: %q after the prelude", name, w)
			}
		}
		if !strings.Contains(body, "| awk -v mode=") && !strings.Contains(body, "awk -v mode=") {
			t.Errorf("%s: no awk", name)
		}
		// What awk decided is held, the file pinned again, and printed only
		// when the pin is unchanged.
		if !strings.HasSuffix(script, readRepin) || !strings.Contains(body, "out=$(") ||
			strings.Index(readRepin, `if [ "$pin2" != "$pin" ]; then exit 9; fi`) > strings.Index(readRepin, `printf '%s' "$out"`) {
			t.Errorf("%s: the output is not held until the second pin", name)
		}
	}
	for _, mode := range []string{"mode == \"public\"", "mode == \"text\""} {
		i := strings.Index(awkRules, mode)
		j := strings.Index(awkRules[i:], "\n}\n")
		if i < 0 || j < 0 || strings.Contains(awkRules[i:i+j], "print") {
			t.Errorf("%s: prints before END", mode)
		}
	}
}

// TestRemoteUnixSwapRace runs the reviewer's race loops (race.sh) on this
// machine: rename swaps, in-place rewrites and appends, 1,000 reads each.
// No read may be refused AFTER its bytes crossed (Go's recheck), and nothing
// but the certificate may ever be returned.
func TestRemoteUnixSwapRace(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	if testing.Short() {
		t.Skip("3,000 remote reads")
	}
	certPEM, keyPEM, _, _ := tgtMaterial(t)
	for _, mode := range []string{"rename", "inplace", "grow"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			swap := filepath.Join(dir, "swap.pem")
			tgtWrite(t, dir, "swap.pem", certPEM, 0o644)
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					switch mode {
					case "rename":
						content := certPEM
						if i%2 == 1 {
							content = keyPEM
						}
						tmp := filepath.Join(dir, "next.tmp")
						if os.WriteFile(tmp, content, 0o644) == nil {
							_ = os.Rename(tmp, swap)
						}
					case "inplace":
						_ = os.WriteFile(swap, certPEM, 0o644)
						_ = os.WriteFile(swap, keyPEM, 0o644)
					case "grow":
						_ = os.WriteFile(swap, certPEM, 0o644)
						if f, err := os.OpenFile(swap, os.O_APPEND|os.O_WRONLY, 0); err == nil {
							_, _ = f.Write(keyPEM)
							_ = f.Close()
						}
					}
				}
			}()
			rt := NewRemoteUnixTarget(hostinventory.NewLocalRunner(), runtime.GOOS)
			ok, before, after, other := 0, 0, 0, 0
			for i := 0; i < 1000; i++ {
				b, err := rt.ReadFile(context.Background(), swap)
				switch {
				case err == nil:
					ok++
					if string(b) != string(certPEM) {
						t.Errorf("read %d returned something other than the certificate: %q", i, tgtShort(b))
					}
				case strings.Contains(err.Error(), "the host returned more than public content"):
					after++
				case errors.Is(err, ErrNotPublic), errors.Is(err, ErrFileTooLarge), errors.Is(err, ErrNotExist):
					before++
				default:
					other++
				}
			}
			close(stop)
			wg.Wait()
			t.Logf("%s: ok=%d refused-before=%d refused-after-crossing=%d other=%d", mode, ok, before, after, other)
			if after != 0 {
				t.Fatalf("%d reads were refused after their bytes crossed", after)
			}
		})
	}
}

// TestFIFOsNeverHang: a FIFO named like a certificate hung the local target
// forever. Every target must refuse it as not a regular file, quickly.
func TestFIFOsNeverHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs in the Windows file namespace")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo.pem")
	if out, err := exec.Command("mkfifo", fifo).CombinedOutput(); err != nil {
		t.Skipf("mkfifo: %v %s", err, out)
	}
	targets := map[string]Target{"local": NewLocalTarget()}
	if tgtRealToolsAvailable() {
		targets["remote-unix"] = NewRemoteUnixTarget(hostinventory.NewLocalRunner(), runtime.GOOS)
	}
	for name, tg := range targets {
		ops := map[string]func(ctx context.Context) error{
			"Identify": func(ctx context.Context) error { _, err := tg.Identify(ctx, fifo); return err },
			"ReadFile": func(ctx context.Context) error { _, err := tg.ReadFile(ctx, fifo); return err },
			"ReadText": func(ctx context.Context) error { _, _, err := tg.ReadText(ctx, fifo, []string{"a"}); return err },
		}
		for op, f := range ops {
			done := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			go func() { done <- f(ctx) }()
			select {
			case err := <-done:
				if !errors.Is(err, errNotRegular) || errors.Is(err, ErrNotPublic) || errors.Is(err, ErrNotExist) {
					t.Errorf("%s %s: %v, want only errNotRegular", name, op, err)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("%s %s hung on a FIFO", name, op)
			}
			cancel()
		}
		if _, err := tg.Stat(context.Background(), fifo); err != nil {
			t.Errorf("%s Stat of a FIFO: %v", name, err)
		}
		files, _ := tg.List(context.Background(), dir, ListOptions{MaxDepth: 1})
		if len(files) != 0 {
			t.Errorf("%s List returned a FIFO", name)
		}
	}
}

// TestLongPathIsCounted is the reviewer's 4,150-character path: stat cannot
// name it, so it must be counted as unreadable, not dropped.
func TestLongPathIsCounted(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("POSIX tools not available")
	}
	dir := t.TempDir()
	certPEM, _, _, _ := tgtMaterial(t)
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// 21 components of 200 characters: past PATH_MAX (4096 on Linux, 1024 on
	// macOS), built with os.Root, which works relative to an open directory.
	comp := strings.Repeat("L", 200)
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 21; i++ {
		if err := r.Mkdir(comp, 0o755); err != nil {
			t.Skipf("cannot build a deep tree: %v", err)
		}
		next, err := r.OpenRoot(comp)
		_ = r.Close()
		if err != nil {
			t.Skipf("cannot build a deep tree: %v", err)
		}
		r = next
	}
	if err := r.WriteFile("deep.pem", certPEM, 0o644); err != nil {
		t.Skipf("cannot write in the deep tree: %v", err)
	}
	_ = r.Close()
	for name, tg := range map[string]Target{
		"local":       NewLocalTarget(),
		"remote-unix": NewRemoteUnixTarget(hostinventory.NewLocalRunner(), runtime.GOOS),
	} {
		files, err := tg.List(context.Background(), dir, ListOptions{MaxDepth: 30})
		var lerr *ListError
		if !errors.As(err, &lerr) || lerr.Unreadable == 0 {
			t.Errorf("%s: err = %v; the long path vanished silently", name, err)
		}
		if len(files) != 1 {
			t.Errorf("%s: %d files", name, len(files))
		}
	}
}

// TestUTF16AndBOM (review item E).
func TestUTF16AndBOM(t *testing.T) {
	_, keyPEM, _, _ := tgtMaterial(t)
	certPEM, _, _, _ := tgtMaterial(t)
	u16 := func(s string) []byte {
		b := []byte{0xff, 0xfe}
		for _, c := range []byte(s) {
			b = append(b, c, 0)
		}
		return b
	}
	if id := tgtID("/x/k.pem", u16(string(keyPEM))); id.Class != ClassPrivateKey || id.Public() {
		t.Errorf("UTF-16 private key: %q", id.Class)
	}
	if id := tgtID("/x/c.pem", u16(string(certPEM))); id.Public() {
		t.Errorf("UTF-16 certificate is public: %q", id.Class)
	}
	if id := tgtID("/x/c.pem", append([]byte("\xef\xbb\xbf"), certPEM...)); id.Class != ClassCertificate || !id.Public() {
		t.Errorf("UTF-8 BOM certificate: %q", id.Class)
	}
}
