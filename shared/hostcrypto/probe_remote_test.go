package hostcrypto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// The reviewed commands
// ---------------------------------------------------------------------------

// No probe command holds a word that would make a tool print private
// material or take a password in its arguments, and the check fires on each.
func TestJobProbeCommandsCarryNoSecretWords(t *testing.T) {
	for name, cmd := range jobProbeCommands() {
		if w := jobProbeForbidden(cmd); w != "" {
			t.Errorf("%s contains %q", name, w)
		}
	}
	for _, w := range jobProbeForbiddenWords {
		if jobProbeForbidden("x"+w+"y") == "" {
			t.Errorf("the check passes %q", w)
		}
	}
	for _, bad := range []string{"openssl pkey -in f -text", "openssl pkcs12 -in f -nodes", "keytool -list -v -keystore f",
		"keytool -list -keystore f -storepass changeit", "openssl pkcs12 -in f -nocerts -passin pass:changeit"} {
		if jobProbeForbidden(bad) == "" {
			t.Errorf("the check passes %q", bad)
		}
	}
	// Each command carries its public-only options (checked here, where the
	// tools need not exist): ssh-keygen -e (export the public key) and
	// openssl pkey -pubout for keys, openssl pkcs12 -nokeys for keystores.
	cmds := jobProbeCommands()
	for name, want := range map[string][]string{
		"key-probe":      {"ssh-keygen -e -f", "openssl pkey -in \"$1\" -pubout -passin pass:"},
		"keystore-probe": {"-nokeys", "keytool -list -keystore"},
		"win-key-probe":  {"'-e -f \"'"},
	} {
		for _, w := range want {
			if !strings.Contains(cmds[name], w) {
				t.Errorf("%s does not contain its public-only option %q", name, w)
			}
		}
	}
	// No default password is ever text of a command: they go on stdin.
	for _, cmd := range jobProbeCommands() {
		for _, pw := range DefaultKeystorePasswords {
			// "password" is also an ordinary word in an error a script matches.
			if pw != "" && pw != "password" && strings.Contains(cmd, pw) {
				t.Errorf("a default password is in a command: %q", pw)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// The parsers
// ---------------------------------------------------------------------------

type jobProbeKey struct {
	name    string
	signer  crypto.Signer
	secrets [][]byte
}

func jobProbeKeys(t *testing.T) []jobProbeKey {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, d, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return []jobProbeKey{
		{"rsa", r, ksSecretsOf(t, r)},
		{"ecdsa", e, ksSecretsOf(t, e)},
		{"ed25519", d, ksSecretsOf(t, d)},
	}
}

func jobSPKIHash(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func jobPubLine(t *testing.T, s crypto.Signer) string {
	t.Helper()
	p, err := ssh.NewPublicKey(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	return "B " + base64.StdEncoding.EncodeToString(p.Marshal()) + "\nBLOBEND"
}

func jobSPKILines(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	b := base64.StdEncoding.EncodeToString(der)
	var lines []string
	for len(b) > 64 {
		lines = append(lines, b[:64])
		b = b[64:]
	}
	lines = append(lines, b)
	return "SPKI\n" + strings.Join(lines, "\n") + "\nEND\n"
}

var jobBase = PrivateKey{Format: KeyFormatPKCS8, Protection: KeyProtectionFile, Unknown: "markers"}

// Each answer completes the markers' description as it should, and only
// with what a public key gives.
func TestJobParseKeyProbe(t *testing.T) {
	ossh := PrivateKey{Format: KeyFormatOpenSSH, Protection: KeyProtectionFile, Unknown: "markers"}
	for _, k := range jobProbeKeys(t) {
		want := jobSPKIHash(t, k.signer.Public())
		got := jobParseKeyProbe([]byte(jobPubLine(t, k.signer)+"\n"), jobBase)
		if got.PublicKeySHA256 != want || got.Algorithm == "" || got.SizeBits == 0 || got.SSHFingerprint == "" ||
			got.Encrypted == nil || *got.Encrypted || got.Unknown != "" || got.Format != KeyFormatPKCS8 {
			t.Errorf("%s blob: %+v", k.name, got)
		}
		got = jobParseKeyProbe([]byte(jobSPKILines(t, k.signer.Public())), jobBase)
		if got.PublicKeySHA256 != want || got.Algorithm == "" || got.Encrypted == nil || *got.Encrypted {
			t.Errorf("%s SPKI: %+v", k.name, got)
		}
		// An encrypted OpenSSH key: described from its clear public half,
		// and encrypted.
		got = jobParseKeyProbe([]byte("ENC 1\n"+jobPubLine(t, k.signer)+"\n"), ossh)
		if got.PublicKeySHA256 != want || got.Encrypted == nil || !*got.Encrypted {
			t.Errorf("%s encrypted openssh: %+v", k.name, got)
		}
		// An OpenSSH key whose cipher was not read: encrypted unknown.
		if got = jobParseKeyProbe([]byte(jobPubLine(t, k.signer)+"\n"), ossh); got.Encrypted != nil || got.PublicKeySHA256 != want {
			t.Errorf("%s openssh, cipher unknown: %+v", k.name, got)
		}
	}
	if got := jobParseKeyProbe([]byte("ENCRYPTED\n"), jobBase); got.Encrypted == nil || !*got.Encrypted || got.Algorithm != "" {
		t.Errorf("ENCRYPTED: %+v", got)
	}
	for in, want := range map[string]string{
		"DENIED\n": "may not read", "NOTOOL\n": "no ssh-keygen or openssl", "FAILED\n": "cannot read", "": "cannot read",
		"NOTKEY\n": "not a key", "TIMEUP\n": "time bound", "B !!!\nBLOBEND\n": "cannot read", "SPKI\nAAAA\n": "cannot read",
		"B " + base64.StdEncoding.EncodeToString([]byte("not a key blob at all")) + "\nBLOBEND\n": "cannot read",
	} {
		if got := jobParseKeyProbe([]byte(in), jobBase); !strings.Contains(got.Unknown, want) || got.PublicKeySHA256 != "" {
			t.Errorf("%q: %+v", in, got)
		}
	}
	// A batch answer splits at its index lines; an index out of range is
	// ignored, a missing one leaves its path unanswered.
	parts := jobSplitProbeAnswers([]byte("=== 0\nNOTKEY\n=== 2\nDENIED\n=== 9\nFAILED\n"), 3)
	if string(parts[0]) != "NOTKEY\n" || parts[1] != nil || string(parts[2]) != "DENIED\n" {
		t.Errorf("split: %q", parts)
	}
}

// A host that answers with private material, around a valid answer or in
// place of one, gets none of it stored: whatever the fake host returns, the
// parsed key holds no run of the private bytes.
func TestJobKeyProbeStoresNothingPrivate(t *testing.T) {
	for _, k := range jobProbeKeys(t) {
		der, err := x509.MarshalPKCS8PrivateKey(k.signer)
		if err != nil {
			t.Fatal(err)
		}
		pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		b64 := base64.StdEncoding.EncodeToString(der)
		hexd := hex.EncodeToString(k.secrets[0])
		for name, answer := range map[string]string{
			"pem after a valid line": jobPubLine(t, k.signer) + "\n" + pemKey,
			"key DER as SPKI":        "SPKI\n" + b64 + "\nEND\n",
			"hex after SPKI":         jobSPKILines(t, k.signer.Public()) + hexd + "\n",
			"blob is the key":        "B " + b64 + "\nBLOBEND\n",
			"private key alone":      pemKey,
			"hex as a blob":          "B " + hexd + "\nBLOBEND\n",
			"verdict then key":       "ENCRYPTED\n" + pemKey + "\n" + hexd,
		} {
			got := jobParseKeyProbe([]byte(answer), jobBase)
			ksAssertNoSecret(t, k.name+": "+name, got, append(k.secrets, der)...)
		}
	}
}

func TestJobParseKeystoreProbe(t *testing.T) {
	openssl := "I MAC: sha256, Iteration 2048\nI MAC length: 32, salt length: 8\n" +
		"I PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256\nI Certificate bag\n" +
		"I PKCS7 Data\nI Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256\nN server\nCERT\nOPENED empty\n"
	kc, ok := jobParseKeystoreProbe([]byte(openssl), KeystorePKCS12, false)
	ks := kc.Keystore
	if !ok || ks.Opened != OpenedWithoutPassword || ks.EntryCount == nil || *ks.EntryCount != 2 || ks.DefaultPassword != nil ||
		ks.Entries[0].Kind != "certificate" || ks.Entries[0].Alias != "server" || ks.Entries[1].Kind != "private_key" ||
		!strings.Contains(ks.Protection, "MAC: sha256") || !strings.Contains(ks.Protection, "keys PBES2") {
		t.Fatalf("openssl: %+v", ks)
	}
	// LibreSSL's spelling of the same listing.
	libre := "I MAC Iteration 2048\nI PKCS7 Encrypted data: Certificate bag\nI PKCS7 Data\nI Shrouded Keybag: Bag Attributes\nCERT\nOPENED default\n"
	kc, _ = jobParseKeystoreProbe([]byte(libre), KeystorePKCS12, true)
	if ks := kc.Keystore; ks.Opened != OpenedDefaultPassword || ks.DefaultPassword == nil || !*ks.DefaultPassword ||
		*ks.EntryCount != 2 || ks.Protection != "MAC Iteration 2048" {
		t.Fatalf("libressl: %+v", ks)
	}
	keytool := "V 1\nC 2\nE server, Nov 25, 2026, PrivateKeyEntry, \nF " + strings.Repeat("AB:", 31) + "CD\n" +
		"E ca, Nov 25, 2026, trustedCertEntry, \nF " + strings.Repeat("01:", 31) + "02\nOPENED empty\n"
	// The empty password's digest matched on the host: no password needed.
	kc, _ = jobParseKeystoreProbe([]byte(keytool), KeystoreJKS, true)
	if ks := kc.Keystore; ks.Opened != OpenedWithoutPassword || *ks.EntryCount != 2 || ks.DefaultPassword == nil || *ks.DefaultPassword ||
		ks.Entries[0].Alias != "server" || ks.Entries[0].CertificateFingerprint != strings.Repeat("ab", 31)+"cd" ||
		ks.Entries[1].Kind != "certificate" || ks.Unknown != "" {
		t.Fatalf("keytool: %+v", ks)
	}
	// Listed in clear, the digest not the empty password's: not opened, the
	// entries kept.
	listed := strings.Replace(keytool, "OPENED empty", "LISTED", 1)
	for _, tried := range []bool{false, true} {
		kc, _ = jobParseKeystoreProbe([]byte(listed), KeystoreJKS, tried)
		ks := kc.Keystore
		if ks.Opened != OpenedNot || len(ks.Entries) != 2 || *ks.EntryCount != 2 || (ks.DefaultPassword != nil) != tried ||
			(tried && *ks.DefaultPassword) || !strings.Contains(ks.Unknown, "stated in clear") {
			t.Fatalf("keytool listed (tried %v): %+v", tried, ks)
		}
	}
	kc, _ = jobParseKeystoreProbe([]byte(strings.Replace(keytool, "OPENED empty", "LISTED unchecked", 1)), KeystoreJKS, false)
	if ks := kc.Keystore; ks.Opened != OpenedNot || len(ks.Entries) != 2 || !strings.Contains(ks.Unknown, "not checked") {
		t.Fatalf("keytool unchecked: %+v", ks)
	}
	// A random password was accepted too: nothing checks a password. With an
	// encrypted key that is not opened; with nothing encrypted it needs none.
	nocheck := "I MAC: none\nI PKCS7 Data\nI Certificate bag\nI PKCS7 Data\nI Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256\nCERT\nOPENED nocheck\n"
	kc, _ = jobParseKeystoreProbe([]byte(nocheck), KeystorePKCS12, true)
	if ks := kc.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword != nil || kc.DefaultsNotTried != ksNotTriedNoCheck || len(ks.Entries) != 2 {
		t.Fatalf("nocheck with a shrouded key: %q %+v", kc.DefaultsNotTried, ks)
	}
	plain := "I PKCS7 Data\nI Certificate bag\nCERT\nOPENED nocheck\n"
	kc, _ = jobParseKeystoreProbe([]byte(plain), KeystorePKCS12, true)
	if ks := kc.Keystore; ks.Opened != OpenedWithoutPassword || ks.DefaultPassword != nil || kc.DefaultsNotTried != ksNotTriedUnprotected {
		t.Fatalf("nocheck, nothing protected: %q %+v", kc.DefaultsNotTried, ks)
	}
	kc, _ = jobParseKeystoreProbe([]byte(strings.Replace(nocheck, "OPENED nocheck", "LOCKED clear", 1)), KeystorePKCS12, true)
	if ks := kc.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword == nil || *ks.DefaultPassword || len(ks.Entries) != 2 || !strings.Contains(ks.Unknown, "unencrypted parts") {
		t.Fatalf("locked clear: %+v", ks)
	}
	kc, _ = jobParseKeystoreProbe([]byte("LOCKED\n"), KeystorePKCS12, true)
	if ks := kc.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword == nil || *ks.DefaultPassword || len(ks.Entries) != 0 {
		t.Fatalf("locked: %+v", ks)
	}
	for _, in := range []string{"DENIED\n", "NOTOOL\n"} {
		if kc, ok := jobParseKeystoreProbe([]byte(in), KeystoreJKS, false); !ok || kc.Keystore.Unknown == "" || kc.Keystore.Opened != OpenedNot {
			t.Fatalf("%q: %+v", in, kc.Keystore)
		}
	}
	for _, in := range []string{"UNSUPPORTED\n", "", "I MAC: x\n"} {
		if _, ok := jobParseKeystoreProbe([]byte(in), KeystoreJKS, false); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

// Private bytes a host slips into a keystore answer (an alias, a friendly
// name, a protection line) are not stored.
func TestJobKeystoreProbeStoresNothingPrivate(t *testing.T) {
	for _, k := range jobProbeKeys(t) {
		der, _ := x509.MarshalPKCS8PrivateKey(k.signer)
		b64 := base64.StdEncoding.EncodeToString(der)
		hexd := hex.EncodeToString(k.secrets[0])
		answer := "I MAC: sha256 " + hexd + "\nI Shrouded Keybag: " + b64 + "\nN " + hexd + "\nI Certificate bag\nN " + b64 +
			"\nE " + hexd + ", Nov 25, 2026, PrivateKeyEntry, \n-----BEGIN PRIVATE KEY-----\n" + b64 + "\nOPENED empty\n"
		kc, ok := jobParseKeystoreProbe([]byte(answer), KeystorePKCS12, false)
		if !ok {
			t.Fatal("refused")
		}
		ksAssertNoSecret(t, k.name, kc, append(k.secrets, der)...)
	}
}

// ---------------------------------------------------------------------------
// The real tools
// ---------------------------------------------------------------------------

// jobRecRunner is the remote transport, run here, recording every byte the
// "host" returned.
type jobRecRunner struct {
	inner fxRunner
	mu    sync.Mutex
	out   []byte
	calls int
}

func (r *jobRecRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	o, e, x, err := r.inner.Run(ctx, argv)
	r.mu.Lock()
	r.calls++
	r.out = append(append(r.out, o...), e...)
	r.mu.Unlock()
	return o, e, x, err
}

func (r *jobRecRunner) RunInput(ctx context.Context, argv []string, stdin []byte) ([]byte, []byte, int, error) {
	o, e, x, err := r.inner.RunInput(ctx, argv, stdin)
	r.mu.Lock()
	r.out = append(append(r.out, o...), e...)
	r.mu.Unlock()
	return o, e, x, err
}

func (r *jobRecRunner) ReadFile(context.Context, string) ([]byte, error) {
	return nil, ErrNotPublic
}

func jobNeedTools(t *testing.T, tools ...string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX probes run under sh")
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not installed here")
		}
	}
}

func jobWrite(t *testing.T, dir, name string, b []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// jobProbeCollection is a collection over a remote target, for calling the
// probe the way a pass does.
func jobProbeCollection(t Target) *collection {
	return &collection{target: t, report: newReport(Options{})}
}

// jobLibreSSL reports whether this machine's openssl is LibreSSL (macOS),
// which cannot read an Ed25519 PKCS#8 key.
func jobLibreSSL() bool {
	out, _ := exec.Command("openssl", "version").Output()
	return strings.Contains(string(out), "LibreSSL")
}

// The key probe against the real ssh-keygen and openssl of this machine,
// every file in ONE host program: every byte the tools printed holds no run
// of a key's private bytes; what was kept is the key's real public
// description; an encrypted PEM key is decided from its header with no
// tool run; an encrypted OpenSSH key and one others may read are still
// described.
func TestJobKeyProbeRealTools(t *testing.T) {
	jobNeedTools(t, "ssh-keygen", "openssl")
	dir := t.TempDir()
	type want struct {
		hash      string
		encrypted bool
		unknown   bool // nothing public could be read (and the reason says why)
	}
	files := map[string]want{}
	var secrets [][]byte
	for _, k := range jobProbeKeys(t) {
		der, err := x509.MarshalPKCS8PrivateKey(k.signer)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := ssh.MarshalPrivateKey(k.signer, "")
		encBlock, _ := ssh.MarshalPrivateKeyWithPassphrase(k.signer, "", []byte("job-probe-pass"))
		h := jobSPKIHash(t, k.signer.Public())
		secrets = append(secrets, k.secrets...)
		p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		ed8 := k.name == "ed25519"
		files[jobWrite(t, dir, k.name+".p8", p8, 0o600)] = want{h, false, ed8 && jobLibreSSL()}
		files[jobWrite(t, dir, k.name+".p8-0644", p8, 0o644)] = want{h, false, ed8 && jobLibreSSL()}
		files[jobWrite(t, dir, k.name+".ossh", pem.EncodeToMemory(block), 0o600)] = want{h, false, false}
		files[jobWrite(t, dir, k.name+".ossh-0644", pem.EncodeToMemory(block), 0o644)] = want{h, false, false}
		files[jobWrite(t, dir, k.name+".ossh-enc", pem.EncodeToMemory(encBlock), 0o600)] = want{h, true, false}
		if r, ok := k.signer.(*rsa.PrivateKey); ok {
			files[jobWrite(t, dir, k.name+".p1", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r)}), 0o600)] = want{h, false, false}
			//nolint:staticcheck // a legacy encrypted PEM is what the header check is for
			eb, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(r), []byte("job-pass"), x509.PEMCipherAES256)
			if err != nil {
				t.Fatal(err)
			}
			files[jobWrite(t, dir, k.name+".p1-enc", pem.EncodeToMemory(eb), 0o600)] = want{"", true, true}
		}
	}
	files[jobWrite(t, dir, "not-a-key.txt", []byte("hello\n"), 0o600)] = want{"", false, true}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	rr := &jobRecRunner{inner: fxLocalRunner()}
	c := jobProbeCollection(NewRemoteUnixTarget(rr, runtime.GOOS))
	c.jobPrefetchKeyProbes(context.Background(), paths)
	if rr.calls != 1 {
		t.Fatalf("%d host programs for %d files, want one batch", rr.calls, len(paths))
	}
	if where := ksFindSecret(string(rr.out), secrets...); where != "" {
		t.Fatalf("the tools printed private material: %s", where)
	}
	for p, w := range files {
		base := jobBase
		if strings.Contains(p, ".ossh") {
			base.Format = KeyFormatOpenSSH
		}
		got, ok := jobProbeRemoteKey(context.Background(), c, p, Identity{}, base)
		if !ok {
			t.Fatalf("%s: no answer", p)
		}
		ksAssertNoSecret(t, p, got, secrets...)
		name := filepath.Base(p)
		switch {
		case w.unknown:
			if got.PublicKeySHA256 != "" || got.Unknown == "" {
				t.Errorf("%s: %+v", name, got)
			}
		default:
			if got.PublicKeySHA256 != w.hash || got.Algorithm == "" || got.SizeBits == 0 || got.Unknown != "" {
				t.Errorf("%s: %+v", name, got)
			}
		}
		if w.encrypted && (got.Encrypted == nil || !*got.Encrypted) {
			t.Errorf("%s: not reported encrypted: %+v", name, got)
		}
		if !w.encrypted && !w.unknown && (got.Encrypted == nil || *got.Encrypted) {
			t.Errorf("%s: encrypted %v", name, got.Encrypted)
		}
	}
	if rr.calls != 1 {
		t.Fatalf("the prefetched answers were not used: %d host programs", rr.calls)
	}
}

// The keystore probe against the real openssl: a PKCS#12 with no password
// lists; one with "changeit" lists only with the opt-in, the password sent
// on standard input; the bytes the tool printed hold no private run.
func TestJobKeystoreProbeRealOpenSSL(t *testing.T) {
	jobNeedTools(t, "openssl")
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	secrets := ksSecretsOf(t, key)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "probe.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kp := jobWrite(t, dir, "k.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	cp := jobWrite(t, dir, "c.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0o600)
	mk := func(name, pass string, extra ...string) string {
		out := filepath.Join(dir, name)
		cmd := exec.Command("openssl", append([]string{"pkcs12", "-export", "-inkey", kp, "-in", cp, "-name", "server", "-passout", "pass:" + pass, "-out", out}, extra...)...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building the fixture: %v %s", err, b)
		}
		return out
	}
	open, locked := mk("open.p12", ""), mk("changeit.p12", "changeit")
	run := func(path string, tries bool) (KeystoreContents, []byte) {
		rr := &jobRecRunner{inner: fxLocalRunner()}
		kc, ok := jobProbeRemoteKeystore(context.Background(), NewRemoteUnixTarget(rr, runtime.GOOS), path, KeystorePKCS12, tries)
		if !ok {
			t.Fatalf("%s: the probe did not run (%q)", path, rr.out)
		}
		if where := ksFindSecret(string(rr.out), secrets...); where != "" {
			t.Fatalf("%s: openssl printed private material: %s", path, where)
		}
		ksAssertNoSecret(t, path, kc, secrets...)
		return kc, rr.out
	}
	kc, _ := run(open, false)
	if ks := kc.Keystore; ks.Opened != OpenedWithoutPassword || ks.EntryCount == nil || *ks.EntryCount != 2 || ks.Protection == "" {
		t.Fatalf("open: %+v", ks)
	}
	kc, _ = run(locked, false)
	if ks := kc.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword != nil {
		t.Fatalf("locked without the opt-in: %+v", ks)
	}
	kc, _ = run(locked, true)
	if ks := kc.Keystore; ks.Opened != OpenedDefaultPassword || ks.DefaultPassword == nil || !*ks.DefaultPassword || *ks.EntryCount != 2 {
		t.Fatalf("changeit with the opt-in: %+v", ks)
	}
	// With the opt-in, a store with no password is still one that needs
	// none, never "opened by a default"; a real password opens nothing.
	kc, _ = run(open, true)
	if ks := kc.Keystore; ks.Opened != OpenedWithoutPassword || ks.DefaultPassword == nil || *ks.DefaultPassword || *ks.EntryCount != 2 {
		t.Fatalf("empty password with the opt-in: %+v", ks)
	}
	kc, _ = run(mk("real.p12", "Real-Pass-7"), true)
	if ks := kc.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword == nil || *ks.DefaultPassword {
		t.Fatalf("a real password with the opt-in: %+v", ks)
	}
	// The friendly name OpenSSL prints with the certificate is the
	// certificate's, not the key bag's printed before it.
	kc, _ = run(open, false)
	for _, e := range kc.Keystore.Entries {
		if (e.Kind == "certificate") != (e.Alias == "server") {
			t.Errorf("friendly name on the wrong entry: %+v", kc.Keystore.Entries)
		}
	}

	// Files nothing checks a password on: openssl lists them under any
	// password, so a default "opening" one proves nothing.
	bare := mk("bare.p12", "changeit", "-nomac", "-certpbe", "NONE", "-keypbe", "NONE")
	for _, tries := range []bool{false, true} {
		kc, _ = run(bare, tries)
		if ks := kc.Keystore; ks.Opened != OpenedWithoutPassword || ks.DefaultPassword != nil || *ks.EntryCount != 2 {
			t.Fatalf("nothing protected (opt-in %v): %+v", tries, ks)
		}
	}
	shroudedOnly := mk("nomac-shrouded.p12", "Real-Pass-7", "-nomac", "-certpbe", "NONE")
	for _, tries := range []bool{false, true} {
		kc, _ = run(shroudedOnly, tries)
		if ks := kc.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword != nil || len(ks.Entries) != 2 || !strings.Contains(ks.Unknown, "verifies a password") {
			t.Fatalf("no MAC, a shrouded key (opt-in %v): %+v", tries, ks)
		}
	}
	// A MAC under a real password over a clear certificate: not opened, the
	// clear certificate still listed (the MAC unverified, the key not read).
	clearCert := mk("clear-cert.p12", "Real-Pass-7", "-certpbe", "NONE")
	for _, tries := range []bool{false, true} {
		kc, _ = run(clearCert, tries)
		ks := kc.Keystore
		certs := 0
		for _, e := range ks.Entries {
			if e.Kind == "certificate" {
				certs++
			}
		}
		if ks.Opened != OpenedNot || (ks.DefaultPassword != nil) != tries || (tries && *ks.DefaultPassword) || certs != 1 {
			t.Fatalf("a clear certificate under a MAC (opt-in %v): %+v", tries, ks)
		}
	}
}

// TestJobKeystoreProbeRandomIsFresh: every probe gets its own random value.
func TestJobKeystoreProbeRandomIsFresh(t *testing.T) {
	a, b := jobProbeRandom(), jobProbeRandom()
	if a == b || len(a) < 32 {
		t.Fatalf("random values %q %q", a, b)
	}
}

// TestJobKeystoreProbeJKSDigest runs the script's JKS branch on the host
// with a stand-in keytool (none is needed for the digest, which the host's
// own SHA-1 tool computes): a store whose password is empty is opened, one
// under a real password is listed and not opened, one under changeit is
// opened by a default only with the opt-in.
func TestJobKeystoreProbeJKSDigest(t *testing.T) {
	jobNeedTools(t, "od", "head", "tail", "wc")
	if _, err := exec.LookPath("sha1sum"); err != nil {
		if _, err := exec.LookPath("shasum"); err != nil {
			t.Skip("no SHA-1 tool")
		}
	}
	bin := t.TempDir()
	// The stand-in keytool lists one entry without verifying when the
	// password is empty, and otherwise verifies the password against the one
	// the test's file name records ("s-<password>.jks").
	fake := "#!/bin/sh\nread -r pw\nb=$(basename \"$3\" .jks); want=${b#s-}\nif [ -z \"$pw\" ]; then echo '***  WARNING: The integrity of the information stored in your keystore  ***'; echo '* has NOT been verified!'; elif [ \"$pw\" != \"$want\" ]; then echo 'keytool error: java.io.IOException: Keystore was tampered with, or password was incorrect'; exit 1; fi\necho 'Your keystore contains 1 entry'\necho 'ca, Nov 26, 2026, trustedCertEntry, '\n"
	jobWrite(t, bin, "keytool", []byte(fake), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := t.TempDir()
	for _, tc := range []struct {
		password string
		tries    bool
		opened   string
		deflt    *bool
	}{
		{"", false, OpenedWithoutPassword, nil},
		{"", true, OpenedWithoutPassword, boolPtrEmptyPw(false)},
		{"Real-Pass-7", false, OpenedNot, nil},
		{"Real-Pass-7", true, OpenedNot, boolPtrEmptyPw(false)},
		{"changeit", false, OpenedNot, nil},
		{"changeit", true, OpenedDefaultPassword, boolPtrEmptyPw(true)},
	} {
		path := jobWrite(t, dir, "s-"+tc.password+".jks", ksMakeJKSFixture(t, ksMagicJKS, 2, tc.password).store, 0o600)
		rr := &jobRecRunner{inner: fxLocalRunner()}
		kc, ok := jobProbeRemoteKeystore(context.Background(), NewRemoteUnixTarget(rr, runtime.GOOS), path, KeystoreJKS, tc.tries)
		if !ok {
			t.Fatalf("%q: the probe did not run (%q)", tc.password, rr.out)
		}
		ks := kc.Keystore
		if ks.Opened != tc.opened || (ks.DefaultPassword == nil) != (tc.deflt == nil) || (ks.DefaultPassword != nil && *ks.DefaultPassword != *tc.deflt) || len(ks.Entries) != 1 {
			t.Errorf("%q (opt-in %v): %+v (%q)", tc.password, tc.tries, ks, rr.out)
		}
	}
}

// End to end: a remote collection (the remote target over a local
// transport) sweeps generated keys and a keystore, and its report carries
// each key's algorithm, size and public key hash, the encrypted key as
// encrypted, the keystore listed, and no private byte.
func TestJobRemoteCollectionUsesTheProbes(t *testing.T) {
	jobNeedTools(t, "ssh-keygen", "openssl")
	dir := t.TempDir()
	ks := jobProbeKeys(t)
	der, _ := x509.MarshalPKCS8PrivateKey(ks[1].signer)
	jobWrite(t, dir, "server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	enc, _ := ssh.MarshalPrivateKeyWithPassphrase(ks[2].signer, "", []byte("job-pass"))
	jobWrite(t, dir, "id_ed25519", pem.EncodeToMemory(enc), 0o600)
	rep, err := Collect(context.Background(), NewRemoteUnixTarget(fxLocalRunner(), runtime.GOOS),
		Options{Platform: runtime.GOOS, SweepRoots: []string{dir}, MaxDuration: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var ecOK, encOK bool
	for _, k := range rep.PrivateKeys {
		switch k.Location.Path {
		case filepath.Join(dir, "server.key"):
			ecOK = k.Algorithm == "ECDSA" && k.SizeBits == 384 && k.PublicKeySHA256 == jobSPKIHash(t, ks[1].signer.Public())
		case filepath.Join(dir, "id_ed25519"):
			encOK = k.Encrypted != nil && *k.Encrypted
		}
	}
	if !ecOK || !encOK {
		t.Fatalf("probed keys: ec %v encrypted %v: %+v", ecOK, encOK, rep.PrivateKeys)
	}
	b, _, err := ResultPayload(rep, 0)
	if err != nil {
		t.Fatal(err)
	}
	var secrets [][]byte
	for _, k := range ks {
		secrets = append(secrets, k.secrets...)
	}
	jobAssertNoSecret(t, "remote report", b, secrets)
}
