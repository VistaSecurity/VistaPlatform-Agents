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

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
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
	return "PUB " + p.Type() + " " + base64.StdEncoding.EncodeToString(p.Marshal())
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
	for _, k := range jobProbeKeys(t) {
		want := jobSPKIHash(t, k.signer.Public())
		got := jobParseKeyProbe([]byte(jobPubLine(t, k.signer)+"\n"), jobBase)
		if got.PublicKeySHA256 != want || got.Algorithm == "" || got.SizeBits == 0 || got.SSHFingerprint == "" ||
			got.Encrypted == nil || *got.Encrypted || got.Unknown != "" || got.Format != KeyFormatPKCS8 {
			t.Errorf("%s PUB: %+v", k.name, got)
		}
		got = jobParseKeyProbe([]byte(jobSPKILines(t, k.signer.Public())), jobBase)
		if got.PublicKeySHA256 != want || got.Algorithm == "" || got.Encrypted == nil || *got.Encrypted {
			t.Errorf("%s SPKI: %+v", k.name, got)
		}
	}
	if got := jobParseKeyProbe([]byte("ENCRYPTED\n"), jobBase); got.Encrypted == nil || !*got.Encrypted || got.Algorithm != "" {
		t.Errorf("ENCRYPTED: %+v", got)
	}
	for in, want := range map[string]string{
		"DENIED\n": "may not read", "NOTOOL\n": "neither ssh-keygen nor openssl", "FAILED\n": "could not read", "": "could not read",
		"PUB ssh-rsa !!!\n": "could not read", "SPKI\nAAAA\n": "could not read",
	} {
		if got := jobParseKeyProbe([]byte(in), jobBase); !strings.Contains(got.Unknown, want) || got.PublicKeySHA256 != "" {
			t.Errorf("%q: %+v", in, got)
		}
	}
	// A line that names one type and carries another's blob is refused.
	ks := jobProbeKeys(t)
	line := strings.Replace(jobPubLine(t, ks[0].signer), "ssh-rsa", "ssh-ed25519", 1)
	if got := jobParseKeyProbe([]byte(line), jobBase); got.PublicKeySHA256 != "" {
		t.Errorf("mismatched type accepted: %+v", got)
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
			"blob is the key":        "PUB ssh-ed25519 " + b64 + "\n",
			"private key alone":      pemKey,
			"hex as a field":         "PUB " + hexd + " " + b64 + "\n",
		} {
			got := jobParseKeyProbe([]byte(answer), jobBase)
			ksAssertNoSecret(t, k.name+": "+name, got, append(k.secrets, der)...)
		}
	}
}

func TestJobParseKeystoreProbe(t *testing.T) {
	openssl := "I MAC: sha256, Iteration 2048\nI MAC length: 32, salt length: 8\n" +
		"I PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256\nI Certificate bag\nN server\n" +
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
	kc, _ = jobParseKeystoreProbe([]byte(keytool), KeystoreJKS, true)
	if ks := kc.Keystore; ks.Opened != OpenedWithoutPassword || *ks.EntryCount != 2 || ks.DefaultPassword == nil || *ks.DefaultPassword ||
		ks.Entries[0].Alias != "server" || ks.Entries[0].CertificateFingerprint != strings.Repeat("ab", 31)+"cd" ||
		ks.Entries[1].Kind != "certificate" || !strings.Contains(ks.Unknown, "integrity") {
		t.Fatalf("keytool: %+v", ks)
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
	inner *hostinventory.LocalRunner
	mu    sync.Mutex
	out   []byte
}

func (r *jobRecRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	o, e, x, err := r.inner.Run(ctx, argv)
	r.mu.Lock()
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

// The key probe against the real ssh-keygen and openssl of this machine:
// every byte the tools printed holds no run of the key's private bytes, and
// what was kept is the key's real public description.
func TestJobKeyProbeRealTools(t *testing.T) {
	jobNeedTools(t, "ssh-keygen", "openssl")
	dir := t.TempDir()
	for _, k := range jobProbeKeys(t) {
		der, err := x509.MarshalPKCS8PrivateKey(k.signer)
		if err != nil {
			t.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(k.signer, "")
		if err != nil {
			t.Fatal(err)
		}
		encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(k.signer, "", []byte("job-probe-pass"))
		if err != nil {
			t.Fatal(err)
		}
		want := jobSPKIHash(t, k.signer.Public())
		files := map[string]struct {
			path      string
			encrypted bool
		}{
			"pkcs8":       {jobWrite(t, dir, k.name+".p8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600), false},
			"openssh":     {jobWrite(t, dir, k.name+".ossh", pem.EncodeToMemory(block), 0o600), false},
			"openssh-enc": {jobWrite(t, dir, k.name+".ossh-enc", pem.EncodeToMemory(encBlock), 0o600), true},
			"pkcs8-0644":  {jobWrite(t, dir, k.name+".open", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o644), false},
		}
		if r, ok := k.signer.(*rsa.PrivateKey); ok {
			files["pkcs1"] = struct {
				path      string
				encrypted bool
			}{jobWrite(t, dir, k.name+".p1", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r)}), 0o600), false}
		}
		for name, f := range files {
			rr := &jobRecRunner{inner: hostinventory.NewLocalRunner()}
			got, ok := jobProbeRemoteKey(context.Background(), NewRemoteUnixTarget(rr, runtime.GOOS), f.path, Identity{}, jobBase)
			if !ok {
				t.Fatalf("%s %s: the probe did not run", k.name, name)
			}
			// The private scalars, not the whole encoding: a PKCS#8 key also
			// carries the public key, which the tools rightly print.
			if where := ksFindSecret(string(rr.out), k.secrets...); where != "" {
				t.Fatalf("%s %s: the tools printed private material: %s", k.name, name, where)
			}
			ksAssertNoSecret(t, k.name+" "+name, got, k.secrets...)
			if f.encrypted {
				if got.Encrypted == nil || !*got.Encrypted || got.PublicKeySHA256 != "" {
					t.Errorf("%s %s: %+v", k.name, name, got)
				}
				continue
			}
			if got.PublicKeySHA256 != want || got.Algorithm == "" || got.SizeBits == 0 || got.Encrypted == nil || *got.Encrypted {
				t.Errorf("%s %s: %+v (tools said %q)", k.name, name, got, rr.out)
			}
		}
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
	mk := func(name, pass string) string {
		out := filepath.Join(dir, name)
		cmd := exec.Command("openssl", "pkcs12", "-export", "-inkey", kp, "-in", cp, "-name", "server", "-passout", "pass:"+pass, "-out", out)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building the fixture: %v %s", err, b)
		}
		return out
	}
	open, locked := mk("open.p12", ""), mk("changeit.p12", "changeit")
	run := func(path string, tries bool) (KeystoreContents, []byte) {
		rr := &jobRecRunner{inner: hostinventory.NewLocalRunner()}
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
	if !strings.Contains(kc.Keystore.Entries[0].Alias+kc.Keystore.Entries[1].Alias, "server") {
		t.Errorf("friendly name not read: %+v", kc.Keystore.Entries)
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
	rep, err := Collect(context.Background(), NewRemoteUnixTarget(hostinventory.NewLocalRunner(), runtime.GOOS),
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
