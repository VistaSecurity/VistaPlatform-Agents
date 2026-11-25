package hostcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const keyTestComment = "alice.person@example.com"

func keyTestOpenSSH(t testing.TB, tk keyTestKey, passphrase string) []byte {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(tk.priv, keyTestComment)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(tk.priv, keyTestComment, []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestParseOpenSSHPrivateKey(t *testing.T) {
	t.Parallel() // real tools or long loops: overlapped with the other slow tests
	for _, tk := range keyTestKeys(t) {
		sshPub, err := ssh.NewPublicKey(tk.priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		for _, pass := range []string{"", "correct horse battery"} {
			label := tk.name + "/plain"
			if pass != "" {
				label = tk.name + "/encrypted"
			}
			file := keyTestOpenSSH(t, tk, pass)
			pc := ParsePEMFile(file, PEMLimits{})
			if len(pc.PrivateKeys) != 1 || pc.Malformed != 0 {
				t.Fatalf("%s: %d keys, %d malformed", label, len(pc.PrivateKeys), pc.Malformed)
			}
			k := pc.PrivateKeys[0]
			if k.Format != KeyFormatOpenSSH || k.Algorithm != tk.alg || k.SizeBits != tk.bits || k.Curve != tk.curve {
				t.Errorf("%s: %+v", label, k)
			}
			if k.Encrypted == nil || *k.Encrypted != (pass != "") {
				t.Errorf("%s: Encrypted = %v", label, k.Encrypted)
			}
			wantEnc := ""
			if pass != "" {
				wantEnc = "bcrypt (16 rounds) + aes256-ctr"
			}
			if k.Encryption != wantEnc {
				t.Errorf("%s: Encryption = %q, want %q", label, k.Encryption, wantEnc)
			}
			if k.SSHFingerprint != ssh.FingerprintSHA256(sshPub) {
				t.Errorf("%s: fingerprint %q", label, k.SSHFingerprint)
			}
			// Readable from an encrypted key too: the public section is clear.
			if k.PublicKeySHA256 != keyTestSPKIHash(t, tk.priv.Public()) {
				t.Errorf("%s: PublicKeySHA256 %q", label, k.PublicKeySHA256)
			}
			block, _ := pem.Decode(file)
			keyAssertNoLeak(t, label, pc, append(keyTestSecrets(t, tk.priv), []byte(pass), block.Bytes[len(block.Bytes)-64:])...)
			blob, _ := json.Marshal(pc)
			if bytes.Contains(blob, []byte(keyTestComment)) || (pass != "" && bytes.Contains(blob, []byte(pass))) {
				t.Errorf("%s: the comment or passphrase reached the record", label)
			}
		}
	}
}

// keyTestSSHString is the SSH wire string encoding.
func keyTestSSHString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func keyTestSKEd25519(t testing.TB) ssh.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	blob := keyTestSSHString([]byte(ssh.KeyAlgoSKED25519))
	blob = append(blob, keyTestSSHString(pub)...)
	blob = append(blob, keyTestSSHString([]byte("ssh:"))...)
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseOpenSSHPrivateKey_SecurityKey(t *testing.T) {
	sk := keyTestSKEd25519(t)
	container := []byte(keyOpenSSHMagic)
	for _, s := range [][]byte{[]byte("none"), []byte("none"), nil} {
		container = append(container, keyTestSSHString(s)...)
	}
	container = binary.BigEndian.AppendUint32(container, 1)
	container = append(container, keyTestSSHString(sk.Marshal())...)
	container = append(container, keyTestSSHString(keyTestRandom(64))...)
	keys, ok := ParseOpenSSHPrivateKey(container)
	if !ok || len(keys) != 1 {
		t.Fatal("sk container not read")
	}
	k := keys[0]
	if k.Algorithm != "Ed25519" || k.SSHFingerprint != ssh.FingerprintSHA256(sk) || k.PublicKeySHA256 != "" || !strings.Contains(k.Unknown, "security-key") {
		t.Errorf("sk key: %+v", k)
	}
}

// Every length in the container is attacker-controlled. None may cause a
// panic, a read past the end, or an allocation of its size.
func TestParseOpenSSHPrivateKey_HostileLengths(t *testing.T) {
	keys := keyTestKeys(t)
	block, _ := pem.Decode(keyTestOpenSSH(t, keys[5], ""))
	good := block.Bytes
	if _, ok := ParseOpenSSHPrivateKey(good); !ok {
		t.Fatal("the good container does not parse")
	}
	huge := []byte{0xff, 0xff, 0xff, 0xf0}
	off := len(keyOpenSSHMagic)
	var cases = map[string][]byte{
		"cipher length":    append(append(append([]byte{}, good[:off]...), huge...), good[off+4:]...),
		"truncated":        good[:off+6],
		"magic only":       []byte(keyOpenSSHMagic),
		"wrong magic":      append([]byte("openssh-key-v2\x00"), good[off:]...),
		"zero keys":        keyTestContainer("none", "none", nil, 0, nil),
		"million keys":     keyTestContainer("none", "none", nil, 1_000_000, nil),
		"key length huge":  append(keyTestContainer("none", "none", nil, 1, nil), huge...),
		"bcrypt opts bad":  keyTestContainer("aes256-ctr", "bcrypt", []byte{0, 0, 0, 200}, 1, [][]byte{keys[5].sshBlob(t)}),
		"bad public blob":  keyTestContainer("none", "none", nil, 1, [][]byte{[]byte("not a key")}),
		"name not a name":  keyTestContainer("aes\n256 <script>", "none", nil, 1, [][]byte{keys[5].sshBlob(t)}),
		"each prefix cut":  nil,
		"length of length": append(keyTestContainer("none", "none", nil, 1, nil), 0, 0),
	}
	for name, in := range cases {
		if name == "each prefix cut" {
			for i := range good {
				_, _ = ParseOpenSSHPrivateKey(good[:i])
			}
			continue
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		got, ok := ParseOpenSSHPrivateKey(in)
		runtime.ReadMemStats(&after)
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
			t.Errorf("%s: allocated %d bytes", name, grew)
		}
		switch name {
		case "bad public blob":
			if !ok || len(got) != 1 || got[0].Unknown == "" || got[0].Algorithm != "" {
				t.Errorf("%s: %+v", name, got)
			}
		case "bcrypt opts bad":
			if !ok || len(got) != 1 || got[0].Encryption != "bcrypt + aes256-ctr" {
				t.Errorf("%s: %+v", name, got)
			}
		case "name not a name":
			if !ok || len(got) != 1 || got[0].Encryption != "none + unrecognised" {
				t.Errorf("%s: %+v", name, got)
			}
		default:
			if ok {
				t.Errorf("%s: accepted", name)
			}
		}
	}
}

func (tk keyTestKey) sshBlob(t testing.TB) []byte {
	p, err := ssh.NewPublicKey(tk.priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return p.Marshal()
}

func keyTestContainer(cipher, kdf string, kdfOpts []byte, n uint32, pubs [][]byte) []byte {
	b := []byte(keyOpenSSHMagic)
	b = append(b, keyTestSSHString([]byte(cipher))...)
	b = append(b, keyTestSSHString([]byte(kdf))...)
	b = append(b, keyTestSSHString(kdfOpts)...)
	b = binary.BigEndian.AppendUint32(b, n)
	for _, p := range pubs {
		b = append(b, keyTestSSHString(p)...)
	}
	return b
}

func keyTestAuthorizedLine(t testing.TB, pub ssh.PublicKey, opts, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if opts != "" {
		line = opts + " " + line
	}
	if comment != "" {
		line += " " + comment
	}
	return line
}

func TestParseAuthorizedKeys(t *testing.T) {
	keys := keyTestKeys(t)
	pub := func(i int) ssh.PublicKey {
		p, err := ssh.NewPublicKey(keys[i].priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	sk := keyTestSKEd25519(t)
	file := strings.Join([]string{
		"# managed by someone",
		keyTestAuthorizedLine(t, pub(5), "", keyTestComment),
		keyTestAuthorizedLine(t, pub(0), `from="10.0.0.0/8",no-pty`, "bob@example.org"),
		keyTestAuthorizedLine(t, pub(2), `cert-authority,principals="carol@example.net"`, ""),
		keyTestAuthorizedLine(t, pub(3), `environment="WHO=dave@example.net"`, "dave"),
		"",
		"this line is not a key",
		keyTestAuthorizedLine(t, sk, "restrict", "yubikey"),
		keyTestAuthorizedLine(t, pub(1), `Command="/bin/backup"`, "") + "\r",
	}, "\n")

	got, malformed, truncated := ParseAuthorizedKeys([]byte(file), 0)
	if len(got) != 6 || malformed != 1 || truncated {
		t.Fatalf("got %d keys, %d malformed: %+v", len(got), malformed, got)
	}
	want := []struct {
		alg        string
		bits       int
		restricted bool
		ca         bool
	}{
		{"ssh-ed25519", 256, false, false},
		{"ssh-rsa", 2048, true, false},
		{"ecdsa-sha2-nistp256", 256, true, true},
		{"ecdsa-sha2-nistp384", 384, false, false},
		{"sk-ssh-ed25519@openssh.com", 256, true, false},
		{"ssh-rsa", 3072, true, false},
	}
	for i, w := range want {
		g := got[i]
		if g.Algorithm != w.alg || g.SizeBits != w.bits || g.Restricted == nil || *g.Restricted != w.restricted || g.CertificateAuthority == nil || *g.CertificateAuthority != w.ca {
			t.Errorf("line %d: got %+v (restricted %v), want %+v", i, g, g.Restricted, w)
		}
		if !strings.HasPrefix(g.Fingerprint, "SHA256:") {
			t.Errorf("line %d: fingerprint %q", i, g.Fingerprint)
		}
	}
	blob, _ := json.Marshal(got)
	for _, private := range []string{keyTestComment, "bob@example.org", "carol", "dave", "10.0.0.0", "/bin/backup", "yubikey", "managed"} {
		if bytes.Contains(blob, []byte(private)) {
			t.Errorf("%q from a comment or option reached the record: %s", private, blob)
		}
	}

	if got, _, truncated := ParseAuthorizedKeys([]byte(file), 2); len(got) != 2 || !truncated {
		t.Errorf("max 2 gave %d keys, truncated %v", len(got), truncated)
	}
	if got, _, truncated := ParseAuthorizedKeys([]byte(file), 6); len(got) != 6 || truncated {
		t.Errorf("max exactly 6 gave %d keys, truncated %v", len(got), truncated)
	}
	if _, _, truncated := ParseAuthorizedKeys([]byte(file+"\n# trailing comment\n\n"), 6); truncated {
		t.Error("a trailing comment counted as an unread entry")
	}

	// A single pathological line is malformed, not a crash.
	long := bytes.Repeat([]byte("A"), 10<<20)
	if got, bad, _ := ParseAuthorizedKeys(append([]byte("ssh-rsa "), long...), 0); len(got) != 0 || bad != 1 {
		t.Errorf("10 MiB line: %d keys, %d malformed", len(got), bad)
	}
}

func TestParseSSHPublicKeyFile(t *testing.T) {
	keys := keyTestKeys(t)
	p, _ := ssh.NewPublicKey(keys[4].priv.Public())
	got, ok := ParseSSHPublicKeyFile([]byte("\n" + keyTestAuthorizedLine(t, p, "", "root@host.example.com") + "\n"))
	if !ok || got.Algorithm != "ecdsa-sha2-nistp521" || got.SizeBits != 521 || got.Restricted != nil || got.Fingerprint != ssh.FingerprintSHA256(p) {
		t.Errorf("%+v", got)
	}
	if blob, _ := json.Marshal(got); bytes.Contains(blob, []byte("root@")) {
		t.Error("comment kept")
	}
	if _, ok := ParseSSHPublicKeyFile([]byte("ssh-ed25519 not-base64!")); ok {
		t.Error("garbage accepted")
	}
	if _, ok := ParseSSHPublicKeyLine([]byte("# ssh-ed25519 AAAA")); ok {
		t.Error("a comment line accepted")
	}
}

func TestSummariseKnownHosts(t *testing.T) {
	keys := keyTestKeys(t)
	p, _ := ssh.NewPublicKey(keys[5].priv.Public())
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))
	plain := "server.example.com,192.0.2.1 " + line + "\n# comment\n\n@cert-authority *.example.com " + line + "\n"
	if n, hashed := SummariseKnownHosts([]byte(plain)); n != 2 || hashed {
		t.Errorf("plain: %d entries hashed=%v", n, hashed)
	}
	h := "|1|" + base64.StdEncoding.EncodeToString(keyTestRandom(20)) + "|" + base64.StdEncoding.EncodeToString(keyTestRandom(20)) + " " + line
	if n, hashed := SummariseKnownHosts([]byte(plain + h)); n != 3 || !hashed {
		t.Errorf("hashed: %d entries hashed=%v", n, hashed)
	}
	if n, hashed := SummariseKnownHosts([]byte("@revoked " + h)); n != 1 || !hashed {
		t.Errorf("marker + hashed: %d entries hashed=%v", n, hashed)
	}
	if n, hashed := SummariseKnownHosts(nil); n != 0 || hashed {
		t.Error("empty file")
	}
}

func FuzzParseOpenSSH(f *testing.F) {
	for _, tk := range keyTestKeys(f) {
		for _, pass := range []string{"", "pw"} {
			block, _ := pem.Decode(keyTestOpenSSH(f, tk, pass))
			f.Add(block.Bytes)
		}
	}
	f.Add([]byte(keyOpenSSHMagic))
	f.Add(keyTestContainer("none", "none", nil, 3, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, ok := ParseOpenSSHPrivateKey(b)
		if !ok && keys != nil {
			t.Fatal("keys returned with ok=false")
		}
		if _, err := json.Marshal(keys); err != nil {
			t.Fatal(err)
		}
	})
}

// ssh-dss: x/crypto/ssh no longer parses DSA, but hosts still hold such keys. The SSH
// form and the legacy PEM form of one key must agree on the public key hash.
func TestParseOpenSSH_DSAPairsWithPEM(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 1024)
	q, _ := rand.Prime(rand.Reader, 160)
	g, _ := rand.Int(rand.Reader, p)
	x, _ := rand.Int(rand.Reader, q)
	y := new(big.Int).Exp(g, x, p)
	mpint := func(n *big.Int) []byte {
		b := n.Bytes()
		if len(b) > 0 && b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return keyTestSSHString(b)
	}
	blob := keyTestSSHString([]byte("ssh-dss"))
	for _, n := range []*big.Int{p, q, g, y} {
		blob = append(blob, mpint(n)...)
	}
	sum := sha256.Sum256(blob)
	wantFP := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	keys, ok := ParseOpenSSHPrivateKey(append(keyTestContainer("none", "none", nil, 1, [][]byte{blob}), keyTestSSHString(keyTestRandom(32))...))
	if !ok || len(keys) != 1 {
		t.Fatal("DSA container not read")
	}
	legacy, _ := ParsePrivateKeyDER(keyTestMarshal(t, struct{ V, P, Q, G, Y, X *big.Int }{big.NewInt(0), p, q, g, y, x}))
	if keys[0].Algorithm != "DSA" || keys[0].SizeBits != 1024 || keys[0].SSHFingerprint != wantFP || keys[0].PublicKeySHA256 == "" || keys[0].PublicKeySHA256 != legacy.PublicKeySHA256 {
		t.Errorf("ssh %+v, pem hash %q", keys[0], legacy.PublicKeySHA256)
	}
	b64 := base64.StdEncoding.EncodeToString(blob)
	for line, restricted := range map[string]bool{
		"ssh-dss " + b64 + " old@example.com":                                   false,
		`command="echo a, b",no-pty ssh-dss ` + b64:                             true,
		`environment="X=1" ssh-dss ` + b64:                                      false,
		`cert-authority,from="192.0.2.0/24" ssh-dss ` + b64 + " ca@example.com": true,
	} {
		k, ok := ParseSSHPublicKeyLine([]byte(line))
		if !ok || k.Algorithm != "ssh-dss" || k.SizeBits != 1024 || k.Fingerprint != wantFP || k.Restricted == nil || *k.Restricted != restricted {
			t.Errorf("authorized ssh-dss %q: %+v", line, k)
		}
	}
	if k, ok := ParseSSHPublicKeyFile([]byte("ssh-dss " + b64 + " root@host\n")); !ok || k.Algorithm != "ssh-dss" || k.Restricted != nil {
		t.Errorf("ssh-dss .pub: %+v", k)
	}
	if _, ok := ParseSSHPublicKeyLine([]byte("ssh-dss " + base64.StdEncoding.EncodeToString(blob[:20]))); ok {
		t.Error("a truncated ssh-dss blob was accepted")
	}
	trailing := append(append([]byte{}, blob...), 0, 0, 0, 1, 9)
	if _, ok := ParseSSHPublicKeyLine([]byte("ssh-dss " + base64.StdEncoding.EncodeToString(trailing))); ok {
		t.Error("an ssh-dss blob with trailing bytes was accepted")
	}
	// A quoted option that contains " ssh-dss <key> " must not be taken for
	// the key: the real key type here is one nothing knows.
	misleading := `command="echo ssh-dss ` + b64 + ` done" ssh-unknown AAAA`
	if k, ok := ParseSSHPublicKeyLine([]byte(misleading)); ok {
		t.Errorf("the key was read out of a quoted option: %+v", k)
	}
	quotedOK := `command="echo ssh-dss here",no-pty ssh-dss ` + b64
	if k, ok := ParseSSHPublicKeyLine([]byte(quotedOK)); !ok || k.Restricted == nil || !*k.Restricted {
		t.Errorf("quoted option before a real ssh-dss key: %+v ok=%v", k, ok)
	}
}

// An SSH certificate is fingerprinted by the key it certifies, as
// `ssh-keygen -lf` does, in every path.
func TestSSHCertificateFingerprintIsTheCertifiedKey(t *testing.T) {
	keys := keyTestKeys(t)
	userPub, _ := ssh.NewPublicKey(keys[5].priv.Public())
	caSigner, err := ssh.NewSignerFromSigner(keys[2].priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key:             userPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "alice",
		ValidPrincipals: []string{"alice"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	want := ssh.FingerprintSHA256(userPub)
	if want == ssh.FingerprintSHA256(cert) {
		t.Fatal("fixture: certificate and key fingerprints coincide")
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))

	pubFile, ok := ParseSSHPublicKeyFile([]byte(line + " alice@example.com\n"))
	if !ok || pubFile.Fingerprint != want || pubFile.Algorithm != ssh.CertAlgoED25519v01 || pubFile.SizeBits != 256 {
		t.Errorf(".pub: %+v", pubFile)
	}
	auth, ok := ParseSSHPublicKeyLine([]byte(line))
	if !ok || auth.Fingerprint != want {
		t.Errorf("authorized_keys: %+v", auth)
	}
	keysOut, ok := ParseOpenSSHPrivateKey(append(keyTestContainer("none", "none", nil, 1, [][]byte{cert.Marshal()}), keyTestSSHString(keyTestRandom(32))...))
	if !ok || len(keysOut) != 1 || keysOut[0].SSHFingerprint != want || keysOut[0].PublicKeySHA256 != keyTestSPKIHash(t, keys[5].priv.Public()) {
		t.Errorf("container: %+v", keysOut)
	}
}
