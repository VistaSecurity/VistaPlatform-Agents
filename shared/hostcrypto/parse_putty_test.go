package hostcrypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// keyTestPPKLines wraps base64 at 64 characters, as PuTTY writes it.
func keyTestPPKLines(b []byte) []string {
	s := base64.StdEncoding.EncodeToString(b)
	var out []string
	for len(s) > 64 {
		out = append(out, s[:64])
		s = s[64:]
	}
	return append(out, s)
}

// keyTestPPK builds a .ppk with real public lines and, as private lines, the
// key's own secret bytes, so the projection test below has something real to
// look for.
func keyTestPPK(t testing.TB, tk keyTestKey, version int, encrypted bool) []byte {
	t.Helper()
	pub, err := ssh.NewPublicKey(tk.priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	var priv []byte
	for _, s := range keyTestSecrets(t, tk.priv) {
		priv = append(priv, keyTestSSHString(s)...)
	}
	enc := "none"
	if encrypted {
		enc = "aes256-cbc"
	}
	pubLines := keyTestPPKLines(pub.Marshal())
	privLines := keyTestPPKLines(priv)
	var b strings.Builder
	fmt.Fprintf(&b, "PuTTY-User-Key-File-%d: %s\r\n", version, pub.Type())
	fmt.Fprintf(&b, "Encryption: %s\r\n", enc)
	fmt.Fprintf(&b, "Comment: %s\r\n", keyTestComment)
	fmt.Fprintf(&b, "Public-Lines: %d\r\n%s\r\n", len(pubLines), strings.Join(pubLines, "\r\n"))
	if version == 3 && encrypted {
		b.WriteString("Key-Derivation: Argon2id\r\nArgon2-Memory: 8192\r\nArgon2-Passes: 13\r\nArgon2-Parallelism: 1\r\n")
		fmt.Fprintf(&b, "Argon2-Salt: %s\r\n", hex.EncodeToString(keyTestRandom(16)))
	}
	fmt.Fprintf(&b, "Private-Lines: %d\r\n%s\r\n", len(privLines), strings.Join(privLines, "\r\n"))
	fmt.Fprintf(&b, "Private-MAC: %s\r\n", hex.EncodeToString(keyTestRandom(32)))
	return []byte(b.String())
}

func TestParsePuTTYKey(t *testing.T) {
	for _, tk := range keyTestKeys(t) {
		pub, _ := ssh.NewPublicKey(tk.priv.Public())
		for _, v := range []int{2, 3} {
			for _, enc := range []bool{false, true} {
				label := fmt.Sprintf("%s/v%d/encrypted=%v", tk.name, v, enc)
				file := keyTestPPK(t, tk, v, enc)
				k, ok := ParsePuTTYKey(file)
				if !ok {
					t.Fatalf("%s: not recognised", label)
				}
				if k.Format != KeyFormatPuTTY || k.Algorithm != tk.alg || k.SizeBits != tk.bits || k.Curve != tk.curve {
					t.Errorf("%s: %+v", label, k)
				}
				if k.Encrypted == nil || *k.Encrypted != enc {
					t.Errorf("%s: Encrypted %v", label, k.Encrypted)
				}
				want := ""
				switch {
				case enc && v == 3:
					want = "Argon2id (8192 KiB, 13 passes, parallelism 1) + aes256-cbc"
				case enc:
					want = "aes256-cbc"
				}
				if k.Encryption != want {
					t.Errorf("%s: Encryption %q, want %q", label, k.Encryption, want)
				}
				if k.SSHFingerprint != ssh.FingerprintSHA256(pub) || k.PublicKeySHA256 != keyTestSPKIHash(t, tk.priv.Public()) {
					t.Errorf("%s: fingerprints %q / %q", label, k.SSHFingerprint, k.PublicKeySHA256)
				}
				// The private lines carry the real secret bytes here.
				keyAssertNoLeak(t, label, k, keyTestSecrets(t, tk.priv)...)
				if blob, _ := json.Marshal(k); bytes.Contains(blob, []byte(keyTestComment)) {
					t.Errorf("%s: comment kept", label)
				}
			}
		}
	}
}

func TestParsePuTTYKey_Rejects(t *testing.T) {
	keys := keyTestKeys(t)
	good := keyTestPPK(t, keys[5], 3, false)
	for name, b := range map[string][]byte{
		"not putty":     []byte("-----BEGIN RSA PRIVATE KEY-----\n"),
		"version 1":     bytes.Replace(good, []byte("File-3"), []byte("File-1"), 1),
		"no encryption": bytes.Replace(good, []byte("Encryption: none\r\n"), nil, 1),
		"huge lines":    keyTestPublicLinesRE.ReplaceAll(good, []byte("Public-Lines: 99999999\r\n")),
		"short lines":   []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPublic-Lines: 4\nAAAA\n"),
		"truncated":     good[:40],
	} {
		if k, ok := ParsePuTTYKey(b); ok {
			t.Errorf("%s: accepted: %+v", name, k)
		}
	}
	// Unreadable public lines: still a PuTTY key, said so.
	bad := keyTestPublicLinesRE.ReplaceAll(good, []byte("${0}!!!!"))
	if k, ok := ParsePuTTYKey(bad); ok {
		t.Errorf("bad base64 accepted: %+v", k)
	}
	notKey := []byte("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nPublic-Lines: 1\n" + base64.StdEncoding.EncodeToString([]byte("nope")) + "\nPrivate-Lines: 0\n")
	if k, ok := ParsePuTTYKey(notKey); !ok || k.Algorithm != "RSA" || k.Unknown == "" {
		t.Errorf("unparseable public blob: %+v ok=%v", k, ok)
	}
}

var keyTestPublicLinesRE = regexp.MustCompile(`Public-Lines: \d+\r\n`)
