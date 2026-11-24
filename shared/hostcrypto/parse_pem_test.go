package hostcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func keyTestLegacyEncrypted(t testing.TB, label string, der []byte) []byte {
	t.Helper()
	//nolint:staticcheck // legacy PEM encryption is deprecated, and that is exactly what is being tested.
	block, err := x509.EncryptPEMBlock(rand.Reader, label, der, []byte("pw"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestParsePEMFile_Bundle(t *testing.T) {
	keys := keyTestKeys(t)
	rsaKey := keys[0].priv.(*rsa.PrivateKey)
	ecKey := keys[2].priv.(*ecdsa.PrivateKey)
	sec1, _ := x509.MarshalECPrivateKey(ecKey)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(keys[5].priv)
	spki, _ := x509.MarshalPKIXPublicKey(ecKey.Public())
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ecKey)
	if err != nil {
		t.Fatal(err)
	}

	var file bytes.Buffer
	file.WriteString("Bag Attributes\n    friendlyName: whatever\n")
	file.Write(keyTestPEM("CERTIFICATE", keyTestSelfSigned(t, ecKey, "bundle one")))
	file.Write(keyTestPEM("CERTIFICATE", keyTestSelfSigned(t, rsaKey, "bundle two")))
	file.Write(keyTestPEM("EC PARAMETERS", []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}))
	file.Write(keyTestPEM("EC PRIVATE KEY", sec1))
	file.Write(keyTestPEM("PRIVATE KEY", pkcs8))
	encRSA := keyTestLegacyEncrypted(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))
	encEC := keyTestLegacyEncrypted(t, "EC PRIVATE KEY", sec1)
	file.Write(encRSA)
	file.Write(encEC)
	file.Write(keyTestPEM("PUBLIC KEY", spki))
	file.Write(keyTestPEM("RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)))
	file.Write(keyTestPEM("CERTIFICATE REQUEST", csr))
	file.Write(keyTestPEM("X509 CRL", []byte{0x30, 0x00}))
	file.Write(keyTestPEM("DH PARAMETERS", []byte{0x30, 0x00}))
	file.WriteString("-----BEGIN CERTIFICATE-----\n!!!! not base64 !!!!\n-----END CERTIFICATE-----\n")
	file.Write(keyTestPEM("CERTIFICATE", []byte("not DER")))
	file.Write(keyTestPEM("PRIVATE KEY", []byte("not DER")))
	file.Write(keyTestPEM("lower case label", []byte{1}))
	file.WriteString("trailing garbage after the last block \x00\x01\x02")

	pc := ParsePEMFile(file.Bytes(), PEMLimits{})
	if len(pc.Certificates) != 2 || len(pc.PrivateKeys) != 4 || len(pc.PublicKeys) != 2 {
		t.Fatalf("certs %d keys %d pubs %d", len(pc.Certificates), len(pc.PrivateKeys), len(pc.PublicKeys))
	}
	if pc.Malformed != 4 || pc.Truncated {
		t.Errorf("Malformed = %d (want 4), Truncated = %v", pc.Malformed, pc.Truncated)
	}
	wantOther := map[string]int{"EC PARAMETERS": 1, "CERTIFICATE REQUEST": 1, "X509 CRL": 1, "DH PARAMETERS": 1}
	if len(pc.Other) != len(wantOther) {
		t.Errorf("Other = %v", pc.Other)
	}
	for k, v := range wantOther {
		if pc.Other[k] != v {
			t.Errorf("Other[%q] = %d", k, pc.Other[k])
		}
	}

	ecHash := keyTestSPKIHash(t, ecKey.Public())
	if pc.Certificates[0].PublicKeySHA256 != ecHash || pc.PrivateKeys[0].PublicKeySHA256 != ecHash || pc.PublicKeys[0].PublicKeySHA256 != ecHash {
		t.Error("certificate, SEC1 key and public key of one EC key do not agree")
	}
	if pc.PublicKeys[1].PublicKeySHA256 != keyTestSPKIHash(t, rsaKey.Public()) || pc.PublicKeys[1].Algorithm != "RSA" || pc.PublicKeys[1].SizeBits != 2048 {
		t.Errorf("RSA PUBLIC KEY: %+v", pc.PublicKeys[1])
	}
	if pc.PublicKeys[0].Algorithm != "ECDSA" || pc.PublicKeys[0].Curve != "P-256" {
		t.Errorf("PUBLIC KEY: %+v", pc.PublicKeys[0])
	}

	for i, want := range []struct{ format, alg string }{{KeyFormatPKCS1, "RSA"}, {KeyFormatSEC1, "ECDSA"}} {
		k := pc.PrivateKeys[2+i]
		if k.Format != want.format || k.Algorithm != want.alg || k.Encrypted == nil || !*k.Encrypted || k.Encryption != "aes-256-cbc" || k.SizeBits != 0 || k.PublicKeySHA256 != "" || k.Unknown == "" {
			t.Errorf("legacy encrypted %s: %+v", want.alg, k)
		}
	}

	// The mixed file: every private component of every key it holds, and the
	// encrypted blocks' ciphertext, must be absent. (The certificates are
	// public and carried as PEM, so the public halves the key encodings also
	// hold legitimately appear: only private components are checked here.
	// The single-key projection test checks whole key encodings.)
	secrets := append(keyTestSecrets(t, rsaKey), keyTestSecrets(t, ecKey)...)
	secrets = append(secrets, keyTestSecrets(t, keys[5].priv)...)
	for _, e := range [][]byte{encRSA, encEC} {
		b, _ := pem.Decode(e)
		secrets = append(secrets, b.Bytes)
	}
	keyAssertNoLeak(t, "mixed file", pc, secrets...)
}

func TestParsePEMFile_Bounds(t *testing.T) {
	keys := keyTestKeys(t)
	one := keyTestPEM("CERTIFICATE", keyTestSelfSigned(t, keys[5].priv, "bound"))
	file := bytes.Repeat(one, 10)
	pc := ParsePEMFile(file, PEMLimits{MaxBlocks: 3})
	if len(pc.Certificates) != 3 || !pc.Truncated {
		t.Errorf("MaxBlocks 3: %d certificates, truncated %v", len(pc.Certificates), pc.Truncated)
	}
	if pc := ParsePEMFile(file, PEMLimits{MaxBlocks: 10}); len(pc.Certificates) != 10 || pc.Truncated {
		t.Errorf("exactly at the bound: %d, truncated %v", len(pc.Certificates), pc.Truncated)
	}

	// Distinct labels are bounded.
	var many bytes.Buffer
	for i := 0; i < keyMaxOtherLabels+5; i++ {
		many.Write(keyTestPEM("LABEL "+strings.Repeat("X", i+1), []byte{1}))
	}
	pc = ParsePEMFile(many.Bytes(), PEMLimits{})
	if len(pc.Other) != keyMaxOtherLabels+1 || pc.Other[keyOtherLabel] != 5 {
		t.Errorf("Other has %d labels, %d under %q", len(pc.Other), pc.Other[keyOtherLabel], keyOtherLabel)
	}
}

func TestParsePEMFile_Hostile(t *testing.T) {
	keys := keyTestKeys(t)
	good := keyTestPEM("CERTIFICATE", keyTestSelfSigned(t, keys[2].priv, "hostile"))

	// Every truncation of a valid block: no panic, never a certificate from
	// half a block.
	for i := 0; i < len(good); i++ {
		pc := ParsePEMFile(good[:i], PEMLimits{})
		if len(pc.Certificates) != 0 && i < len(good)-1 {
			t.Fatalf("a truncated block at %d parsed as a certificate", i)
		}
	}
	// A 10 MiB line, with and without a BEGIN in front of it.
	long := bytes.Repeat([]byte("A"), 10<<20)
	if pc := ParsePEMFile(long, PEMLimits{}); pc.Malformed != 0 || len(pc.Certificates) != 0 {
		t.Errorf("10 MiB of text: %+v", pc)
	}
	pc := ParsePEMFile(append([]byte("-----BEGIN CERTIFICATE-----\n"), long...), PEMLimits{})
	if pc.Malformed != 1 {
		t.Errorf("10 MiB block body: malformed %d", pc.Malformed)
	}
	// Many BEGIN lines and no END: linear, every one malformed, bounded.
	many := bytes.Repeat([]byte("-----BEGIN X-----\n"), 5000)
	pc = ParsePEMFile(many, PEMLimits{})
	if pc.Malformed != keyDefaultMaxRecords || !pc.Truncated {
		t.Errorf("BEGIN flood: malformed %d truncated %v", pc.Malformed, pc.Truncated)
	}
	// A good block after a broken one is still read; garbage after a good
	// block changes nothing.
	file := append([]byte("-----BEGIN CERTIFICATE-----\n%%%%\n"), good...)
	file = append(file, []byte("\x00\xff garbage -----END CERTIFICATE-----")...)
	pc = ParsePEMFile(file, PEMLimits{})
	if len(pc.Certificates) != 1 || pc.Malformed != 1 {
		t.Errorf("broken then good: %d certificates, %d malformed", len(pc.Certificates), pc.Malformed)
	}
	// A hostile label is not repeated into the report.
	pc = ParsePEMFile(keyTestPEM("secret password hunter2", []byte{1}), PEMLimits{})
	if blob, _ := json.Marshal(pc); bytes.Contains(blob, []byte("hunter2")) || pc.Malformed != 1 {
		t.Errorf("hostile label kept: %s", blob)
	}
}

// The projection rule for every private-key path that reaches a PEM file:
// PKCS#8, PKCS#1, SEC1, OpenSSH, each alone, and DER.
func TestKeyProjection_PEMAndDER(t *testing.T) {
	for _, tk := range keyTestKeys(t) {
		pkcs8, _ := x509.MarshalPKCS8PrivateKey(tk.priv)
		files := map[string][]byte{
			"pkcs8":   keyTestPEM("PRIVATE KEY", pkcs8),
			"openssh": keyTestOpenSSH(t, tk, ""),
		}
		blobs := [][]byte{pkcs8}
		switch k := tk.priv.(type) {
		case *rsa.PrivateKey:
			d := x509.MarshalPKCS1PrivateKey(k)
			files["pkcs1"], blobs = keyTestPEM("RSA PRIVATE KEY", d), append(blobs, d)
		case *ecdsa.PrivateKey:
			d, _ := x509.MarshalECPrivateKey(k)
			files["sec1"], blobs = keyTestPEM("EC PRIVATE KEY", d), append(blobs, d)
		}
		secrets := append(keyTestSecrets(t, tk.priv), blobs...)
		for name, f := range files {
			pc := ParsePEMFile(f, PEMLimits{})
			if len(pc.PrivateKeys) != 1 {
				t.Fatalf("%s/%s: %d keys", tk.name, name, len(pc.PrivateKeys))
			}
			keyAssertNoLeak(t, tk.name+"/"+name, pc, secrets...)
		}
		for _, d := range blobs {
			k, _ := ParsePrivateKeyDER(d)
			keyAssertNoLeak(t, tk.name+"/der", k, secrets...)
		}
	}
}

func FuzzParsePEMFile(f *testing.F) {
	keys := keyTestKeys(f)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(keys[2].priv)
	f.Add(keyTestPEM("CERTIFICATE", keyTestSelfSigned(f, keys[2].priv, "fuzz")))
	f.Add(keyTestPEM("PRIVATE KEY", pkcs8))
	f.Add(keyTestOpenSSH(f, keys[5], ""))
	f.Add(keyTestLegacyEncrypted(f, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(keys[0].priv.(*rsa.PrivateKey))))
	f.Add([]byte("-----BEGIN X-----\n-----BEGIN Y-----\nAAAA\n-----END Y-----\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		pc := ParsePEMFile(b, PEMLimits{MaxBlocks: 50})
		if _, err := json.Marshal(pc); err != nil {
			t.Fatal(err)
		}
		if n := len(pc.Certificates) + len(pc.PublicKeys) + pc.Malformed; n > 50 {
			t.Fatalf("%d records from at most 50 blocks", n)
		}
		// Every DER key path, on the raw input too.
		_, _ = ParsePrivateKeyDER(b)
		_, _ = ParseCertificateDER(b)
		_, _ = ParsePuTTYKey(b)
	})
}
