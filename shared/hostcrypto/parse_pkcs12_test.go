package hostcrypto

import (
	"crypto/x509"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// PKCS#12 files are built here with the library's own encoders: Modern2023
// (PBES2/AES, HMAC-SHA256), Modern2026 (PBMAC1), LegacyDES (3DES both),
// LegacyRC2 (40-bit RC2 certificates) and Passwordless.

const (
	ksP12Modern  = "certificates: PBES2 (PBKDF2-HMAC-SHA256, 2048 iterations, AES-256-CBC); keys: PBES2 (PBKDF2-HMAC-SHA256, 2048 iterations, AES-256-CBC); MAC: HMAC-SHA256, 2048 iterations"
	ksP12M2026   = "certificates: PBES2 (PBKDF2-HMAC-SHA256, 2048 iterations, AES-256-CBC); keys: PBES2 (PBKDF2-HMAC-SHA256, 2048 iterations, AES-256-CBC); MAC: PBMAC1 (HMAC-SHA256, PBKDF2-HMAC-SHA256, 2048 iterations)"
	ksP12DES     = "certificates: pbeWithSHAAnd3-KeyTripleDES-CBC, 2048 iterations; keys: pbeWithSHAAnd3-KeyTripleDES-CBC, 2048 iterations; MAC: HMAC-SHA1, 1 iteration"
	ksP12RC2     = "certificates: pbeWithSHAAnd40BitRC2-CBC, 2048 iterations; keys: pbeWithSHAAnd3-KeyTripleDES-CBC, 2048 iterations; MAC: HMAC-SHA1, 1 iteration"
	ksP12NoCrypt = "certificates: not encrypted; keys: not encrypted; MAC: none"
)

type ksP12Fixture struct {
	key     any
	leaf    *x509.Certificate
	ca      *x509.Certificate
	secrets [][]byte
}

func ksMakeP12Fixture(t *testing.T) ksP12Fixture {
	t.Helper()
	caKey := ksTestECDSA(t)
	ca := ksTestCert(t, caKey, "Example Fixture Root", true)
	key := ksTestRSA(t)
	leaf := ksTestCert(t, key, "server", false)
	return ksP12Fixture{key: key, leaf: leaf, ca: ca, secrets: ksSecretsOf(t, key)}
}

func TestParsePKCS12_ProtectionAndDefaults(t *testing.T) {
	fx := ksMakeP12Fixture(t)
	for _, tc := range []struct {
		name string
		enc  *pkcs12.Encoder
		prot string
	}{
		{"modern2023", pkcs12.Modern2023, ksP12Modern},
		{"modern2026", pkcs12.Modern2026, ksP12M2026},
		{"legacyDES", pkcs12.LegacyDES, ksP12DES},
		{"legacyRC2", pkcs12.LegacyRC2, ksP12RC2},
	} {
		for _, pw := range []struct {
			password string
			isDef    bool
		}{{"changeit", true}, {"", true}, {"Not-A-Default-9", false}} {
			p12, err := tc.enc.Encode(fx.key, fx.leaf, []*x509.Certificate{fx.ca}, pw.password)
			if err != nil {
				t.Fatal(err)
			}
			label := tc.name + "/" + pw.password

			// Without the opt-in: protection only; the certificates are
			// encrypted, so nothing is listed.
			off, err := ParsePKCS12(p12, false)
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			if off.Keystore.Protection != tc.prot {
				t.Errorf("%s: protection\n got %q\nwant %q", label, off.Keystore.Protection, tc.prot)
			}
			if off.Keystore.Opened != OpenedNot || off.Keystore.DefaultPassword != nil || len(off.Keystore.Entries) != 0 || len(off.Certificates) != 0 || off.Keystore.EntryCount != nil {
				t.Errorf("%s: listed or tried without the opt-in: %+v", label, off.Keystore)
			}

			on, err := ParsePKCS12(p12, true)
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			ks := on.Keystore
			if ks.DefaultPassword == nil || *ks.DefaultPassword != pw.isDef {
				t.Errorf("%s: DefaultPassword %v, want %v", label, ks.DefaultPassword, pw.isDef)
			}
			if !pw.isDef {
				if ks.Opened != OpenedNot || len(ks.Entries) != 0 {
					t.Errorf("%s: listed with a wrong password: %+v", label, ks)
				}
				continue
			}
			if ks.Opened != OpenedDefaultPassword || len(on.Certificates) != 2 || ks.EntryCount == nil || *ks.EntryCount != 3 {
				t.Fatalf("%s: opened %q, %d certificates, %+v", label, ks.Opened, len(on.Certificates), ks.Entries)
			}
			leaf, _ := ksCertificate(fx.leaf.Raw)
			var pk *KeystoreEntry
			for i := range ks.Entries {
				if ks.Entries[i].Kind == "private_key" {
					pk = &ks.Entries[i]
				}
			}
			if pk == nil || pk.Algorithm != "RSA" || pk.SizeBits != 2048 || pk.PublicKeySHA256 != leaf.PublicKeySHA256 || pk.CertificateFingerprint != leaf.FingerprintSHA256 {
				t.Errorf("%s: private key entry %+v", label, pk)
			}
			ksAssertNoSecret(t, label, on, fx.secrets...)
		}
	}
}

func TestParsePKCS12_TrustStores(t *testing.T) {
	fx := ksMakeP12Fixture(t)
	certs := []*x509.Certificate{fx.ca, fx.leaf}

	// A passwordless Java trust store lists without any password.
	plain, err := pkcs12.Passwordless.EncodeTrustStore(certs, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePKCS12(plain, false)
	if err != nil {
		t.Fatal(err)
	}
	ks := got.Keystore
	if ks.Opened != OpenedWithoutPassword || ks.Protection != "certificates: not encrypted; MAC: none" || ks.EntryCount == nil || *ks.EntryCount != 2 {
		t.Errorf("passwordless: %+v", ks)
	}
	if len(got.Certificates) != 2 || !got.Certificates[0].TrustAnchor || got.Certificates[0].CertificatePEM != "" {
		t.Errorf("passwordless certificates: %+v", got.Certificates)
	}
	// Trying defaults on a store with nothing protected: the empty default
	// works, and the listing still says no password was needed.
	got, _ = ParsePKCS12(plain, true)
	if got.Keystore.DefaultPassword == nil || !*got.Keystore.DefaultPassword || got.Keystore.Opened != OpenedWithoutPassword {
		t.Errorf("passwordless with defaults: %+v", got.Keystore)
	}

	// An encrypted trust store opens with "changeit".
	enc, err := pkcs12.Modern.EncodeTrustStore(certs, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	got, err = ParsePKCS12(enc, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Keystore.Opened != OpenedDefaultPassword || len(got.Certificates) != 2 || !got.Certificates[1].TrustAnchor {
		t.Errorf("encrypted trust store: %+v %d", got.Keystore, len(got.Certificates))
	}
	if got.Keystore.Protection != "certificates: PBES2 (PBKDF2-HMAC-SHA256, 2048 iterations, AES-256-CBC); MAC: HMAC-SHA256, 2048 iterations" {
		t.Errorf("trust store protection: %q", got.Keystore.Protection)
	}
}

// A passwordless PFX holding a key stores the key UNENCRYPTED. Its public half
// is derived and the key dropped; none of it reaches the record.
func TestParsePKCS12_UnencryptedKeyBag(t *testing.T) {
	fx := ksMakeP12Fixture(t)
	p12, err := pkcs12.Passwordless.Encode(fx.key, fx.leaf, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePKCS12(p12, false)
	if err != nil {
		t.Fatal(err)
	}
	ks := got.Keystore
	if ks.Protection != ksP12NoCrypt || ks.Opened != OpenedWithoutPassword || ks.EntryCount == nil || *ks.EntryCount != 2 {
		t.Errorf("unencrypted: %+v", ks)
	}
	leaf, _ := ksCertificate(fx.leaf.Raw)
	found := false
	for _, e := range ks.Entries {
		if e.Kind == "private_key" {
			found = true
			if e.Algorithm != "RSA" || e.SizeBits != 2048 || e.PublicKeySHA256 != leaf.PublicKeySHA256 {
				t.Errorf("key entry: %+v", e)
			}
		}
	}
	if !found {
		t.Error("no private key entry")
	}
	ksAssertNoSecret(t, "unencrypted key bag", got, fx.secrets...)
	got, _ = ParsePKCS12(p12, true)
	ksAssertNoSecret(t, "unencrypted key bag, defaults", got, fx.secrets...)
}

func TestParsePKCS12_HostileInput(t *testing.T) {
	fx := ksMakeP12Fixture(t)
	p12, err := pkcs12.Modern.Encode(fx.key, fx.leaf, nil, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(p12); n++ {
		got, err := ParsePKCS12(p12[:n], false)
		if err == nil {
			t.Fatalf("prefix %d accepted", n)
		}
		if got.Keystore.Type != KeystorePKCS12 || got.Keystore.EntryCount != nil {
			t.Fatalf("prefix %d: %+v", n, got.Keystore)
		}
	}
	for name, b := range map[string][]byte{
		"empty":       nil,
		"not asn1":    []byte("hello world"),
		"jks magic":   {0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2},
		"huge length": {0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01, 0x03},
	} {
		if _, err := ParsePKCS12(b, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A hostile iteration count is not tried: DefaultPassword stays nil.
	heavy, err := pkcs12.Modern.WithIterations(ksMaxTrialIterations+1).Encode(fx.key, fx.leaf, nil, "Not-A-Default-9")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePKCS12(heavy, true)
	if err != nil || got.Keystore.DefaultPassword != nil {
		t.Errorf("costly file was tried: %v %+v", err, got.Keystore)
	}
}

func TestKsUnmarshalAll_RefusesTrailingData(t *testing.T) {
	var n int
	if ksUnmarshalAll([]byte{0x02, 0x01, 0x03, 0x00}, &n) == nil {
		t.Error("trailing byte accepted")
	}
}
