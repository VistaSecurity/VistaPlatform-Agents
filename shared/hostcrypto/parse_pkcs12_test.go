package hostcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// PKCS#12 files come from two sources here: the sslmate library's encoders
// (Modern2023, Modern2026 with PBMAC1, LegacyDES, LegacyRC2, Passwordless),
// which are an independent implementation of the KDF, the MAC and the
// ciphers this file's trial uses; and a builder below that lays a file out
// the way keytool does, which the library cannot.

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

func ksMakeP12Fixture(t testing.TB) ksP12Fixture {
	t.Helper()
	caKey := ksTestECDSA(t)
	ca := ksTestCert(t, caKey, "Example Fixture Root", true)
	key := ksTestRSA(t)
	leaf := ksTestCert(t, key, "server", false)
	return ksP12Fixture{key: key, leaf: leaf, ca: ca, secrets: ksSecretsOf(t, key)}
}

func ksKeyEntry(ks Keystore) *KeystoreEntry {
	for i := range ks.Entries {
		if ks.Entries[i].Kind == "private_key" {
			return &ks.Entries[i]
		}
	}
	return nil
}

func TestParsePKCS12_ProtectionAndDefaults(t *testing.T) {
	fx := ksMakeP12Fixture(t)
	leaf, _ := ksCertificate(fx.leaf.Raw)
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
		}{{"changeit", true}, {"password", true}, {"", false}, {"Not-A-Default-9", false}} {
			p12, err := tc.enc.Encode(fx.key, fx.leaf, []*x509.Certificate{fx.ca}, pw.password)
			if err != nil {
				t.Fatal(err)
			}
			label := tc.name + "/" + pw.password

			// Without the opt-in: protection, and the key bag the library
			// keeps in a plain part (no alias: the library writes none). The
			// empty password is tried all the same: it opens the store whose
			// password is empty, and no other. A store it does not open is
			// not_opened, although its plain part lists the key bag.
			off, err := ParsePKCS12(p12, false)
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			if off.Keystore.Protection != tc.prot {
				t.Errorf("%s: protection\n got %q\nwant %q", label, off.Keystore.Protection, tc.prot)
			}
			if off.Keystore.DefaultPassword != nil || off.DefaultsNotTried != "" {
				t.Errorf("%s: without the opt-in, default %v (%q)", label, off.Keystore.DefaultPassword, off.DefaultsNotTried)
			}
			if pw.password == "" {
				if off.Keystore.Opened != OpenedWithoutPassword || len(off.Certificates) != 2 || off.Keystore.EntryCount == nil || *off.Keystore.EntryCount != 2 {
					t.Errorf("%s: without the opt-in: %+v", label, off.Keystore)
				}
			} else if off.Keystore.Opened != OpenedNot || len(off.Keystore.Entries) != 1 || len(off.Certificates) != 0 || off.Keystore.EntryCount != nil {
				t.Errorf("%s: without the opt-in: %+v", label, off.Keystore)
			}

			on, err := ParsePKCS12(p12, true)
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			ks := on.Keystore
			if ks.DefaultPassword == nil || *ks.DefaultPassword != pw.isDef || on.DefaultsNotTried != "" {
				t.Errorf("%s: DefaultPassword %v (%q), want %v", label, ks.DefaultPassword, on.DefaultsNotTried, pw.isDef)
			}
			if !pw.isDef && pw.password != "" {
				if ks.Opened != OpenedNot || len(on.Certificates) != 0 || ks.EntryCount != nil {
					t.Errorf("%s: listed with a wrong password: %+v", label, ks)
				}
				continue
			}
			// The key, with its own certificate, is one entry; the unrelated
			// root is the other. An empty password opens the store too, and
			// says it needs none.
			wantOpened := OpenedDefaultPassword
			if pw.password == "" {
				wantOpened = OpenedWithoutPassword
			}
			if ks.Opened != wantOpened || len(on.Certificates) != 2 || ks.EntryCount == nil || *ks.EntryCount != 2 {
				t.Fatalf("%s: opened %q, %d certificates, %+v", label, ks.Opened, len(on.Certificates), ks.Entries)
			}
			pk := ksKeyEntry(ks)
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
	// Nothing is protected, so there is nothing to try, and that is said.
	got, _ = ParsePKCS12(plain, true)
	if got.Keystore.DefaultPassword != nil || got.DefaultsNotTried != ksNotTriedUnprotected || got.Keystore.Opened != OpenedWithoutPassword {
		t.Errorf("passwordless with defaults: %q %+v", got.DefaultsNotTried, got.Keystore)
	}

	enc, err := pkcs12.Modern.EncodeTrustStore(certs, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	got, err = ParsePKCS12(enc, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Keystore.Opened != OpenedDefaultPassword || len(got.Certificates) != 2 || !got.Certificates[1].TrustAnchor || *got.Keystore.EntryCount != 2 {
		t.Errorf("encrypted trust store: %+v %d", got.Keystore, len(got.Certificates))
	}
	if got.Keystore.Protection != "certificates: PBES2 (PBKDF2-HMAC-SHA256, 2048 iterations, AES-256-CBC); MAC: HMAC-SHA256, 2048 iterations" {
		t.Errorf("trust store protection: %q", got.Keystore.Protection)
	}
}

// A passwordless PFX holding a key stores the key UNENCRYPTED. Only its
// algorithm identifier is read; the entry's facts come from its certificate.
func TestParsePKCS12_UnencryptedKeyBag(t *testing.T) {
	fx := ksMakeP12Fixture(t)
	p12, err := pkcs12.Passwordless.Encode(fx.key, fx.leaf, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, try := range []bool{false, true} {
		got, err := ParsePKCS12(p12, try)
		if err != nil {
			t.Fatal(err)
		}
		ks := got.Keystore
		if ks.Protection != ksP12NoCrypt || ks.Opened != OpenedWithoutPassword || ks.EntryCount == nil || *ks.EntryCount != 1 {
			t.Errorf("unencrypted: %+v", ks)
		}
		leaf, _ := ksCertificate(fx.leaf.Raw)
		if e := ksKeyEntry(ks); e == nil || e.Algorithm != "RSA" || e.SizeBits != 2048 || e.PublicKeySHA256 != leaf.PublicKeySHA256 {
			t.Errorf("key entry: %+v", e)
		}
		ksAssertNoSecret(t, "unencrypted key bag", got, fx.secrets...)
	}
	// Without a certificate to pair with, the algorithm identifier still
	// names the algorithm.
	alg, bits, _ := ksPKCS8Algorithm(ksPKCS8(t, ksTestECDSA(t)))
	if alg != "ECDSA" || bits != 256 {
		t.Errorf("pkcs8 algorithm: %q %d", alg, bits)
	}
}

// ---- A builder for layouts the library cannot write ----

var (
	ksTestOIDAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	ksTestOIDHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	ksTestOIDSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	ksTestOIDAnyEKU     = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
)

func ksExplicit0(inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
}

func ksAttr(t testing.TB, id asn1.ObjectIdentifier, element []byte) ksPKCS12Attribute {
	set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: element})
	if err != nil {
		t.Fatal(err)
	}
	return ksPKCS12Attribute{ID: id, Value: asn1.RawValue{FullBytes: set}}
}

func ksAttrName(t testing.TB, name string) ksPKCS12Attribute {
	var b []byte
	for _, r := range name {
		b = append(b, byte(r>>8), byte(r))
	}
	el, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagBMPString, Bytes: b})
	return ksAttr(t, ksOIDFriendlyName, el)
}

func ksAttrKeyID(t testing.TB, id []byte) ksPKCS12Attribute {
	el, _ := asn1.Marshal(id)
	return ksAttr(t, ksOIDLocalKeyID, el)
}

func ksAttrTrusted(t testing.TB) ksPKCS12Attribute {
	el, _ := asn1.Marshal(ksTestOIDAnyEKU)
	return ksAttr(t, ksOIDJavaTrusted, el)
}

func ksCertSafeBag(t testing.TB, der []byte, attrs ...ksPKCS12Attribute) ksSafeBag {
	inner, err := asn1.Marshal(ksCertBag{ID: ksOIDX509Cert, Data: der})
	if err != nil {
		t.Fatal(err)
	}
	return ksSafeBag{ID: ksOIDCertBag, Value: ksExplicit0(inner), Attributes: attrs}
}

func ksTestPBES2(t testing.TB, iters int, iv []byte) ksAlgorithmIdentifier {
	salt, _ := asn1.Marshal([]byte("saltsalt"))
	kdfp, err := asn1.Marshal(struct {
		Salt       asn1.RawValue
		Iterations int
		PRF        ksAlgorithmIdentifier
	}{asn1.RawValue{FullBytes: salt}, iters, ksAlgorithmIdentifier{Algorithm: ksTestOIDHMACSHA256, Parameters: asn1.NullRawValue}})
	if err != nil {
		t.Fatal(err)
	}
	ivDER, _ := asn1.Marshal(iv)
	p, err := asn1.Marshal(ksPBES2Params{
		KDF: ksAlgorithmIdentifier{Algorithm: ksOIDPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfp}},
		Enc: ksAlgorithmIdentifier{Algorithm: ksTestOIDAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ksAlgorithmIdentifier{Algorithm: ksOIDPBES2, Parameters: asn1.RawValue{FullBytes: p}}
}

// ksShroudedSafeBag is a key bag whose "ciphertext" is the given bytes; the
// parser must never look inside it.
func ksShroudedSafeBag(t testing.TB, iters int, ciphertext []byte, attrs ...ksPKCS12Attribute) ksSafeBag {
	epki, err := asn1.Marshal(ksEncryptedPrivateKeyInfo{Algorithm: ksTestPBES2(t, iters, make([]byte, 16)), Data: ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	return ksSafeBag{ID: ksOIDShroudedBag, Value: ksExplicit0(epki), Attributes: attrs}
}

func ksDataPart(t testing.TB, bags ...ksSafeBag) ksContentInfo {
	sc, err := asn1.Marshal(bags)
	if err != nil {
		t.Fatal(err)
	}
	os, _ := asn1.Marshal(sc)
	return ksContentInfo{ContentType: ksOIDData, Content: ksExplicit0(os)}
}

// ksEncryptedPart encrypts the bags with PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC)
// using the standard library directly.
func ksEncryptedPart(t testing.TB, password string, iters int, bags ...ksSafeBag) ksContentInfo {
	sc, err := asn1.Marshal(bags)
	if err != nil {
		t.Fatal(err)
	}
	return ksEncryptedBytes(t, password, iters, sc)
}

// ksEncryptedBytes encrypts any plaintext as an encryptedData part.
func ksEncryptedBytes(t testing.TB, password string, iters int, sc []byte) ksContentInfo {
	sc = append([]byte{}, sc...)
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	key, err := pbkdf2.Key(sha256.New, password, []byte("saltsalt"), iters, 32)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(key)
	n := 16 - len(sc)%16
	for i := 0; i < n; i++ {
		sc = append(sc, byte(n))
	}
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(sc, sc)
	type eci struct {
		ContentType asn1.ObjectIdentifier
		Alg         ksAlgorithmIdentifier
		Content     []byte `asn1:"tag:0,optional"`
	}
	ed, err := asn1.Marshal(struct {
		Version int
		ECI     eci
	}{0, eci{ksOIDData, ksTestPBES2(t, iters, iv), sc}})
	if err != nil {
		t.Fatal(err)
	}
	return ksContentInfo{ContentType: ksOIDEncryptedData, Content: ksExplicit0(ed)}
}

// ksBuildPFX assembles the parts; with macPassword set it adds an
// HMAC-SHA256 MacData for it.
func ksBuildPFX(t testing.TB, macPassword *string, parts ...ksContentInfo) []byte {
	authSafe, err := asn1.Marshal(parts)
	if err != nil {
		t.Fatal(err)
	}
	os, _ := asn1.Marshal(authSafe)
	ci := ksContentInfo{ContentType: ksOIDData, Content: ksExplicit0(os)}
	if macPassword == nil {
		pfx, err := asn1.Marshal(struct {
			Version  int
			AuthSafe ksContentInfo
		}{3, ci})
		if err != nil {
			t.Fatal(err)
		}
		return pfx
	}
	var bmp []byte
	for _, r := range *macPassword {
		bmp = append(bmp, byte(r>>8), byte(r))
	}
	bmp = append(bmp, 0, 0)
	salt := []byte("macsalt!")
	key := ksP12KDF(sha256.New, 32, 64, 3, salt, bmp, 2048, 32)
	mac := hmac.New(sha256.New, key)
	mac.Write(authSafe)
	pfx, err := asn1.Marshal(ksPFX{Version: 3, AuthSafe: ci, MacData: ksMacData{
		Mac:     ksDigestInfo{Algorithm: ksAlgorithmIdentifier{Algorithm: ksTestOIDSHA256, Parameters: asn1.NullRawValue}, Digest: mac.Sum(nil)},
		MacSalt: salt, Iterations: 2048,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return pfx
}

func ksStr(s string) *string { return &s }

// keytool's layout: the shrouded key in a PLAIN part with its alias and key
// id in clear attributes; the key's certificate and a trusted certificate
// (with the Java trustedKeyUsage attribute) in an ENCRYPTED part.
func ksKeytoolPFX(t testing.TB, password string, mac bool, keyCiphertext []byte) (b []byte, leaf, trusted *x509.Certificate) {
	leafKey := ksTestRSA(t)
	leaf = ksTestCert(t, leafKey, "server", false)
	trusted = ksTestCert(t, ksTestECDSA(t), "partner-ca", true)
	keyID := []byte("Time 1767225600000")
	var macPW *string
	if mac {
		macPW = &password
	}
	b = ksBuildPFX(t, macPW,
		ksDataPart(t, ksShroudedSafeBag(t, 10000, keyCiphertext, ksAttrName(t, "rsakey"), ksAttrKeyID(t, keyID))),
		ksEncryptedPart(t, password, 10000,
			ksCertSafeBag(t, leaf.Raw, ksAttrName(t, "rsakey"), ksAttrKeyID(t, keyID)),
			ksCertSafeBag(t, trusted.Raw, ksAttrName(t, "trusted"), ksAttrTrusted(t)),
		),
	)
	return b, leaf, trusted
}

func TestParsePKCS12_KeytoolLayout(t *testing.T) {
	secret := ksRandKey(t, 96) // stands in for the shrouded key's ciphertext
	for _, mac := range []bool{true, false} {
		b, leafX, trustedX := ksKeytoolPFX(t, "changeit", mac, secret)
		leaf, _ := ksCertificate(leafX.Raw)
		trusted, _ := ksCertificate(trustedX.Raw)

		// Defaults off: the key entry and its alias from the clear
		// attributes, and the store not opened.
		off, err := ParsePKCS12(b, false)
		if err != nil {
			t.Fatal(err)
		}
		if off.Keystore.Opened != OpenedNot || len(off.Keystore.Entries) != 1 || off.Keystore.Entries[0].Alias != "rsakey" ||
			off.Keystore.Entries[0].Kind != "private_key" || off.Keystore.EntryCount != nil || len(off.Certificates) != 0 {
			t.Errorf("mac=%v off: %+v", mac, off.Keystore)
		}

		on, err := ParsePKCS12(b, true)
		if err != nil {
			t.Fatal(err)
		}
		ks := on.Keystore
		if ks.Opened != OpenedDefaultPassword || ks.DefaultPassword == nil || !*ks.DefaultPassword || ks.EntryCount == nil || *ks.EntryCount != 2 {
			t.Fatalf("mac=%v on: %q %+v", mac, on.DefaultsNotTried, ks)
		}
		want := []KeystoreEntry{
			{Alias: "rsakey", Kind: "private_key", Algorithm: "RSA", SizeBits: 2048, CertificateFingerprint: leaf.FingerprintSHA256, PublicKeySHA256: leaf.PublicKeySHA256},
			{Alias: "trusted", Kind: "certificate", Algorithm: "ECDSA", SizeBits: 256, Curve: "P-256", CertificateFingerprint: trusted.FingerprintSHA256, PublicKeySHA256: trusted.PublicKeySHA256},
		}
		for i := range want {
			if ks.Entries[i] != want[i] {
				t.Errorf("mac=%v entry %d:\n got %+v\nwant %+v", mac, i, ks.Entries[i], want[i])
			}
		}
		if len(on.Certificates) != 2 {
			t.Fatalf("certificates: %d", len(on.Certificates))
		}
		if c := on.Certificates[0]; c.Location.Alias != "rsakey" || c.TrustAnchor || c.CertificatePEM == "" {
			t.Errorf("leaf certificate: %q %v", c.Location.Alias, c.TrustAnchor)
		}
		if c := on.Certificates[1]; c.Location.Alias != "trusted" || !c.TrustAnchor || c.CertificatePEM != "" {
			t.Errorf("trusted certificate: %q %v", c.Location.Alias, c.TrustAnchor)
		}
		ksAssertNoSecret(t, "keytool layout", on, secret)

		// A wrong password is proved wrong: by the MAC, or without one by the
		// encrypted part's padding and structure.
		bad, _, _ := ksKeytoolPFX(t, "S3cret-Other", mac, secret)
		got, _ := ParsePKCS12(bad, true)
		if got.Keystore.DefaultPassword == nil || *got.Keystore.DefaultPassword || got.Keystore.Opened != OpenedNot {
			t.Errorf("mac=%v wrong password: %q %+v", mac, got.DefaultsNotTried, got.Keystore)
		}
	}
}

// The reviewer's hang: no MAC, one encrypted part at 1 iteration under the
// empty password, and inside it a key bag asking for 2,000,000,000
// iterations. Keys are never decrypted, so the count is only described.
func TestParsePKCS12_HiddenKeyIterationsCostNothing(t *testing.T) {
	ca := ksTestCert(t, ksTestECDSA(t), "hidden", false)
	inner := []ksSafeBag{ksCertSafeBag(t, ca.Raw), ksShroudedSafeBag(t, 2_000_000_000, make([]byte, 32))}
	for name, b := range map[string][]byte{
		"no MAC, empty password": ksBuildPFX(t, nil, ksEncryptedPart(t, "", 1, inner...)),
		"MAC, changeit":          ksBuildPFX(t, ksStr("changeit"), ksEncryptedPart(t, "changeit", 1, inner...)),
	} {
		start := time.Now()
		got, err := ParsePKCS12(b, true)
		if d := time.Since(start); d > 30*time.Second {
			t.Fatalf("%s: took %v", name, d)
		}
		// Opened either way; only "changeit" is a default.
		wantDefault := strings.Contains(name, "changeit")
		if err != nil || got.Keystore.DefaultPassword == nil || *got.Keystore.DefaultPassword != wantDefault || len(got.Certificates) != 1 {
			t.Errorf("%s: %v %q %+v", name, err, got.DefaultsNotTried, got.Keystore)
		}
		if !strings.Contains(got.Keystore.Protection, "keys: PBES2 (PBKDF2-HMAC-SHA256, 2000000000 iterations, AES-256-CBC)") {
			t.Errorf("%s: protection %q", name, got.Keystore.Protection)
		}
	}
}

// The reviewer's false positive: a signedData authenticated safe, even with a
// MacData beside it, cannot be checked by a password.
func TestParsePKCS12_SignedDataIsNotCheckable(t *testing.T) {
	inner, _ := asn1.Marshal([]byte("x"))
	pfx, err := asn1.Marshal(ksPFX{
		Version:  3,
		AuthSafe: ksContentInfo{ContentType: ksOIDSignedData, Content: ksExplicit0(inner)},
		MacData: ksMacData{Mac: ksDigestInfo{Algorithm: ksAlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, Parameters: asn1.NullRawValue}, Digest: make([]byte, 20)},
			MacSalt: []byte("12345678"), Iterations: 2048},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePKCS12(pfx, true)
	if err != nil || got.Keystore.DefaultPassword != nil || got.Keystore.Opened != OpenedNot ||
		got.Keystore.Protection != "signed (public-key integrity)" || got.DefaultsNotTried != ksNotTriedSigned || got.Keystore.EntryCount != nil {
		t.Errorf("signedData: %v %q %+v", err, got.DefaultsNotTried, got.Keystore)
	}
}

// Nothing can prove a password right or wrong: no MAC, no encrypted part,
// only a shrouded key (which is never decrypted). DefaultPassword is nil, and
// the key's alias is listed from the plain part, but the store is not opened:
// the key is protected by a password nothing could check.
func TestParsePKCS12_NothingToCheck(t *testing.T) {
	b := ksBuildPFX(t, nil, ksDataPart(t, ksShroudedSafeBag(t, 2048, make([]byte, 32), ksAttrName(t, "k"))))
	got, err := ParsePKCS12(b, true)
	if err != nil || got.Keystore.DefaultPassword != nil || got.DefaultsNotTried != ksNotTriedNoCheck || got.Keystore.Opened != OpenedNot ||
		len(got.Keystore.Entries) != 1 || got.Keystore.Entries[0].Alias != "k" {
		t.Errorf("%v %q %+v", err, got.DefaultsNotTried, got.Keystore)
	}
}

// Without a MAC a wrong password is caught by the padding AND the structure:
// here the part decrypts under "changeit" to valid padding around bytes that
// are not a SafeContents, so only the structure check refuses it.
func TestParsePKCS12_NoMACNeedsValidStructure(t *testing.T) {
	b := ksBuildPFX(t, nil, ksEncryptedBytes(t, "changeit", 1, []byte("not a SafeContents, just bytes")))
	got, err := ParsePKCS12(b, true)
	if err != nil || got.Keystore.DefaultPassword == nil || *got.Keystore.DefaultPassword {
		t.Errorf("%v %q %+v", err, got.DefaultsNotTried, got.Keystore)
	}
}

func TestKsCBCDecrypt_Padding(t *testing.T) {
	key := make([]byte, 16)
	blk, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	enc := func(pt []byte) []byte {
		ct := append([]byte{}, pt...)
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, ct)
		return ct
	}
	good := append([]byte("0123456789ab"), 4, 4, 4, 4)
	if pt, ok := ksCBCDecrypt(blk, iv, enc(good)); !ok || string(pt) != "0123456789ab" {
		t.Errorf("good padding: %v %q", ok, pt)
	}
	for name, pt := range map[string][]byte{
		"zero":      append([]byte("0123456789abcde"), 0),
		"too large": append([]byte("0123456789abcde"), 17),
		"mixed":     append([]byte("0123456789ab"), 1, 4, 4, 4),
	} {
		if _, ok := ksCBCDecrypt(blk, iv, enc(pt)); ok {
			t.Errorf("%s padding accepted", name)
		}
	}
	if _, ok := ksCBCDecrypt(blk, iv, []byte("short")); ok {
		t.Error("partial block accepted")
	}
}

func TestParsePKCS12_WorkIsBounded(t *testing.T) {
	fx := ksMakeP12Fixture(t)
	// Five candidate passwords at 1,000,000 MAC iterations is over the budget.
	heavy, err := pkcs12.Modern.WithIterations(1_000_000).Encode(fx.key, fx.leaf, nil, "Not-A-Default-9")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got, err := ParsePKCS12(heavy, true)
	if err != nil || got.Keystore.DefaultPassword != nil || got.DefaultsNotTried != ksNotTriedCost || time.Since(start) > 30*time.Second {
		t.Errorf("costly file: %v %q %+v %v", err, got.DefaultsNotTried, got.Keystore, time.Since(start))
	}
	// Many cheap parts add up: 2,000 encrypted parts of 2,500 iterations.
	var parts []ksContentInfo
	part := ksEncryptedPart(t, "Not-A-Default-9", 2500)
	for i := 0; i < 2000; i++ {
		parts = append(parts, part)
	}
	got, _ = ParsePKCS12(ksBuildPFX(t, ksStr("x"), parts...), true)
	if got.DefaultsNotTried != ksNotTriedCost {
		t.Errorf("summed parts not bounded: %q", got.DefaultsNotTried)
	}
	if ksMulCost(1<<40, 1<<40) <= ksMaxTrialWork || ksAddCost(int(^uint(0)>>1), 5) <= ksMaxTrialWork {
		t.Error("cost arithmetic overflowed")
	}
}

func TestParsePKCS12_EntryCap(t *testing.T) {
	ca := ksTestCert(t, ksTestECDSA(t), "ca", true)
	var bags []ksSafeBag
	for i := 0; i < 9; i++ {
		bags = append(bags, ksCertSafeBag(t, ca.Raw, ksAttrTrusted(t)))
	}
	got, err := ksParsePKCS12(ksBuildPFX(t, nil, ksDataPart(t, bags...)), false, 4)
	if err != nil || !got.Truncated || len(got.Keystore.Entries) != 4 || got.Keystore.EntryCount != nil {
		t.Errorf("cap: %v %v %d %v", err, got.Truncated, len(got.Keystore.Entries), got.Keystore.EntryCount)
	}
}

func TestParsePKCS12_HostileInput(t *testing.T) {
	fx := ksMakeP12Fixture(t)
	p12, err := pkcs12.Modern.Encode(fx.key, fx.leaf, nil, "changeit")
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(p12); n++ {
		got, err := ParsePKCS12(p12[:n], true)
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
}

func TestKsUnmarshalAll_RefusesTrailingData(t *testing.T) {
	var n int
	if ksUnmarshalAll([]byte{0x02, 0x01, 0x03, 0x00}, &n) == nil {
		t.Error("trailing byte accepted")
	}
}

// RC2 is checked against RFC 2268 section 5 and the table is checked to be a
// permutation. The library interop above (LegacyRC2) checks it in CBC use.
func TestKsRC2(t *testing.T) {
	seen := map[byte]bool{}
	for _, b := range ksRC2Pi {
		seen[b] = true
	}
	if len(seen) != 256 {
		t.Fatalf("PITABLE is not a permutation: %d values", len(seen))
	}
	for _, v := range []struct {
		key  string
		eff  int
		pt   string
		want string
	}{
		{"0000000000000000", 63, "0000000000000000", "ebb773f993278eff"},
		{"ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"},
		{"3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"},
		{"88", 64, "0000000000000000", "61a8a244adacccf0"},
		{"88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"},
		{"88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"},
		{"88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"},
	} {
		key, _ := hex.DecodeString(v.key)
		pt, _ := hex.DecodeString(v.pt)
		c := ksNewRC2(key, v.eff)
		ct := make([]byte, 8)
		c.Encrypt(ct, pt)
		if hex.EncodeToString(ct) != v.want {
			t.Errorf("RC2 %s/%d: got %x want %s", v.key, v.eff, ct, v.want)
		}
		back := make([]byte, 8)
		c.Decrypt(back, ct)
		if hex.EncodeToString(back) != v.pt {
			t.Errorf("RC2 %s/%d: decrypt gave %x", v.key, v.eff, back)
		}
	}
}

func FuzzParsePKCS12(f *testing.F) {
	// Small seeds at low iteration counts, so the fuzzer spends its time on
	// structure rather than on PBKDF2 and minimisation does not stall. The
	// budget, not the seeds, bounds the cost of what it mutates them into.
	key := ksTestEd25519(f)
	leaf := ksTestCert(f, key, "f", false)
	for _, enc := range []*pkcs12.Encoder{pkcs12.Modern2023, pkcs12.LegacyRC2, pkcs12.Modern2026} {
		b, err := enc.WithIterations(1).Encode(key, leaf, nil, "changeit")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	inner := []ksSafeBag{ksCertSafeBag(f, leaf.Raw, ksAttrName(f, "a"), ksAttrKeyID(f, []byte{1})), ksShroudedSafeBag(f, 2_000_000_000, make([]byte, 16), ksAttrKeyID(f, []byte{1}))}
	f.Add(ksBuildPFX(f, nil, ksEncryptedPart(f, "", 1, inner...)))
	f.Add(ksBuildPFX(f, ksStr("changeit"), ksDataPart(f, inner...)))
	f.Fuzz(func(t *testing.T, b []byte) {
		start := time.Now()
		got, _ := ksParsePKCS12(b, true, 50)
		if d := time.Since(start); d > 30*time.Second {
			t.Fatalf("took %v", d)
		}
		if len(got.Keystore.Entries) > 50 {
			t.Fatal("cap exceeded")
		}
		if got.DefaultsNotTried != "" && got.Keystore.DefaultPassword != nil {
			t.Fatal("not tried, yet answered")
		}
	})
}
