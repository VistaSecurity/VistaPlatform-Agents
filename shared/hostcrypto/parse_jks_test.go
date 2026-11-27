package hostcrypto

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // the test encoder computes the format's own digest
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// A JKS / JCEKS encoder for the tests, written from the format description
// in parse_jks.go. It lets every case be built here, with keys generated
// here, and with the real integrity digest for a chosen password.

type ksJKSEntry struct {
	tag          uint32
	alias        string
	protectedKey []byte   // tag 1
	chain        [][]byte // tag 1
	cert         []byte   // tag 2
	secretBlob   []byte   // tag 3: stands in for a serialized Java object
}

func ksBuildJKS(magic, version uint32, password string, entries ...ksJKSEntry) []byte {
	var b bytes.Buffer
	w32 := func(v uint32) { _ = binary.Write(&b, binary.BigEndian, v) }
	utf := func(s string) { _ = binary.Write(&b, binary.BigEndian, uint16(len(s))); b.WriteString(s) }
	cert := func(der []byte) {
		if version == 2 {
			utf("X.509")
		}
		w32(uint32(len(der)))
		b.Write(der)
	}
	w32(magic)
	w32(version)
	w32(uint32(len(entries)))
	for _, e := range entries {
		w32(e.tag)
		utf(e.alias)
		_ = binary.Write(&b, binary.BigEndian, uint64(1767225600000))
		switch e.tag {
		case 1:
			w32(uint32(len(e.protectedKey)))
			b.Write(e.protectedKey)
			w32(uint32(len(e.chain)))
			for _, c := range e.chain {
				cert(c)
			}
		case 2:
			cert(e.cert)
		case 3:
			b.Write(e.secretBlob)
		}
	}
	h := sha1.New() //nolint:gosec // the format's digest
	for _, c := range utf16.Encode([]rune(password)) {
		h.Write([]byte{byte(c >> 8), byte(c)})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(b.Bytes())
	b.Write(h.Sum(nil))
	return b.Bytes()
}

// ksJKSFixture is a store with a trusted CA and a private-key entry whose
// "protected key" is the RAW PKCS#8 of a generated key, so the projection
// test is as hard as it can be: a real JKS would hold it encrypted.
type ksJKSFixture struct {
	store   []byte
	secrets [][]byte
	caFP    string
	leafFP  string
	leafPK  string
}

func ksMakeJKSFixture(t *testing.T, magic, version uint32, password string) ksJKSFixture {
	t.Helper()
	caKey := ksTestRSA(t)
	ca := ksTestCert(t, caKey, "Example Fixture Root", true)
	leafKey := ksTestECDSA(t)
	leaf := ksTestCert(t, leafKey, "server", false)
	leafCert, _ := ksCertificate(leaf.Raw)
	secrets := ksSecretsOf(t, leafKey)
	store := ksBuildJKS(magic, version, password,
		ksJKSEntry{tag: 2, alias: "rootca", cert: ca.Raw},
		ksJKSEntry{tag: 1, alias: "server", protectedKey: ksPKCS8(t, leafKey), chain: [][]byte{leaf.Raw, ca.Raw}},
	)
	return ksJKSFixture{store: store, secrets: secrets, caFP: ksDERFingerprint(ca.Raw), leafFP: leafCert.FingerprintSHA256, leafPK: leafCert.PublicKeySHA256}
}

func TestParseJKS_ListsWithoutAPassword(t *testing.T) {
	for _, tc := range []struct {
		name    string
		magic   uint32
		version uint32
		typ     string
		prot    string
	}{
		{"jks v2", ksMagicJKS, 2, KeystoreJKS, "JKS proprietary (SHA-1 keystream)"},
		{"jks v1", ksMagicJKS, 1, KeystoreJKS, "JKS proprietary (SHA-1 keystream)"},
		{"jceks v2", ksMagicJCEKS, 2, KeystoreJCEKS, "JCEKS (PBEWithMD5AndTripleDES)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := ksMakeJKSFixture(t, tc.magic, tc.version, "s3cret-not-default")
			got, err := ParseJKS(fx.store, false)
			if err != nil {
				t.Fatal(err)
			}
			ks := got.Keystore
			if got.Truncated || got.DefaultsNotTried != "" {
				t.Errorf("truncated %v, not tried %q", got.Truncated, got.DefaultsNotTried)
			}
			if ks.Type != tc.typ || ks.Protection != tc.prot || ks.Opened != OpenedNot {
				t.Errorf("type/protection/opened: %q %q %q", ks.Type, ks.Protection, ks.Opened)
			}
			if ks.DefaultPassword != nil {
				t.Error("DefaultPassword set without the opt-in")
			}
			if ks.EntryCount == nil || *ks.EntryCount != 2 || len(ks.Entries) != 2 {
				t.Fatalf("entries: %+v", ks.Entries)
			}
			trusted, pk := ks.Entries[0], ks.Entries[1]
			if trusted.Kind != "certificate" || trusted.Alias != "rootca" || trusted.CertificateFingerprint != fx.caFP || trusted.Algorithm != "RSA" || trusted.SizeBits != 2048 {
				t.Errorf("trusted entry: %+v", trusted)
			}
			if pk.Kind != "private_key" || pk.Alias != "server" || pk.Algorithm != "ECDSA" || pk.SizeBits != 256 ||
				pk.CertificateFingerprint != fx.leafFP || pk.PublicKeySHA256 != fx.leafPK {
				t.Errorf("private key entry: %+v", pk)
			}
			// Three certificates: the trusted root, and the chain's leaf and root.
			if len(got.Certificates) != 3 {
				t.Fatalf("certificates: %d", len(got.Certificates))
			}
			if c := got.Certificates[0]; !c.TrustAnchor || c.CertificatePEM != "" || c.Location.Alias != "rootca" {
				t.Errorf("trust anchor: %+v", c.Location)
			}
			if c := got.Certificates[1]; c.TrustAnchor || c.CertificatePEM == "" || c.Location.Alias != "server" || c.FingerprintSHA256 != fx.leafFP {
				t.Errorf("chain leaf: alias %q anchor %v", c.Location.Alias, c.TrustAnchor)
			}
		})
	}
}

func TestParseJKS_DefaultPassword(t *testing.T) {
	for _, tc := range []struct {
		password string
		want     bool
	}{
		{"changeit", true},
		{"changeme", true},
		{"password", true},
		// An empty password is no default: the store needs none.
		{"", false},
		{"s3cret-not-default", false},
	} {
		for _, magic := range []uint32{ksMagicJKS, ksMagicJCEKS} {
			fx := ksMakeJKSFixture(t, magic, 2, tc.password)
			got, err := ParseJKS(fx.store, true)
			if err != nil {
				t.Fatal(err)
			}
			ks := got.Keystore
			if ks.DefaultPassword == nil || *ks.DefaultPassword != tc.want {
				t.Errorf("%q magic %x: DefaultPassword %v, want %v", tc.password, magic, ks.DefaultPassword, tc.want)
			}
			// Only the empty digest makes the store no_password; a default
			// makes it default_password; anything else is not_opened, its
			// clear entries still listed.
			wantOpened, wantOff := OpenedNot, OpenedNot
			switch {
			case tc.password == "":
				wantOpened, wantOff = OpenedWithoutPassword, OpenedWithoutPassword
			case tc.want:
				wantOpened = OpenedDefaultPassword
			}
			if ks.Opened != wantOpened || len(ks.Entries) != 2 || len(got.Certificates) != 3 {
				t.Errorf("%q: opened %q, %d entries, %d certificates", tc.password, ks.Opened, len(ks.Entries), len(got.Certificates))
			}
			if (ks.Opened == OpenedNot) != strings.Contains(ks.Unknown, "neither empty nor a well-known default") {
				t.Errorf("%q: unknown %q", tc.password, ks.Unknown)
			}
			// Off: the empty digest only, DefaultPassword absent.
			off, _ := ParseJKS(fx.store, false)
			if off.Keystore.DefaultPassword != nil || off.Keystore.Opened != wantOff || len(off.Keystore.Entries) != 2 || len(off.Certificates) != 3 {
				t.Errorf("%q: without the opt-in: %+v", tc.password, off.Keystore)
			}
			if (wantOff == OpenedNot) != (off.Keystore.Unknown == "aliases and certificates are stated in clear; the store's integrity password is not empty") {
				t.Errorf("%q: without the opt-in, unknown %q", tc.password, off.Keystore.Unknown)
			}
		}
	}
}

// A JCEKS secret key cannot be stepped over; listing stops there honestly.
func TestParseJKS_JCEKSSecretKeyStopsTheListing(t *testing.T) {
	ca := ksTestCert(t, ksTestECDSA(t), "ca", true)
	store := ksBuildJKS(ksMagicJCEKS, 2, "changeit",
		ksJKSEntry{tag: 2, alias: "first", cert: ca.Raw},
		ksJKSEntry{tag: 3, alias: "hmac-key", secretBlob: []byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x72}},
		ksJKSEntry{tag: 2, alias: "after", cert: ca.Raw},
	)
	got, err := ParseJKS(store, true)
	if err != nil {
		t.Fatal(err)
	}
	ks := got.Keystore
	if len(ks.Entries) != 2 || ks.Entries[1].Kind != "secret_key" || ks.Entries[1].Alias != "hmac-key" {
		t.Fatalf("entries: %+v", ks.Entries)
	}
	if ks.EntryCount == nil || *ks.EntryCount != 3 || !got.Truncated {
		t.Errorf("EntryCount should keep the header's 3 and say the listing stopped: %v %v", ks.EntryCount, got.Truncated)
	}
	if ks.DefaultPassword == nil || !*ks.DefaultPassword {
		t.Error("the digest check does not depend on the listing")
	}
	// A secret key entry in a plain JKS is malformed.
	bad := ksBuildJKS(ksMagicJKS, 2, "x", ksJKSEntry{tag: 3, alias: "k", secretBlob: []byte{1, 2, 3, 4}})
	if _, err := ParseJKS(bad, false); err == nil {
		t.Error("JKS with a secret key entry accepted")
	}
}

func TestParseJKS_EntryCap(t *testing.T) {
	ca := ksTestCert(t, ksTestECDSA(t), "ca", true)
	var entries []ksJKSEntry
	for i := 0; i < 7; i++ {
		entries = append(entries, ksJKSEntry{tag: 2, alias: "a", cert: ca.Raw})
	}
	got, err := ksParseJKS(ksBuildJKS(ksMagicJKS, 2, "x", entries...), false, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Keystore.Entries) != 5 || *got.Keystore.EntryCount != 7 || !got.Truncated {
		t.Errorf("cap: %d entries, count %d", len(got.Keystore.Entries), *got.Keystore.EntryCount)
	}
}

func TestParseJKS_HostileInput(t *testing.T) {
	fx := ksMakeJKSFixture(t, ksMagicJKS, 2, "changeit")
	// Every prefix of a valid store: no panic, and never a complete count.
	for n := 0; n < len(fx.store); n++ {
		got, err := ParseJKS(fx.store[:n], true)
		if err == nil && got.Keystore.EntryCount != nil && *got.Keystore.EntryCount == 2 && len(got.Keystore.Entries) == 2 && n < len(fx.store)-ksJKSDigestLen {
			t.Fatalf("prefix %d read as complete", n)
		}
	}
	for name, b := range map[string][]byte{
		"empty":           nil,
		"magic only":      {0xfe, 0xed, 0xfe, 0xed},
		"wrong magic":     ksBuildJKS(0x12345678, 2, "x"),
		"bad version":     ksBuildJKS(ksMagicJKS, 7, "x"),
		"billion entries": ksPatchU32(ksBuildJKS(ksMagicJKS, 2, "x"), 8, 1_000_000_000),
		"huge key length": ksPatchU32(ksBuildJKS(ksMagicJKS, 2, "x", ksJKSEntry{tag: 1, alias: "k", protectedKey: []byte{1}}), 12+4+2+1+8, 0xfffffff0),
		"huge chain":      ksPatchU32(ksBuildJKS(ksMagicJKS, 2, "x", ksJKSEntry{tag: 1, alias: "k", protectedKey: []byte{1}}), 12+4+2+1+8+4+1, 0x7fffffff),
		"huge alias":      ksPatchU16(ksBuildJKS(ksMagicJKS, 2, "x", ksJKSEntry{tag: 2, alias: "k", cert: []byte{1}}), 12+4, 0xffff),
		"huge cert":       ksPatchU32(ksBuildJKS(ksMagicJKS, 1, "x", ksJKSEntry{tag: 2, alias: "k", cert: []byte{1}}), 12+4+2+1+8, 0xffffffff),
		"unknown tag":     ksBuildJKS(ksMagicJKS, 2, "x", ksJKSEntry{tag: 9, alias: "k"}),
	} {
		got, err := ParseJKS(b, true)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if got.Keystore.EntryCount != nil {
			t.Errorf("%s: claimed a count", name)
		}
	}
	// Too short to hold a digest: not tried, and said so.
	if got, _ := ParseJKS([]byte{0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 0}, true); got.Keystore.DefaultPassword != nil || got.DefaultsNotTried == "" {
		t.Errorf("short store: %+v %q", got.Keystore, got.DefaultsNotTried)
	}
	// Zero entries is a valid, empty store.
	got, err := ParseJKS(ksBuildJKS(ksMagicJKS, 2, "changeit"), true)
	if err != nil || got.Keystore.EntryCount == nil || *got.Keystore.EntryCount != 0 || !*got.Keystore.DefaultPassword {
		t.Errorf("empty store: %v %+v", err, got.Keystore)
	}
}

func ksPatchU32(b []byte, off int, v uint32) []byte {
	binary.BigEndian.PutUint32(b[off:], v)
	return b
}

func ksPatchU16(b []byte, off int, v uint16) []byte {
	binary.BigEndian.PutUint16(b[off:], v)
	return b
}

// The protected key bytes are skipped by length; none of them reach the
// record.
func TestParseJKS_ProjectionCarriesNoKeyMaterial(t *testing.T) {
	for _, magic := range []uint32{ksMagicJKS, ksMagicJCEKS} {
		fx := ksMakeJKSFixture(t, magic, 2, "changeit")
		got, err := ParseJKS(fx.store, true)
		if err != nil {
			t.Fatal(err)
		}
		ksAssertNoSecret(t, "jks", got, fx.secrets...)
	}
}

func FuzzParseJKS(f *testing.F) {
	ca := ksTestCert(f, ksTestECDSA(f), "ca", true)
	f.Add(ksBuildJKS(ksMagicJKS, 2, "changeit", ksJKSEntry{tag: 2, alias: "a", cert: ca.Raw}))
	f.Add(ksBuildJKS(ksMagicJCEKS, 1, "x", ksJKSEntry{tag: 1, alias: "k", protectedKey: []byte{1, 2}, chain: [][]byte{ca.Raw}}))
	f.Add(ksBuildJKS(ksMagicJCEKS, 2, "x", ksJKSEntry{tag: 3, alias: "s", secretBlob: []byte{0xac, 0xed}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ksParseJKS(b, true, 50)
		if len(got.Keystore.Entries) > 50 {
			t.Fatal("cap exceeded")
		}
		if err != nil && got.Keystore.EntryCount != nil {
			t.Fatal("a count claimed for a malformed store")
		}
	})
}
