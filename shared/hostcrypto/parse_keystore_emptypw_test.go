package hostcrypto

import (
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

// TestEmptyPasswordIsNotADefault (owner, 2026-11-25): with the
// default-password opt-in, a store whose password is empty reads as
// needing none (no_password, DefaultPassword false); only a well-known
// default (changeit) is default_password/true; a real password is
// DefaultPassword false and opens nothing it would need a password for.
// Every store is generated here. Without the opt-in nothing is tried.
func TestEmptyPasswordIsNotADefault(t *testing.T) {
	type want struct {
		opened  string
		deflt   bool
		entries int // certificates listed
	}
	p12 := ksMakeP12Fixture(t)
	mkP12 := func(pw string) []byte {
		b, err := pkcs12.Modern2023.Encode(p12.key, p12.leaf, nil, pw)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name  string
		parse func(pw string) (KeystoreContents, error)
		want  map[string]want
	}{
		{"pkcs12", func(pw string) (KeystoreContents, error) { return ParsePKCS12(mkP12(pw), true) }, map[string]want{
			"":            {OpenedWithoutPassword, false, 1},
			"changeit":    {OpenedDefaultPassword, true, 1},
			"Real-Pass-7": {OpenedWithoutPassword, false, 0}, // the key bag's plain part only
		}},
		{"jks", func(pw string) (KeystoreContents, error) {
			return ParseJKS(ksMakeJKSFixture(t, ksMagicJKS, 2, pw).store, true)
		}, map[string]want{
			// A JKS lists without a password whatever it is; the digest says
			// which password it has.
			"":            {OpenedWithoutPassword, false, -1},
			"changeit":    {OpenedDefaultPassword, true, -1},
			"Real-Pass-7": {OpenedWithoutPassword, false, -1},
		}},
		{"jceks", func(pw string) (KeystoreContents, error) {
			return ParseJKS(ksMakeJKSFixture(t, ksMagicJCEKS, 2, pw).store, true)
		}, map[string]want{
			"":            {OpenedWithoutPassword, false, -1},
			"changeit":    {OpenedDefaultPassword, true, -1},
			"Real-Pass-7": {OpenedWithoutPassword, false, -1},
		}},
	}
	for _, tc := range cases {
		for pw, w := range tc.want {
			got, err := tc.parse(pw)
			if err != nil {
				t.Fatalf("%s %q: %v", tc.name, pw, err)
			}
			ks := got.Keystore
			if ks.Opened != w.opened || ks.DefaultPassword == nil || *ks.DefaultPassword != w.deflt {
				t.Errorf("%s %q: opened %q default %v, want %q %v", tc.name, pw, ks.Opened, ks.DefaultPassword, w.opened, w.deflt)
			}
			if w.entries >= 0 && len(got.Certificates) != w.entries {
				t.Errorf("%s %q: %d certificates listed, want %d", tc.name, pw, len(got.Certificates), w.entries)
			}
		}
	}
	// Without the opt-in the empty password is not tried: an encrypted
	// PKCS#12 lists only its plain part, and DefaultPassword is nil.
	off, err := ParsePKCS12(mkP12(""), false)
	if err != nil || off.Keystore.DefaultPassword != nil || len(off.Certificates) != 0 {
		t.Fatalf("without the opt-in: %v %+v", err, off.Keystore)
	}
	// The default list holds no empty password; it is its own step.
	for _, pw := range DefaultKeystorePasswords {
		if pw == "" {
			t.Fatal("the empty password is back among the defaults")
		}
	}
}

// TestPKCS12MixedPasswords: a store whose MAC (or cheapest part) takes one
// password and another part another. A well-known default that opens any
// part is reported, whichever passed first; a part nothing opens leaves
// EntryCount nil and Unknown set.
func TestPKCS12MixedPasswords(t *testing.T) {
	a := ksTestCert(t, ksTestECDSA(t), "part-a", false)
	b := ksTestCert(t, ksTestECDSA(t), "part-b", false)
	for _, tc := range []struct {
		name  string
		build func() []byte
		certs int
	}{
		{"MAC empty, certificate part changeit", func() []byte {
			return ksBuildPFX(t, ksStr(""), ksEncryptedPart(t, "changeit", 1, ksCertSafeBag(t, a.Raw)))
		}, 1},
		{"MAC changeit, certificate part empty", func() []byte {
			return ksBuildPFX(t, ksStr("changeit"), ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw)))
		}, 1},
		{"no MAC, cheap part empty, costlier part changeit", func() []byte {
			return ksBuildPFX(t, nil, ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw)), ksEncryptedPart(t, "changeit", 50, ksCertSafeBag(t, b.Raw)))
		}, 2},
		{"no MAC, cheap part changeit, costlier part empty", func() []byte {
			return ksBuildPFX(t, nil, ksEncryptedPart(t, "changeit", 1, ksCertSafeBag(t, a.Raw)), ksEncryptedPart(t, "", 50, ksCertSafeBag(t, b.Raw)))
		}, 2},
	} {
		got, err := ParsePKCS12(tc.build(), true)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		ks := got.Keystore
		if ks.Opened != OpenedDefaultPassword || ks.DefaultPassword == nil || !*ks.DefaultPassword || len(got.Certificates) != tc.certs {
			t.Errorf("%s: opened %q default %v, %d certificates; want default_password, true, %d", tc.name, ks.Opened, ks.DefaultPassword, len(got.Certificates), tc.certs)
		}
		if ks.EntryCount == nil || ks.Unknown != "" {
			t.Errorf("%s: every part opened, yet entry count %v, unknown %q", tc.name, ks.EntryCount, ks.Unknown)
		}
	}
	// The empty password opens the MAC and one part; the other part takes a
	// real password: no default, the listed part read without a password,
	// and the store says a part is hidden.
	got, err := ParsePKCS12(ksBuildPFX(t, nil, ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw)), ksEncryptedPart(t, "Real-Pass-7", 50, ksCertSafeBag(t, b.Raw))), true)
	if err != nil {
		t.Fatal(err)
	}
	ks := got.Keystore
	if ks.Opened != OpenedWithoutPassword || ks.DefaultPassword == nil || *ks.DefaultPassword || len(got.Certificates) != 1 || ks.EntryCount != nil || ks.Unknown == "" {
		t.Fatalf("empty plus a real password: %+v, %d certificates", ks, len(got.Certificates))
	}
}
