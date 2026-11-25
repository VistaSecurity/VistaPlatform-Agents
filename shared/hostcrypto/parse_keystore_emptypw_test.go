package hostcrypto

import (
	"encoding/asn1"
	"strings"
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

// ksEmptyPwUnsupportedPart is an encryptedData part under an algorithm this
// package does not decrypt.
func ksEmptyPwUnsupportedPart(t *testing.T) ksContentInfo {
	type eci struct {
		ContentType asn1.ObjectIdentifier
		Alg         ksAlgorithmIdentifier
		Content     []byte `asn1:"tag:0,optional"`
	}
	ed, err := asn1.Marshal(struct {
		Version int
		ECI     eci
	}{0, eci{ksOIDData, ksAlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}}, make([]byte, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	return ksContentInfo{ContentType: ksOIDEncryptedData, Content: ksExplicit0(ed)}
}

// ksEmptyPwEnvelopedPart is a public-key encrypted part: no password opens
// it, and none is tried.
func ksEmptyPwEnvelopedPart(t *testing.T) ksContentInfo {
	null, _ := asn1.Marshal(asn1.NullRawValue)
	return ksContentInfo{ContentType: ksOIDEnvelopedData, Content: ksExplicit0(null)}
}

// TestPKCS12HiddenPartReasons: the reason a part stayed shut says only what
// the trial established about it.
func TestPKCS12HiddenPartReasons(t *testing.T) {
	a := ksTestCert(t, ksTestECDSA(t), "listed", false)
	b := ksTestCert(t, ksTestECDSA(t), "hidden", false)
	listed := ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw))
	const (
		refused    = "needs a password that is neither empty nor a well-known default"
		unreadable = "decrypted to contents that are not a list of entries"
		untried    = "protected in a way the collector does not try"
	)
	for _, tc := range []struct {
		name     string
		pfx      []byte
		want     []string
		wantNot  []string
		wantCert int
	}{
		{"(a) public-key encrypted part", ksBuildPFX(t, ksStr(""), listed, ksEmptyPwEnvelopedPart(t)), []string{untried}, []string{refused, unreadable}, 1},
		{"(b) an algorithm not decrypted here", ksBuildPFX(t, ksStr(""), listed, ksEmptyPwUnsupportedPart(t)), []string{untried}, []string{refused, unreadable}, 1},
		{"(c) decrypts to something that is not entries", ksBuildPFX(t, ksStr(""), listed, ksEncryptedBytes(t, "", 1, []byte("not a SafeContents at all"))), []string{unreadable}, []string{refused, untried}, 1},
		{"MAC empty, a part under a real password", ksBuildPFX(t, ksStr(""), listed, ksEncryptedPart(t, "Real-Pass-7", 1, ksCertSafeBag(t, b.Raw))), []string{refused}, []string{unreadable, untried}, 1},
		{"no MAC, cheap part empty, costlier part real", ksBuildPFX(t, nil, listed, ksEncryptedPart(t, "Real-Pass-7", 50, ksCertSafeBag(t, b.Raw))), []string{refused}, []string{unreadable, untried}, 1},
		{"both kinds", ksBuildPFX(t, ksStr(""), listed, ksEncryptedPart(t, "Real-Pass-7", 1, ksCertSafeBag(t, b.Raw)), ksEmptyPwEnvelopedPart(t)), []string{refused, untried}, []string{unreadable}, 1},
	} {
		got, err := ParsePKCS12(tc.pfx, true)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		ks := got.Keystore
		if ks.Opened != OpenedWithoutPassword || ks.DefaultPassword == nil || *ks.DefaultPassword || ks.EntryCount != nil || len(got.Certificates) != tc.wantCert {
			t.Errorf("%s: %+v, %d certificates", tc.name, ks, len(got.Certificates))
		}
		for _, w := range tc.want {
			if !strings.Contains(ks.Unknown, w) {
				t.Errorf("%s: unknown %q lacks %q", tc.name, ks.Unknown, w)
			}
		}
		for _, w := range tc.wantNot {
			if strings.Contains(ks.Unknown, w) {
				t.Errorf("%s: unknown %q claims %q", tc.name, ks.Unknown, w)
			}
		}
	}
}

// TestPKCS12RetryBudget: a store that fitted the trial budget before the
// empty password was tried apart still gets its answer (the other parts are
// budgeted once, under the password that passes the check); a retry whose
// key equals one already tried is not run again; and a retry the budget
// does not allow leaves "does a default open this?" unanswered.
func TestPKCS12RetryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("derives keys at 600,000 to 1,200,000 iterations")
	}
	a := ksTestCert(t, ksTestECDSA(t), "costly", false)
	// 600,000 PBKDF2 iterations cost 1,200,000: five of them (the old
	// budget for one part) exceed 4,000,000, one does not.
	fits := ksBuildPFX(t, ksStr("changeit"), ksEncryptedPart(t, "changeit", 600_000, ksCertSafeBag(t, a.Raw)))
	got, err := ParsePKCS12(fits, true)
	if err != nil || got.DefaultsNotTried != "" || got.Keystore.Opened != OpenedDefaultPassword || len(got.Certificates) != 1 {
		t.Fatalf("a store that fitted before: %v %q %+v", err, got.DefaultsNotTried, got.Keystore)
	}
	// 900,000 iterations cost 1,800,000: the first try (the empty password,
	// which passes the MAC) and the retry with "changeit" fit, because the
	// second spelling of the empty password is the same PBES2 key and is
	// not derived again.
	same := ksBuildPFX(t, ksStr(""), ksEncryptedPart(t, "changeit", 900_000, ksCertSafeBag(t, a.Raw)))
	got, err = ParsePKCS12(same, true)
	if ks := got.Keystore; err != nil || got.DefaultsNotTried != "" || ks.Opened != OpenedDefaultPassword || ks.DefaultPassword == nil || !*ks.DefaultPassword || len(got.Certificates) != 1 {
		t.Fatalf("the empty password's second spelling was derived again: %v %q %+v", err, got.DefaultsNotTried, ks)
	}
	// 1,200,000 iterations cost 2,400,000: the first try fits, the retry
	// with "changeit" does not. The defaults were not tried on that part,
	// so DefaultPassword has no answer and the store says why, as an
	// untried store does; the part's reason is the cost, not refusal.
	cut := ksBuildPFX(t, ksStr(""), ksEncryptedPart(t, "changeit", 1_200_000, ksCertSafeBag(t, a.Raw)))
	got, err = ParsePKCS12(cut, true)
	if err != nil || got.DefaultsNotTried != ksNotTriedCost {
		t.Fatalf("cut: %v %q", err, got.DefaultsNotTried)
	}
	ks := got.Keystore
	if ks.Opened != OpenedWithoutPassword || ks.DefaultPassword != nil || ks.EntryCount != nil ||
		!strings.Contains(ks.Unknown, "iteration count is above the limit") || strings.Contains(ks.Unknown, "neither empty") || strings.Contains(ks.Unknown, "does not try") {
		t.Fatalf("cut: %+v", ks)
	}
}

// TestPKCS12WrongPasswordPaddingIsNotUnreadable: a wrong candidate that
// happens to give valid padding (about once in 256) decrypts to garbage; that
// is the candidate not opening the part, not the part being unreadable. The
// case is built directly: the part is encrypted under "changeit" around bytes
// that are not SafeContents, the MAC takes the empty password, and the part
// is rebuilt until the empty password's key gives invalid padding, so only
// the retry with "changeit" decrypts it.
func TestPKCS12WrongPasswordPaddingIsNotUnreadable(t *testing.T) {
	a := ksTestCert(t, ksTestECDSA(t), "listed", false)
	listed := ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw))
	var part ksContentInfo
	for i := 0; ; i++ {
		if i > 64 {
			t.Fatal("could not build a part the empty password does not decrypt")
		}
		part = ksEncryptedBytes(t, "changeit", 1, []byte("decrypts with valid padding, but is no SafeContents"))
		var ed ksEncryptedData
		if err := ksUnmarshalAll(part.Content.Bytes, &ed); err != nil {
			t.Fatal(err)
		}
		_, open, ok := ksP12Decrypter(ed.EncryptedContentInfo.ContentEncryptionAlgorithm, ed.EncryptedContentInfo.EncryptedContent.Bytes)
		if !ok {
			t.Fatal("the part's scheme is not decrypted here")
		}
		if _, ok := open(ksP12Password{bmp: []byte{0, 0}, utf8: []byte{}, empty: true}); !ok {
			break
		}
	}
	got, err := ParsePKCS12(ksBuildPFX(t, ksStr(""), listed, part), true)
	if err != nil {
		t.Fatal(err)
	}
	ks := got.Keystore
	if strings.Contains(ks.Unknown, "not a list of entries") || !strings.Contains(ks.Unknown, "neither empty nor a well-known default") ||
		ks.DefaultPassword == nil || *ks.DefaultPassword {
		t.Fatalf("a wrong password's garbage was called unreadable: %+v", ks)
	}
	// Under the password that passed the check, the same garbage is
	// unreadable: that password is the store's.
	got, err = ParsePKCS12(ksBuildPFX(t, ksStr("changeit"), part), true)
	if err != nil || !strings.Contains(got.Keystore.Unknown, "not a list of entries") {
		t.Fatalf("under the store's password: %v %+v", err, got.Keystore)
	}
}
