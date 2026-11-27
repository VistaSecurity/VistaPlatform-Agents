package hostcrypto

import (
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

// TestEmptyPasswordIsNotADefault: with the
// default-password opt-in, a store whose password is empty reads as
// needing none (no_password, DefaultPassword false); only a well-known
// default (changeit) is default_password/true; a real password is
// DefaultPassword false and opens nothing it would need a password for.
// Every store is generated here. Without the opt-in only the empty password
// is tried, and DefaultPassword stays nil.
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
			"Real-Pass-7": {OpenedNot, false, 0}, // the key bag's plain part is listed; the store is not opened
		}},
		{"jks", func(pw string) (KeystoreContents, error) {
			return ParseJKS(ksMakeJKSFixture(t, ksMagicJKS, 2, pw).store, true)
		}, map[string]want{
			// A JKS lists without a password whatever it is; the digest says
			// which password it has, and only an empty one is no_password.
			"":            {OpenedWithoutPassword, false, -1},
			"changeit":    {OpenedDefaultPassword, true, -1},
			"Real-Pass-7": {OpenedNot, false, -1},
		}},
		{"jceks", func(pw string) (KeystoreContents, error) {
			return ParseJKS(ksMakeJKSFixture(t, ksMagicJCEKS, 2, pw).store, true)
		}, map[string]want{
			"":            {OpenedWithoutPassword, false, -1},
			"changeit":    {OpenedDefaultPassword, true, -1},
			"Real-Pass-7": {OpenedNot, false, -1},
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
	// Without the opt-in the empty password is still tried: it opens the
	// store whose password is empty and lists its certificate; a store under
	// a default or a real password stays not_opened. DefaultPassword is nil.
	for pw, w := range map[string]want{
		"":            {OpenedWithoutPassword, false, 1},
		"changeit":    {OpenedNot, false, 0},
		"Real-Pass-7": {OpenedNot, false, 0},
	} {
		off, err := ParsePKCS12(mkP12(pw), false)
		if err != nil || off.Keystore.DefaultPassword != nil || off.Keystore.Opened != w.opened || len(off.Certificates) != w.entries {
			t.Fatalf("without the opt-in %q: %v %+v", pw, err, off.Keystore)
		}
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

// ksEmptyPwMalformedBag is a safeContentsBag whose value is not SafeContents:
// a list of bags that parses, and a walk that cannot read it.
func ksEmptyPwMalformedBag(t *testing.T) ksSafeBag {
	inner, err := asn1.Marshal([]byte("not a SafeContents"))
	if err != nil {
		t.Fatal(err)
	}
	return ksSafeBag{ID: ksOIDSafeContBag, Value: ksExplicit0(inner)}
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
	// A no-MAC store whose cheapest part (the verifier, proved by the
	// empty password) holds a bag the walk cannot read.
	malformed := ksEncryptedPart(t, "", 1, ksEmptyPwMalformedBag(t))
	listedCostlier := ksEncryptedPart(t, "", 2, ksCertSafeBag(t, a.Raw))
	for _, tc := range []struct {
		name     string
		pfx      []byte
		want     []string
		wantNot  []string
		wantCert int
		// notTried is the DefaultsNotTried a store gives when a default was
		// not tried on a password-based part; DefaultPassword is then nil.
		notTried string
	}{
		{"(a) public-key encrypted part", ksBuildPFX(t, ksStr(""), listed, ksEmptyPwEnvelopedPart(t)), []string{untried}, []string{refused, unreadable}, 1, ""},
		{"(b) a password scheme not decrypted here", ksBuildPFX(t, ksStr(""), listed, ksEmptyPwUnsupportedPart(t)), []string{untried}, []string{refused, unreadable}, 1, ksNotTriedScheme},
		{"(c) the verifier part decrypts to something that is not entries", ksBuildPFX(t, nil, malformed, listedCostlier), []string{unreadable}, []string{refused, untried}, 1, ""},
		{"MAC empty, a part under a real password", ksBuildPFX(t, ksStr(""), listed, ksEncryptedPart(t, "Real-Pass-7", 1, ksCertSafeBag(t, b.Raw))), []string{refused}, []string{unreadable, untried}, 1, ""},
		{"no MAC, cheap part empty, costlier part real", ksBuildPFX(t, nil, listed, ksEncryptedPart(t, "Real-Pass-7", 50, ksCertSafeBag(t, b.Raw))), []string{refused}, []string{unreadable, untried}, 1, ""},
		{"both kinds", ksBuildPFX(t, ksStr(""), listed, ksEncryptedPart(t, "Real-Pass-7", 1, ksCertSafeBag(t, b.Raw)), ksEmptyPwEnvelopedPart(t)), []string{refused, untried}, []string{unreadable}, 1, ""},
	} {
		got, err := ParsePKCS12(tc.pfx, true)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		ks := got.Keystore
		answered := ks.DefaultPassword != nil && !*ks.DefaultPassword
		if tc.notTried != "" {
			answered = ks.DefaultPassword == nil && got.DefaultsNotTried == tc.notTried
		}
		if ks.Opened != OpenedWithoutPassword || !answered || ks.EntryCount != nil || len(got.Certificates) != tc.wantCert {
			t.Errorf("%s: %+v (not tried %q), %d certificates", tc.name, ks, got.DefaultsNotTried, len(got.Certificates))
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

	// Without the opt-in the same stores: the empty password alone, so no
	// default answer, and the same "opened" whenever the empty password is
	// what opens the store.
	for name, b := range map[string][]byte{"fits": fits, "same": same, "cut": cut} {
		off, err := ParsePKCS12(b, false)
		if err != nil || off.DefaultsNotTried != "" || off.Keystore.DefaultPassword != nil {
			t.Fatalf("%s without the opt-in: %v %q %+v", name, err, off.DefaultsNotTried, off.Keystore)
		}
		want := OpenedWithoutPassword // the MAC is the empty password's
		if name == "fits" {
			want = OpenedNot // the MAC is changeit's
		}
		if off.Keystore.Opened != want || len(off.Certificates) != 0 {
			t.Fatalf("%s without the opt-in: %+v, %d certificates", name, off.Keystore, len(off.Certificates))
		}
	}
}

// TestPKCS12EmptyPasswordSameAcrossTheCostWindow: a store whose password is
// empty reads the same with the opt-in on and off at every iteration count
// the empty password alone can afford; past what the defaults can afford the
// opt-in says they were cut, and leaves default_password absent.
func TestPKCS12EmptyPasswordSameAcrossTheCostWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("derives keys at up to 1,900,000 iterations")
	}
	a := ksTestCert(t, ksTestECDSA(t), "window", false)
	for _, iters := range []int{1, 600_000, 900_000, 1_900_000} {
		for _, mac := range []bool{false, true} {
			var macPW *string
			if mac {
				macPW = ksStr("")
			}
			b := ksBuildPFX(t, macPW, ksEncryptedPart(t, "", iters, ksCertSafeBag(t, a.Raw)))
			off, err1 := ParsePKCS12(b, false)
			on, err2 := ParsePKCS12(b, true)
			if err1 != nil || err2 != nil {
				t.Fatal(err1, err2)
			}
			label := fmt.Sprintf("%d iterations, MAC %v", iters, mac)
			if off.Keystore.Opened != OpenedWithoutPassword || on.Keystore.Opened != OpenedWithoutPassword || len(off.Certificates) != 1 || len(on.Certificates) != 1 {
				t.Errorf("%s: off %q (%d), on %q (%d)", label, off.Keystore.Opened, len(off.Certificates), on.Keystore.Opened, len(on.Certificates))
			}
			// Where the defaults do not fit, they are said to be cut.
			if d := on.Keystore.DefaultPassword; on.DefaultsNotTried == "" {
				if d == nil || *d {
					t.Errorf("%s: default %v", label, d)
				}
			} else if d != nil || on.DefaultsNotTried != ksNotTriedDefaultsCost {
				t.Errorf("%s: default %v, not tried %q", label, d, on.DefaultsNotTried)
			}
		}
	}
}

// TestPKCS12NoAnswerWhenAPartWasNotTried: when no candidate passes the
// store's check, the other parts are still tried, so "does a default open
// this?" is answered from what was tried, and is absent when the budget cut
// a try.
func TestPKCS12NoAnswerWhenAPartWasNotTried(t *testing.T) {
	a := ksTestCert(t, ksTestECDSA(t), "a", false)
	b := ksTestCert(t, ksTestECDSA(t), "b", false)
	// No MAC: the cheapest part under a real password, the other under
	// changeit. Every part is its own check: a default opens one.
	noMAC := ksBuildPFX(t, nil, ksEncryptedPart(t, "Real-Pass-7", 1, ksCertSafeBag(t, a.Raw)), ksEncryptedPart(t, "changeit", 50, ksCertSafeBag(t, b.Raw)))
	got, err := ParsePKCS12(noMAC, true)
	if ks := got.Keystore; err != nil || ks.Opened != OpenedDefaultPassword || ks.DefaultPassword == nil || !*ks.DefaultPassword || len(got.Certificates) != 1 || ks.EntryCount != nil {
		t.Errorf("no MAC, real then changeit: %v %+v", err, ks)
	}
	off, _ := ParsePKCS12(noMAC, false)
	if ks := off.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword != nil || len(off.Certificates) != 0 {
		t.Errorf("no MAC, real then changeit, opt-in off: %+v", ks)
	}
	// A MAC under a real password and a part under changeit: the MAC is not
	// opened, so the store is not; a default does open part of it.
	locked := ksBuildPFX(t, ksStr("Real-Pass-7"), ksEncryptedPart(t, "changeit", 1, ksCertSafeBag(t, a.Raw)))
	got, err = ParsePKCS12(locked, true)
	if ks := got.Keystore; err != nil || ks.Opened != OpenedNot || ks.DefaultPassword == nil || !*ks.DefaultPassword || len(got.Certificates) != 1 ||
		!strings.Contains(ks.Unknown, "opens part of it") {
		t.Errorf("MAC real, part changeit: %v %+v", err, ks)
	}
	// Every part refused every candidate: the answer is false.
	refused := ksBuildPFX(t, ksStr("Real-Pass-7"), ksEncryptedPart(t, "Real-Pass-7", 1, ksCertSafeBag(t, a.Raw)))
	got, _ = ParsePKCS12(refused, true)
	if ks := got.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword == nil || *ks.DefaultPassword || got.DefaultsNotTried != "" {
		t.Errorf("all refused: %q %+v", got.DefaultsNotTried, ks)
	}
	if testing.Short() {
		return
	}
	// The same as "locked", where the budget cannot try changeit on the part
	// after the MAC refused: not checked, so absent, and said why.
	costly := ksBuildPFX(t, ksStr("Real-Pass-7"), ksEncryptedPart(t, "changeit", 1_200_000, ksCertSafeBag(t, a.Raw)))
	got, _ = ParsePKCS12(costly, true)
	if ks := got.Keystore; ks.Opened != OpenedNot || ks.DefaultPassword != nil || got.DefaultsNotTried != ksNotTriedCost {
		t.Errorf("MAC real, costly part: %q %+v", got.DefaultsNotTried, ks)
	}
}

// TestPKCS12UncomputableMACIsNotOpened: a MAC this code does not compute
// cannot be stood in for by a part that decrypts: not opened, and why.
func TestPKCS12UncomputableMACIsNotOpened(t *testing.T) {
	a := ksTestCert(t, ksTestECDSA(t), "a", false)
	authSafe, err := asn1.Marshal([]ksContentInfo{ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw))})
	if err != nil {
		t.Fatal(err)
	}
	os, _ := asn1.Marshal(authSafe)
	pfx, err := asn1.Marshal(ksPFX{Version: 3, AuthSafe: ksContentInfo{ContentType: ksOIDData, Content: ksExplicit0(os)}, MacData: ksMacData{
		// HMAC-MD5: named, and not computed here.
		Mac:     ksDigestInfo{Algorithm: ksAlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}, Parameters: asn1.NullRawValue}, Digest: make([]byte, 16)},
		MacSalt: []byte("macsalt!"), Iterations: 2048,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, try := range []bool{false, true} {
		got, err := ParsePKCS12(pfx, try)
		ks := got.Keystore
		wantNotTried := ""
		if try {
			wantNotTried = ksNotTriedMAC
		}
		if err != nil || ks.Opened != OpenedNot || ks.DefaultPassword != nil || got.DefaultsNotTried != wantNotTried || !strings.Contains(ks.Unknown, "MAC") {
			t.Errorf("opt-in %v: %v %q %+v", try, err, got.DefaultsNotTried, ks)
		}
	}
}

// ksEmptyPwPart builds an encryptedData part under password around plain,
// rebuilt until the empty password's key gives valid padding (wantValid) or
// invalid padding (!wantValid), so a test does not rest on chance.
func ksEmptyPwPart(t *testing.T, password string, plain []byte, wantValid bool) ksContentInfo {
	for i := 0; i < 4096; i++ {
		part := ksEncryptedBytes(t, password, 1, plain)
		var ed ksEncryptedData
		if err := ksUnmarshalAll(part.Content.Bytes, &ed); err != nil {
			t.Fatal(err)
		}
		_, open, ok := ksP12Decrypter(ed.EncryptedContentInfo.ContentEncryptionAlgorithm, ed.EncryptedContentInfo.EncryptedContent.Bytes)
		if !ok {
			t.Fatal("the part's scheme is not decrypted here")
		}
		if _, valid := open(ksP12Password{bmp: []byte{0, 0}, utf8: []byte{}, empty: true}); valid == wantValid {
			return part
		}
	}
	t.Fatal("could not build the part")
	return ksContentInfo{}
}

// TestPKCS12WrongPasswordPaddingIsNotUnreadable: a password that is not
// proved for a part, and happens to give valid padding (about once in 256),
// decrypts it to garbage; that is the password not opening the part, not the
// part being unreadable. Built directly, not left to chance.
func TestPKCS12WrongPasswordPaddingIsNotUnreadable(t *testing.T) {
	a := ksTestCert(t, ksTestECDSA(t), "listed", false)
	b := ksTestCert(t, ksTestECDSA(t), "hidden", false)
	listed := ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw))
	notEntries := []byte("decrypts with valid padding, but is no SafeContents")
	const refused, unreadable = "neither empty nor a well-known default", "not a list of entries"
	check := func(name string, pfx []byte) {
		t.Helper()
		got, err := ParsePKCS12(pfx, true)
		if err != nil {
			t.Fatal(err)
		}
		ks := got.Keystore
		if strings.Contains(ks.Unknown, unreadable) || !strings.Contains(ks.Unknown, refused) || ks.DefaultPassword == nil || *ks.DefaultPassword {
			t.Fatalf("%s: %+v", name, ks)
		}
	}
	// A retried candidate ("changeit") with valid padding over garbage.
	check("a retry's accident", ksBuildPFX(t, ksStr(""), listed, ksEmptyPwPart(t, "changeit", notEntries, false)))
	// The MAC's own password (empty), proved for the MAC but not for this
	// part, with valid padding over the part's real contents.
	inner, err := asn1.Marshal([]ksSafeBag{ksCertSafeBag(t, b.Raw)})
	if err != nil {
		t.Fatal(err)
	}
	check("the MAC password's accident", ksBuildPFX(t, ksStr(""), listed, ksEmptyPwPart(t, "Real-Pass-7", inner, true)))
	// Proved for the part (the verifier of a store without a MAC), the same
	// kind of failure is unreadable.
	got, err := ParsePKCS12(ksBuildPFX(t, nil, ksEncryptedPart(t, "", 1, ksEmptyPwMalformedBag(t)), ksEncryptedPart(t, "", 2, ksCertSafeBag(t, a.Raw))), true)
	if err != nil || !strings.Contains(got.Keystore.Unknown, unreadable) {
		t.Fatalf("proved for the part: %v %+v", err, got.Keystore)
	}
}

// TestPKCS12UntriedPasswordScheme: a password-based part under a scheme not
// decrypted here leaves "does a default open this?" unanswered; a
// public-key encrypted part does not; a default found still answers true.
func TestPKCS12UntriedPasswordScheme(t *testing.T) {
	a := ksTestCert(t, ksTestECDSA(t), "listed", false)
	for _, tc := range []struct {
		name     string
		pfx      []byte
		deflt    *bool
		notTried string
	}{
		{"an unsupported password scheme", ksBuildPFX(t, ksStr(""), ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw)), ksEmptyPwUnsupportedPart(t)), nil, ksNotTriedScheme},
		{"a public-key encrypted part", ksBuildPFX(t, ksStr(""), ksEncryptedPart(t, "", 1, ksCertSafeBag(t, a.Raw)), ksEmptyPwEnvelopedPart(t)), boolPtrEmptyPw(false), ""},
		{"a default found beside an unsupported scheme", ksBuildPFX(t, ksStr("changeit"), ksEncryptedPart(t, "changeit", 1, ksCertSafeBag(t, a.Raw)), ksEmptyPwUnsupportedPart(t)), boolPtrEmptyPw(true), ""},
	} {
		got, err := ParsePKCS12(tc.pfx, true)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		d := got.Keystore.DefaultPassword
		if (d == nil) != (tc.deflt == nil) || (d != nil && *d != *tc.deflt) || got.DefaultsNotTried != tc.notTried {
			t.Errorf("%s: default %v, not tried %q", tc.name, d, got.DefaultsNotTried)
		}
	}
}

func boolPtrEmptyPw(b bool) *bool { return &b }
