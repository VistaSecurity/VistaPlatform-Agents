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
		build func(pw string) []byte
		want  map[string]want
	}{
		{"pkcs12", func(pw string) (KeystoreContents, error) { return ParsePKCS12(mkP12(pw), true) }, nil, map[string]want{
			"":            {OpenedWithoutPassword, false, 1},
			"changeit":    {OpenedDefaultPassword, true, 1},
			"Real-Pass-7": {OpenedWithoutPassword, false, 0}, // the key bag's plain part only
		}},
		{"jks", func(pw string) (KeystoreContents, error) {
			return ParseJKS(ksMakeJKSFixture(t, ksMagicJKS, 2, pw).store, true)
		}, nil, map[string]want{
			// A JKS lists without a password whatever it is; the digest says
			// which password it has.
			"":            {OpenedWithoutPassword, false, -1},
			"changeit":    {OpenedDefaultPassword, true, -1},
			"Real-Pass-7": {OpenedWithoutPassword, false, -1},
		}},
		{"jceks", func(pw string) (KeystoreContents, error) {
			return ParseJKS(ksMakeJKSFixture(t, ksMagicJCEKS, 2, pw).store, true)
		}, nil, map[string]want{
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
