package hostcrypto

import (
	"encoding/asn1"
	"encoding/binary"
	"testing"
)

// BCFKS is built here from Bouncy Castle's published ASN.1 module for the
// object store, not from a file Bouncy Castle wrote; see parse_bcfks.go.

func ksAlgID(t *testing.T, oid asn1.ObjectIdentifier, params any) ksAlgorithmIdentifier {
	t.Helper()
	a := ksAlgorithmIdentifier{Algorithm: oid}
	if params != nil {
		der, err := asn1.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		a.Parameters = asn1.RawValue{FullBytes: der}
	}
	return a
}

var (
	ksOIDHmacSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	ksOIDAES256CCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 47}
)

func ksMarshal(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func ksTestPBKDF2Alg(t *testing.T, iters int) ksAlgorithmIdentifier {
	type p struct {
		Salt       []byte
		Iterations int
		KeyLength  int
		PRF        ksAlgorithmIdentifier
	}
	return ksAlgID(t, ksOIDPBKDF2, p{Salt: make([]byte, 32), Iterations: iters, KeyLength: 32, PRF: ksAlgID(t, ksOIDHmacSHA512, asn1.NullRawValue)})
}

func TestParseBCFKS(t *testing.T) {
	type ccm struct {
		Nonce  []byte
		ICVLen int
	}
	enc := ksAlgID(t, ksOIDPBES2, ksPBES2Params{KDF: ksTestPBKDF2Alg(t, 51200), Enc: ksAlgID(t, ksOIDAES256CCM, ccm{make([]byte, 12), 16})})
	type encStore struct {
		Alg  ksAlgorithmIdentifier
		Data []byte
	}
	type store struct {
		Data  encStore
		Check ksBCFKSPbkdMac
	}
	scrypt := ksAlgID(t, ksOIDScrypt, ksScryptParams{Salt: make([]byte, 16), CostParameter: 16384, BlockSize: 8, Parallelization: 1, KeyLength: 64})
	for _, tc := range []struct {
		name string
		kdf  ksAlgorithmIdentifier
		want string
	}{
		{"pbkdf2", ksTestPBKDF2Alg(t, 51200), "PBES2 (PBKDF2-HMAC-SHA512, 51200 iterations, AES-256-CCM); MAC: HMAC-SHA512 (PBKDF2-HMAC-SHA512, 51200 iterations)"},
		{"scrypt", scrypt, "PBES2 (PBKDF2-HMAC-SHA512, 51200 iterations, AES-256-CCM); MAC: HMAC-SHA512 (scrypt N=16384 r=8 p=1)"},
	} {
		der := ksMarshal(t, store{
			Data:  encStore{Alg: enc, Data: []byte{1, 2, 3}},
			Check: ksBCFKSPbkdMac{MacAlgorithm: ksAlgID(t, ksOIDHmacSHA512, nil), PbkdAlgorithm: tc.kdf, Mac: make([]byte, 64)},
		})
		got, err := ParseBCFKS(der)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Keystore.Type != KeystoreBCFKS || got.Keystore.Opened != OpenedNot || got.Keystore.Protection != tc.want {
			t.Errorf("%s: %+v", tc.name, got.Keystore)
		}
		for n := 0; n < len(der); n++ {
			if _, err := ParseBCFKS(der[:n]); err == nil {
				t.Fatalf("%s: prefix %d accepted", tc.name, n)
			}
		}
	}
	for name, b := range map[string][]byte{
		"empty":     nil,
		"integer":   ksMarshal(t, 5),
		"one field": ksMarshal(t, struct{ A []byte }{[]byte{1}}),
	} {
		got, err := ParseBCFKS(b)
		if err == nil || got.Keystore.Type != KeystoreBCFKS {
			t.Errorf("%s: %v %+v", name, err, got.Keystore)
		}
	}
}

func TestParseBKS(t *testing.T) {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint32(b, 2)
	b = binary.BigEndian.AppendUint32(b, 20)
	b = append(b, make([]byte, 20)...)
	b = binary.BigEndian.AppendUint32(b, 1500)
	b = append(b, 0)
	got, err := ParseBKS(b)
	if err != nil || got.Keystore.Type != KeystoreBKS || got.Keystore.Protection != "BKS or UBER (version 2, 1500 iterations)" || got.Keystore.Opened != OpenedNot {
		t.Errorf("bks: %v %+v", err, got.Keystore)
	}
	for n := 0; n < 32; n++ {
		if _, err := ParseBKS(b[:n]); err == nil {
			t.Fatalf("prefix %d accepted", n)
		}
	}
	for name, bad := range map[string][]byte{
		"version 9":  ksPatchU32(append([]byte{}, b...), 0, 9),
		"huge salt":  ksPatchU32(append([]byte{}, b...), 4, 0xffffffff),
		"zero iters": ksPatchU32(append([]byte{}, b...), 28, 0),
	} {
		if _, err := ParseBKS(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIdentifyNSSDatabase(t *testing.T) {
	for _, tc := range []struct {
		files []string
		ok    bool
		want  string
	}{
		{[]string{"cert9.db", "key4.db", "pkcs11.txt"}, true, "NSS SQLite database (cert9.db, key4.db)"},
		{[]string{"cert8.db", "key3.db", "secmod.db"}, true, "NSS legacy Berkeley DB database (cert8.db, key3.db)"},
		{[]string{"key4.db"}, true, "NSS SQLite database (cert9.db missing, key4.db)"},
		{[]string{"Cert9.DB", "key4.db", "cert8.db", "key3.db"}, true, "NSS SQLite database (cert9.db, key4.db); NSS legacy Berkeley DB database (cert8.db, key3.db)"},
		{[]string{"prefs.js", "places.sqlite"}, false, ""},
	} {
		ks, ok := IdentifyNSSDatabase(tc.files)
		if ok != tc.ok || ks.Protection != tc.want || (ok && (ks.Type != KeystoreNSS || ks.Opened != OpenedNot)) {
			t.Errorf("%v: %v %+v", tc.files, ok, ks)
		}
	}
}

func TestIdentifyKeychain(t *testing.T) {
	ks, ok := IdentifyKeychain([]byte("kych\x00\x01\x00\x00rest"))
	if !ok || ks.Type != KeystoreKeychain || ks.Opened != OpenedNot {
		t.Errorf("keychain: %v %+v", ok, ks)
	}
	for _, b := range [][]byte{nil, []byte("kyc"), []byte("SQLite format 3\x00")} {
		if _, ok := IdentifyKeychain(b); ok {
			t.Errorf("%q identified as a keychain", b)
		}
	}
}
