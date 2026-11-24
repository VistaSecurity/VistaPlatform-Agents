package hostcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// A keytab encoder for the tests, from the layout in parse_keytab.go.

type ksKeytabRec struct {
	realm   string
	comps   []string
	vno8    uint8
	enctype uint16
	key     []byte
	vno32   *uint32 // nil: no trailer
	hole    int     // >0: write a hole of this many bytes instead
}

func ksBuildKeytab(recs ...ksKeytabRec) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(0x0502))
	for _, r := range recs {
		if r.hole > 0 {
			_ = binary.Write(&b, binary.BigEndian, int32(-r.hole))
			b.Write(make([]byte, r.hole))
			continue
		}
		var rec bytes.Buffer
		str := func(s []byte) { _ = binary.Write(&rec, binary.BigEndian, uint16(len(s))); rec.Write(s) }
		_ = binary.Write(&rec, binary.BigEndian, uint16(len(r.comps)))
		str([]byte(r.realm))
		for _, c := range r.comps {
			str([]byte(c))
		}
		_ = binary.Write(&rec, binary.BigEndian, uint32(1))          // KRB5_NT_PRINCIPAL
		_ = binary.Write(&rec, binary.BigEndian, uint32(1767225600)) // timestamp
		rec.WriteByte(r.vno8)
		_ = binary.Write(&rec, binary.BigEndian, r.enctype)
		str(r.key)
		if r.vno32 != nil {
			_ = binary.Write(&rec, binary.BigEndian, *r.vno32)
		}
		_ = binary.Write(&b, binary.BigEndian, int32(rec.Len()))
		b.Write(rec.Bytes())
	}
	return b.Bytes()
}

func ksRandKey(t testing.TB, n int) []byte {
	t.Helper()
	k := make([]byte, n)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseKeytab(t *testing.T) {
	k1, k2, k3 := ksRandKey(t, 32), ksRandKey(t, 16), ksRandKey(t, 16)
	vno := uint32(300)
	zero := uint32(0)
	kt := ksBuildKeytab(
		ksKeytabRec{realm: "EXAMPLE.TEST", comps: []string{"HTTP", "web.example.test"}, vno8: 3, enctype: 18, key: k1},
		ksKeytabRec{hole: 40},
		ksKeytabRec{realm: "EXAMPLE.TEST", comps: []string{"host", "db.example.test"}, vno8: 44, enctype: 23, key: k2, vno32: &vno},
		ksKeytabRec{realm: "EXAMPLE.TEST", comps: []string{"svc"}, vno8: 7, enctype: 99, key: k3, vno32: &zero},
	)
	got, err := ParseKeytab(kt)
	if err != nil {
		t.Fatal(err)
	}
	ks := got.Keystore
	if ks.Type != KeystoreKeytab || ks.Opened != OpenedWithoutPassword || ks.DefaultPassword != nil || ks.EntryCount == nil || *ks.EntryCount != 3 {
		t.Fatalf("keystore: %+v", ks)
	}
	want := []KeystoreEntry{
		{Kind: "kerberos_key", Principal: "HTTP/web.example.test@EXAMPLE.TEST", KVNO: 3, EncryptionType: "aes256-cts-hmac-sha1-96"},
		// The 32-bit trailer overrides the 8-bit kvno, which wraps at 255.
		{Kind: "kerberos_key", Principal: "host/db.example.test@EXAMPLE.TEST", KVNO: 300, EncryptionType: "rc4-hmac"},
		// A zero trailer does not.
		{Kind: "kerberos_key", Principal: "svc@EXAMPLE.TEST", KVNO: 7, EncryptionType: "etype-99"},
	}
	for i, w := range want {
		if ks.Entries[i] != w {
			t.Errorf("entry %d: got %+v want %+v", i, ks.Entries[i], w)
		}
	}
	ksAssertNoSecret(t, "keytab", got, k1, k2, k3)
}

func TestKsKerberosEnctypeNames(t *testing.T) {
	for n, want := range map[uint16]string{
		17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96",
		19: "aes128-cts-hmac-sha256-128", 20: "aes256-cts-hmac-sha384-192",
		23: "rc4-hmac", 16: "des3-cbc-sha1", 1: "des-cbc-crc", 3: "des-cbc-md5",
		25: "camellia128-cts-cmac", 26: "camellia256-cts-cmac", 4242: "etype-4242",
	} {
		if got := ksKerberosEnctypeName(n); got != want {
			t.Errorf("%d: %q", n, got)
		}
	}
}

func TestParseKeytab_HostileInput(t *testing.T) {
	vno := uint32(9)
	kt := ksBuildKeytab(
		ksKeytabRec{realm: "R", comps: []string{"a", "b"}, enctype: 17, key: ksRandKey(t, 16), vno32: &vno},
		ksKeytabRec{hole: 8},
		ksKeytabRec{realm: "R", comps: []string{"c"}, enctype: 18, key: ksRandKey(t, 32)},
	)
	for n := 0; n <= len(kt); n++ {
		got, err := ParseKeytab(kt[:n])
		if n == len(kt) {
			if err != nil || *got.Keystore.EntryCount != 2 {
				t.Fatalf("whole file: %v %+v", err, got.Keystore)
			}
			continue
		}
		if err == nil && got.Keystore.EntryCount != nil && *got.Keystore.EntryCount == 2 {
			t.Fatalf("prefix %d read as complete", n)
		}
	}
	for name, b := range map[string][]byte{
		"empty":              nil,
		"wrong version":      {0x05, 0x03},
		"record past end":    {0x05, 0x02, 0x00, 0x00, 0x10, 0x00, 0x01},
		"hole past end":      {0x05, 0x02, 0xff, 0xff, 0xff, 0x00},
		"min int hole":       {0x05, 0x02, 0x80, 0x00, 0x00, 0x00},
		"components too big": ksPatchU16(ksBuildKeytab(ksKeytabRec{realm: "R", comps: []string{"a"}, key: []byte{1}}), 6, 0xffff),
		"key length too big": ksPatchU16(ksBuildKeytab(ksKeytabRec{realm: "R", comps: []string{"a"}, key: []byte{1}}), 6+2+3+3+4+4+1+2, 0xffff),
	} {
		got, err := ParseKeytab(b)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if got.Keystore.EntryCount != nil {
			t.Errorf("%s: claimed a count", name)
		}
	}
	// The legacy native-order version is refused by name, not guessed.
	got, err := ParseKeytab([]byte{0x05, 0x01, 0, 0, 0, 0})
	if err == nil || got.Keystore.Type != KeystoreKeytab || got.Keystore.Protection == "" {
		t.Errorf("0x0501: %v %+v", err, got.Keystore)
	}
	// Zero entries.
	got, err = ParseKeytab([]byte{0x05, 0x02})
	if err != nil || *got.Keystore.EntryCount != 0 {
		t.Errorf("empty keytab: %v", err)
	}
	// The cap keeps counting.
	var recs []ksKeytabRec
	for i := 0; i < 9; i++ {
		recs = append(recs, ksKeytabRec{realm: "R", comps: []string{"p"}, enctype: 18, key: []byte{1, 2}})
	}
	got, err = ksParseKeytab(ksBuildKeytab(recs...), 4)
	if err != nil || len(got.Keystore.Entries) != 4 || *got.Keystore.EntryCount != 9 {
		t.Errorf("cap: %v %d %v", err, len(got.Keystore.Entries), got.Keystore.EntryCount)
	}
}

func FuzzParseKeytab(f *testing.F) {
	vno := uint32(5)
	f.Add(ksBuildKeytab(
		ksKeytabRec{realm: "EXAMPLE.TEST", comps: []string{"HTTP", "h"}, enctype: 18, key: make([]byte, 32), vno32: &vno},
		ksKeytabRec{hole: 12},
		ksKeytabRec{realm: "EXAMPLE.TEST", comps: []string{"x"}, enctype: 23, key: make([]byte, 16)},
	))
	f.Add([]byte{0x05, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ksParseKeytab(b, 50)
		if len(got.Keystore.Entries) > 50 {
			t.Fatal("cap exceeded")
		}
		if err != nil && got.Keystore.EntryCount != nil {
			t.Fatal("a count claimed for a malformed keytab")
		}
	})
}
