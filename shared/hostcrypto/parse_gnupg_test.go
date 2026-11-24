package hostcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the test recomputes the format's fingerprint
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// OpenPGP packets are built by hand here, from RFC 4880 / RFC 9580 framing.

const ksUserID = "Alice Example <alice@example.org>"

func ksPGPOld(tag int, body []byte) []byte {
	var b bytes.Buffer
	switch {
	case len(body) < 256:
		b.WriteByte(0x80 | byte(tag)<<2) // length type 0
		b.WriteByte(byte(len(body)))
	case len(body) < 65536:
		b.WriteByte(0x80 | byte(tag)<<2 | 1)
		_ = binary.Write(&b, binary.BigEndian, uint16(len(body)))
	default:
		b.WriteByte(0x80 | byte(tag)<<2 | 2)
		_ = binary.Write(&b, binary.BigEndian, uint32(len(body)))
	}
	b.Write(body)
	return b.Bytes()
}

func ksPGPNew(tag int, body []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0xc0 | byte(tag))
	n := len(body)
	switch {
	case n < 192:
		b.WriteByte(byte(n))
	case n < 8384:
		n -= 192
		b.WriteByte(byte(n>>8) + 192)
		b.WriteByte(byte(n))
	default:
		b.WriteByte(255)
		_ = binary.Write(&b, binary.BigEndian, uint32(n))
	}
	b.Write(body)
	return b.Bytes()
}

// ksPGPPartial writes a new-format packet with one 512-byte partial chunk.
func ksPGPPartial(tag int, body []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0xc0 | byte(tag))
	b.WriteByte(224 + 9) // 1<<9 = 512
	b.Write(body[:512])
	rest := body[512:]
	b.WriteByte(byte(len(rest)))
	b.Write(rest)
	return b.Bytes()
}

func ksMPIOf(v []byte) []byte {
	for len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	bits := len(v) * 8
	for i := 7; i >= 0 && v[0]&(1<<i) == 0; i-- {
		bits--
	}
	return append([]byte{byte(bits >> 8), byte(bits)}, v...)
}

var ksPGPTime = []byte{0x69, 0x55, 0x00, 0x00}

func ksPGPv4(algo byte, material []byte) []byte {
	return append(append([]byte{4}, ksPGPTime...), append([]byte{algo}, material...)...)
}

func ksPGPv4FP(body []byte) string {
	h := sha1.New() //nolint:gosec // the format's fingerprint
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

type ksPGPFixture struct {
	ring             []byte
	rsaFP, edFP      string
	cvFP, p256FP, v6 string
}

func ksMakePGPRing(t testing.TB) ksPGPFixture {
	t.Helper()
	rsaKey := ksTestRSA(t)
	rsaBody := ksPGPv4(1, append(ksMPIOf(rsaKey.N.Bytes()), ksMPIOf([]byte{1, 0, 1})...))

	ed := ksTestEd25519(t)
	edOID := []byte("\x2b\x06\x01\x04\x01\xda\x47\x0f\x01")
	edBody := ksPGPv4(22, append(append([]byte{byte(len(edOID))}, edOID...), ksMPIOf(append([]byte{0x40}, ed.Public().(ed25519.PublicKey)...))...))

	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cvOID := []byte("\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01")
	cvMat := append(append([]byte{byte(len(cvOID))}, cvOID...), ksMPIOf(append([]byte{0x40}, x.PublicKey().Bytes()...))...)
	cvBody := ksPGPv4(18, append(cvMat, 3, 1, 8, 7))

	ec := ksTestECDSA(t)
	ecPub, err := ec.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	p256OID := []byte("\x2a\x86\x48\xce\x3d\x03\x01\x07")
	p256Body := ksPGPv4(19, append(append([]byte{byte(len(p256OID))}, p256OID...), ksMPIOf(ecPub)...))

	ed6 := ksTestEd25519(t).Public().(ed25519.PublicKey)
	v6Body := append(append([]byte{6}, ksPGPTime...), 27, 0, 0, 0, 32)
	v6Body = append(v6Body, ed6...)
	h := sha256.New()
	h.Write([]byte{0x9b, 0, 0, 0, byte(len(v6Body))})
	h.Write(v6Body)

	var ring bytes.Buffer
	ring.Write(ksPGPOld(ksPGPTagPublicKey, rsaBody))
	ring.Write(ksPGPOld(13, []byte(ksUserID)))
	ring.Write(ksPGPOld(2, bytes.Repeat([]byte{0x55}, 300))) // a signature, stepped over
	ring.Write(ksPGPNew(ksPGPTagPublicKey, edBody))
	ring.Write(ksPGPNew(13, []byte(ksUserID)))
	ring.Write(ksPGPNew(ksPGPTagPublicSubkey, cvBody))
	ring.Write(ksPGPPartial(11, bytes.Repeat([]byte{0x42}, 600))) // partial lengths
	ring.Write(ksPGPNew(ksPGPTagPublicKey, p256Body))
	ring.Write(ksPGPNew(ksPGPTagPublicKey, v6Body))
	return ksPGPFixture{
		ring:  ring.Bytes(),
		rsaFP: ksPGPv4FP(rsaBody), edFP: ksPGPv4FP(edBody), cvFP: ksPGPv4FP(cvBody), p256FP: ksPGPv4FP(p256Body),
		v6: strings.ToUpper(hex.EncodeToString(h.Sum(nil))),
	}
}

func ksWantRing(fx ksPGPFixture) []KeystoreEntry {
	return []KeystoreEntry{
		{Alias: fx.rsaFP, Kind: "pgp_public_key", Algorithm: "RSA", SizeBits: 2048},
		{Alias: fx.edFP, Kind: "pgp_public_key", Algorithm: "Ed25519", SizeBits: 256},
		{Alias: fx.cvFP, Kind: "pgp_public_subkey", Algorithm: "X25519", SizeBits: 256},
		{Alias: fx.p256FP, Kind: "pgp_public_key", Algorithm: "ECDSA", SizeBits: 256},
		{Alias: fx.v6, Kind: "pgp_public_key", Algorithm: "Ed25519", SizeBits: 256},
	}
}

func TestParseOpenPGPPublicKeyring(t *testing.T) {
	fx := ksMakePGPRing(t)
	got := ParseOpenPGPPublicKeyring(fx.ring, 0)
	want := ksWantRing(fx)
	if len(got) != len(want) {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
	ksAssertNoUserID(t, got)
	if n := len(ParseOpenPGPPublicKeyring(fx.ring, 2)); n != 2 {
		t.Errorf("max 2 returned %d", n)
	}
}

// ksAssertNoUserID: a user ID is a name and an address; none of it travels.
func ksAssertNoUserID(t *testing.T, v any) {
	t.Helper()
	blob, _ := json.Marshal(v)
	for _, part := range []string{"Alice", "alice@example.org", "example.org"} {
		if strings.Contains(string(blob), part) {
			t.Fatalf("user ID text %q in the output", part)
		}
	}
}

// ksBuildKeybox wraps keyblocks the way pubring.kbx does: a header blob, then
// one OpenPGP blob per keyblock, plus an X.509 blob that is not listed.
func ksBuildKeybox(keyblocks ...[]byte) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 32)
	binary.BigEndian.PutUint32(hdr, 32)
	hdr[4], hdr[5] = 1, 1
	copy(hdr[8:], "KBXf")
	b.Write(hdr)
	blob := func(typ byte, payload []byte) {
		const off = 20
		blob := make([]byte, off+len(payload)+20) // trailing bytes stand in for the checksum
		binary.BigEndian.PutUint32(blob, uint32(len(blob)))
		blob[4], blob[5] = typ, 1
		binary.BigEndian.PutUint32(blob[8:], off)
		binary.BigEndian.PutUint32(blob[12:], uint32(len(payload)))
		copy(blob[off:], payload)
		b.Write(blob)
	}
	for _, kb := range keyblocks {
		blob(2, kb)
	}
	blob(3, []byte("an X.509 certificate would be here"))
	return b.Bytes()
}

func TestParseOpenPGPPublicKeyring_Keybox(t *testing.T) {
	fx := ksMakePGPRing(t)
	got := ParseOpenPGPPublicKeyring(ksBuildKeybox(fx.ring[:len(fx.ring)/2], fx.ring), 0)
	if len(got) < len(ksWantRing(fx)) || got[len(got)-1].Alias != fx.v6 {
		t.Fatalf("keybox: %+v", got)
	}
	ksAssertNoUserID(t, got)
}

func TestParseOpenPGPPublicKeyring_HostileInput(t *testing.T) {
	fx := ksMakePGPRing(t)
	kbx := ksBuildKeybox(fx.ring)
	for _, b := range [][]byte{fx.ring, kbx} {
		for n := 0; n < len(b); n++ {
			if got := ParseOpenPGPPublicKeyring(b[:n], 0); len(got) > 5 {
				t.Fatalf("prefix %d grew entries", n)
			}
		}
	}
	for name, b := range map[string][]byte{
		"not a packet":       {0x00, 0x01, 0x02},
		"huge old length":    {0x80 | 6<<2 | 2, 0x7f, 0xff, 0xff, 0xff, 4},
		"huge new length":    {0xc0 | 6, 255, 0xff, 0xff, 0xff, 0xff, 4},
		"huge partial":       {0xc0 | 11, 224 + 30, 1, 2},
		"huge mpi":           ksPGPNew(6, ksPGPv4(1, []byte{0xff, 0xff, 1})),
		"huge oid":           ksPGPNew(6, ksPGPv4(19, []byte{200, 1})),
		"huge v6 material":   ksPGPNew(6, []byte{6, 1, 2, 3, 4, 27, 0x7f, 0, 0, 0}),
		"keybox huge blob":   append(ksBuildKeybox(), 0x7f, 0xff, 0xff, 0xff, 2),
		"keybox bad offset":  ksPatchU32(ksBuildKeybox(fx.ring), 32+8, 0xffffff00),
		"keybox bad length":  ksPatchU32(ksBuildKeybox(fx.ring), 32+12, 0xffffff00),
		"keybox zero blob":   append(ksBuildKeybox(), 0, 0, 0, 0),
		"unknown version":    ksPGPNew(6, []byte{9, 1, 2, 3, 4, 1}),
		"truncated v4 body":  ksPGPNew(6, []byte{4, 1, 2}),
		"empty":              nil,
		"single header byte": {0xc6},
	} {
		got := ParseOpenPGPPublicKeyring(b, 0)
		for _, e := range got {
			if e.Kind == "" {
				t.Errorf("%s: entry without a kind", name)
			}
		}
		if name == "huge mpi" || name == "huge oid" {
			if len(got) != 1 || got[0].SizeBits != 0 {
				t.Errorf("%s: %+v", name, got)
			}
		} else if len(got) != 0 {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func FuzzParseOpenPGP(f *testing.F) {
	// Small seeds keep the fuzzer's minimisation quick: a short fake RSA
	// modulus, a legacy Ed25519 key, a user ID and a v6 key.
	edOID := []byte("\x2b\x06\x01\x04\x01\xda\x47\x0f\x01")
	var ring []byte
	ring = append(ring, ksPGPOld(ksPGPTagPublicKey, ksPGPv4(1, append(ksMPIOf(bytes.Repeat([]byte{0xc3}, 16)), ksMPIOf([]byte{3})...)))...)
	ring = append(ring, ksPGPNew(13, []byte("x"))...)
	ring = append(ring, ksPGPNew(ksPGPTagPublicSubkey, ksPGPv4(22, append(append([]byte{9}, edOID...), ksMPIOf(append([]byte{0x40}, make([]byte, 32)...))...)))...)
	ring = append(ring, ksPGPNew(ksPGPTagPublicKey, append(append([]byte{6}, ksPGPTime...), 27, 0, 0, 0, 4, 1, 2, 3, 4))...)
	f.Add(ring)
	f.Add(ksBuildKeybox(ring))
	f.Add([]byte("Key: (private-key (rsa (n #00#)))"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if got := ParseOpenPGPPublicKeyring(b, 20); len(got) > 20 {
			t.Fatal("cap exceeded")
		}
		_ = ClassifyGnuPGPrivateKeyFile(b)
	})
}

func TestClassifyGnuPGPrivateKeyFile(t *testing.T) {
	key := ksTestRSA(t)
	d := key.D.Bytes()
	canon := func(name string) []byte {
		var b bytes.Buffer
		b.WriteString("(" + strconv.Itoa(len(name)) + ":" + name + "(3:rsa(1:d")
		b.WriteString(strconv.Itoa(len(d)) + ":")
		b.Write(d)
		b.WriteString(")))")
		return b.Bytes()
	}
	advanced := func(name string) []byte {
		return []byte("(" + name + "\n (rsa\n  (d #" + hex.EncodeToString(d) + "#)\n  )\n )\n")
	}
	extended := func(name string) []byte {
		return []byte("Created: 20260101T000000\nLabel: Example Fixture\nKey: (" + name + " (rsa (d #" +
			hex.EncodeToString(d) + "#)\n (e #010001#)))\n")
	}
	for _, tc := range []struct {
		name string
		want GnuPGKeyProtection
	}{
		{"protected-private-key", GnuPGKeyProtected},
		{"private-key", GnuPGKeyUnprotected},
		{"shadowed-private-key", GnuPGKeyShadowed},
		{"public-key", GnuPGKeyUnknown},
	} {
		for form, b := range map[string][]byte{"canonical": canon(tc.name), "advanced": advanced(tc.name), "extended": extended(tc.name)} {
			got := ClassifyGnuPGPrivateKeyFile(b)
			if got != tc.want {
				t.Errorf("%s %s: %q", form, tc.name, got)
			}
			ksAssertNoSecret(t, form+" "+tc.name, got, d)
		}
	}
	for name, b := range map[string][]byte{
		"empty":            nil,
		"no paren":         []byte("hello"),
		"long atom":        []byte("(9999:" + strings.Repeat("x", 100)),
		"atom past end":    []byte("(21:protected"),
		"bare long token":  []byte("(" + strings.Repeat("p", 200)),
		"extended, no key": []byte("Created: 20260101T000000\nLabel: x\n"),
	} {
		if got := ClassifyGnuPGPrivateKeyFile(b); got != GnuPGKeyUnknown {
			t.Errorf("%s: %q", name, got)
		}
	}
}
