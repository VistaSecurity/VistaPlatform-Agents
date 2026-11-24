package hostcrypto

import (
	"bytes"
	"crypto/md5"  //nolint:gosec // the OpenPGP v3 fingerprint IS MD5; computing it is not choosing it
	"crypto/sha1" //nolint:gosec // the OpenPGP v4 fingerprint IS SHA-1
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// GnuPG homes: the public keyring and the agent's private key files.
//
// The public keyring is read packet by packet (RFC 4880 and RFC 9580 framing)
// and only public-key and public-subkey packets are kept. User ID packets,
// signatures and everything else are stepped over unread: a user ID is a
// person's name and e-mail address, and a report has no use for it.
//
// A private key file is never parsed. Its first S-expression token says
// whether the key under it is protected, unprotected or held on a smartcard,
// and that one word is all that is taken from it.

// OpenPGP packet tags this file acts on.
const (
	ksPGPTagPublicKey    = 6
	ksPGPTagPublicSubkey = 14
)

// Keystore entry kinds for OpenPGP keys.
const (
	ksKindPGPPublicKey    = "pgp_public_key"
	ksKindPGPPublicSubkey = "pgp_public_subkey"
)

// ksPGPCurves maps the DER content of an ECC curve OID, as OpenPGP writes
// it, to the curve's name and size in bits.
var ksPGPCurves = map[string]struct {
	name string
	bits int
}{
	"\x2a\x86\x48\xce\x3d\x03\x01\x07":         {"P-256", 256},
	"\x2b\x81\x04\x00\x22":                     {"P-384", 384},
	"\x2b\x81\x04\x00\x23":                     {"P-521", 521},
	"\x2b\x24\x03\x03\x02\x08\x01\x01\x07":     {"brainpoolP256r1", 256},
	"\x2b\x24\x03\x03\x02\x08\x01\x01\x0b":     {"brainpoolP384r1", 384},
	"\x2b\x24\x03\x03\x02\x08\x01\x01\x0d":     {"brainpoolP512r1", 512},
	"\x2b\x81\x04\x00\x0a":                     {"secp256k1", 256},
	"\x2b\x06\x01\x04\x01\xda\x47\x0f\x01":     {"Ed25519", 256},
	"\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01": {"Curve25519", 256},
	"\x2b\x65\x71":                             {"Ed448", 448},
	"\x2b\x65\x6f":                             {"X448", 448},
}

// ParseOpenPGPPublicKeyring lists the public keys and subkeys of a GnuPG
// public keyring: the legacy pubring.gpg (a stream of OpenPGP packets) or a
// keybox, pubring.kbx (its OpenPGP blobs; its X.509 blobs, gpgsm's
// certificates, are not listed). At most max entries are returned
// (DefaultMaxKeystoreEntries when max <= 0).
//
// Each entry's Alias is the key's fingerprint in upper-case hex, which is how
// GnuPG prints it and how a person looks it up. It stops at max entries or at
// the first packet (or keybox blob) that does not parse, returns what it had,
// and says so with truncated.
func ParseOpenPGPPublicKeyring(b []byte, max int) (entries []KeystoreEntry, truncated bool) {
	if max <= 0 {
		max = DefaultMaxKeystoreEntries
	}
	if ksIsKeybox(b) {
		return ksParseKeybox(b, max)
	}
	return ksParsePGPPackets(b, max, nil)
}

// ksIsKeybox recognises a keybox by its first blob, the header blob: type 1
// and the "KBXf" magic at offset 8.
func ksIsKeybox(b []byte) bool {
	return len(b) >= 12 && b[4] == 1 && string(b[8:12]) == "KBXf"
}

// ksParseKeybox walks the keybox blobs. Each blob starts with its length
// (u32), type (u8: 1 header, 2 OpenPGP, 3 X.509) and version (u8), flags
// (u16), and, for the key blobs, the offset and length of the embedded
// keyblock, relative to the blob's start.
func ksParseKeybox(b []byte, max int) ([]KeystoreEntry, bool) {
	var out []KeystoreEntry
	damaged := false
	r := &ksReader{b: b}
	for r.remaining() > 0 {
		if len(out) >= max {
			return out, true
		}
		start := r.off
		blobLen := int(r.u32())
		if r.bad || blobLen < 6 || blobLen-4 > r.remaining() {
			return out, true
		}
		blob := b[start : start+blobLen]
		r.skip(blobLen - 4)
		if blob[4] != 2 || len(blob) < 16 {
			continue
		}
		br := &ksReader{b: blob, off: 8}
		off := int(br.u32())
		n := int(br.u32())
		if br.bad || off < 0 || n < 0 || off > len(blob) || n > len(blob)-off {
			// One damaged blob: its length is still good, so go on.
			damaged = true
			continue
		}
		var cut bool
		if out, cut = ksParsePGPPackets(blob[off:off+n], max, out); cut {
			if len(out) >= max {
				return out, true
			}
			damaged = true
		}
	}
	return out, damaged
}

// ksParsePGPPackets walks a packet stream and appends the keys it finds.
func ksParsePGPPackets(b []byte, max int, out []KeystoreEntry) ([]KeystoreEntry, bool) {
	for len(b) > 0 {
		if len(out) >= max {
			return out, true
		}
		tag, body, rest, ok := ksPGPPacket(b)
		if !ok {
			return out, true
		}
		b = rest
		if tag != ksPGPTagPublicKey && tag != ksPGPTagPublicSubkey {
			continue
		}
		entry, ok := ksPGPPublicKey(body)
		if !ok {
			continue
		}
		entry.Kind = ksKindPGPPublicKey
		if tag == ksPGPTagPublicSubkey {
			entry.Kind = ksKindPGPPublicSubkey
		}
		out = append(out, entry)
	}
	return out, false
}

// ksPGPPacket splits off one packet in either header format. A packet with
// partial body lengths is stepped over with body nil: key packets may not use
// them, and the others are not read.
func ksPGPPacket(b []byte) (tag int, body, rest []byte, ok bool) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return 0, nil, nil, false
	}
	if b[0]&0x40 == 0 {
		// Old format: tag in bits 5-2, length type in bits 1-0.
		tag = int(b[0]>>2) & 0x0f
		var n, hdr int
		switch b[0] & 0x03 {
		case 0:
			n, hdr = int(b[1]), 2
		case 1:
			if len(b) < 3 {
				return 0, nil, nil, false
			}
			n, hdr = int(b[1])<<8|int(b[2]), 3
		case 2:
			if len(b) < 5 {
				return 0, nil, nil, false
			}
			n, hdr = ksBE32(b[1:5]), 5
		case 3:
			// Indeterminate: to the end of the input.
			return tag, b[1:], nil, true
		}
		if n < 0 || n > len(b)-hdr {
			return 0, nil, nil, false
		}
		return tag, b[hdr : hdr+n], b[hdr+n:], true
	}
	// New format.
	tag = int(b[0] & 0x3f)
	p := 1
	partial := false
	for {
		n, hdr, isPartial, lok := ksPGPNewLength(b[p:])
		if !lok || n > len(b)-p-hdr {
			return 0, nil, nil, false
		}
		if !isPartial {
			if partial {
				return tag, nil, b[p+hdr+n:], true
			}
			return tag, b[p+hdr : p+hdr+n], b[p+hdr+n:], true
		}
		partial = true
		p += hdr + n
	}
}

// ksPGPNewLength decodes a new-format length at the start of b.
func ksPGPNewLength(b []byte) (n, hdr int, partial, ok bool) {
	if len(b) < 1 {
		return 0, 0, false, false
	}
	o := int(b[0])
	switch {
	case o < 192:
		return o, 1, false, true
	case o < 224:
		if len(b) < 2 {
			return 0, 0, false, false
		}
		return (o-192)<<8 + int(b[1]) + 192, 2, false, true
	case o == 255:
		if len(b) < 5 {
			return 0, 0, false, false
		}
		n := ksBE32(b[1:5])
		return n, 5, false, n >= 0
	default:
		return 1 << (o & 0x1f), 1, true, true
	}
}

func ksBE32(b []byte) int {
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if v > 1<<30 {
		return -1 // larger than any buffer this package is handed
	}
	return int(v)
}

// ksPGPPublicKey describes one public-key packet body.
func ksPGPPublicKey(body []byte) (KeystoreEntry, bool) {
	if len(body) < 1 {
		return KeystoreEntry{}, false
	}
	var e KeystoreEntry
	var algo byte
	var material []byte
	switch v := body[0]; v {
	case 2, 3:
		// version, created(4), validity days(2), algorithm, MPIs. RSA only.
		if len(body) < 8 {
			return KeystoreEntry{}, false
		}
		algo, material = body[7], body[8:]
		if fp, ok := ksPGPv3Fingerprint(material); ok {
			e.Alias = fp
		}
	case 4:
		if len(body) < 6 {
			return KeystoreEntry{}, false
		}
		algo, material = body[5], body[6:]
		h := sha1.New() //nolint:gosec // the format's fingerprint
		h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
		h.Write(body)
		e.Alias = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	case 5, 6:
		// version, created(4), algorithm, u32 material length, material.
		if len(body) < 10 {
			return KeystoreEntry{}, false
		}
		algo = body[5]
		n := ksBE32(body[6:10])
		if n < 0 || n > len(body)-10 {
			return KeystoreEntry{}, false
		}
		material = body[10 : 10+n]
		prefix := byte(0x9a)
		if v == 6 {
			prefix = 0x9b
		}
		h := sha256.New()
		l := len(body)
		h.Write([]byte{prefix, byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)})
		h.Write(body)
		e.Alias = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	default:
		return KeystoreEntry{}, false
	}
	var curve string
	e.Algorithm, e.SizeBits, curve = ksPGPAlgorithm(algo, material)
	_ = curve // TODO(merge): set Curve
	return e, true
}

// ksPGPv3Fingerprint is MD5 over the bodies of the RSA modulus and exponent.
func ksPGPv3Fingerprint(material []byte) (string, bool) {
	n, rest, ok := ksMPI(material)
	if !ok {
		return "", false
	}
	ex, _, ok := ksMPI(rest)
	if !ok {
		return "", false
	}
	sum := md5.Sum(append(append([]byte{}, n...), ex...)) //nolint:gosec // the format's fingerprint
	return strings.ToUpper(hex.EncodeToString(sum[:])), true
}

// ksMPI splits off one multiprecision integer: a u16 bit count and the bytes.
func ksMPI(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	bits := int(b[0])<<8 | int(b[1])
	n := (bits + 7) / 8
	if n > len(b)-2 {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

// ksMPIBits is the stated bit count of the first MPI, which is the key size
// for RSA (the modulus), DSA and ElGamal (the prime).
func ksMPIBits(b []byte) int {
	if _, _, ok := ksMPI(b); !ok {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}

// ksPGPAlgorithm names a public-key algorithm id and finds its size and,
// for the curves that do not name themselves, its curve.
func ksPGPAlgorithm(algo byte, material []byte) (name string, bits int, curve string) {
	switch algo {
	case 1, 2, 3:
		return "RSA", ksMPIBits(material), ""
	case 16, 20:
		return "ElGamal", ksMPIBits(material), ""
	case 17:
		return "DSA", ksMPIBits(material), ""
	case 18, 19, 22:
		c, bits := ksPGPCurve(material)
		switch {
		case algo == 22 && (c == "Ed25519" || c == "Ed448"):
			return c, bits, ""
		case algo == 22:
			return "EdDSA", bits, c
		case algo == 18 && c == "Curve25519":
			return "X25519", bits, ""
		case algo == 18 && c == "X448":
			return "X448", bits, ""
		case algo == 18:
			return "ECDH", bits, c
		default:
			return "ECDSA", bits, c
		}
	case 25:
		return "X25519", 256, ""
	case 26:
		return "X448", 448, ""
	case 27:
		return "Ed25519", 256, ""
	case 28:
		return "Ed448", 448, ""
	default:
		return "", 0, ""
	}
}

// ksPGPCurve reads the length-prefixed curve OID at the start of ECC key
// material.
func ksPGPCurve(material []byte) (string, int) {
	if len(material) < 1 {
		return "", 0
	}
	n := int(material[0])
	if n == 0 || n == 0xff || n > len(material)-1 {
		return "", 0
	}
	if c, ok := ksPGPCurves[string(material[1:1+n])]; ok {
		return c.name, c.bits
	}
	return "", 0
}

// GnuPGKeyProtection is what the first token of a GnuPG agent private key
// file says about the key under it.
type GnuPGKeyProtection string

const (
	// GnuPGKeyUnknown: not a key file this package recognises.
	GnuPGKeyUnknown GnuPGKeyProtection = ""
	// GnuPGKeyProtected: "protected-private-key", passphrase-protected.
	GnuPGKeyProtected GnuPGKeyProtection = "protected"
	// GnuPGKeyUnprotected: "private-key", a secret key with NO passphrase.
	GnuPGKeyUnprotected GnuPGKeyProtection = "unprotected"
	// GnuPGKeyShadowed: "shadowed-private-key", a stub; the key is on a
	// smartcard or token and not in the file at all.
	GnuPGKeyShadowed GnuPGKeyProtection = "shadowed"
)

// ClassifyGnuPGPrivateKeyFile reads the first token of a file from
// private-keys-v1.d. Two encodings exist: the original S-expression
// ("(21:protected-private-key(3:rsa..." canonical, or "(protected-private-key
// (rsa..." advanced), and the extended key format GnuPG 2.1.12+ writes,
// "Name: value" lines of which "Key:" holds that S-expression. Only the name
// of the first token is compared against the three known forms; nothing else
// is read or returned.
func ClassifyGnuPGPrivateKeyFile(b []byte) GnuPGKeyProtection {
	sexp := b
	if len(bytes.TrimLeft(b, " \t\r\n")) > 0 && bytes.TrimLeft(b, " \t\r\n")[0] != '(' {
		sexp = ksExtendedKeyValue(b)
		if sexp == nil {
			return GnuPGKeyUnknown
		}
	}
	switch ksFirstSexpToken(sexp) {
	case "protected-private-key":
		return GnuPGKeyProtected
	case "private-key":
		return GnuPGKeyUnprotected
	case "shadowed-private-key":
		return GnuPGKeyShadowed
	default:
		return GnuPGKeyUnknown
	}
}

// ksExtendedKeyValue finds the "Key:" item of the extended format and returns
// the bytes after the colon.
func ksExtendedKeyValue(b []byte) []byte {
	for len(b) > 0 {
		line := b
		next := []byte(nil)
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, next = b[:i], b[i+1:]
		}
		if len(line) >= 4 && strings.EqualFold(string(line[:4]), "key:") {
			return b[4:]
		}
		b = next
	}
	return nil
}

// ksFirstSexpToken returns the first atom after the first "(": either a
// canonical "<len>:<bytes>" atom or a bare token. Atoms longer than any of the
// three names are not returned.
func ksFirstSexpToken(b []byte) string {
	i := bytes.IndexByte(b, '(')
	if i < 0 {
		return ""
	}
	b = bytes.TrimLeft(b[i+1:], " \t\r\n")
	const longest = len("protected-private-key")
	// Canonical: digits then ':'.
	j := 0
	for j < len(b) && j < 4 && b[j] >= '0' && b[j] <= '9' {
		j++
	}
	if j > 0 && j < len(b) && b[j] == ':' {
		n := 0
		for _, c := range b[:j] {
			n = n*10 + int(c-'0')
		}
		if n > longest || n > len(b)-j-1 {
			return ""
		}
		return string(b[j+1 : j+1+n])
	}
	k := 0
	for k < len(b) && k <= longest && !strings.ContainsRune(" \t\r\n()", rune(b[k])) {
		k++
	}
	if k > longest {
		return ""
	}
	return string(b[:k])
}
