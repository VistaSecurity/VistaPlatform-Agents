package hostcrypto

import (
	"crypto/sha1" //nolint:gosec // the JKS integrity digest IS SHA-1; checking it is not choosing it
	"crypto/subtle"
	"errors"
	"strings"
	"unicode/utf16"
)

// The Java keystore formats, JKS and JCEKS.
//
// Both are the JDK's own simple binary layout, big-endian throughout:
//
//	magic        u32   FEEDFEED (JKS) or CECECECE (JCEKS)
//	version      u32   1 or 2 (2 adds a certificate type string before each certificate)
//	count        u32
//	count times:
//	  tag        u32   1 private key, 2 trusted certificate, 3 secret key (JCEKS only)
//	  alias      u16 length + modified UTF-8
//	  timestamp  u64   milliseconds
//	  tag 1:     u32 length + protected key (an EncryptedPrivateKeyInfo), u32 chain length,
//	             then per certificate: [v2: u16 length + type] u32 length + DER
//	  tag 2:     [v2: u16 length + type] u32 length + DER
//	  tag 3:     a serialized Java object (a SealedObject)
//	digest       20 bytes: SHA-1(password as UTF-16BE || "Mighty Aphrodite" || everything before)
//
// The point that matters for posture: the aliases and the certificates are in
// the clear. Listing a JKS needs no password, so a JKS read is
// [OpenedWithoutPassword]. The password protects only the private keys (each
// under its own key password, usually the same) and the integrity digest.
//
// The protected key bytes are skipped by length and never copied out: the
// private-key entry's algorithm, size and public-key hash come from the first
// certificate of its chain, which is public.

const (
	ksMagicJKS   uint32 = 0xFEEDFEED
	ksMagicJCEKS uint32 = 0xCECECECE

	ksJKSTagPrivateKey  = 1
	ksJKSTagTrustedCert = 2
	ksJKSTagSecretKey   = 3

	// ksJKSDigestLen is the SHA-1 integrity digest at the end of the file.
	ksJKSDigestLen = sha1.Size
)

const (
	ksProtectionJKS   = "JKS proprietary (SHA-1 keystream)"
	ksProtectionJCEKS = "JCEKS (PBEWithMD5AndTripleDES)"
)

var errKsNotJKS = errors.New("not a JKS or JCEKS keystore")

// ParseJKS lists a JKS or JCEKS keystore without a password: every alias,
// every certificate, and for a private key entry what its certificate says
// about the key.
//
// With tryDefaults it also checks the integrity digest against each of
// [DefaultKeystorePasswords]. That answers "does a default password open
// this?" without decrypting anything: the digest is keyed by the store
// password, and a match proves it.
//
// A JCEKS secret-key entry is a serialized Java object whose length is not
// stated; it cannot be stepped over without a Java deserializer, which this
// package will not carry. Listing stops at the first one, EntryCount keeps the
// header's count, and the entries after it are simply not listed.
//
// On a malformed file it returns what it listed before the fault and an error;
// EntryCount is then nil because the count could not be confirmed.
func ParseJKS(b []byte, tryDefaults bool) (KeystoreContents, error) {
	return ksParseJKS(b, tryDefaults, DefaultMaxKeystoreEntries)
}

func ksParseJKS(b []byte, tryDefaults bool, maxEntries int) (KeystoreContents, error) {
	var out KeystoreContents
	r := &ksReader{b: b}
	magic := r.u32()
	switch {
	case r.bad:
		return out, errKsNotJKS
	case magic == ksMagicJKS:
		out.Keystore = Keystore{Type: KeystoreJKS, Protection: ksProtectionJKS}
	case magic == ksMagicJCEKS:
		out.Keystore = Keystore{Type: KeystoreJCEKS, Protection: ksProtectionJCEKS}
	default:
		return out, errKsNotJKS
	}
	out.Keystore.Opened = OpenedWithoutPassword

	if tryDefaults {
		ok := ksJKSDefaultPassword(b)
		out.Keystore.DefaultPassword = &ok
		if ok {
			out.Keystore.Opened = OpenedDefaultPassword
		}
	}

	version := r.u32()
	count := r.u32()
	if r.bad {
		return out, errors.New("jks: truncated header")
	}
	if version != 1 && version != 2 {
		return out, errors.New("jks: unsupported version")
	}
	// The listing must leave the digest behind it.
	if r.remaining() < ksJKSDigestLen {
		return out, errors.New("jks: truncated")
	}
	r.b = r.b[:len(r.b)-ksJKSDigestLen]

	for i := uint32(0); i < count; i++ {
		if len(out.Keystore.Entries) >= maxEntries {
			out.Keystore.EntryCount = ksIntPtr(int(count))
			return out, nil
		}
		tag := r.u32()
		alias := ksJavaUTF(r)
		r.u64() // timestamp: not part of the record
		if r.bad {
			return out, errors.New("jks: truncated entry")
		}
		switch tag {
		case ksJKSTagPrivateKey:
			keyLen := r.u32()
			// Skipped by length, never copied: this is the protected private key.
			r.skip(int(keyLen))
			chainLen := r.u32()
			if r.bad || uint64(chainLen)*4 > uint64(r.remaining()) {
				return out, errors.New("jks: bad certificate chain")
			}
			entry := KeystoreEntry{Alias: alias, Kind: "private_key"}
			for j := uint32(0); j < chainLen; j++ {
				der, ok := ksJKSCert(r, version)
				if !ok {
					return out, errors.New("jks: truncated certificate")
				}
				fp := ksDERFingerprint(der)
				cert, parsed := ksCertificate(der)
				if j == 0 {
					entry.CertificateFingerprint = fp
					if parsed {
						entry.Algorithm = cert.KeyAlgorithm
						entry.SizeBits = cert.KeySize
						entry.PublicKeySHA256 = cert.PublicKeySHA256
					}
				}
				if parsed {
					cert.Location.Alias = alias
					out.Certificates = append(out.Certificates, cert)
				}
			}
			out.Keystore.Entries = append(out.Keystore.Entries, entry)
		case ksJKSTagTrustedCert:
			der, ok := ksJKSCert(r, version)
			if !ok {
				return out, errors.New("jks: truncated certificate")
			}
			entry := KeystoreEntry{Alias: alias, Kind: "certificate", CertificateFingerprint: ksDERFingerprint(der)}
			if cert, parsed := ksCertificate(der); parsed {
				entry.Algorithm = cert.KeyAlgorithm
				entry.SizeBits = cert.KeySize
				entry.PublicKeySHA256 = cert.PublicKeySHA256
				cert = ksTrustAnchor(cert)
				cert.Location.Alias = alias
				out.Certificates = append(out.Certificates, cert)
			}
			out.Keystore.Entries = append(out.Keystore.Entries, entry)
		case ksJKSTagSecretKey:
			if out.Keystore.Type != KeystoreJCEKS {
				return out, errors.New("jks: secret key entry in a JKS store")
			}
			// See the function comment: the rest cannot be listed honestly.
			out.Keystore.Entries = append(out.Keystore.Entries, KeystoreEntry{Alias: alias, Kind: "secret_key"})
			out.Keystore.EntryCount = ksIntPtr(int(count))
			return out, nil
		default:
			return out, errors.New("jks: unknown entry type")
		}
	}
	if r.remaining() != 0 {
		return out, errors.New("jks: trailing bytes before the digest")
	}
	out.Keystore.EntryCount = ksIntPtr(int(count))
	return out, nil
}

// ksJKSCert reads one certificate: in version 2 a type string ("X.509") and
// then the length-prefixed encoding.
func ksJKSCert(r *ksReader, version uint32) ([]byte, bool) {
	if version == 2 {
		r.skip(int(r.u16()))
	}
	n := r.u32()
	der := r.take(int(n))
	return der, !r.bad
}

// ksJavaUTF reads a Java DataOutput.writeUTF string: a u16 byte length and
// modified UTF-8, which differs from UTF-8 only in writing NUL as C0 80 and
// supplementary characters as surrogate pairs. Aliases are almost always
// ASCII; anything that is not valid UTF-8 is replaced rather than guessed.
func ksJavaUTF(r *ksReader) string {
	s := r.take(int(r.u16()))
	if s == nil {
		return ""
	}
	return strings.ToValidUTF8(strings.ReplaceAll(string(s), "\xc0\x80", "\x00"), "�")
}

// ksJKSDefaultPassword reports whether one of the default passwords produces
// the file's integrity digest. It needs nothing but the last 20 bytes and what
// precedes them, so it answers even when the listing could not finish.
func ksJKSDefaultPassword(b []byte) bool {
	if len(b) < 12+ksJKSDigestLen {
		return false
	}
	body, want := b[:len(b)-ksJKSDigestLen], b[len(b)-ksJKSDigestLen:]
	for _, pw := range DefaultKeystorePasswords {
		if subtle.ConstantTimeCompare(ksJKSDigest(pw, body), want) == 1 {
			return true
		}
	}
	return false
}

// ksJKSDigest is the JDK's keystore integrity digest for one password.
func ksJKSDigest(password string, body []byte) []byte {
	h := sha1.New() //nolint:gosec // the format's own digest
	for _, c := range utf16.Encode([]rune(password)) {
		h.Write([]byte{byte(c >> 8), byte(c)})
	}
	h.Write([]byte("Mighty Aphrodite"))
	h.Write(body)
	return h.Sum(nil)
}
