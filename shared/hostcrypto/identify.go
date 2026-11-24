package hostcrypto

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

// What a file is, from its markers.
//
// Identification has ONE job that matters more than the others: deciding
// whether a file is public, because on a remote target that decision is what
// lets its bytes cross the connection ([Identity.Public]). Every rule below is
// therefore written to fail towards "not public":
//
//   - A label this file does not recognise makes the file ClassUnknown, even
//     beside certificate labels. "OpenVPN Static key V1" is a secret that
//     carries a PEM-shaped header; a list of known public labels is an
//     allowlist, and anything off it is not public.
//   - Any label containing PRIVATE is a private key, whatever else it says.
//   - A file name can make a file LESS public (a .p12 that looks like DER is a
//     keystore) but never MORE: no name turns an unidentified file into a
//     public one. The one name rule that yields a public class, an OpenSSH
//     .pub line, needs the content to start with a public key type as well.
//   - Bare DER (an ASN.1 SEQUENCE header) is ClassUnknown. Eight bytes cannot
//     tell a DER certificate from a DER private key or a PKCS#12 file. The
//     LOCAL collector resolves it by parsing the bytes in memory; a REMOTE
//     collector must treat it as not public, which ClassUnknown is.

// maxPEMLabels bounds how many PEM labels one file contributes: a bundle of
// 64 certificates already says what the file is, and the bound keeps a hostile
// file from turning identification into a transfer.
const maxPEMLabels = 64

// maxPEMLabelLen bounds one label. Real labels are under 40 characters.
const maxPEMLabelLen = 80

// pemLabelKind is what one PEM label says on its own.
type pemLabelKind int

const (
	pemOther pemLabelKind = iota // not recognised: not public
	pemCertificate
	pemPrivate
	pemPublicKey
	pemCSR
	pemCRL
	pemDHParams
	pemPGP
	pemNeutral // public, but says nothing about the file (EC PARAMETERS before a key)
)

// classifyPEMLabel names one label. Comparison is case-sensitive for the
// public allowlist (OpenSSL writes them in capitals) and case-insensitive for
// PRIVATE, so an oddly cased private label still fails closed.
func classifyPEMLabel(label string) pemLabelKind {
	l := strings.TrimSpace(label)
	upper := strings.ToUpper(l)
	switch {
	case strings.HasPrefix(upper, "PGP "):
		// PGP PRIVATE KEY BLOCK, PGP PUBLIC KEY BLOCK, PGP MESSAGE, PGP
		// SIGNATURE: an armoured OpenPGP block. Checked before PRIVATE so a
		// secret key block is reported as PGP, which is still not public.
		return pemPGP
	case strings.Contains(upper, "PRIVATE"):
		return pemPrivate
	}
	switch l {
	case "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE", "X.509 CERTIFICATE":
		return pemCertificate
	case "PUBLIC KEY", "RSA PUBLIC KEY", "SSH2 PUBLIC KEY":
		return pemPublicKey
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		return pemCSR
	case "X509 CRL":
		return pemCRL
	case "DH PARAMETERS", "X9.42 DH PARAMETERS":
		return pemDHParams
	case "EC PARAMETERS":
		return pemNeutral
	}
	return pemOther
}

// Magic numbers. Each is at most [MagicBytes] long.
var (
	magicJKS     = []byte{0xFE, 0xED, 0xFE, 0xED}
	magicJCEKS   = []byte{0xCE, 0xCE, 0xCE, 0xCE}
	magicKeytab2 = []byte{0x05, 0x02}
	magicKeytab1 = []byte{0x05, 0x01}
	magicPuTTY   = []byte("PuTTY-Us") // PuTTY-User-Key-File-2/3
	// magicSSH1 is "SSH PRIVATE KEY FILE FORMAT 1.1", the legacy SSH-1 key.
	// It is printable, so without this entry it would read as ClassText and
	// be public.
	magicSSH1   = []byte("SSH PRIV")
	magicSQLite = []byte("SQLite f") // "SQLite format 3\000": NSS cert9/key4, among many others
)

// Classify turns a file's first bytes (at most [MagicBytes]) and its PEM
// labels into an [Identity]. It is pure: no I/O, no file name. Callers that
// know the base name use [ClassifyNamed], which can only make the answer less
// public.
//
// Order: a binary magic number first (a keystore can contain PEM-looking text,
// a PEM file never starts with a keystore's magic), then the PEM labels, then
// whether the start is printable text.
func Classify(magic []byte, pemLabels []string) Identity {
	if len(magic) > MagicBytes {
		magic = magic[:MagicBytes]
	}
	id := Identity{Magic: cloneBytes(magic), PEMLabels: cloneLabels(pemLabels)}

	switch {
	case bytes.HasPrefix(magic, magicJKS):
		id.Class, id.KeystoreType = ClassKeystore, KeystoreJKS
		return id
	case bytes.HasPrefix(magic, magicJCEKS):
		id.Class, id.KeystoreType = ClassKeystore, KeystoreJCEKS
		return id
	case bytes.HasPrefix(magic, magicPuTTY), bytes.HasPrefix(magic, magicSSH1):
		id.Class = ClassPrivateKey
		return id
	case bytes.HasPrefix(magic, magicKeytab2), bytes.HasPrefix(magic, magicKeytab1):
		id.Class, id.KeystoreType = ClassKeystore, KeystoreKeytab
		return id
	}

	if len(pemLabels) > 0 {
		id.Class = classFromLabels(pemLabels)
		return id
	}

	switch {
	case bytes.HasPrefix(magic, magicSQLite):
		// Any SQLite database. Only the name says it is NSS (ClassifyNamed).
		id.Class = ClassUnknown
	case isDERStart(magic):
		id.Class = ClassUnknown
	case isPrintableText(magic):
		id.Class = ClassText
	default:
		id.Class = ClassUnknown
	}
	return id
}

// classFromLabels decides a PEM file's class from all of its labels. Private
// material beats everything; an unrecognised label beats every public class.
func classFromLabels(labels []string) Class {
	var cert, priv, pub, csr, crl, dh, pgp, other, neutral bool
	for _, l := range labels {
		switch classifyPEMLabel(l) {
		case pemCertificate:
			cert = true
		case pemPrivate:
			priv = true
		case pemPublicKey:
			pub = true
		case pemCSR:
			csr = true
		case pemCRL:
			crl = true
		case pemDHParams:
			dh = true
		case pemPGP:
			pgp = true
		case pemNeutral:
			neutral = true
		default:
			other = true
		}
	}
	switch {
	case priv && cert:
		return ClassMixed
	case priv:
		return ClassPrivateKey
	case pgp:
		return ClassPGP
	case other:
		return ClassUnknown
	case cert:
		return ClassCertificate
	case csr:
		return ClassCSR
	case crl:
		return ClassCRL
	case pub:
		return ClassPublicKey
	case dh:
		return ClassDHParams
	case neutral:
		// EC PARAMETERS on its own: harmless, but not one of the classes, and
		// the safe answer for "not sure" is not public.
		return ClassUnknown
	}
	return ClassUnknown
}

// ClassifyNamed is [Classify] with the file's name taken into account. name
// may be a full path in either separator style; only its base is read.
//
// What the content says wins when it says something definite. The name is
// consulted when the content is unknown, text, or absent (nil magic, which is
// how a remote sweep classifies by name alone), and then only to make the
// answer less public, with one exception: an OpenSSH ".pub" file whose
// content starts with a public key type is ClassPublicKey.
func ClassifyNamed(name string, magic []byte, pemLabels []string) Identity {
	id := Classify(magic, pemLabels)
	base := strings.ToLower(baseName(name))

	// The definite content classes stand.
	if id.Class != ClassUnknown && id.Class != ClassText {
		return id
	}

	switch base {
	case "cert9.db", "key4.db":
		// Modern NSS is SQLite. With magic present it must say SQLite; with
		// none (name-only) the name alone marks it, which is not public.
		if magic == nil || bytes.HasPrefix(magic, magicSQLite) {
			id.Class, id.KeystoreType = ClassKeystore, KeystoreNSS
			return id
		}
	case "cert8.db", "key3.db":
		// Legacy NSS is Berkeley DB, whose magic is not at the start.
		id.Class, id.KeystoreType = ClassKeystore, KeystoreNSS
		return id
	case "pubring.gpg", "secring.gpg", "pubring.kbx", "trustdb.gpg":
		id.Class, id.KeystoreType = ClassPGP, ""
		return id
	}

	ext := extOf(base)
	switch ext {
	case ".kbx":
		id.Class, id.KeystoreType = ClassPGP, ""
		return id
	case ".keychain", ".keychain-db":
		id.Class, id.KeystoreType = ClassKeystore, KeystoreKeychain
		return id
	case ".p12", ".pfx":
		id.Class, id.KeystoreType = ClassKeystore, KeystorePKCS12
		return id
	case ".bcfks":
		id.Class, id.KeystoreType = ClassKeystore, KeystoreBCFKS
		return id
	case ".bks":
		id.Class, id.KeystoreType = ClassKeystore, KeystoreBKS
		return id
	case ".jks":
		// A real JKS would have matched its magic above. A .jks whose start
		// is unreadable or not JKS is still a keystore by intent.
		id.Class, id.KeystoreType = ClassKeystore, KeystoreJKS
		return id
	case ".jceks":
		id.Class, id.KeystoreType = ClassKeystore, KeystoreJCEKS
		return id
	case ".keytab":
		id.Class, id.KeystoreType = ClassKeystore, KeystoreKeytab
		return id
	case ".ppk":
		id.Class, id.KeystoreType = ClassPrivateKey, ""
		return id
	case ".pub":
		if hasSSHPublicKeyPrefix(magic) {
			id.Class = ClassPublicKey
			return id
		}
	}
	return id
}

// hasSSHPublicKeyPrefix reports whether a file starts like an OpenSSH public
// key line: "ssh-rsa ", "ecdsa-sha2-...", "sk-ssh-ed25519@...".
func hasSSHPublicKeyPrefix(magic []byte) bool {
	for _, p := range [][]byte{[]byte("ssh-"), []byte("ecdsa-"), []byte("sk-ssh-"), []byte("sk-ecdsa-")} {
		n := len(p)
		if n > len(magic) {
			// Eight bytes cover every prefix in full except the two
			// security-key forms, whose first eight bytes are distinctive.
			n = len(magic)
		}
		if n >= 4 && bytes.Equal(magic[:n], p[:n]) {
			return true
		}
	}
	return false
}

// isDERStart reports an ASN.1 SEQUENCE with a long-form or indefinite length:
// how a DER certificate, a DER key, PKCS#12 and BCFKS all begin.
func isDERStart(magic []byte) bool {
	if len(magic) < 2 || magic[0] != 0x30 {
		return false
	}
	switch magic[1] {
	case 0x80, 0x81, 0x82, 0x83, 0x84:
		return true
	}
	return false
}

// isPrintableText reports whether b is printable UTF-8 (tabs, newlines and a
// byte-order mark allowed). A rune cut off at the end of b is allowed: b is a
// file's first few bytes, not the whole file.
func isPrintableText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size <= 1 {
			// An incomplete rune at the very end is the read bound, not
			// binary data.
			if !utf8.FullRune(b) && len(b) < utf8.UTFMax {
				return true
			}
			return false
		}
		switch {
		case r == '\t' || r == '\n' || r == '\r':
		case unicode.IsPrint(r):
		default:
			return false
		}
		b = b[size:]
	}
	return true
}

// ScanPEMLabels returns the labels of the PEM headers in b, in order, at most
// max of them (max <= 0 means the package bound of 64). It recognises the
// RFC 7468 form "-----BEGIN X-----" and the RFC 4716 form "---- BEGIN X ----"
// used by SSH2 public keys. It is pure and reads nothing outside b.
//
// The remote targets run the same two patterns on the host (see
// [remotePEMPattern]), so a file is labelled the same way whichever side looks.
func ScanPEMLabels(b []byte, max int) []string {
	if max <= 0 || max > maxPEMLabels {
		max = maxPEMLabels
	}
	var out []string
	for len(b) > 0 && len(out) < max {
		i5 := bytes.Index(b, []byte("-----BEGIN "))
		i4 := bytes.Index(b, []byte("---- BEGIN "))
		var start int
		var closer []byte
		switch {
		case i5 < 0 && i4 < 0:
			return out
		case i4 < 0 || (i5 >= 0 && i5 < i4):
			start, closer = i5+len("-----BEGIN "), []byte("-----")
		default:
			start, closer = i4+len("---- BEGIN "), []byte(" ----")
		}
		rest := b[start:]
		label, ok := pemLabelAt(rest, closer)
		if ok {
			out = append(out, label)
			b = rest[len(label)+len(closer):]
			continue
		}
		b = rest
	}
	return out
}

// pemLabelAt reads a label from the start of b up to closer: one to 80 bytes,
// none of them a dash or a line break, as the remote grep pattern requires.
func pemLabelAt(b, closer []byte) (string, bool) {
	end := bytes.Index(b, closer)
	if end <= 0 || end > maxPEMLabelLen {
		return "", false
	}
	label := b[:end]
	if bytes.ContainsAny(label, "-\r\n") {
		return "", false
	}
	return string(label), true
}

// hasPrivateMarker reports whether b contains a PEM header naming private
// material anywhere, beyond the label bound. A bundle of 64 certificates
// followed by a private key would otherwise identify as a certificate file.
// The remote targets compute the same answer on the host.
func hasPrivateMarker(b []byte) bool {
	upper := bytes.ToUpper(b)
	for {
		i := bytes.Index(upper, []byte("BEGIN "))
		if i < 0 {
			return false
		}
		line := upper[i:]
		if j := bytes.IndexAny(line, "\r\n"); j >= 0 {
			line = line[:j]
		}
		// The label runs to the next dash, as in the remote pattern.
		label := line[len("BEGIN "):]
		if j := bytes.IndexByte(label, '-'); j >= 0 {
			label = label[:j]
		}
		if bytes.Contains(label, []byte("PRIVATE")) {
			return true
		}
		upper = upper[i+len("BEGIN "):]
	}
}

// identityFrom is how every target assembles an Identity: classify by name and
// markers, then let a private marker the label bound missed demote a public
// answer. It is the one place this rule lives.
func identityFrom(name string, magic []byte, labels []string, privateMarker bool) Identity {
	id := ClassifyNamed(name, magic, labels)
	if privateMarker {
		switch id.Class {
		case ClassCertificate:
			id.Class = ClassMixed
		case ClassPrivateKey, ClassMixed, ClassPGP, ClassKeystore:
		default:
			id.Class = ClassPrivateKey
		}
	}
	return id
}

// baseName returns the last element of a path in either separator style. A
// Windows path read by a Linux agent must still have a base name.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// extOf returns the extension of a base name, including the dot, or "".
func extOf(base string) string {
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		return base[i:]
	}
	return ""
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneLabels(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	if len(l) > maxPEMLabels {
		l = l[:maxPEMLabels]
	}
	return append([]string(nil), l...)
}
