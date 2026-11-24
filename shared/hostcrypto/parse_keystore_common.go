package hostcrypto

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/certificates"
)

// KeystoreContents is what one keystore file yielded.
//
// Entries follow keytool's rule in every format, so a JKS and the same store
// converted to PKCS#12 list alike: ONE ENTRY PER KEY, carrying its
// certificate chain, and ONE PER TRUSTED CERTIFICATE (a certificate that is
// in no key's chain). A key's own certificate and its chain are not separate
// entries; they are in Certificates, under the key's alias. EntryCount counts
// entries by the same rule.
type KeystoreContents struct {
	Keystore     Keystore
	Certificates []Certificate // certificates inside it; Location.Alias set

	// DefaultsNotTried says, in a few words, why default passwords were not
	// tried although the operator asked ("iteration count above the limit",
	// "integrity is by signature"). Empty when they were tried or not asked
	// for. Keystore.DefaultPassword is nil whenever this is set; the collector
	// records it as a LimitHit or a reason.
	DefaultsNotTried string
	// Truncated is true when the listing stopped before the end: the entry
	// cap, or a JCEKS secret key that cannot be stepped over.
	Truncated bool
}

// DefaultKeystorePasswords are the well-known defaults tried against JKS,
// JCEKS and PKCS#12 files when the operator opts in (Scope.DefaultKeystorePasswords):
// the JDK's "changeit", the common "changeme" and "password", and empty.
//
// Only "one of them worked" is ever recorded ([Keystore.DefaultPassword]),
// never WHICH one: which default opens a store is itself the store's
// password, and a report must not carry a password.
var DefaultKeystorePasswords = []string{"changeit", "changeme", "password", ""}

// DefaultMaxKeystoreEntries bounds how many entries one keystore listing keeps.
// A store claiming more is listed that far; its EntryCount still says how many
// it claims, so a reader can see the list is cut short.
const DefaultMaxKeystoreEntries = 5000

// ksCertificate describes one DER certificate found inside a keystore.
// Location is left zero: the caller sets Location.Alias, and the collector the
// rest. It reports false when the bytes are not a certificate.
//
// The fingerprint and DN spelling come from shared/certificates, exactly as
// hostinventory's summariseCert takes them, so the same certificate found in a
// keystore, in a trust store and on the wire carries the same identity.
//
// TODO(merge): replace with ParseCertificateDER
func ksCertificate(der []byte) (Certificate, bool) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Certificate{}, false
	}
	return ksCertificateFrom(cert), true
}

// ksCertificateFrom is ksCertificate for a certificate already parsed.
//
// TODO(merge): replace with the shared certificate parser
func ksCertificateFrom(cert *x509.Certificate) Certificate {
	info := certificates.ExtractCertificatesFromX509([]*x509.Certificate{cert})[0]
	out := Certificate{
		SubjectDN:         info.SubjectDN,
		IssuerDN:          info.IssuerDN,
		SerialNumber:      info.SerialNumber,
		FingerprintSHA256: info.FingerprintSHA256,
		NotBefore:         cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          cert.NotAfter.UTC().Format(time.RFC3339),
		KeyAlgorithm:      ksKeyAlgorithmName(cert.PublicKeyAlgorithm),
		KeySize:           certificates.CalculateKeySize(cert.PublicKey),
		Curve:             certificates.PublicKeyCurve(cert.PublicKey),
		SignatureAlg:      info.SignatureAlg,
		IsCA:              cert.IsCA,
		SelfSigned:        ksSelfSigned(cert),
		DNSNames:          cert.DNSNames,
		PublicKeySHA256:   certificates.PublicKeyFingerprintSHA256(cert),
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	for _, ip := range cert.IPAddresses {
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}
	return out
}

// ksKeyAlgorithmName spells a certificate's key algorithm the catalogue's way.
func ksKeyAlgorithmName(a x509.PublicKeyAlgorithm) string {
	switch a {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	case x509.DSA:
		return "DSA"
	default:
		return ""
	}
}

// ksSelfSigned is true when the certificate names itself as issuer and its
// own key verifies its signature. CheckSignatureFrom is not used: it also
// demands the issuer be a CA, and a self-signed leaf is exactly what a
// keystore often holds.
func ksSelfSigned(cert *x509.Certificate) bool {
	if string(cert.RawIssuer) != string(cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// ksDERFingerprint is the SHA-256 of bytes that should be a certificate, in
// the same spelling as a parsed certificate's fingerprint. It lets an entry
// name its certificate even when the bytes do not parse.
func ksDERFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ksTrustAnchor marks a certificate as a trust store member and drops its PEM,
// as [Certificate.TrustAnchor] asks: a trust store has hundreds and the
// fingerprint identifies them.
func ksTrustAnchor(c Certificate) Certificate {
	c.TrustAnchor = true
	c.CertificatePEM = ""
	return c
}

// ksIntPtr makes an optional count.
func ksIntPtr(n int) *int { return &n }

// ksReader reads big-endian fields from a byte slice and refuses, rather
// than panics on, any read past the end. Every length a file states is
// checked against what is left before anything is sliced, so a hostile
// length costs nothing.
type ksReader struct {
	b   []byte
	off int
	bad bool
}

func (r *ksReader) remaining() int { return len(r.b) - r.off }

// take returns the next n bytes, or nil and marks the reader bad.
func (r *ksReader) take(n int) []byte {
	if r.bad || n < 0 || n > r.remaining() {
		r.bad = true
		return nil
	}
	s := r.b[r.off : r.off+n]
	r.off += n
	return s
}

// skip moves past n bytes without exposing them.
func (r *ksReader) skip(n int) {
	if r.bad || n < 0 || n > r.remaining() {
		r.bad = true
		return
	}
	r.off += n
}

func (r *ksReader) u8() uint8 {
	s := r.take(1)
	if s == nil {
		return 0
	}
	return s[0]
}

func (r *ksReader) u16() uint16 {
	s := r.take(2)
	if s == nil {
		return 0
	}
	return uint16(s[0])<<8 | uint16(s[1])
}

func (r *ksReader) u32() uint32 {
	s := r.take(4)
	if s == nil {
		return 0
	}
	return uint32(s[0])<<24 | uint32(s[1])<<16 | uint32(s[2])<<8 | uint32(s[3])
}

func (r *ksReader) u64() uint64 {
	hi := r.u32()
	lo := r.u32()
	return uint64(hi)<<32 | uint64(lo)
}
