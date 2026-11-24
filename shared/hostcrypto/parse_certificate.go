package hostcrypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// Certificates in DER.
//
// The spellings here are host inventory's and the sensor's, on purpose: the
// fingerprint is lowercase hex without separators of the SHA-256 of the DER
// (shared/certificates.ExtractCertificatesFromX509), the DNs are
// pkix.Name.String(), the dates RFC 3339 in UTC. A certificate found on disk
// and the same certificate seen served must produce the same strings or the
// platform cannot join them.

// keyMaxNames bounds the subject alternative names kept per certificate. A
// certificate with ten thousand names is legal and would otherwise dominate a
// report.
const keyMaxNames = 100

var errNotCertificate = errors.New("hostcrypto: not a certificate")

// ParseCertificateDER describes one X.509 certificate. Location,
// TrustAnchor and HasPrivateKey are the caller's to fill.
//
// Bytes after the certificate's own SEQUENCE are ignored, which is what an
// OpenSSL "TRUSTED CERTIFICATE" (the certificate followed by its trust
// settings) needs. A certificate crypto/x509 refuses (an unsupported curve
// such as secp256k1 or brainpool, a negative serial number, a malformed
// extension) is still described from its TBSCertificate, with the fields
// that need the full parse left empty. The error is generic and never quotes
// the input.
func ParseCertificateDER(der []byte) (Certificate, error) {
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(der, &first); err != nil || !keyIsSeq(first) {
		return Certificate{}, errNotCertificate
	}
	der = first.FullBytes

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return keyCertificateFallback(der)
	}
	sum := sha256.Sum256(cert.Raw)
	out := Certificate{
		SubjectDN:         cert.Subject.String(),
		IssuerDN:          cert.Issuer.String(),
		SerialNumber:      keySerial(cert.SerialNumber),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		NotBefore:         cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          cert.NotAfter.UTC().Format(time.RFC3339),
		SignatureAlg:      cert.SignatureAlgorithm.String(),
		IsCA:              cert.IsCA,
		SelfSigned:        keySelfSigned(cert),
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		out.SignatureAlg = keySignatureName(der)
	}
	if info, ok := keySPKIInfo(cert.RawSubjectPublicKeyInfo); ok {
		out.KeyAlgorithm, out.KeySize, out.Curve = info.Algorithm, info.SizeBits, info.Curve
		out.PublicKeySHA256 = info.PublicKeySHA256
	}
	for i, n := range cert.DNSNames {
		if i >= keyMaxNames {
			break
		}
		out.DNSNames = append(out.DNSNames, n)
	}
	for i, ip := range cert.IPAddresses {
		if i >= keyMaxNames {
			break
		}
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}
	return out, nil
}

// keySerial spells a serial number as lowercase hex without a prefix.
func keySerial(n *big.Int) string {
	if n == nil {
		return ""
	}
	return n.Text(16)
}

// keySelfSigned is true when the certificate names itself as issuer AND its
// signature verifies with its own key. Where the signature cannot be checked
// (an algorithm crypto/x509 does not implement, or one it refuses as
// insecure, such as SHA-1 on an old root) the name comparison alone decides:
// that is the best available answer, and an old self-signed root is exactly
// the case that must not read as "not self-signed".
func keySelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	if cert.PublicKey == nil {
		return true
	}
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err == nil {
		return true
	}
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		return true
	}
	return false
}

// keyTBS is the start of a TBSCertificate, enough to describe a certificate
// crypto/x509 refused. encoding/asn1 allows the trailing fields (unique IDs,
// extensions) it does not name.
type keyTBS struct {
	Version   int `asn1:"optional,explicit,default:0,tag:0"`
	Serial    asn1.RawValue
	Signature asn1.RawValue
	Issuer    asn1.RawValue
	Validity  struct {
		NotBefore, NotAfter time.Time
	}
	Subject   asn1.RawValue
	PublicKey asn1.RawValue
}

func keyCertificateFallback(der []byte) (Certificate, error) {
	_, el, ok := keySequence(der)
	if !ok || len(el) != 3 || !keyIsSeq(el[0]) || !keyIsSeq(el[1]) {
		return Certificate{}, errNotCertificate
	}
	var tbs keyTBS
	if _, err := asn1.Unmarshal(el[0].FullBytes, &tbs); err != nil {
		return Certificate{}, errNotCertificate
	}
	spki, ok := keySPKIInfo(tbs.PublicKey.FullBytes)
	if !ok {
		return Certificate{}, errNotCertificate
	}
	sum := sha256.Sum256(der)
	out := Certificate{
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		NotBefore:         tbs.Validity.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          tbs.Validity.NotAfter.UTC().Format(time.RFC3339),
		KeyAlgorithm:      spki.Algorithm,
		KeySize:           spki.SizeBits,
		Curve:             spki.Curve,
		PublicKeySHA256:   spki.PublicKeySHA256,
		SignatureAlg:      keySignatureName(der),
		// Without the full parse the signature cannot be checked; the names
		// are what is left.
		SelfSigned:     bytes.Equal(tbs.Subject.FullBytes, tbs.Issuer.FullBytes),
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
	// The serial is reported even when negative, which crypto/x509 refuses.
	if serial, ok := keyBigInt(tbs.Serial); ok {
		out.SerialNumber = serial.Text(16)
	}
	out.SubjectDN = keyDN(tbs.Subject.FullBytes)
	out.IssuerDN = keyDN(tbs.Issuer.FullBytes)
	return out, nil
}

func keyDN(der []byte) string {
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdn); err != nil || len(rest) != 0 {
		return ""
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdn)
	return n.String()
}

// keySignatures names the signature algorithms crypto/x509 does not, in its
// spelling where it has one, for a certificate it could not or would not
// fully read.
var keySignatures = map[string]string{
	"1.2.840.113549.1.1.5":    "SHA1-RSA",
	"1.2.840.113549.1.1.11":   "SHA256-RSA",
	"1.2.840.113549.1.1.12":   "SHA384-RSA",
	"1.2.840.113549.1.1.13":   "SHA512-RSA",
	"1.2.840.113549.1.1.10":   "RSASSA-PSS",
	"1.2.840.10045.4.1":       "ECDSA-SHA1",
	"1.2.840.10045.4.3.2":     "ECDSA-SHA256",
	"1.2.840.10045.4.3.3":     "ECDSA-SHA384",
	"1.2.840.10045.4.3.4":     "ECDSA-SHA512",
	"1.3.101.112":             "Ed25519",
	"1.3.101.113":             "Ed448",
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
	"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	"1.2.156.10197.1.501":     "SM2-SM3",
}

// keySignatureName reads the outer signatureAlgorithm of a certificate.
func keySignatureName(der []byte) string {
	_, el, ok := keySequence(der)
	if !ok || len(el) != 3 {
		return ""
	}
	oid, _, ok := keyAlgorithmID(el[1])
	if !ok {
		return ""
	}
	if name, ok := keySignatures[oid]; ok {
		return name
	}
	if info, ok := keyAlgorithms[oid]; ok {
		return info.name // the SLH-DSA family signs under its key OIDs
	}
	return oid
}
