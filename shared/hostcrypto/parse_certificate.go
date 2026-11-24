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
	"net"
	"time"
	"unicode/utf8"
)

// Certificates in DER.
//
// The spellings here are host inventory's and the sensor's, on purpose: the
// fingerprint is lowercase hex without separators of the SHA-256 of the DER
// (shared/certificates.ExtractCertificatesFromX509), the serial number is
// decimal (big.Int.String(), as that shared entry's serial_number is), the
// DNs are pkix.Name.String(), the dates RFC 3339 in UTC. A certificate found on disk
// and the same certificate seen served must produce the same strings or the
// platform cannot join them.

// keyMaxNames bounds the subject alternative names kept per certificate. A
// certificate with ten thousand names is legal and would otherwise dominate a
// report.
const keyMaxNames = 100

const (
	// keyMaxDNText caps a distinguished name; a DN is input and may be
	// megabytes long.
	keyMaxDNText = 1024
	// keyMaxDNSName is the longest DNS name kept (RFC 1035's 253 octets);
	// a longer entry is not a host name and is dropped.
	keyMaxDNSName = 253
	// keyMaxVerifyRSABits: a self-signature over a larger RSA key is not
	// checked (each check costs time quadratic in the modulus); the name
	// comparison decides instead.
	keyMaxVerifyRSABits = 8192
	// keyMaxVerificationsPerFile caps self-signature checks per file. A trust
	// bundle has a few hundred roots.
	keyMaxVerificationsPerFile = 512
)

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
	return keyParseCertificateDER(der, newKeyBudget())
}

func keyParseCertificateDER(der []byte, budget *keyBudget) (Certificate, error) {
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
		SubjectDN:         keyCapText(cert.Subject.String(), keyMaxDNText),
		IssuerDN:          keyCapText(cert.Issuer.String(), keyMaxDNText),
		SerialNumber:      keySerial(cert.SerialNumber),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		NotBefore:         cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          cert.NotAfter.UTC().Format(time.RFC3339),
		SignatureAlg:      cert.SignatureAlgorithm.String(),
		IsCA:              cert.IsCA,
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		out.SignatureAlg = keySignatureName(der)
	}
	if info, ok := keySPKIInfo(cert.RawSubjectPublicKeyInfo); ok {
		out.KeyAlgorithm, out.KeySize, out.Curve = info.Algorithm, info.SizeBits, info.Curve
		out.PublicKeySHA256 = info.PublicKeySHA256
	}
	out.SelfSigned = keySelfSigned(cert, out.KeyAlgorithm == "RSA" && out.KeySize > keyMaxVerifyRSABits, budget)
	keyAddNames(&out, cert.DNSNames, cert.IPAddresses)
	return out, nil
}

func keyAddNames(out *Certificate, dns []string, ips []net.IP) {
	for _, n := range dns {
		if len(out.DNSNames) >= keyMaxNames {
			break
		}
		if n != "" && len(n) <= keyMaxDNSName {
			out.DNSNames = append(out.DNSNames, n)
		}
	}
	for _, ip := range ips {
		if len(out.IPAddresses) >= keyMaxNames {
			break
		}
		if len(ip) == net.IPv4len || len(ip) == net.IPv6len {
			out.IPAddresses = append(out.IPAddresses, ip.String())
		}
	}
}

// keyCapText truncates s to at most n bytes on a UTF-8 boundary.
func keyCapText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// keySerial spells a serial number in decimal, as the shared certificate
// entry does. A serial is at most 20 octets by RFC 5280 but a hostile one is
// not, so the text is capped.
func keySerial(n *big.Int) string {
	if n == nil {
		return ""
	}
	if n.BitLen() > 1024 {
		return ""
	}
	return n.String()
}

// keySelfSigned is true when the certificate names itself as issuer AND its
// signature verifies with its own key. Where the signature cannot be checked
// (an algorithm crypto/x509 does not implement, or one it refuses as
// insecure, such as SHA-1 on an old root) the name comparison alone decides:
// that is the best available answer, and an old self-signed root is exactly
// the case that must not read as "not self-signed". The same holds for a key
// too large to check cheaply and for checks beyond the file's budget.
func keySelfSigned(cert *x509.Certificate, tooLarge bool, budget *keyBudget) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	if cert.PublicKey == nil || tooLarge || !budget.takeVerification() {
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
// crypto/x509 refused. encoding/asn1 allows the trailing fields it does not
// name; the extensions are found by keyTBSExtensions.
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
		out.SerialNumber = keySerial(serial)
	}
	out.SubjectDN = keyCapText(keyDN(tbs.Subject.FullBytes), keyMaxDNText)
	out.IssuerDN = keyCapText(keyDN(tbs.Issuer.FullBytes), keyMaxDNText)
	keyFallbackExtensions(&out, el[0].FullBytes)
	return out, nil
}

var (
	keyOIDBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	keyOIDSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// keyFallbackExtensions reads basicConstraints and subjectAltName from a
// TBSCertificate's [3] extensions, for a certificate crypto/x509 refused. An
// extension that does not parse is skipped, not fatal: a malformed extension
// may be the very reason crypto/x509 refused the certificate.
func keyFallbackExtensions(out *Certificate, tbs []byte) {
	_, el, ok := keySequence(tbs)
	if !ok {
		return
	}
	var exts []pkix.Extension
	for _, e := range el {
		if e.Class == asn1.ClassContextSpecific && e.Tag == 3 && e.IsCompound {
			if rest, err := asn1.Unmarshal(e.Bytes, &exts); err != nil || len(rest) != 0 {
				return
			}
		}
	}
	var dns []string
	var ips []net.IP
	for _, x := range exts {
		switch {
		case x.Id.Equal(keyOIDBasicConstraints):
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional,default:-1"`
			}
			if rest, err := asn1.Unmarshal(x.Value, &bc); err == nil && len(rest) == 0 {
				out.IsCA = bc.IsCA
			}
		case x.Id.Equal(keyOIDSubjectAltName):
			var seq asn1.RawValue
			if rest, err := asn1.Unmarshal(x.Value, &seq); err != nil || len(rest) != 0 || !keyIsSeq(seq) {
				continue
			}
			names := seq.Bytes
			for len(names) > 0 && len(dns)+len(ips) < 2*keyMaxNames {
				var gn asn1.RawValue
				r, err := asn1.Unmarshal(names, &gn)
				if err != nil {
					break
				}
				names = r
				if gn.Class != asn1.ClassContextSpecific || gn.IsCompound {
					continue
				}
				switch gn.Tag {
				case 2: // dNSName
					dns = append(dns, string(gn.Bytes))
				case 7: // iPAddress
					ips = append(ips, net.IP(gn.Bytes))
				}
			}
		}
	}
	keyAddNames(out, dns, ips)
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
	return keyUnrecognised("", oid)
}
