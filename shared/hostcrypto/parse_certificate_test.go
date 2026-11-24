package hostcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/certificates"
)

// The certificate spellings must be the ones host inventory and the sensor
// produce, or a certificate on disk and the same certificate on the wire do
// not join. shared/certificates is what both use; compare against it.
func TestParseCertificateDER_MatchesSharedSpelling(t *testing.T) {
	keys := keyTestKeys(t)
	der := keyTestSelfSigned(t, keys[2].priv, "spelling")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	shared := certificates.ExtractCertificatesFromX509([]*x509.Certificate{cert})[0]

	c, err := ParseCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if c.FingerprintSHA256 != shared.FingerprintSHA256 {
		t.Errorf("fingerprint %q, shared spells it %q", c.FingerprintSHA256, shared.FingerprintSHA256)
	}
	if c.SubjectDN != shared.SubjectDN || c.IssuerDN != shared.IssuerDN {
		t.Errorf("DNs %q / %q, shared %q / %q", c.SubjectDN, c.IssuerDN, shared.SubjectDN, shared.IssuerDN)
	}
	// host inventory's summariseCert format.
	if want := shared.NotAfter.UTC().Format(time.RFC3339); c.NotAfter != want || c.NotAfter != "2027-01-01T00:00:00Z" {
		t.Errorf("NotAfter %q, want %q", c.NotAfter, want)
	}
	if c.NotBefore != "2026-01-01T00:00:00Z" {
		t.Errorf("NotBefore %q", c.NotBefore)
	}
	if c.SignatureAlg != shared.SignatureAlg || c.KeyAlgorithm != shared.KeyAlgorithm || c.KeySize != shared.KeySize {
		t.Errorf("sig %q key %q/%d; shared %q %q/%d", c.SignatureAlg, c.KeyAlgorithm, c.KeySize, shared.SignatureAlg, shared.KeyAlgorithm, shared.KeySize)
	}
	if c.PublicKeySHA256 != certificates.PublicKeyFingerprintSHA256(cert) {
		t.Errorf("PublicKeySHA256 %q, shared %q", c.PublicKeySHA256, certificates.PublicKeyFingerprintSHA256(cert))
	}
	if c.CertificatePEM != shared.CertificatePEM {
		t.Error("CertificatePEM differs from the shared encoding")
	}
	if c.SerialNumber != "1f2e3d" {
		t.Errorf("serial %q, want lowercase hex without prefix", c.SerialNumber)
	}
	if !c.IsCA || !c.SelfSigned || c.Curve != "P-256" {
		t.Errorf("IsCA=%v SelfSigned=%v Curve=%q", c.IsCA, c.SelfSigned, c.Curve)
	}
	if strings.Join(c.DNSNames, ",") != "a.example.test,b.example.test" {
		t.Errorf("DNSNames %v", c.DNSNames)
	}
	if c.Location.FoundBy != "" || c.TrustAnchor || c.HasPrivateKey != nil {
		t.Error("filled a field that is the caller's")
	}
}

func TestParseCertificateDER_SelfSigned(t *testing.T) {
	keys := keyTestKeys(t)
	ca, caKey := keys[2], keys[3]
	caDER := keyTestSelfSigned(t, ca.priv, "Example CA")
	caCert, _ := x509.ParseCertificate(caDER)

	issue := func(subject pkix.Name, signer keyTestKey, parent *x509.Certificate) []byte {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(7),
			Subject:      subject,
			NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			IPAddresses:  []net.IP{net.ParseIP("192.0.2.10")},
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, keys[4].priv.Public(), signer.priv)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	leaf, _ := ParseCertificateDER(issue(pkix.Name{CommonName: "leaf"}, ca, caCert))
	if leaf.SelfSigned || leaf.IsCA {
		t.Errorf("a CA-issued leaf reads self-signed=%v ca=%v", leaf.SelfSigned, leaf.IsCA)
	}
	if strings.Join(leaf.IPAddresses, ",") != "192.0.2.10" {
		t.Errorf("IPAddresses %v", leaf.IPAddresses)
	}
	// Subject equals issuer, but the signature is another key's: the name
	// comparison alone would call it self-signed.
	impostor, _ := ParseCertificateDER(issue(caCert.Subject, caKey, &x509.Certificate{Subject: caCert.Subject}))
	if impostor.SelfSigned {
		t.Error("a certificate whose signature does not verify with its own key read as self-signed")
	}
	// A self-signed, non-CA leaf: CheckSignatureFrom would refuse it for the
	// missing CA flag; the self-signed answer must not depend on that.
	self, _ := ParseCertificateDER(issue(pkix.Name{CommonName: "self"}, keys[4], nil))
	if !self.SelfSigned {
		t.Error("a self-signed leaf read as not self-signed")
	}
}

// keyTestHandCert builds a certificate DER by hand, for key types
// crypto/x509 cannot create (or parse).
func keyTestHandCert(t testing.TB, spkiAlg keyTestAlg, pub []byte, sigOID string, serial *big.Int, cn string) []byte {
	t.Helper()
	name := keyTestMarshal(t, pkix.Name{CommonName: cn}.ToRDNSequence())
	type validity struct{ NotBefore, NotAfter time.Time }
	tbs := keyTestMarshal(t, struct {
		Version   int `asn1:"optional,explicit,default:0,tag:0"`
		Serial    *big.Int
		Sig       keyTestAlg
		Issuer    asn1.RawValue
		Validity  validity
		Subject   asn1.RawValue
		PublicKey struct {
			Alg keyTestAlg
			Pub asn1.BitString
		}
	}{
		2, serial, keyTestAlg{OID: keyMustOID(sigOID)}, keyTestRaw(name),
		validity{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		keyTestRaw(name),
		struct {
			Alg keyTestAlg
			Pub asn1.BitString
		}{spkiAlg, asn1.BitString{Bytes: pub, BitLength: 8 * len(pub)}},
	})
	sig := keyTestRandom(64)
	return keyTestMarshal(t, struct {
		TBS asn1.RawValue
		Alg keyTestAlg
		Sig asn1.BitString
	}{keyTestRaw(tbs), keyTestAlg{OID: keyMustOID(sigOID)}, asn1.BitString{Bytes: sig, BitLength: 512}})
}

func keyTestSPKIOf(t testing.TB, der []byte) string {
	t.Helper()
	var c struct {
		TBS struct {
			Version   int `asn1:"optional,explicit,default:0,tag:0"`
			Serial    asn1.RawValue
			Sig       asn1.RawValue
			Issuer    asn1.RawValue
			Validity  asn1.RawValue
			Subject   asn1.RawValue
			PublicKey asn1.RawValue
		}
	}
	if _, err := asn1.Unmarshal(der, &c); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(c.TBS.PublicKey.FullBytes)
	return hex.EncodeToString(s[:])
}

func TestParseCertificateDER_MLDSA(t *testing.T) {
	pub := keyTestRandom(1952)
	der := keyTestHandCert(t, keyTestAlg{OID: keyMustOID("2.16.840.1.101.3.4.3.18")}, pub, "2.16.840.1.101.3.4.3.18", big.NewInt(42), "ml-dsa test")
	c, err := ParseCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if c.KeyAlgorithm != "ML-DSA-65" || c.KeySize != 0 || !strings.Contains(c.SignatureAlg, "ML-DSA-65") {
		t.Errorf("key %q/%d sig %q", c.KeyAlgorithm, c.KeySize, c.SignatureAlg)
	}
	if c.FingerprintSHA256 != hex.EncodeToString(sum[:]) || c.PublicKeySHA256 != keyTestSPKIOf(t, der) {
		t.Errorf("fingerprint %q / spki %q", c.FingerprintSHA256, c.PublicKeySHA256)
	}
	if c.SubjectDN != "CN=ml-dsa test" || !c.SelfSigned || c.SerialNumber != "2a" {
		t.Errorf("subject %q self-signed %v serial %q", c.SubjectDN, c.SelfSigned, c.SerialNumber)
	}
}

// crypto/x509 refuses secp256k1 and a negative serial; the certificate is
// still described from its TBSCertificate.
func TestParseCertificateDER_FallbackWhenX509Refuses(t *testing.T) {
	point := append([]byte{4}, keyTestRandom(64)...)
	alg := keyTestAlg{OID: keyMustOID(keyOIDEC), Params: keyTestRaw(keyTestMarshal(t, keyMustOID("1.3.132.0.10")))}
	for _, serial := range []*big.Int{big.NewInt(0x0abc), big.NewInt(-5)} {
		der := keyTestHandCert(t, alg, point, "1.2.840.10045.4.3.2", serial, "k1 test")
		if _, err := x509.ParseCertificate(der); err == nil {
			t.Fatal("the fixture parses with crypto/x509; it no longer tests the fallback")
		}
		c, err := ParseCertificateDER(der)
		if err != nil {
			t.Fatalf("serial %v: %v", serial, err)
		}
		sum := sha256.Sum256(der)
		if c.KeyAlgorithm != "ECDSA" || c.Curve != "secp256k1" || c.KeySize != 256 || c.SignatureAlg != "ECDSA-SHA256" {
			t.Errorf("key %q %q %d sig %q", c.KeyAlgorithm, c.Curve, c.KeySize, c.SignatureAlg)
		}
		if c.FingerprintSHA256 != hex.EncodeToString(sum[:]) || c.PublicKeySHA256 != keyTestSPKIOf(t, der) || c.CertificatePEM == "" {
			t.Error("fingerprint, SPKI hash or PEM missing from the fallback")
		}
		if c.SubjectDN != "CN=k1 test" || c.IssuerDN != "CN=k1 test" || !c.SelfSigned || c.NotAfter != "2027-01-01T00:00:00Z" {
			t.Errorf("subject %q issuer %q self %v notAfter %q", c.SubjectDN, c.IssuerDN, c.SelfSigned, c.NotAfter)
		}
		if c.SerialNumber != serial.Text(16) {
			t.Errorf("serial %q, want %q", c.SerialNumber, serial.Text(16))
		}
	}
}

func TestParseCertificateDER_TrailingDataAndErrors(t *testing.T) {
	keys := keyTestKeys(t)
	der := keyTestSelfSigned(t, keys[5].priv, "trusted")
	// OpenSSL's TRUSTED CERTIFICATE: the certificate, then its trust settings.
	aux := keyTestMarshal(t, struct{ Trust []asn1.ObjectIdentifier }{[]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}}})
	c, err := ParseCertificateDER(append(append([]byte{}, der...), aux...))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if c.FingerprintSHA256 != hex.EncodeToString(sum[:]) {
		t.Error("the fingerprint covered the trailing trust settings")
	}
	secret := "SECRET-CONTENT-1234"
	for _, bad := range [][]byte{nil, []byte(secret), der[:len(der)/2]} {
		_, err := ParseCertificateDER(bad)
		if err == nil {
			t.Error("garbage parsed as a certificate")
		} else if strings.Contains(err.Error(), secret) || err.Error() != "hostcrypto: not a certificate" {
			t.Errorf("error %q is not the generic one", err)
		}
	}
}
