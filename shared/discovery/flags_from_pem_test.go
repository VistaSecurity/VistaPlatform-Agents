package discovery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeTestCertPEM builds a minimal self-signed RSA cert of the given key size
// and returns its PEM.
func makeTestCertPEM(t *testing.T, commonName string, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestClassifyCertChainFromPEMs_EmptyAndGarbage(t *testing.T) {
	if v := ClassifyCertChainFromPEMs(nil, false); v != nil {
		t.Errorf("nil input: want nil, got %+v", v)
	}
	if v := ClassifyCertChainFromPEMs([]string{"", "not a pem"}, false); v != nil {
		t.Errorf("garbage input: want nil, got %+v", v)
	}
}

func TestClassifyCertChainFromPEMs_ForwardsObservedQualityFlags(t *testing.T) {
	// Both key sizes parse and retain observed quality facts. The classifier
	// does not label either certificate weak; policy owns that judgment.
	strong := makeTestCertPEM(t, "strong.example.com", 2048)
	v := ClassifyCertChainFromPEMs([]string{strong}, false)
	if v == nil {
		t.Fatal("want non-nil validation for a parseable cert")
	}
	// cert_has_sct is always emitted by ClassifyCertificateFlags — its presence
	// proves the adapter parsed the PEM and ran the shared classifier.
	if _, ok := v.QualityFlags["cert_has_sct"].(bool); !ok {
		t.Fatalf("cert_has_sct missing or wrong type: %#v", v.QualityFlags["cert_has_sct"])
	}
	small := makeTestCertPEM(t, "small-key.example.com", 1024)
	vw := ClassifyCertChainFromPEMs([]string{small}, false)
	if vw == nil {
		t.Fatal("want non-nil validation for a parseable 1024-bit cert")
	}
	for _, flags := range []map[string]interface{}{v.QualityFlags, vw.QualityFlags} {
		if _, ok := flags["cert_weak_public_key"]; ok {
			t.Errorf("retired cert_weak_public_key judgment present: %#v", flags)
		}
		if _, ok := flags["cert_weak_signature"]; ok {
			t.Errorf("retired cert_weak_signature judgment present: %#v", flags)
		}
	}
}
