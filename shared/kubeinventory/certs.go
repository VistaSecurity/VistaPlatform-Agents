package kubeinventory

import (
	"crypto/x509"
	"encoding/pem"
	"sort"
	"sync"

	"github.com/vistasecurity/vistaplatform-agents/shared/certificates"
)

// maxCertificatesPerBundle bounds how many certificates one PEM bundle
// contributes, and maxChainLen how many a row may name (the schema's bound).
const (
	maxCertificatesPerBundle = 256
	maxChainLen              = 32
)

// parseCertificates returns the certificates of a PEM bundle. Blocks of any
// other type are skipped without being parsed, whatever they are; a
// certificate that does not parse is skipped.
func parseCertificates(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for len(data) > 0 && len(out) < maxCertificatesPerBundle {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
	return out
}

// parseCSR describes a PEM certificate signing request, or returns nil.
func parseCSR(data []byte) *CSR {
	block, _ := pem.Decode(data)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil
	}
	return &CSR{
		SubjectDN:    clip(req.Subject.String(), 2048),
		DNSNames:     limit(clipAll(req.DNSNames, 253), 1024),
		KeyAlgorithm: req.PublicKeyAlgorithm.String(),
		KeySize:      certificates.CalculateKeySize(req.PublicKey),
		SignatureAlg: req.SignatureAlgorithm.String(),
	}
}

// certTable holds each distinct certificate of a collection once.
type certTable struct {
	mu         sync.Mutex
	byFP       map[string]Certificate
	includePEM bool
}

func newCertTable(includePEM bool) *certTable {
	return &certTable{byFP: map[string]Certificate{}, includePEM: includePEM}
}

// add records the certificates and returns their SHA-256 fingerprints in the
// order given, at most maxChainLen of them. The result is never nil.
func (t *certTable) add(certs []*x509.Certificate) []string {
	fps := []string{}
	if len(certs) > maxChainLen {
		certs = certs[:maxChainLen]
	}
	infos := certificates.ExtractCertificatesFromX509(certs)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, info := range infos {
		fp := info.FingerprintSHA256
		fps = append(fps, fp)
		if _, ok := t.byFP[fp]; ok {
			continue
		}
		notBefore, notAfter := info.NotBefore.UTC(), info.NotAfter.UTC()
		entry := Certificate{
			SubjectDN:               clip(info.SubjectDN, 2048),
			IssuerDN:                clip(info.IssuerDN, 2048),
			SerialNumber:            clip(info.SerialNumber, 128),
			NotBefore:               &notBefore,
			NotAfter:                &notAfter,
			KeyAlgorithm:            info.KeyAlgorithm,
			KeySize:                 info.KeySize,
			SignatureAlg:            info.SignatureAlg,
			IsCA:                    info.IsCA,
			FingerprintSHA256:       fp,
			FingerprintSHA1:         info.FingerprintSHA1,
			SubjectAlternativeNames: limit(clipAll(info.SubjectAlternativeNames, 512), 1024),
			KeyUsage:                limit(info.KeyUsage, 16),
			ExtendedKeyUsage:        limit(info.ExtendedKeyUsage, 32),
		}
		if t.includePEM && len(info.CertificatePEM) <= 65536 {
			entry.CertificatePEM = info.CertificatePEM
		}
		t.byFP[fp] = entry
	}
	return fps
}

// addPEM is add for a PEM bundle.
func (t *certTable) addPEM(data []byte) []string { return t.add(parseCertificates(data)) }

// all returns the table sorted by fingerprint.
func (t *certTable) all() []Certificate {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Certificate, 0, len(t.byFP))
	for _, c := range t.byFP {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FingerprintSHA256 < out[j].FingerprintSHA256 })
	return out
}
