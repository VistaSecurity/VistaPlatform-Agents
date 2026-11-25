package hostcrypto

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"strings"
)

// PEM files: every block in one file, whatever it holds.

const (
	// keyDefaultMaxRecords is the per-file bound on PEM blocks and
	// authorized_keys lines, the same number as the per-section bound in
	// docs/design/host-crypto.md. A CA bundle has a few hundred blocks.
	keyDefaultMaxRecords = 2000
	// keyMaxOtherLabels bounds the distinct labels counted in
	// PEMContents.Other; the rest are counted under keyOtherLabel.
	keyMaxOtherLabels = 32
	keyOtherLabel     = "(other)"
	keyMaxLabelLen    = 64
	keyPEMBegin       = "-----BEGIN "
)

// PEMLimits bounds one [ParsePEMFile] call.
type PEMLimits struct {
	// MaxBlocks stops the walk after this many blocks. 0 means 2000.
	MaxBlocks int
}

// PEMContents is what one PEM file holds. Location is left zero on every
// record for the caller to fill.
type PEMContents struct {
	Certificates []Certificate   `json:"certificates,omitempty"`
	PrivateKeys  []PrivateKey    `json:"private_keys,omitempty"`
	PublicKeys   []PublicKeyInfo `json:"public_keys,omitempty"`
	// Other counts the blocks that are neither certificates nor keys, by
	// label: "CERTIFICATE REQUEST", "X509 CRL", "DH PARAMETERS", "EC
	// PARAMETERS".
	Other map[string]int `json:"other,omitempty"`
	// Malformed counts blocks that did not decode or did not parse as what
	// their label says. Nothing of them is kept.
	Malformed int `json:"malformed"`
	// Truncated is true when MaxBlocks stopped the walk, so a caller can
	// record the bound in [Report.Limits].
	Truncated bool `json:"truncated"`
}

// PublicKeyInfo is a bare public key ("PUBLIC KEY", "RSA PUBLIC KEY"). No
// report section lists bare public keys; a collector can use PublicKeySHA256
// to pair one with a private key or certificate.
type PublicKeyInfo struct {
	Algorithm       string `json:"algorithm,omitempty"`
	SizeBits        int    `json:"size_bits,omitempty"`
	Curve           string `json:"curve,omitempty"`
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
}

// ParsePEMFile walks every PEM block in b, in order, within limits.
//
// The file is split on "-----BEGIN " lines by this function, and each block
// is decoded on its own, so a broken block is counted as malformed and the
// next one is still read (encoding/pem on the whole file would skip past a
// broken block without saying so). Text outside blocks (OpenSSL's "Bag
// Attributes", a certificate's text dump) is ignored. Each byte of the input
// is scanned a bounded number of times whatever its shape.
//
// Legacy OpenSSL encryption ("Proc-Type: 4,ENCRYPTED" with "DEK-Info") is
// reported from the headers: encrypted, the cipher named, the algorithm from
// the label, and the size unknown.
func ParsePEMFile(b []byte, limits PEMLimits) PEMContents {
	max := limits.MaxBlocks
	if max <= 0 {
		max = keyDefaultMaxRecords
	}
	var out PEMContents
	begin := []byte(keyPEMBegin)
	pos := 0
	blocks := 0
	budget := newKeyBudget()
	for {
		i := bytes.Index(b[pos:], begin)
		if i < 0 {
			break
		}
		start := pos + i
		end := len(b)
		if j := bytes.Index(b[start+len(begin):], begin); j >= 0 {
			end = start + len(begin) + j
		}
		pos = end
		if blocks >= max {
			out.Truncated = true
			break
		}
		blocks++
		block, _ := pem.Decode(b[start:end])
		if block == nil {
			out.Malformed++
			continue
		}
		keyPEMBlock(&out, block, budget)
	}
	return out
}

func keyPEMBlock(out *PEMContents, block *pem.Block, budget *keyBudget) {
	switch block.Type {
	case "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE":
		c, err := keyParseCertificateDER(block.Bytes, budget)
		if err != nil {
			out.Malformed++
			return
		}
		out.Certificates = append(out.Certificates, c)
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "ANY PRIVATE KEY":
		if k, ok := keyLegacyEncrypted(block); ok {
			out.PrivateKeys = append(out.PrivateKeys, k)
			return
		}
		k, ok := keyParsePrivateKeyDER(block.Bytes, budget)
		if !ok {
			out.Malformed++
			return
		}
		out.PrivateKeys = append(out.PrivateKeys, k)
	case "OPENSSH PRIVATE KEY":
		keys, ok := ParseOpenSSHPrivateKey(block.Bytes)
		if !ok {
			out.Malformed++
			return
		}
		out.PrivateKeys = append(out.PrivateKeys, keys...)
	case "PUBLIC KEY":
		var first asn1.RawValue
		if _, err := asn1.Unmarshal(block.Bytes, &first); err != nil {
			out.Malformed++
			return
		}
		info, ok := keySPKIInfo(first.FullBytes)
		if !ok {
			out.Malformed++
			return
		}
		out.PublicKeys = append(out.PublicKeys, info)
	case "RSA PUBLIC KEY":
		_, el, ok := keySequence(block.Bytes)
		if !ok || len(el) != 2 || !keyAllInts(el) {
			out.Malformed++
			return
		}
		n, _ := keyBigInt(el[0])
		e, _ := keyBigInt(el[1])
		info, ok := keySPKIInfo(keyRSASPKI(n, e, nil))
		if n == nil || e == nil || !ok {
			out.Malformed++
			return
		}
		out.PublicKeys = append(out.PublicKeys, info)
	default:
		keyCountOther(out, block.Type)
	}
}

// keyLegacyEncrypted describes a key encrypted with OpenSSL's traditional PEM
// encryption. The algorithm is the label's; the size is inside the
// ciphertext.
func keyLegacyEncrypted(block *pem.Block) (PrivateKey, bool) {
	if !strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return PrivateKey{}, false
	}
	format, alg := KeyFormatPKCS8, ""
	switch block.Type {
	case "RSA PRIVATE KEY":
		format, alg = KeyFormatPKCS1, "RSA"
	case "EC PRIVATE KEY":
		format, alg = KeyFormatSEC1, "ECDSA"
	case "DSA PRIVATE KEY":
		format, alg = KeyFormatDSA, "DSA"
	}
	k := keyNew(format, true)
	k.Algorithm = alg
	cipher, _, _ := strings.Cut(block.Headers["DEK-Info"], ",")
	k.Encryption = strings.ToLower(keySafeName([]byte(strings.TrimSpace(cipher))))
	k.Unknown = "encrypted; size and public key not readable without the passphrase"
	return k, true
}

func keyCountOther(out *PEMContents, label string) {
	if !keyPlausibleLabel(label) {
		out.Malformed++
		return
	}
	if out.Other == nil {
		out.Other = map[string]int{}
	}
	if _, seen := out.Other[label]; !seen && len(out.Other) >= keyMaxOtherLabels {
		label = keyOtherLabel
	}
	out.Other[label]++
}

// keyPlausibleLabel accepts the labels RFC 7468 allows (printable ASCII
// without hyphen-runs) up to a sane length, so the report never repeats an
// arbitrary line of a hostile file as a map key.
func keyPlausibleLabel(l string) bool {
	if l == "" || len(l) > keyMaxLabelLen {
		return false
	}
	for _, c := range []byte(l) {
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ' ', c == '-', c == '.', c == '_', c == '/':
		default:
			return false
		}
	}
	return true
}
