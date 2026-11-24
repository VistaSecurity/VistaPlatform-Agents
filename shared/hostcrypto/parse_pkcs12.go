package hostcrypto

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf16"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// PKCS#12 (RFC 7292), the PFX file.
//
// Without a password this package walks the outer ASN.1 itself, far enough to
// say how the file protects what it holds: the integrity MAC (or PBMAC1) and,
// for each part of the authenticated safe, whether it is plain data or
// encrypted and with which scheme and iteration count. All of that is in the
// clear by design. Where a part is plain data (Java trust stores, OpenSSL's
// "-certpbe NONE", some appliances) its certificates are listed too, and that
// read is [OpenedWithoutPassword].
//
// With tryDefaults each of [DefaultKeystorePasswords] is tried through
// software.sslmate.com/src/go-pkcs12, which verifies the MAC before it
// decrypts anything. A private key it decrypts is used only to find its
// public half, from which the entry's algorithm, size and public-key hash are
// taken; the key is then overwritten where Go lets us and dropped. It is
// never returned.

var (
	ksOIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	ksOIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	ksOIDEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	ksOIDEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	ksOIDKeyBag      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	ksOIDShroudedBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	ksOIDCertBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	ksOIDCRLBag      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}
	ksOIDSecretBag   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	ksOIDSafeContBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	ksOIDX509Cert    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}

	ksOIDFriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	ksOIDLocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	ksOIDJavaTrusted  = asn1.ObjectIdentifier{2, 16, 840, 1, 113894, 746875, 1, 1}

	ksOIDPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	ksOIDPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	ksOIDPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	ksOIDScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

// ksAlgorithmNames names the algorithm identifiers a keystore's protection is
// described with.
var ksAlgorithmNames = map[string]string{
	// PKCS#12 PBE (RFC 7292 appendix C)
	"1.2.840.113549.1.12.1.1": "pbeWithSHAAnd128BitRC4",
	"1.2.840.113549.1.12.1.2": "pbeWithSHAAnd40BitRC4",
	"1.2.840.113549.1.12.1.3": "pbeWithSHAAnd3-KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.4": "pbeWithSHAAnd2-KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.5": "pbeWithSHAAnd128BitRC2-CBC",
	"1.2.840.113549.1.12.1.6": "pbeWithSHAAnd40BitRC2-CBC",
	// PKCS#5 PBES1
	"1.2.840.113549.1.5.3":  "pbeWithMD5AndDES-CBC",
	"1.2.840.113549.1.5.10": "pbeWithSHA1AndDES-CBC",
	// PRFs and MACs
	"1.2.840.113549.2.7":  "HMAC-SHA1",
	"1.2.840.113549.2.8":  "HMAC-SHA224",
	"1.2.840.113549.2.9":  "HMAC-SHA256",
	"1.2.840.113549.2.10": "HMAC-SHA384",
	"1.2.840.113549.2.11": "HMAC-SHA512",
	"1.2.840.113549.2.12": "HMAC-SHA512/224",
	"1.2.840.113549.2.13": "HMAC-SHA512/256",
	// Digests, as a PKCS#12 MacData names its HMAC
	"1.3.14.3.2.26":           "HMAC-SHA1",
	"2.16.840.1.101.3.4.2.4":  "HMAC-SHA224",
	"2.16.840.1.101.3.4.2.1":  "HMAC-SHA256",
	"2.16.840.1.101.3.4.2.2":  "HMAC-SHA384",
	"2.16.840.1.101.3.4.2.3":  "HMAC-SHA512",
	"2.16.840.1.101.3.4.2.5":  "HMAC-SHA512/224",
	"2.16.840.1.101.3.4.2.6":  "HMAC-SHA512/256",
	"1.2.840.113549.2.5":      "HMAC-MD5",
	"2.16.840.1.101.3.4.2.8":  "HMAC-SHA3-256",
	"2.16.840.1.101.3.4.2.10": "HMAC-SHA3-512",
	// Ciphers
	"1.2.840.113549.3.7":      "DES-EDE3-CBC",
	"1.3.14.3.2.7":            "DES-CBC",
	"1.2.840.113549.3.2":      "RC2-CBC",
	"2.16.840.1.101.3.4.1.2":  "AES-128-CBC",
	"2.16.840.1.101.3.4.1.22": "AES-192-CBC",
	"2.16.840.1.101.3.4.1.42": "AES-256-CBC",
	"2.16.840.1.101.3.4.1.6":  "AES-128-GCM",
	"2.16.840.1.101.3.4.1.26": "AES-192-GCM",
	"2.16.840.1.101.3.4.1.46": "AES-256-GCM",
	"2.16.840.1.101.3.4.1.7":  "AES-128-CCM",
	"2.16.840.1.101.3.4.1.27": "AES-192-CCM",
	"2.16.840.1.101.3.4.1.47": "AES-256-CCM",
	"2.16.840.1.101.3.4.1.8":  "AES-128-KWP",
	"2.16.840.1.101.3.4.1.28": "AES-192-KWP",
	"2.16.840.1.101.3.4.1.48": "AES-256-KWP",
	"2.16.840.1.101.3.4.1.5":  "AES-128-KW",
	"2.16.840.1.101.3.4.1.45": "AES-256-KW",
	// The JDK's own
	"1.3.6.1.4.1.42.2.17.1.1": "JKS proprietary (SHA-1 keystream)",
	"1.3.6.1.4.1.42.2.19.1":   "PBEWithMD5AndTripleDES",
}

// ksIterations spells an iteration count.
func ksIterations(n int) string {
	if n == 1 {
		return "1 iteration"
	}
	return strconv.Itoa(n) + " iterations"
}

func ksAlgName(oid asn1.ObjectIdentifier) string {
	if s, ok := ksAlgorithmNames[oid.String()]; ok {
		return s
	}
	return oid.String()
}

type ksAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type ksContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type ksDigestInfo struct {
	Algorithm ksAlgorithmIdentifier
	Digest    []byte
}

type ksMacData struct {
	Mac        ksDigestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type ksPFX struct {
	Version  int
	AuthSafe ksContentInfo
	MacData  ksMacData `asn1:"optional"`
}

type ksEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm ksAlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type ksEncryptedData struct {
	Version              int
	EncryptedContentInfo ksEncryptedContentInfo
}

type ksSafeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue       `asn1:"tag:0,explicit"`
	Attributes []ksPKCS12Attribute `asn1:"set,optional"`
}

type ksPKCS12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type ksCertBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type ksEncryptedPrivateKeyInfo struct {
	Algorithm ksAlgorithmIdentifier
	Data      []byte
}

type ksPBEParams struct {
	Salt       []byte
	Iterations int
}

type ksPBES2Params struct {
	KDF ksAlgorithmIdentifier
	Enc ksAlgorithmIdentifier
}

type ksPBKDF2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                   `asn1:"optional"`
	PRF        ksAlgorithmIdentifier `asn1:"optional"`
}

type ksScryptParams struct {
	Salt            []byte
	CostParameter   int
	BlockSize       int
	Parallelization int
	KeyLength       int `asn1:"optional"`
}

type ksPBMAC1Params struct {
	KDF ksAlgorithmIdentifier
	MAC ksAlgorithmIdentifier
}

// ksUnmarshalAll decodes exactly one value and refuses trailing bytes.
func ksUnmarshalAll(b []byte, v any) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}

// ksDescribeKDF describes a PBES2 key derivation function.
func ksDescribeKDF(kdf ksAlgorithmIdentifier) string {
	switch {
	case kdf.Algorithm.Equal(ksOIDPBKDF2):
		var p ksPBKDF2Params
		if ksUnmarshalAll(kdf.Parameters.FullBytes, &p) != nil {
			return "PBKDF2"
		}
		prf := "HMAC-SHA1" // the PKCS#5 default when the PRF is absent
		if len(p.PRF.Algorithm) > 0 {
			prf = ksAlgName(p.PRF.Algorithm)
		}
		return "PBKDF2-" + prf + ", " + ksIterations(p.Iterations)
	case kdf.Algorithm.Equal(ksOIDScrypt):
		var p ksScryptParams
		if ksUnmarshalAll(kdf.Parameters.FullBytes, &p) != nil {
			return "scrypt"
		}
		return fmt.Sprintf("scrypt N=%d r=%d p=%d", p.CostParameter, p.BlockSize, p.Parallelization)
	default:
		return ksAlgName(kdf.Algorithm)
	}
}

// ksDescribeEncryption describes a password-based encryption algorithm:
// "PBES2 (PBKDF2-HMAC-SHA256, 2048 iterations, AES-256-CBC)" or
// "pbeWithSHAAnd3-KeyTripleDES-CBC, 2048 iterations".
func ksDescribeEncryption(alg ksAlgorithmIdentifier) string {
	if alg.Algorithm.Equal(ksOIDPBES2) {
		var p ksPBES2Params
		if ksUnmarshalAll(alg.Parameters.FullBytes, &p) != nil {
			return "PBES2"
		}
		return "PBES2 (" + ksDescribeKDF(p.KDF) + ", " + ksAlgName(p.Enc.Algorithm) + ")"
	}
	name := ksAlgName(alg.Algorithm)
	var p ksPBEParams
	if ksUnmarshalAll(alg.Parameters.FullBytes, &p) == nil {
		return name + ", " + ksIterations(p.Iterations)
	}
	return name
}

// ksDescribeMac describes a PFX's integrity protection.
func ksDescribeMac(m ksMacData) string {
	if len(m.Mac.Algorithm.Algorithm) == 0 {
		return "none"
	}
	if m.Mac.Algorithm.Algorithm.Equal(ksOIDPBMAC1) {
		var p ksPBMAC1Params
		if ksUnmarshalAll(m.Mac.Algorithm.Parameters.FullBytes, &p) != nil {
			return "PBMAC1"
		}
		return "PBMAC1 (" + ksAlgName(p.MAC.Algorithm) + ", " + ksDescribeKDF(p.KDF) + ")"
	}
	return ksAlgName(m.Mac.Algorithm.Algorithm) + ", " + ksIterations(m.Iterations)
}

// ksP12Bag is what one plain safe bag tells without a password.
type ksP12Bag struct {
	kind       string // "certificate", "private_key", "secret_key", "crl", "other"
	alias      string
	localKeyID []byte
	trusted    bool
	certDER    []byte
	// keyEncryption describes a shrouded key; empty for a plain key bag.
	keyEncryption string
	// plainKey is set for a keyBag: an UNENCRYPTED private key in the file.
	// It is used only to derive the public half and never leaves this file.
	plainKey []byte
}

// ksP12Structure is the password-free view of a PFX.
type ksP12Structure struct {
	pfx      ksPFX
	certs    []string // how each certificate-holding part is protected
	keys     []string // how keys are protected
	bags     []ksP12Bag
	hidden   bool // some part is encrypted, so bags is not the whole store
	maxed    bool
	authSafe []ksContentInfo
	// shrouded is true when a key bag in the clear is itself encrypted.
	shrouded bool
	// macCheckable is true when the file has a MAC the library computes, so
	// a password the MAC accepts is proved right.
	macCheckable bool
	// maxIterations is the largest iteration count any part asks for. It
	// bounds what trying passwords may cost: a hostile file can ask for
	// billions.
	maxIterations int
}

// ksMaxTrialIterations caps the key-derivation work a default-password trial
// will do per password. Real files ask for 1 to about 600,000 (OpenSSL 2048,
// Java 10,000, PBMAC1 recommendations 100,000+); a file asking for more is
// not tried, and DefaultPassword stays nil because nothing was learned.
const ksMaxTrialIterations = 1_000_000

func (st *ksP12Structure) noteIterations(n int) {
	if n > st.maxIterations {
		st.maxIterations = n
	}
}

// ksIterationsOf reads the iteration count of a password-based algorithm
// (PBES1 parameters, or PBES2's PBKDF2), or 0.
func ksIterationsOf(alg ksAlgorithmIdentifier) int {
	if alg.Algorithm.Equal(ksOIDPBES2) {
		var p ksPBES2Params
		if ksUnmarshalAll(alg.Parameters.FullBytes, &p) != nil {
			return 0
		}
		return ksKDFIterations(p.KDF)
	}
	var p ksPBEParams
	if ksUnmarshalAll(alg.Parameters.FullBytes, &p) == nil {
		return p.Iterations
	}
	return 0
}

func ksKDFIterations(kdf ksAlgorithmIdentifier) int {
	if kdf.Algorithm.Equal(ksOIDPBKDF2) {
		var p ksPBKDF2Params
		if ksUnmarshalAll(kdf.Parameters.FullBytes, &p) == nil {
			return p.Iterations
		}
	}
	if kdf.Algorithm.Equal(ksOIDScrypt) {
		var p ksScryptParams
		if ksUnmarshalAll(kdf.Parameters.FullBytes, &p) == nil {
			// scrypt's cost is N*r*p; it is never tried below, but bound it anyway.
			return p.CostParameter * max(p.BlockSize, 1) * max(p.Parallelization, 1)
		}
	}
	return 0
}

// ksMacInfo reports whether the library can verify this MAC and how many
// iterations it costs.
func ksMacInfo(m ksMacData) (checkable bool, iterations int) {
	alg := m.Mac.Algorithm.Algorithm
	switch alg.String() {
	case "1.3.14.3.2.26", "2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.3":
		return true, m.Iterations
	}
	if !alg.Equal(ksOIDPBMAC1) {
		return false, 0
	}
	var p ksPBMAC1Params
	if ksUnmarshalAll(m.Mac.Algorithm.Parameters.FullBytes, &p) != nil || !p.KDF.Algorithm.Equal(ksOIDPBKDF2) {
		return false, 0
	}
	var kp ksPBKDF2Params
	if ksUnmarshalAll(p.KDF.Parameters.FullBytes, &kp) != nil || kp.Salt.Tag != asn1.TagOctetString || kp.KeyLength < 20 || kp.KeyLength > 64 {
		return false, 0
	}
	hmacs := map[string]bool{"1.2.840.113549.2.7": true, "1.2.840.113549.2.9": true, "1.2.840.113549.2.11": true}
	if (len(kp.PRF.Algorithm) > 0 && !hmacs[kp.PRF.Algorithm.String()]) || !hmacs[p.MAC.Algorithm.String()] {
		return false, 0
	}
	return true, kp.Iterations
}

// ParsePKCS12 describes a PKCS#12 / PFX file: its protection always, and its
// certificates where they are stored in the clear or, with tryDefaults, where
// a default password opens it.
//
// On a file that is not a PFX it returns an error and a Keystore with only
// Type set.
func ParsePKCS12(b []byte, tryDefaults bool) (KeystoreContents, error) {
	return ksParsePKCS12(b, tryDefaults, DefaultMaxKeystoreEntries)
}

func ksParsePKCS12(b []byte, tryDefaults bool, maxEntries int) (KeystoreContents, error) {
	out := KeystoreContents{Keystore: Keystore{Type: KeystorePKCS12, Opened: OpenedNot}}
	st, err := ksP12Parse(b, maxEntries)
	if err != nil {
		return out, err
	}
	out.Keystore.Protection = st.protection()

	if !st.hidden {
		// Every bag was in the clear: the listing is complete without a password.
		out.Keystore.Opened = OpenedWithoutPassword
		ksP12List(&out, st.bags)
		if !st.maxed {
			out.Keystore.EntryCount = ksIntPtr(len(st.bags))
		}
	} else if ksP12HasCert(st.bags) {
		// Part is in the clear: list it, and say the count is not known.
		out.Keystore.Opened = OpenedWithoutPassword
		ksP12List(&out, st.bags)
	}

	if !tryDefaults {
		return out, nil
	}
	if st.maxIterations > ksMaxTrialIterations {
		// Too costly to try; nothing learned, so DefaultPassword stays nil.
		return out, nil
	}
	// Nothing protected at all: no part encrypted, no key shrouded, no MAC.
	// The empty default "opens" it in the trivial sense, and the listing
	// above already needed no password, which is the more precise answer.
	unprotected := !st.hidden && !st.shrouded && len(st.pfx.MacData.Mac.Algorithm.Algorithm) == 0
	ok := false
	for _, pw := range DefaultKeystorePasswords {
		res, right := ksP12TryPassword(b, pw, st)
		if !right {
			continue
		}
		ok = true
		if !unprotected {
			out.Keystore.Opened = OpenedDefaultPassword
		}
		if res != nil && st.hidden {
			out.Keystore.Entries = nil
			out.Certificates = nil
			ksP12ListDecoded(&out, res, st.bags, maxEntries)
		}
		break
	}
	out.Keystore.DefaultPassword = &ok
	return out, nil
}

func ksP12HasCert(bags []ksP12Bag) bool {
	for _, b := range bags {
		if b.kind == "certificate" {
			return true
		}
	}
	return false
}

// protection renders the description, in the order certificates, keys, MAC.
func (st *ksP12Structure) protection() string {
	var parts []string
	if len(st.certs) > 0 {
		parts = append(parts, "certificates: "+strings.Join(ksUniq(st.certs), " + "))
	}
	if len(st.keys) > 0 {
		parts = append(parts, "keys: "+strings.Join(ksUniq(st.keys), " + "))
	}
	parts = append(parts, "MAC: "+ksDescribeMac(st.pfx.MacData))
	return strings.Join(parts, "; ")
}

func ksUniq(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ksP12Parse walks the PFX without a password.
func ksP12Parse(b []byte, maxEntries int) (*ksP12Structure, error) {
	st := &ksP12Structure{}
	if err := ksUnmarshalAll(b, &st.pfx); err != nil {
		return nil, errors.New("pkcs12: not a PFX")
	}
	if st.pfx.Version != 3 {
		return nil, errors.New("pkcs12: unsupported PFX version")
	}
	if len(st.pfx.MacData.Mac.Algorithm.Algorithm) > 0 {
		var iters int
		st.macCheckable, iters = ksMacInfo(st.pfx.MacData)
		st.noteIterations(iters)
	}
	switch {
	case st.pfx.AuthSafe.ContentType.Equal(ksOIDData):
	case st.pfx.AuthSafe.ContentType.Equal(ksOIDSignedData):
		// Public-key integrity mode: rare, and not walked here.
		st.certs = append(st.certs, "public-key integrity mode (signedData), not parsed")
		st.hidden = true
		return st, nil
	default:
		return nil, errors.New("pkcs12: unknown authenticated safe type")
	}
	var authSafeBytes []byte
	if err := ksUnmarshalAll(st.pfx.AuthSafe.Content.Bytes, &authSafeBytes); err != nil {
		return nil, errors.New("pkcs12: bad authenticated safe")
	}
	if err := ksUnmarshalAll(authSafeBytes, &st.authSafe); err != nil {
		return nil, errors.New("pkcs12: bad authenticated safe")
	}
	for _, ci := range st.authSafe {
		switch {
		case ci.ContentType.Equal(ksOIDData):
			var data []byte
			if err := ksUnmarshalAll(ci.Content.Bytes, &data); err != nil {
				return nil, errors.New("pkcs12: bad data part")
			}
			if err := st.walkSafeContents(data, maxEntries, 0); err != nil {
				return nil, err
			}
		case ci.ContentType.Equal(ksOIDEncryptedData):
			var ed ksEncryptedData
			if err := ksUnmarshalAll(ci.Content.Bytes, &ed); err != nil {
				return nil, errors.New("pkcs12: bad encrypted part")
			}
			// An encrypted part conventionally holds the certificates (it is
			// what OpenSSL, Windows and Java put there), so it is described
			// as theirs. Keys inside it would be shrouded again and are not
			// visible without the password.
			st.certs = append(st.certs, ksDescribeEncryption(ed.EncryptedContentInfo.ContentEncryptionAlgorithm))
			st.noteIterations(ksIterationsOf(ed.EncryptedContentInfo.ContentEncryptionAlgorithm))
			st.hidden = true
		case ci.ContentType.Equal(ksOIDEnvelopedData):
			st.certs = append(st.certs, "public-key encrypted (envelopedData)")
			st.hidden = true
		default:
			return nil, errors.New("pkcs12: unknown part type")
		}
	}
	return st, nil
}

// walkSafeContents reads a plain SafeContents. depth bounds nested
// safeContentsBags.
func (st *ksP12Structure) walkSafeContents(data []byte, maxEntries, depth int) error {
	if depth > 4 {
		return errors.New("pkcs12: nesting too deep")
	}
	var bags []ksSafeBag
	if err := ksUnmarshalAll(data, &bags); err != nil {
		return errors.New("pkcs12: bad safe contents")
	}
	sawCert := false
	for _, sb := range bags {
		if len(st.bags) >= maxEntries {
			st.maxed = true
			return nil
		}
		bag := ksP12Bag{kind: "other"}
		for _, a := range sb.Attributes {
			switch {
			case a.ID.Equal(ksOIDFriendlyName):
				bag.alias = ksBMPString(a.Value.Bytes)
			case a.ID.Equal(ksOIDLocalKeyID):
				var id []byte
				if _, err := asn1.Unmarshal(a.Value.Bytes, &id); err == nil {
					bag.localKeyID = id
				}
			case a.ID.Equal(ksOIDJavaTrusted):
				bag.trusted = true
			}
		}
		switch {
		case sb.ID.Equal(ksOIDCertBag):
			var cb ksCertBag
			if ksUnmarshalAll(sb.Value.Bytes, &cb) != nil || !cb.ID.Equal(ksOIDX509Cert) {
				bag.kind = "other"
			} else {
				bag.kind = "certificate"
				bag.certDER = cb.Data
				sawCert = true
			}
		case sb.ID.Equal(ksOIDShroudedBag):
			bag.kind = "private_key"
			var epki ksEncryptedPrivateKeyInfo
			st.shrouded = true
			if ksUnmarshalAll(sb.Value.Bytes, &epki) == nil {
				bag.keyEncryption = ksDescribeEncryption(epki.Algorithm)
				st.noteIterations(ksIterationsOf(epki.Algorithm))
			} else {
				bag.keyEncryption = "encrypted (unreadable parameters)"
			}
			st.keys = append(st.keys, bag.keyEncryption)
		case sb.ID.Equal(ksOIDKeyBag):
			bag.kind = "private_key"
			bag.plainKey = sb.Value.Bytes
			st.keys = append(st.keys, "not encrypted")
		case sb.ID.Equal(ksOIDSecretBag):
			bag.kind = "secret_key"
		case sb.ID.Equal(ksOIDCRLBag):
			bag.kind = "crl"
		case sb.ID.Equal(ksOIDSafeContBag):
			if err := st.walkSafeContents(sb.Value.Bytes, maxEntries, depth+1); err != nil {
				return err
			}
			continue
		}
		st.bags = append(st.bags, bag)
	}
	if sawCert {
		st.certs = append(st.certs, "not encrypted")
	}
	return nil
}

// ksBMPString decodes a DER BMPString (a friendlyName) and drops anything
// that is not one.
func ksBMPString(der []byte) string {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil || raw.Tag != asn1.TagBMPString || len(raw.Bytes)%2 != 0 {
		return ""
	}
	u := make([]uint16, 0, len(raw.Bytes)/2)
	for i := 0; i+1 < len(raw.Bytes); i += 2 {
		u = append(u, uint16(raw.Bytes[i])<<8|uint16(raw.Bytes[i+1]))
	}
	return strings.ToValidUTF8(string(utf16.Decode(u)), "�")
}

// ksP12List turns plain bags into entries and certificates.
func ksP12List(out *KeystoreContents, bags []ksP12Bag) {
	certsByKeyID := map[string]Certificate{}
	for _, bag := range bags {
		if bag.kind != "certificate" {
			continue
		}
		entry := KeystoreEntry{Alias: bag.alias, Kind: "certificate", CertificateFingerprint: ksDERFingerprint(bag.certDER)}
		if cert, ok := ksCertificate(bag.certDER); ok {
			entry.Algorithm, entry.SizeBits, entry.PublicKeySHA256 = cert.KeyAlgorithm, cert.KeySize, cert.PublicKeySHA256
			if bag.trusted {
				cert = ksTrustAnchor(cert)
			}
			cert.Location.Alias = bag.alias
			out.Certificates = append(out.Certificates, cert)
			if len(bag.localKeyID) > 0 {
				certsByKeyID[string(bag.localKeyID)] = cert
			}
		}
		out.Keystore.Entries = append(out.Keystore.Entries, entry)
	}
	for _, bag := range bags {
		switch bag.kind {
		case "private_key":
			entry := KeystoreEntry{Alias: bag.alias, Kind: "private_key"}
			if cert, ok := certsByKeyID[string(bag.localKeyID)]; ok && len(bag.localKeyID) > 0 {
				entry.Algorithm, entry.SizeBits = cert.KeyAlgorithm, cert.KeySize
				entry.PublicKeySHA256, entry.CertificateFingerprint = cert.PublicKeySHA256, cert.FingerprintSHA256
			} else if bag.plainKey != nil {
				// An unencrypted key with no matching certificate: its public
				// half is derived in memory and the key is dropped.
				if pub := ksPublicFromPKCS8(bag.plainKey); pub != nil {
					entry.Algorithm, entry.SizeBits, entry.PublicKeySHA256 = ksDescribePublic(pub)
				}
			}
			out.Keystore.Entries = append(out.Keystore.Entries, entry)
		case "secret_key":
			out.Keystore.Entries = append(out.Keystore.Entries, KeystoreEntry{Alias: bag.alias, Kind: "secret_key"})
		}
	}
}

// ksP12Decoded is what a default password opened. It holds only public
// material: the private key was reduced to its public half before this was
// built.
type ksP12Decoded struct {
	certs   []*x509.Certificate
	trusted bool
	keyPub  crypto.PublicKey // nil for a trust store
}

// ksP12TryPassword tries one password. It reports whether the password is
// right; res is nil when it is right but the library could not list the
// contents (more than one key, an unusual layout): the MAC proved the
// password, so DefaultPassword is still true.
func ksP12TryPassword(b []byte, pw string, st *ksP12Structure) (res *ksP12Decoded, right bool) {
	key, leaf, cas, err := pkcs12.DecodeChain(b, pw)
	if err == nil {
		pub := ksPublicOf(key)
		ksZeroKey(key)
		return &ksP12Decoded{certs: append([]*x509.Certificate{leaf}, cas...), keyPub: pub}, true
	}
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return nil, false
	}
	certs, err2 := pkcs12.DecodeTrustStore(b, pw)
	if err2 == nil {
		return &ksP12Decoded{certs: certs, trusted: true}, true
	}
	if errors.Is(err2, pkcs12.ErrIncorrectPassword) {
		return nil, false
	}
	// Neither decoder could list it. The library verifies the MAC before it
	// reads anything else, and the structure already parsed here, so when the
	// MAC is one the library can compute, an error that is not "incorrect
	// password" came after the MAC verified: the password is right. Without a
	// MAC, or with one the library cannot compute, nothing proved it.
	return nil, st.macCheckable
}

// ksP12ListDecoded lists what a default password opened, keeping aliases the
// clear bags gave.
func ksP12ListDecoded(out *KeystoreContents, res *ksP12Decoded, clearBags []ksP12Bag, maxEntries int) {
	alias := map[string]string{}
	keyAlias := ""
	for _, bag := range clearBags {
		if bag.kind == "certificate" && bag.alias != "" {
			alias[ksDERFingerprint(bag.certDER)] = bag.alias
		}
		if bag.kind == "private_key" && keyAlias == "" {
			keyAlias = bag.alias
		}
	}
	var keySPKI string
	if res.keyPub != nil {
		_, _, keySPKI = ksDescribePublic(res.keyPub)
	}
	var keyEntry *KeystoreEntry
	if res.keyPub != nil {
		keyEntry = &KeystoreEntry{Alias: keyAlias, Kind: "private_key"}
		keyEntry.Algorithm, keyEntry.SizeBits, keyEntry.PublicKeySHA256 = ksDescribePublic(res.keyPub)
	}
	n := 0
	for _, c := range res.certs {
		if n >= maxEntries {
			break
		}
		cert, ok := ksCertificate(c.Raw)
		if !ok {
			continue
		}
		cert.Location.Alias = alias[cert.FingerprintSHA256]
		if keyEntry != nil && cert.PublicKeySHA256 == keySPKI {
			// The key's certificate: the entry's facts come from it.
			keyEntry.Algorithm, keyEntry.SizeBits = cert.KeyAlgorithm, cert.KeySize
			keyEntry.CertificateFingerprint = cert.FingerprintSHA256
			if cert.Location.Alias == "" {
				cert.Location.Alias = keyAlias
			}
		}
		if res.trusted {
			cert = ksTrustAnchor(cert)
		}
		out.Certificates = append(out.Certificates, cert)
		out.Keystore.Entries = append(out.Keystore.Entries, KeystoreEntry{
			Alias: cert.Location.Alias, Kind: "certificate",
			Algorithm: cert.KeyAlgorithm, SizeBits: cert.KeySize,
			CertificateFingerprint: cert.FingerprintSHA256, PublicKeySHA256: cert.PublicKeySHA256,
		})
		n++
	}
	if keyEntry != nil {
		out.Keystore.Entries = append(out.Keystore.Entries, *keyEntry)
	}
	out.Keystore.EntryCount = ksIntPtr(len(out.Keystore.Entries))
}

// ksPublicOf returns a decrypted private key's public half.
func ksPublicOf(key any) crypto.PublicKey {
	if s, ok := key.(crypto.Signer); ok {
		return s.Public()
	}
	if k, ok := key.(*ecdh.PrivateKey); ok {
		return k.PublicKey()
	}
	return nil
}

// ksPublicFromPKCS8 parses an unencrypted PKCS#8 key only to reach its
// public half, then overwrites the private value.
func ksPublicFromPKCS8(der []byte) crypto.PublicKey {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil
	}
	pub := ksPublicOf(key)
	ksZeroKey(key)
	return pub
}

// ksZeroKey overwrites what Go lets us overwrite of a private key. It is a
// best effort: big.Int and the runtime may have copied the value, and the
// garbage collector frees, not wipes. Its job is to make sure nothing here
// keeps a usable key alive longer than the call.
func ksZeroKey(key any) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		ksZeroBig(k.D)
		for _, p := range k.Primes {
			ksZeroBig(p)
		}
		ksZeroBig(k.Precomputed.Dp)
		ksZeroBig(k.Precomputed.Dq)
		ksZeroBig(k.Precomputed.Qinv)
	case *ecdsa.PrivateKey:
		ksZeroBig(k.D) //nolint:staticcheck // D is deprecated for reading, not for clearing
	case ed25519.PrivateKey:
		clear(k)
	}
}

func ksZeroBig(n *big.Int) {
	if n == nil {
		return
	}
	words := n.Bits()
	clear(words)
	n.SetInt64(0)
}

// ksDescribePublic returns a public key's catalogue algorithm, size and the
// SHA-256 of its SubjectPublicKeyInfo.
func ksDescribePublic(pub crypto.PublicKey) (alg string, bits int, spkiSHA256 string) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err == nil {
		spkiSHA256 = ksDERFingerprint(spki)
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen(), spkiSHA256
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize, spkiSHA256
	case ed25519.PublicKey:
		return "Ed25519", 256, spkiSHA256
	case *ecdh.PublicKey:
		if k.Curve() == ecdh.X25519() {
			return "X25519", 256, spkiSHA256
		}
		return "ECDH", 0, spkiSHA256
	}
	return "", 0, spkiSHA256
}
