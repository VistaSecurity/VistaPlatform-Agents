package hostcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // decrypting the format's legacy schemes is not choosing them
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // the format's legacy KDF and MAC
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// PKCS#12 (RFC 7292), the PFX file.
//
// Without a password this package walks the outer ASN.1 itself, far enough to
// say how the file protects what it holds: the integrity MAC (or PBMAC1) and,
// for each part of the authenticated safe, whether it is plain data or
// encrypted and with which scheme and iteration count. All of that is in the
// clear by design. Whatever sits in a plain part is listed: certificates
// (Java trust stores, OpenSSL's "-certpbe NONE") and the aliases of the key
// bags (keytool keeps its shrouded keys in a plain part, with the alias and
// key id in clear attributes). That read is [OpenedWithoutPassword].
//
// With tryDefaults each of [DefaultKeystorePasswords] is tried, by this file's
// own code and under a fixed budget of key-derivation work:
//
//   - with a MAC, by verifying the MAC (the RFC 7292 appendix B key
//     derivation and HMAC, or PBMAC1);
//   - without one, by decrypting an encrypted part and checking that its
//     padding and ASN.1 are valid.
//
// A password that passes opens the encrypted parts (PBES2 with PBKDF2 and
// AES-CBC or 3DES, and the PKCS#12 schemes 3DES and RC2), whose certificate
// bags and bag attributes are then read. A PRIVATE KEY IS NEVER DECRYPTED:
// of a shrouded key bag only its algorithm identifier and attributes are read,
// and an entry's algorithm, size and public-key hash come from the certificate
// its key id pairs it with.

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

// ksP12Bag is what one safe bag tells without decrypting a key.
type ksP12Bag struct {
	kind       string // "certificate", "private_key", "secret_key", "crl", "other"
	alias      string
	localKeyID []byte
	trusted    bool // the Java trustedKeyUsage attribute
	certDER    []byte
	// For an UNENCRYPTED key bag, what its PKCS#8 algorithm identifier says.
	// The private key inside it is not parsed.
	plainAlg   string
	plainBits  int
	plainCurve string
}

// ksP12Part is one ContentInfo of the authenticated safe.
type ksP12Part struct {
	encrypted bool
	alg       ksAlgorithmIdentifier
	content   []byte // the ciphertext of an encryptedData part
	opened    bool   // plain, or decrypted by a default password

	// Why an encrypted part stayed shut, for Keystore.Unknown: each
	// candidate decrypted nothing (refused), a candidate decrypted it to
	// bytes that are not SafeContents (unreadable), or the trial budget cut
	// its retries short (cut). A part with none of these was never tried:
	// public-key encrypted, or an algorithm this code does not decrypt.
	refused, unreadable, cut bool
}

// ksP12Structure is the password-free view of a PFX.
type ksP12Structure struct {
	pfx      ksPFX
	signed   bool   // public-key integrity mode
	authSafe []byte // the bytes the MAC is computed over
	parts    []ksP12Part
	certs    []string // how each certificate-holding part is protected
	keys     []string // how keys are protected
	bags     []ksP12Bag
	shrouded bool // some key bag is encrypted
	maxed    bool
}

// ksMaxTrialWork bounds the key-derivation work a default-password trial does
// on one file, summed over every password tried and every part opened, in
// hash computations: an iteration of the PKCS#12 KDF counts 1, an iteration
// of PBKDF2 (an HMAC) counts 2 per output block. 4,000,000 is under a second
// on a laptop core. Common writers ask for 1 to 10,000 iterations (OpenSSL
// 2048, Java 10,000), which costs a few hundred thousand; a file asking for
// more than about 300,000 per derivation is not tried, and says so in
// DefaultsNotTried. The bound covers the check under every candidate and each
// other part once; retrying a part under the other candidates spends only
// what is left, and a part whose retry does not fit says it was not tried.
const ksMaxTrialWork = 4_000_000

// The reasons a default-password trial did not run.
const (
	ksNotTriedSigned      = "integrity is by signature"
	ksNotTriedUnprotected = "nothing in the file is protected by a password"
	ksNotTriedCost        = "iteration count above the limit"
	ksNotTriedScheme      = "a part uses protection the collector does not try"
	ksNotTriedNoCheck     = "nothing in the file can verify a password"
)

// ksMulCost multiplies two non-negative costs, saturating instead of
// overflowing.
func ksMulCost(a, b int) int {
	if a < 0 || b < 0 {
		return math.MaxInt
	}
	if a != 0 && b > math.MaxInt/a {
		return math.MaxInt
	}
	return a * b
}

func ksAddCost(a, b int) int {
	if a < 0 || b < 0 || a > math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}

// ParsePKCS12 describes a PKCS#12 / PFX file: its protection always; what its
// plain parts hold; and, with tryDefaults, what its encrypted parts hold when
// a default password opens them.
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

	found, empty := false, false
	if tryDefaults {
		res, reason := st.trial(maxEntries)
		out.DefaultsNotTried = reason
		// An empty password is no default: the store needs none.
		found, empty = res == ksP12OpenedByDefault, res == ksP12OpenedByEmpty
		if reason == "" {
			out.Keystore.DefaultPassword = &found
		}
	}

	out.Keystore.Protection = st.protection()
	entries, certs, truncated := ksP12Build(st.bags, maxEntries)
	out.Keystore.Entries, out.Certificates = entries, certs
	out.Truncated = truncated || st.maxed
	hidden := false
	for _, p := range st.parts {
		if !p.opened {
			hidden = true
		}
	}
	if !hidden && !st.signed && !out.Truncated {
		out.Keystore.EntryCount = ksIntPtr(len(entries))
	}
	switch {
	case found:
		out.Keystore.Opened = OpenedDefaultPassword
	case empty, len(entries) > 0 || len(certs) > 0:
		out.Keystore.Opened = OpenedWithoutPassword
	}
	// A part that stayed shut keeps what it holds: Opened says how the rest
	// was read, EntryCount stays nil, and Unknown says why the listing is
	// short, in words true of what the trial did to each such part.
	if (found || empty) && hidden {
		out.Keystore.Unknown = st.hiddenReason()
	}
	return out, nil
}

// hiddenReason says, for every part that stayed shut, only what the trial
// established about it: that every candidate was tried and refused, that a
// candidate decrypted it to something that is not a list of entries, or that
// its retries were cut for cost, or that it was not tried at all
// (public-key encrypted, an algorithm not decrypted here). Each reason that
// applies is given.
func (st *ksP12Structure) hiddenReason() string {
	var refused, unreadable, costly, untried bool
	for _, p := range st.parts {
		switch {
		case p.opened:
		case p.unreadable:
			unreadable = true
		case p.cut:
			costly = true
		case p.refused:
			refused = true
		default:
			untried = true
		}
	}
	var why []string
	if refused {
		why = append(why, "part of the store needs a password that is neither empty nor a well-known default")
	}
	if unreadable {
		why = append(why, "part of the store decrypted to contents that are not a list of entries")
	}
	if costly {
		why = append(why, "part of the store was not tried with every default password: its iteration count is above the limit")
	}
	if untried {
		why = append(why, "part of the store is protected in a way the collector does not try")
	}
	return strings.Join(why, "; ") + "; its entries are not listed"
}

// protection renders the description, in the order certificates, keys, MAC.
func (st *ksP12Structure) protection() string {
	if st.signed {
		return "signed (public-key integrity)"
	}
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
	switch {
	case st.pfx.AuthSafe.ContentType.Equal(ksOIDData):
	case st.pfx.AuthSafe.ContentType.Equal(ksOIDSignedData):
		// Public-key integrity mode: rare, not walked, and no password can be
		// checked against it.
		st.signed = true
		st.parts = append(st.parts, ksP12Part{encrypted: true})
		return st, nil
	default:
		return nil, errors.New("pkcs12: unknown authenticated safe type")
	}
	if err := ksUnmarshalAll(st.pfx.AuthSafe.Content.Bytes, &st.authSafe); err != nil {
		return nil, errors.New("pkcs12: bad authenticated safe")
	}
	var cis []ksContentInfo
	if err := ksUnmarshalAll(st.authSafe, &cis); err != nil {
		return nil, errors.New("pkcs12: bad authenticated safe")
	}
	for _, ci := range cis {
		switch {
		case ci.ContentType.Equal(ksOIDData):
			var data []byte
			if err := ksUnmarshalAll(ci.Content.Bytes, &data); err != nil {
				return nil, errors.New("pkcs12: bad data part")
			}
			if err := st.walkSafeContents(data, maxEntries, 0); err != nil {
				return nil, err
			}
			st.parts = append(st.parts, ksP12Part{opened: true})
		case ci.ContentType.Equal(ksOIDEncryptedData):
			var ed ksEncryptedData
			if err := ksUnmarshalAll(ci.Content.Bytes, &ed); err != nil {
				return nil, errors.New("pkcs12: bad encrypted part")
			}
			alg := ed.EncryptedContentInfo.ContentEncryptionAlgorithm
			// An encrypted part conventionally holds the certificates (it is
			// where OpenSSL, Windows and Java put them), so it is described as
			// theirs.
			st.certs = append(st.certs, ksDescribeEncryption(alg))
			st.parts = append(st.parts, ksP12Part{encrypted: true, alg: alg, content: ed.EncryptedContentInfo.EncryptedContent.Bytes})
		case ci.ContentType.Equal(ksOIDEnvelopedData):
			st.certs = append(st.certs, "public-key encrypted (envelopedData)")
			st.parts = append(st.parts, ksP12Part{encrypted: true})
		default:
			return nil, errors.New("pkcs12: unknown part type")
		}
	}
	return st, nil
}

// walkSafeContents reads a SafeContents. depth bounds nested
// safeContentsBags. It never decrypts a key: of a shrouded key bag it reads
// the algorithm identifier and the attributes.
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
			if ksUnmarshalAll(sb.Value.Bytes, &cb) == nil && cb.ID.Equal(ksOIDX509Cert) {
				bag.kind = "certificate"
				bag.certDER = cb.Data
				sawCert = true
			}
		case sb.ID.Equal(ksOIDShroudedBag):
			bag.kind = "private_key"
			st.shrouded = true
			// Only the algorithm identifier; the ciphertext is not touched.
			var epki ksEncryptedPrivateKeyInfo
			if ksUnmarshalAll(sb.Value.Bytes, &epki) == nil {
				st.keys = append(st.keys, ksDescribeEncryption(epki.Algorithm))
			} else {
				st.keys = append(st.keys, "encrypted (unreadable parameters)")
			}
		case sb.ID.Equal(ksOIDKeyBag):
			bag.kind = "private_key"
			bag.plainAlg, bag.plainBits, bag.plainCurve = ksPKCS8Algorithm(sb.Value.Bytes)
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
	if sawCert && depth == 0 {
		st.certs = append(st.certs, "not encrypted")
	}
	return nil
}

// ksPKCS8Algorithm reads the algorithm identifier of an unencrypted PKCS#8
// key: SEQUENCE { version, algorithm, privateKey, ... }. The private key
// element is not parsed. RSA's size is inside the key, so it is left 0.
func ksPKCS8Algorithm(der []byte) (alg string, bits int, curve string) {
	var elems []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &elems); err != nil || len(elems) < 3 {
		return "", 0, ""
	}
	var ai ksAlgorithmIdentifier
	if ksUnmarshalAll(elems[1].FullBytes, &ai) != nil {
		return "", 0, ""
	}
	switch ai.Algorithm.String() {
	case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10":
		return "RSA", 0, ""
	case "1.2.840.10040.4.1":
		return "DSA", 0, ""
	case "1.2.840.10045.2.1":
		var c asn1.ObjectIdentifier
		if ksUnmarshalAll(ai.Parameters.FullBytes, &c) == nil {
			if n, b, ok := ksNamedCurve(c); ok {
				return "ECDSA", b, n
			}
		}
		return "ECDSA", 0, ""
	case "1.3.101.110":
		return "X25519", 256, ""
	case "1.3.101.111":
		return "X448", 448, ""
	case "1.3.101.112":
		return "Ed25519", 256, ""
	case "1.3.101.113":
		return "Ed448", 448, ""
	case "2.16.840.1.101.3.4.3.17":
		return "ML-DSA-44", 0, ""
	case "2.16.840.1.101.3.4.3.18":
		return "ML-DSA-65", 0, ""
	case "2.16.840.1.101.3.4.3.19":
		return "ML-DSA-87", 0, ""
	}
	return "", 0, ""
}

func ksNamedCurve(oid asn1.ObjectIdentifier) (name string, bits int, ok bool) {
	switch oid.String() {
	case "1.2.840.10045.3.1.7":
		return "P-256", 256, true
	case "1.3.132.0.34":
		return "P-384", 384, true
	case "1.3.132.0.35":
		return "P-521", 521, true
	case "1.3.132.0.10":
		return "secp256k1", 256, true
	}
	return "", 0, false
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

// ksP12Build turns bags into entries and certificates by keytool's rule (see
// [KeystoreContents]): one entry per key, carrying its chain, and one per
// certificate that belongs to no key's chain. A key's certificate is the one
// with its key id; its chain follows issuer to subject among the certificates
// that carry neither a key id nor the Java trusted attribute. A trusted
// certificate is always its own entry.
func ksP12Build(bags []ksP12Bag, maxEntries int) (entries []KeystoreEntry, certs []Certificate, truncated bool) {
	type parsed struct {
		x     *x509.Certificate
		c     Certificate
		owner int // index of the key bag whose chain it is in, or -1
	}
	pc := make([]parsed, len(bags))
	for i := range bags {
		pc[i].owner = -1
		if bags[i].kind != "certificate" {
			continue
		}
		if x, err := x509.ParseCertificate(bags[i].certDER); err == nil {
			pc[i].x = x
			pc[i].c = ksCertificateFrom(x)
		}
	}
	leafOf := map[int]int{}
	for k := range bags {
		if bags[k].kind != "private_key" || len(bags[k].localKeyID) == 0 {
			continue
		}
		leaf := -1
		for i := range bags {
			if bags[i].kind == "certificate" && !bags[i].trusted && pc[i].owner < 0 && bytes.Equal(bags[i].localKeyID, bags[k].localKeyID) {
				leaf = i
				break
			}
		}
		if leaf < 0 {
			continue
		}
		leafOf[k] = leaf
		pc[leaf].owner = k
		for cur, depth := leaf, 0; pc[cur].x != nil && depth < 10; depth++ {
			x := pc[cur].x
			if bytes.Equal(x.RawIssuer, x.RawSubject) {
				break
			}
			next := -1
			for i := range bags {
				if pc[i].x != nil && pc[i].owner < 0 && !bags[i].trusted && len(bags[i].localKeyID) == 0 && bytes.Equal(pc[i].x.RawSubject, x.RawIssuer) {
					next = i
					break
				}
			}
			if next < 0 {
				break
			}
			pc[next].owner = k
			cur = next
		}
	}
	add := func(e KeystoreEntry) {
		if len(entries) >= maxEntries {
			truncated = true
			return
		}
		entries = append(entries, e)
	}
	for i, bag := range bags {
		switch bag.kind {
		case "private_key":
			e := KeystoreEntry{Alias: bag.alias, Kind: "private_key"}
			if leaf, ok := leafOf[i]; ok {
				if e.Alias == "" {
					e.Alias = bags[leaf].alias
				}
				e.CertificateFingerprint = ksDERFingerprint(bags[leaf].certDER)
				if pc[leaf].x != nil {
					c := pc[leaf].c
					e.Algorithm, e.SizeBits, e.PublicKeySHA256 = c.KeyAlgorithm, c.KeySize, c.PublicKeySHA256
					e.Curve = c.Curve
				}
			} else if bag.plainAlg != "" {
				e.Algorithm, e.SizeBits = bag.plainAlg, bag.plainBits
				e.Curve = bag.plainCurve
			}
			add(e)
		case "secret_key":
			add(KeystoreEntry{Alias: bag.alias, Kind: "secret_key"})
		case "certificate":
			if pc[i].owner >= 0 {
				continue
			}
			e := KeystoreEntry{Alias: bag.alias, Kind: "certificate", CertificateFingerprint: ksDERFingerprint(bag.certDER)}
			if pc[i].x != nil {
				c := pc[i].c
				e.Algorithm, e.SizeBits, e.PublicKeySHA256 = c.KeyAlgorithm, c.KeySize, c.PublicKeySHA256
				e.Curve = c.Curve
			}
			add(e)
		}
	}
	for i, bag := range bags {
		if bag.kind != "certificate" || pc[i].x == nil {
			continue
		}
		c := pc[i].c
		c.Location.Alias = bag.alias
		if c.Location.Alias == "" && pc[i].owner >= 0 {
			c.Location.Alias = bags[pc[i].owner].alias
		}
		if bag.trusted {
			c = ksTrustAnchor(c)
		}
		certs = append(certs, c)
	}
	return entries, certs, truncated
}

// ---- The default-password trial ----

// ksP12Password is one candidate in the two encodings the format uses: the
// PKCS#12 KDF takes a BMPString with a two-byte terminator; PBKDF2 (PBES2,
// PBMAC1) takes UTF-8.
type ksP12Password struct {
	bmp  []byte
	utf8 []byte
	// empty marks the empty password, which opens a store that needs none
	// rather than proving a well-known default.
	empty bool
}

// What the trial found.
const (
	ksP12NotOpened = iota
	ksP12OpenedByEmpty
	ksP12OpenedByDefault
)

// ksP12Candidates lists the empty password first, as its own step, then the
// defaults. The empty password is tried both as a terminated empty BMPString
// and as no bytes at all, because writers differ.
func ksP12Candidates() []ksP12Password {
	out := []ksP12Password{{bmp: []byte{0, 0}, utf8: []byte{}, empty: true}, {bmp: nil, utf8: nil, empty: true}}
	for _, pw := range DefaultKeystorePasswords {
		var bmp []byte
		for _, c := range utf16.Encode([]rune(pw)) {
			bmp = append(bmp, byte(c>>8), byte(c))
		}
		bmp = append(bmp, 0, 0)
		out = append(out, ksP12Password{bmp: bmp, utf8: []byte(pw)})
	}
	return out
}

// ksP12Check is a way to test one password, and what each test costs.
type ksP12Check struct {
	cost int
	test func(pw ksP12Password) bool
}

// trial tries the empty password, then the defaults. It returns which
// opened the file (ksP12OpenedByEmpty, ksP12OpenedByDefault) or
// ksP12NotOpened, or a reason it was not tried. On success the encrypted
// parts that the password opens are walked into st.bags.
func (st *ksP12Structure) trial(maxEntries int) (res int, notTried string) {
	if st.signed {
		return ksP12NotOpened, ksNotTriedSigned
	}
	hasMAC := len(st.pfx.MacData.Mac.Algorithm.Algorithm) > 0
	anyEncrypted := false
	for _, p := range st.parts {
		anyEncrypted = anyEncrypted || p.encrypted
	}
	if !hasMAC && !anyEncrypted && !st.shrouded {
		return ksP12NotOpened, ksNotTriedUnprotected
	}

	// Each encrypted part that can be opened, and what opening it costs.
	type opener struct {
		idx  int
		cost int
		open func(pw ksP12Password) ([]byte, bool)
		// key is the password as the part's scheme uses it: two
		// candidates with the same key are one try.
		key func(pw ksP12Password) string
	}
	var openers []opener
	for i, p := range st.parts {
		if !p.encrypted || p.content == nil {
			continue
		}
		if cost, open, ok := ksP12Decrypter(p.alg, p.content); ok {
			openers = append(openers, opener{idx: i, cost: cost, open: open, key: ksP12KeyMaterial(p.alg)})
		}
	}
	openerIdx := map[int]bool{}
	for _, o := range openers {
		openerIdx[o.idx] = true
	}

	// The check: the MAC when the file has one this code computes; otherwise
	// the cheapest part to decrypt.
	var check ksP12Check
	verifier := -1
	if hasMAC {
		if c, ok := ksP12MacCheck(st.pfx.MacData, st.authSafe); ok {
			check = c
		}
	}
	if check.test == nil && len(openers) > 0 {
		verifier = 0
		for j := range openers {
			if openers[j].cost < openers[verifier].cost {
				verifier = j
			}
		}
		v := openers[verifier]
		check = ksP12Check{cost: v.cost, test: func(pw ksP12Password) bool {
			pt, ok := v.open(pw)
			if !ok {
				return false
			}
			var bags []ksSafeBag
			return ksUnmarshalAll(pt, &bags) == nil
		}}
	}
	if check.test == nil {
		return ksP12NotOpened, ksNotTriedNoCheck
	}

	// The budget is what the trial runs before its retries: the check under
	// every candidate, and each other part once, under the password that
	// passes it (as before the empty password was tried apart). A part that
	// password does not open is retried with the other candidates only from
	// what is left of the budget; a retry past it is not run and the part
	// says so (cut), so a store that fitted before still gets its answer.
	cands := ksP12Candidates()
	total := ksMulCost(check.cost, len(cands))
	for j, o := range openers {
		if j != verifier {
			total = ksAddCost(total, o.cost)
		}
	}
	if total > ksMaxTrialWork {
		return ksP12NotOpened, ksNotTriedCost
	}
	left := ksMaxTrialWork - total

	// open walks a part the password opens into st.bags. proved says the
	// password is proved for THIS part (it is the verifier part of a store
	// without a MAC); only then does a decryption whose plaintext is not
	// SafeContents mark the part unreadable. Otherwise it is the candidate
	// not opening the part: a wrong password, the MAC's included when the
	// part has another, yields valid padding about once in 256 tries.
	open := func(o opener, pw ksP12Password, proved bool) bool {
		pt, ok := o.open(pw)
		if !ok {
			return false
		}
		before := len(st.bags)
		if st.walkSafeContents(pt, maxEntries, 1) != nil {
			st.bags = st.bags[:before]
			if proved {
				st.parts[o.idx].unreadable = true
			}
			return false
		}
		st.parts[o.idx].opened = true
		return true
	}
	for _, pw := range cands {
		if !check.test(pw) {
			continue
		}
		// pw passes the check (the MAC, or the cheapest part). A part it
		// does not open may take another candidate: each is tried on it, so
		// a well-known default that opens any part of the store is found
		// even when the empty password passed the check, and a store whose
		// MAC is a default but a part is empty is listed in full.
		byDefault, cut := !pw.empty, false
		for j, o := range openers {
			if open(o, pw, j == verifier) {
				continue
			}
			tried := map[string]bool{o.key(pw): true}
			opened := false
			for _, other := range cands {
				k := o.key(other)
				if tried[k] {
					continue // the same key for this part's scheme
				}
				tried[k] = true
				if o.cost > left {
					st.parts[o.idx].cut = true
					cut = true
					break
				}
				left -= o.cost
				if open(o, other, false) {
					byDefault = byDefault || !other.empty
					opened = true
					break
				}
			}
			if !opened && !st.parts[o.idx].cut {
				st.parts[o.idx].refused = true
			}
		}
		// A password-based part that no candidate could be tried on (a
		// scheme this code does not decrypt) leaves the answer open too. A
		// public-key encrypted part does not: no password applies to it.
		untriedPassword := false
		for i, p := range st.parts {
			if p.encrypted && p.content != nil && !p.opened && !openerIdx[i] {
				untriedPassword = true
			}
		}
		switch {
		case byDefault:
			return ksP12OpenedByDefault, ""
		case untriedPassword:
			return ksP12OpenedByEmpty, ksNotTriedScheme
		case cut:
			// A default was not tried on every part: "does a default open
			// this?" has no answer, which is said as for an untried store.
			return ksP12OpenedByEmpty, ksNotTriedCost
		}
		return ksP12OpenedByEmpty, ""
	}
	return ksP12NotOpened, ""
}

// ksP12KeyMaterial is the password as a part's scheme derives from it: PBES2
// takes UTF-8 (where the empty string and no bytes are one key), the PKCS#12
// schemes the terminated BMPString (where they are two).
func ksP12KeyMaterial(alg ksAlgorithmIdentifier) func(pw ksP12Password) string {
	if alg.Algorithm.Equal(ksOIDPBES2) {
		return func(pw ksP12Password) string { return "u:" + string(pw.utf8) }
	}
	return func(pw ksP12Password) string {
		if pw.bmp == nil {
			return "n:"
		}
		return "b:" + string(pw.bmp)
	}
}

// ksHashFor maps a digest OID (as a PKCS#12 MacData names it) or an HMAC OID
// (as PBKDF2 and PBMAC1 name it) to the hash, with its output and block sizes.
func ksHashFor(oid asn1.ObjectIdentifier) (h func() hash.Hash, u, v int, ok bool) {
	switch oid.String() {
	case "1.3.14.3.2.26", "1.2.840.113549.2.7":
		return sha1.New, 20, 64, true
	case "2.16.840.1.101.3.4.2.4", "1.2.840.113549.2.8":
		return sha256.New224, 28, 64, true
	case "2.16.840.1.101.3.4.2.1", "1.2.840.113549.2.9":
		return sha256.New, 32, 64, true
	case "2.16.840.1.101.3.4.2.2", "1.2.840.113549.2.10":
		return sha512.New384, 48, 128, true
	case "2.16.840.1.101.3.4.2.3", "1.2.840.113549.2.11":
		return sha512.New, 64, 128, true
	case "2.16.840.1.101.3.4.2.5", "1.2.840.113549.2.12":
		return sha512.New512_224, 28, 128, true
	case "2.16.840.1.101.3.4.2.6", "1.2.840.113549.2.13":
		return sha512.New512_256, 32, 128, true
	}
	return nil, 0, 0, false
}

// ksP12KDF is the key derivation of RFC 7292 appendix B.2: id 1 for keys, 2
// for IVs, 3 for MAC keys; u and v are the hash's output and block sizes.
func ksP12KDF(newHash func() hash.Hash, u, v int, id byte, salt, password []byte, iterations, n int) []byte {
	fill := func(src []byte) []byte {
		if len(src) == 0 {
			return nil
		}
		out := make([]byte, v*((len(src)+v-1)/v))
		for i := range out {
			out[i] = src[i%len(src)]
		}
		return out
	}
	d := bytes.Repeat([]byte{id}, v)
	in := append(fill(salt), fill(password)...)
	h := newHash()
	var out []byte
	for {
		h.Reset()
		h.Write(d)
		h.Write(in)
		a := h.Sum(nil)
		for r := 1; r < iterations; r++ {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)
		if len(out) >= n {
			return out[:n]
		}
		// I_j = (I_j + B + 1) mod 2^(8v), with B = A repeated to v bytes.
		b := fill(a)
		for j := 0; j+v <= len(in); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				s := int(in[j+k]) + int(b[k]) + carry
				in[j+k] = byte(s)
				carry = s >> 8
			}
		}
	}
}

// ksP12KDFCost is the work of one ksP12KDF call.
func ksP12KDFCost(u, iterations, n int) int {
	return ksMulCost(iterations, (n+u-1)/u)
}

// ksP12MacCheck builds the MAC check, or reports false when the MAC is of a
// kind this code does not compute.
func ksP12MacCheck(m ksMacData, msg []byte) (ksP12Check, bool) {
	alg := m.Mac.Algorithm.Algorithm
	if alg.Equal(ksOIDPBMAC1) {
		var p ksPBMAC1Params
		if ksUnmarshalAll(m.Mac.Algorithm.Parameters.FullBytes, &p) != nil {
			return ksP12Check{}, false
		}
		macHash, _, _, ok := ksHashFor(p.MAC.Algorithm)
		if !ok {
			return ksP12Check{}, false
		}
		// RFC 9579: the key length is required; 20 to 64 octets.
		derive, cost, keyLen, ok := ksPBKDF2(p.KDF, -1)
		if !ok || keyLen < 20 || keyLen > 64 {
			return ksP12Check{}, false
		}
		return ksP12Check{cost: cost, test: func(pw ksP12Password) bool {
			key := derive(pw.utf8)
			if key == nil {
				return false
			}
			mac := hmac.New(macHash, key)
			mac.Write(msg)
			return hmac.Equal(mac.Sum(nil), m.Mac.Digest)
		}}, true
	}
	h, u, v, ok := ksHashFor(alg)
	if !ok || m.Iterations < 1 {
		return ksP12Check{}, false
	}
	return ksP12Check{cost: ksP12KDFCost(u, m.Iterations, u), test: func(pw ksP12Password) bool {
		key := ksP12KDF(h, u, v, 3, m.MacSalt, pw.bmp, m.Iterations, u)
		mac := hmac.New(h, key)
		mac.Write(msg)
		return hmac.Equal(mac.Sum(nil), m.Mac.Digest)
	}}, true
}

// ksPBKDF2 prepares a PBKDF2 derivation from its AlgorithmIdentifier.
// keyLen < 0 means "the length the parameters state" (PBMAC1); otherwise the
// parameters may state only that length. It returns the derivation, its cost
// and the key length.
func ksPBKDF2(kdf ksAlgorithmIdentifier, keyLen int) (derive func(pw []byte) []byte, cost, n int, ok bool) {
	if !kdf.Algorithm.Equal(ksOIDPBKDF2) {
		return nil, 0, 0, false
	}
	var p ksPBKDF2Params
	if ksUnmarshalAll(kdf.Parameters.FullBytes, &p) != nil || p.Salt.Class != asn1.ClassUniversal || p.Salt.Tag != asn1.TagOctetString || p.Iterations < 1 {
		return nil, 0, 0, false
	}
	prf, hlen := sha1.New, 20
	if len(p.PRF.Algorithm) > 0 {
		h, u, _, hok := ksHashFor(p.PRF.Algorithm)
		if !hok || !strings.HasPrefix(p.PRF.Algorithm.String(), "1.2.840.113549.2.") {
			return nil, 0, 0, false
		}
		prf, hlen = h, u
	}
	switch {
	case keyLen < 0:
		keyLen = p.KeyLength
	case p.KeyLength != 0 && p.KeyLength != keyLen:
		return nil, 0, 0, false
	}
	if keyLen <= 0 || keyLen > 64 {
		return nil, 0, 0, false
	}
	salt, iters := p.Salt.Bytes, p.Iterations
	derive = func(pw []byte) []byte {
		k, err := pbkdf2.Key(prf, string(pw), salt, iters, keyLen)
		if err != nil {
			return nil
		}
		return k
	}
	// Each PBKDF2 iteration is an HMAC, two hash computations; the PKCS#12
	// KDF's is one. Counting them so keeps the budget a bound on time.
	return derive, ksMulCost(iters, 2*((keyLen+hlen-1)/hlen)), keyLen, true
}

// ksP12Decrypter prepares decryption of an encryptedData part: the schemes
// RFC 7292 and RFC 8018 define that a PKCS#12 file uses in practice. It
// returns false for anything else (RC4, scrypt, an unknown cipher).
func ksP12Decrypter(alg ksAlgorithmIdentifier, ct []byte) (cost int, open func(pw ksP12Password) ([]byte, bool), ok bool) {
	if alg.Algorithm.Equal(ksOIDPBES2) {
		var p ksPBES2Params
		if ksUnmarshalAll(alg.Parameters.FullBytes, &p) != nil {
			return 0, nil, false
		}
		var iv []byte
		if ksUnmarshalAll(p.Enc.Parameters.FullBytes, &iv) != nil {
			return 0, nil, false
		}
		var keyLen int
		var newBlock func([]byte) (cipher.Block, error)
		switch p.Enc.Algorithm.String() {
		case "2.16.840.1.101.3.4.1.2":
			keyLen, newBlock = 16, aes.NewCipher
		case "2.16.840.1.101.3.4.1.22":
			keyLen, newBlock = 24, aes.NewCipher
		case "2.16.840.1.101.3.4.1.42":
			keyLen, newBlock = 32, aes.NewCipher
		case "1.2.840.113549.3.7":
			keyLen, newBlock = 24, des.NewTripleDESCipher
		default:
			return 0, nil, false
		}
		derive, cost, _, ok := ksPBKDF2(p.KDF, keyLen)
		if !ok {
			return 0, nil, false
		}
		return cost, func(pw ksP12Password) ([]byte, bool) {
			key := derive(pw.utf8)
			if key == nil {
				return nil, false
			}
			blk, err := newBlock(key)
			if err != nil {
				return nil, false
			}
			return ksCBCDecrypt(blk, iv, ct)
		}, true
	}

	var p ksPBEParams
	if ksUnmarshalAll(alg.Parameters.FullBytes, &p) != nil || p.Iterations < 1 {
		return 0, nil, false
	}
	var keyLen int
	var newBlock func([]byte) (cipher.Block, error)
	switch alg.Algorithm.String() {
	case "1.2.840.113549.1.12.1.3": // pbeWithSHAAnd3-KeyTripleDES-CBC
		keyLen, newBlock = 24, des.NewTripleDESCipher
	case "1.2.840.113549.1.12.1.4": // pbeWithSHAAnd2-KeyTripleDES-CBC
		keyLen = 16
		newBlock = func(k []byte) (cipher.Block, error) {
			return des.NewTripleDESCipher(append(append([]byte{}, k...), k[:8]...))
		}
	case "1.2.840.113549.1.12.1.5": // pbeWithSHAAnd128BitRC2-CBC
		keyLen = 16
		newBlock = func(k []byte) (cipher.Block, error) { return ksNewRC2(k, 128), nil }
	case "1.2.840.113549.1.12.1.6": // pbeWithSHAAnd40BitRC2-CBC
		keyLen = 5
		newBlock = func(k []byte) (cipher.Block, error) { return ksNewRC2(k, 40), nil }
	default:
		return 0, nil, false
	}
	cost = ksAddCost(ksP12KDFCost(20, p.Iterations, keyLen), ksP12KDFCost(20, p.Iterations, 8))
	salt, iters := p.Salt, p.Iterations
	return cost, func(pw ksP12Password) ([]byte, bool) {
		key := ksP12KDF(sha1.New, 20, 64, 1, salt, pw.bmp, iters, keyLen)
		iv := ksP12KDF(sha1.New, 20, 64, 2, salt, pw.bmp, iters, 8)
		blk, err := newBlock(key)
		if err != nil {
			return nil, false
		}
		return ksCBCDecrypt(blk, iv, ct)
	}, true
}

// ksCBCDecrypt decrypts and checks the PKCS#7 padding, which is what tells a
// wrong password from a right one when nothing else can.
func ksCBCDecrypt(blk cipher.Block, iv, ct []byte) ([]byte, bool) {
	bs := blk.BlockSize()
	if len(iv) != bs || len(ct) == 0 || len(ct)%bs != 0 {
		return nil, false
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > bs {
		return nil, false
	}
	for _, c := range pt[len(pt)-pad:] {
		if int(c) != pad {
			return nil, false
		}
	}
	return pt[:len(pt)-pad], true
}

// ---- RC2 (RFC 2268), for the legacy pbeWithSHAAnd40BitRC2-CBC that
// OpenSSL's -legacy and older Windows exports still write. Written from the
// RFC.

var ksRC2Pi = [256]byte{
	0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
	0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
	0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
	0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
	0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
	0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
	0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
	0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
	0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
	0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
	0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
	0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
	0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
	0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
	0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
	0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
}

type ksRC2 struct{ k [64]uint16 }

// ksNewRC2 expands a key (1 to 128 bytes) for the given effective key bits.
func ksNewRC2(key []byte, effBits int) *ksRC2 {
	var l [128]byte
	t := len(key)
	copy(l[:], key)
	for i := t; i < 128; i++ {
		l[i] = ksRC2Pi[l[i-1]+l[i-t]]
	}
	t8 := (effBits + 7) / 8
	tm := byte(0xff >> uint(8*t8-effBits))
	l[128-t8] = ksRC2Pi[l[128-t8]&tm]
	for i := 127 - t8; i >= 0; i-- {
		l[i] = ksRC2Pi[l[i+1]^l[i+t8]]
	}
	c := &ksRC2{}
	for i := range c.k {
		c.k[i] = uint16(l[2*i]) | uint16(l[2*i+1])<<8
	}
	return c
}

func (c *ksRC2) BlockSize() int { return 8 }

var ksRC2Shift = [4]uint{1, 2, 3, 5}

func (c *ksRC2) Encrypt(dst, src []byte) {
	var r [4]uint16
	for i := range r {
		r[i] = uint16(src[2*i]) | uint16(src[2*i+1])<<8
	}
	j := 0
	mix := func() {
		for i := 0; i < 4; i++ {
			r[i] += c.k[j] + (r[(i+3)%4] & r[(i+2)%4]) + (^r[(i+3)%4] & r[(i+1)%4])
			j++
			r[i] = r[i]<<ksRC2Shift[i] | r[i]>>(16-ksRC2Shift[i])
		}
	}
	mash := func() {
		for i := 0; i < 4; i++ {
			r[i] += c.k[r[(i+3)%4]&63]
		}
	}
	for _, n := range []int{5, -1, 6, -1, 5} {
		if n < 0 {
			mash()
			continue
		}
		for ; n > 0; n-- {
			mix()
		}
	}
	for i := range r {
		dst[2*i], dst[2*i+1] = byte(r[i]), byte(r[i]>>8)
	}
}

func (c *ksRC2) Decrypt(dst, src []byte) {
	var r [4]uint16
	for i := range r {
		r[i] = uint16(src[2*i]) | uint16(src[2*i+1])<<8
	}
	j := 63
	unmix := func() {
		for i := 3; i >= 0; i-- {
			r[i] = r[i]>>ksRC2Shift[i] | r[i]<<(16-ksRC2Shift[i])
			r[i] -= c.k[j] + (r[(i+3)%4] & r[(i+2)%4]) + (^r[(i+3)%4] & r[(i+1)%4])
			j--
		}
	}
	unmash := func() {
		for i := 3; i >= 0; i-- {
			r[i] -= c.k[r[(i+3)%4]&63]
		}
	}
	for _, n := range []int{5, -1, 6, -1, 5} {
		if n < 0 {
			unmash()
			continue
		}
		for ; n > 0; n-- {
			unmix()
		}
	}
	for i := range r {
		dst[2*i], dst[2*i+1] = byte(r[i]), byte(r[i]>>8)
	}
}
