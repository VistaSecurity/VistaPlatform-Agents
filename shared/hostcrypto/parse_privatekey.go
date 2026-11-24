package hostcrypto

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Private keys in DER: PKCS#8 (plain and encrypted), PKCS#1, SEC1 and the
// legacy OpenSSL DSA structure.
//
// The rule this file is built around: a private key is parsed only as far as
// it takes to learn what it IS and to derive its PUBLIC half. Where a format
// stores the public half beside the private one (SEC1's publicKey, a PKCS#8 v2
// publicKey, the RSA modulus and exponent) that is what is read; the private
// integers are never decoded into a value that outlives the call, and nothing
// derived from them except the public key reaches a [PrivateKey].
//
// Every algorithm, size and curve is worked out from the DERIVED
// SubjectPublicKeyInfo by [keySPKIInfo], the same function the certificate
// parser uses. That is what guarantees a key and the certificate made from it
// agree on algorithm, size, curve and PublicKeySHA256, which is how the
// platform pairs them.

// The OIDs this package names. Dotted strings, because a map keyed by
// asn1.ObjectIdentifier is not possible and the dotted form is what the
// specifications print.
const (
	keyOIDRSA      = "1.2.840.113549.1.1.1"
	keyOIDRSAPSS   = "1.2.840.113549.1.1.10"
	keyOIDEC       = "1.2.840.10045.2.1"
	keyOIDDSA      = "1.2.840.10040.4.1"
	keyOIDEd25519  = "1.3.101.112"
	keyOIDX25519   = "1.3.101.110"
	keyOIDEd448    = "1.3.101.113"
	keyOIDX448     = "1.3.101.111"
	keyOIDPBES2    = "1.2.840.113549.1.5.13"
	keyOIDPBKDF2   = "1.2.840.113549.1.5.12"
	keyOIDScrypt   = "1.3.6.1.4.1.11591.4.11"
	keyMaxElements = 16
	// keyMaxDSABits bounds the one computation this file does with a private
	// value (a DSA public key from a PKCS#8 file, which stores only x). A
	// hostile file cannot make it exponentiate a million-bit modulus.
	keyMaxDSABits = 16384
)

// keyAlg is a catalogue name and, where the algorithm fixes it, a size.
type keyAlg struct {
	name string
	bits int
}

// keyAlgorithms maps a SubjectPublicKeyInfo / PKCS#8 algorithm OID to the
// catalogue's name. A size of 0 means "read it from the key" (RSA, DSA, EC)
// or "a bit count is not the meaningful measure" (ML-DSA, ML-KEM, SLH-DSA:
// the parameter set is in the name).
var keyAlgorithms = map[string]keyAlg{
	keyOIDRSA:     {"RSA", 0},
	keyOIDRSAPSS:  {"RSA", 0}, // RSASSA-PSS: an RSA key restricted to PSS
	keyOIDEC:      {"ECDSA", 0},
	keyOIDDSA:     {"DSA", 0},
	keyOIDEd25519: {"Ed25519", 256},
	keyOIDX25519:  {"X25519", 256},
	keyOIDEd448:   {"Ed448", 448},
	keyOIDX448:    {"X448", 448},
	// FIPS 204 ML-DSA, FIPS 203 ML-KEM and FIPS 205 SLH-DSA, from the NIST
	// Computer Security Objects Register.
	"2.16.840.1.101.3.4.3.17": {"ML-DSA-44", 0},
	"2.16.840.1.101.3.4.3.18": {"ML-DSA-65", 0},
	"2.16.840.1.101.3.4.3.19": {"ML-DSA-87", 0},
	"2.16.840.1.101.3.4.4.1":  {"ML-KEM-512", 0},
	"2.16.840.1.101.3.4.4.2":  {"ML-KEM-768", 0},
	"2.16.840.1.101.3.4.4.3":  {"ML-KEM-1024", 0},
	"2.16.840.1.101.3.4.3.20": {"SLH-DSA-SHA2-128s", 0},
	"2.16.840.1.101.3.4.3.21": {"SLH-DSA-SHA2-128f", 0},
	"2.16.840.1.101.3.4.3.22": {"SLH-DSA-SHA2-192s", 0},
	"2.16.840.1.101.3.4.3.23": {"SLH-DSA-SHA2-192f", 0},
	"2.16.840.1.101.3.4.3.24": {"SLH-DSA-SHA2-256s", 0},
	"2.16.840.1.101.3.4.3.25": {"SLH-DSA-SHA2-256f", 0},
	"2.16.840.1.101.3.4.3.26": {"SLH-DSA-SHAKE-128s", 0},
	"2.16.840.1.101.3.4.3.27": {"SLH-DSA-SHAKE-128f", 0},
	"2.16.840.1.101.3.4.3.28": {"SLH-DSA-SHAKE-192s", 0},
	"2.16.840.1.101.3.4.3.29": {"SLH-DSA-SHAKE-192f", 0},
	"2.16.840.1.101.3.4.3.30": {"SLH-DSA-SHAKE-256s", 0},
	"2.16.840.1.101.3.4.3.31": {"SLH-DSA-SHAKE-256f", 0},
}

// keyCurves maps a named-curve OID to the spelling crypto/elliptic uses
// ("P-256"), so a key the standard library can parse and one it cannot read
// the same, and to the curve's size in bits.
var keyCurves = map[string]keyAlg{
	"1.2.840.10045.3.1.1":   {"P-192", 192},
	"1.3.132.0.33":          {"P-224", 224},
	"1.2.840.10045.3.1.7":   {"P-256", 256},
	"1.3.132.0.34":          {"P-384", 384},
	"1.3.132.0.35":          {"P-521", 521},
	"1.3.132.0.10":          {"secp256k1", 256},
	"1.3.36.3.3.2.8.1.1.7":  {"brainpoolP256r1", 256},
	"1.3.36.3.3.2.8.1.1.11": {"brainpoolP384r1", 384},
	"1.3.36.3.3.2.8.1.1.13": {"brainpoolP512r1", 512},
	"1.2.156.10197.1.301":   {"SM2", 256},
}

// ParsePrivateKeyDER describes one private key in DER: PKCS#8
// PrivateKeyInfo / OneAsymmetricKey, PKCS#8 EncryptedPrivateKeyInfo, PKCS#1
// RSAPrivateKey, SEC1 ECPrivateKey, or OpenSSL's legacy DSA structure. It
// tells them apart by their ASN.1 shape, so a key with no PEM label (a .der
// or .key file in DER) is described as well as a labelled one.
//
// It reports false when the bytes are none of these. Location is left zero
// for the caller.
func ParsePrivateKeyDER(der []byte) (PrivateKey, bool) {
	_, el, ok := keySequence(der)
	if !ok || len(el) < 2 {
		return PrivateKey{}, false
	}
	switch {
	case len(el) == 2 && keyIsSeq(el[0]) && keyIsOctet(el[1]):
		return keyEncryptedPKCS8(el[0])
	case len(el) >= 3 && keyIsInt(el[0]) && keyIsSeq(el[1]) && keyIsOctet(el[2]):
		return keyPKCS8(der, el)
	case keyIsInt(el[0]) && keyIsOctet(el[1]):
		k := keyNew(KeyFormatSEC1, false)
		keySEC1(&k, el, "")
		return k, true
	case len(el) == 6 && keyAllInts(el):
		return keyLegacyDSA(el)
	case len(el) >= 9 && keyAllInts(el[:9]):
		k := keyNew(KeyFormatPKCS1, false)
		keyRSAFromPKCS1(&k, el, nil)
		return k, true
	}
	return PrivateKey{}, false
}

func keyNew(format string, encrypted bool) PrivateKey {
	e := encrypted
	return PrivateKey{Format: format, Encrypted: &e, Protection: KeyProtectionFile}
}

// keyPKCS8 handles PrivateKeyInfo (RFC 5208) and OneAsymmetricKey (RFC 5958):
// version, algorithm, privateKey, [0] attributes, [1] publicKey.
func keyPKCS8(der []byte, el []asn1.RawValue) (PrivateKey, bool) {
	k := keyNew(KeyFormatPKCS8, false)
	oid, params, ok := keyAlgorithmID(el[1])
	if !ok {
		return PrivateKey{}, false
	}
	inner := el[2].Bytes

	// A v2 OneAsymmetricKey may carry its public key; it is the only way to
	// learn the public half of an algorithm the standard library cannot
	// compute (ML-DSA, Ed448...).
	var storedPub []byte
	for _, e := range el[3:] {
		if e.Class == asn1.ClassContextSpecific && e.Tag == 1 && !e.IsCompound && len(e.Bytes) > 1 && e.Bytes[0] == 0 {
			storedPub = e.Bytes[1:] // IMPLICIT BIT STRING: unused-bits octet, then the key
		}
	}

	switch oid {
	case keyOIDRSA, keyOIDRSAPSS:
		_, rsaEl, ok := keySequence(inner)
		if !ok || len(rsaEl) < 9 || !keyAllInts(rsaEl[:9]) {
			k.Algorithm = "RSA"
			k.Unknown = "the RSA key structure could not be read"
			return k, true
		}
		var algID []byte
		if oid == keyOIDRSAPSS {
			// The PSS parameters are part of the public key's identity; a
			// certificate for this key carries the same AlgorithmIdentifier.
			algID = el[1].FullBytes
		}
		keyRSAFromPKCS1(&k, rsaEl, algID)
		return k, true
	case keyOIDEC:
		_, ecEl, ok := keySequence(inner)
		if !ok || len(ecEl) < 2 || !keyIsInt(ecEl[0]) || !keyIsOctet(ecEl[1]) {
			k.Algorithm = "ECDSA"
			keyApplyCurve(&k, params)
			k.Unknown = "the EC key structure could not be read"
			return k, true
		}
		curve := ""
		if params.Tag == asn1.TagOID {
			var c asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(params.FullBytes, &c); err == nil {
				curve = c.String()
			}
		}
		keySEC1(&k, ecEl, curve)
		if k.PublicKeySHA256 == "" {
			// SEC1 inside PKCS#8 without its optional public key: let the
			// standard library compute it for the curves it knows.
			keyApplyStdlibPKCS8(&k, der)
		}
		return k, true
	case keyOIDDSA:
		keyPKCS8DSA(&k, params, inner)
		return k, true
	case keyOIDEd25519, keyOIDX25519:
		if keyApplyStdlibPKCS8(&k, der) {
			return k, true
		}
	}

	info, known := keyAlgorithms[oid]
	if storedPub != nil {
		algID := el[1].FullBytes
		if spki := keyBuildSPKI(algID, storedPub); spki != nil && keyApplySPKI(&k, spki) {
			return k, true
		}
	}
	if !known {
		k.Unknown = "unrecognised key algorithm " + oid
		return k, true
	}
	k.Algorithm = info.name
	k.SizeBits = info.bits
	k.Unknown = "public key not stored in the file and not derivable for " + info.name
	return k, true
}

// keyApplyStdlibPKCS8 lets crypto/x509 derive the public key of a PKCS#8 key
// it understands. The private key value lives only inside this function.
func keyApplyStdlibPKCS8(k *PrivateKey, der []byte) bool {
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return false
	}
	p, ok := priv.(interface{ Public() crypto.PublicKey })
	if !ok {
		return false
	}
	spki, err := x509.MarshalPKIXPublicKey(p.Public())
	if err != nil {
		return false
	}
	if !keyApplySPKI(k, spki) {
		return false
	}
	k.Unknown = ""
	return true
}

// keySEC1 reads an ECPrivateKey (RFC 5915): version, privateKey,
// [0] parameters, [1] publicKey. curve is the curve OID from an enclosing
// PKCS#8 AlgorithmIdentifier, if any.
func keySEC1(k *PrivateKey, el []asn1.RawValue, curve string) {
	k.Algorithm = "ECDSA"
	var pub []byte
	for _, e := range el[2:] {
		if e.Class != asn1.ClassContextSpecific {
			continue
		}
		switch e.Tag {
		case 0:
			var c asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(e.Bytes, &c); err == nil && curve == "" {
				curve = c.String()
			}
		case 1:
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(e.Bytes, &bs); err == nil {
				pub = bs.Bytes
			}
		}
	}
	if c, ok := keyCurves[curve]; ok {
		k.Curve, k.SizeBits = c.name, c.bits
	}
	if pub == nil || curve == "" {
		if curve == "" {
			k.Unknown = "the curve is not named in the key"
		} else {
			k.Unknown = "public key not stored in the key"
		}
		return
	}
	algID, err := asn1.Marshal(struct {
		Alg   asn1.ObjectIdentifier
		Curve asn1.ObjectIdentifier
	}{keyMustOID(keyOIDEC), keyMustOID(curve)})
	if err != nil {
		return
	}
	if spki := keyBuildSPKI(algID, pub); spki != nil {
		if keyApplySPKI(k, spki) {
			k.Unknown = ""
		}
	}
}

func keyApplyCurve(k *PrivateKey, params asn1.RawValue) {
	var c asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params.FullBytes, &c); err == nil {
		if ci, ok := keyCurves[c.String()]; ok {
			k.Curve, k.SizeBits = ci.name, ci.bits
		}
	}
}

// keyRSAFromPKCS1 reads only the modulus and public exponent of an
// RSAPrivateKey (version, n, e, d, p, q, ...). algID overrides the
// rsaEncryption identifier (RSASSA-PSS keys).
func keyRSAFromPKCS1(k *PrivateKey, el []asn1.RawValue, algID []byte) {
	k.Algorithm = "RSA"
	n, ok1 := keyBigInt(el[1])
	e, ok2 := keyBigInt(el[2])
	if !ok1 || !ok2 || n.Sign() <= 0 || e.Sign() <= 0 {
		k.Unknown = "the RSA modulus could not be read"
		return
	}
	k.SizeBits = n.BitLen()
	if spki := keyRSASPKI(n, e, algID); spki != nil {
		keyApplySPKI(k, spki)
	}
}

// keyRSASPKI is exactly what x509.MarshalPKIXPublicKey writes for an RSA key
// (rsaEncryption with NULL parameters), built by hand so a modulus too small
// or odd for crypto/rsa to accept is still described.
func keyRSASPKI(n, e *big.Int, algID []byte) []byte {
	pub, err := asn1.Marshal(struct{ N, E *big.Int }{n, e})
	if err != nil {
		return nil
	}
	if algID == nil {
		algID, err = asn1.Marshal(struct {
			Alg  asn1.ObjectIdentifier
			Null asn1.RawValue
		}{keyMustOID(keyOIDRSA), asn1.NullRawValue})
		if err != nil {
			return nil
		}
	}
	return keyBuildSPKI(algID, pub)
}

// keyLegacyDSA reads OpenSSL's "DSA PRIVATE KEY": version, p, q, g, y, x. The
// public value y is stored, so nothing is computed.
func keyLegacyDSA(el []asn1.RawValue) (PrivateKey, bool) {
	k := keyNew(KeyFormatDSA, false)
	k.Algorithm = "DSA"
	p, ok1 := keyBigInt(el[1])
	q, ok2 := keyBigInt(el[2])
	g, ok3 := keyBigInt(el[3])
	y, ok4 := keyBigInt(el[4])
	if !ok1 || !ok2 || !ok3 || !ok4 || p.Sign() <= 0 {
		k.Unknown = "the DSA parameters could not be read"
		return k, true
	}
	k.SizeBits = p.BitLen()
	if spki := keyDSASPKI(p, q, g, y); spki != nil {
		keyApplySPKI(&k, spki)
	}
	return k, true
}

// keyPKCS8DSA handles a DSA key in PKCS#8, which stores the parameters in the
// AlgorithmIdentifier and only x in the key: y = g^x mod p is computed here
// so the key can be paired with its certificate. The computation is bounded
// by keyMaxDSABits.
func keyPKCS8DSA(k *PrivateKey, params asn1.RawValue, inner []byte) {
	k.Algorithm = "DSA"
	_, pe, ok := keySequence(params.FullBytes)
	if !ok || len(pe) != 3 || !keyAllInts(pe) {
		k.Unknown = "the DSA parameters could not be read"
		return
	}
	p, _ := keyBigInt(pe[0])
	q, _ := keyBigInt(pe[1])
	g, _ := keyBigInt(pe[2])
	if p == nil || q == nil || g == nil || p.Sign() <= 0 {
		k.Unknown = "the DSA parameters could not be read"
		return
	}
	k.SizeBits = p.BitLen()
	if p.BitLen() > keyMaxDSABits || g.Cmp(big.NewInt(1)) <= 0 || g.Cmp(p) >= 0 {
		k.Unknown = "the DSA public key was not derived: parameters out of range"
		return
	}
	x := new(big.Int)
	if rest, err := asn1.Unmarshal(inner, &x); err != nil || len(rest) != 0 || x.Sign() <= 0 || x.Cmp(p) >= 0 {
		k.Unknown = "the DSA key value could not be read"
		return
	}
	y := new(big.Int).Exp(g, x, p)
	x.SetInt64(0)
	if spki := keyDSASPKI(p, q, g, y); spki != nil {
		keyApplySPKI(k, spki)
	}
}

// keyDSASPKI builds the SubjectPublicKeyInfo RFC 3279 defines for DSA:
// id-dsa with Dss-Parms (p, q, g), and the public value y as an INTEGER.
func keyDSASPKI(p, q, g, y *big.Int) []byte {
	algID, err := asn1.Marshal(struct {
		Alg    asn1.ObjectIdentifier
		Params struct{ P, Q, G *big.Int }
	}{keyMustOID(keyOIDDSA), struct{ P, Q, G *big.Int }{p, q, g}})
	if err != nil {
		return nil
	}
	pub, err := asn1.Marshal(y)
	if err != nil {
		return nil
	}
	return keyBuildSPKI(algID, pub)
}

// keyEncryptedPKCS8 describes an EncryptedPrivateKeyInfo (RFC 5958 section
// 3): encryptionAlgorithm, encryptedData. Nothing is decrypted: the
// algorithm, size and public key are inside the ciphertext.
func keyEncryptedPKCS8(alg asn1.RawValue) (PrivateKey, bool) {
	if _, _, ok := keyAlgorithmID(alg); !ok {
		return PrivateKey{}, false
	}
	k := keyNew(KeyFormatPKCS8, true)
	k.Encryption = keyDescribePBE(alg)
	k.Unknown = "encrypted; algorithm not readable without the passphrase"
	return k, true
}

// keyPBES1 names the PKCS#5 v1.5 and PKCS#12 password-based schemes by
// OpenSSL's names for them.
var keyPBES1 = map[string]string{
	"1.2.840.113549.1.5.1":    "pbeWithMD2AndDES-CBC",
	"1.2.840.113549.1.5.3":    "pbeWithMD5AndDES-CBC",
	"1.2.840.113549.1.5.4":    "pbeWithMD2AndRC2-CBC",
	"1.2.840.113549.1.5.6":    "pbeWithMD5AndRC2-CBC",
	"1.2.840.113549.1.5.10":   "pbeWithSHA1AndDES-CBC",
	"1.2.840.113549.1.5.11":   "pbeWithSHA1AndRC2-CBC",
	"1.2.840.113549.1.12.1.1": "pbeWithSHA1And128BitRC4",
	"1.2.840.113549.1.12.1.2": "pbeWithSHA1And40BitRC4",
	"1.2.840.113549.1.12.1.3": "pbeWithSHA1And3-KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.4": "pbeWithSHA1And2-KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.5": "pbeWithSHA1And128BitRC2-CBC",
	"1.2.840.113549.1.12.1.6": "pbeWithSHA1And40BitRC2-CBC",
}

var keyPRFs = map[string]string{
	"1.2.840.113549.2.7":      "HMAC-SHA1",
	"1.2.840.113549.2.8":      "HMAC-SHA224",
	"1.2.840.113549.2.9":      "HMAC-SHA256",
	"1.2.840.113549.2.10":     "HMAC-SHA384",
	"1.2.840.113549.2.11":     "HMAC-SHA512",
	"1.2.840.113549.2.12":     "HMAC-SHA512-224",
	"1.2.840.113549.2.13":     "HMAC-SHA512-256",
	"2.16.840.1.101.3.4.2.13": "HMAC-SHA3-224",
	"2.16.840.1.101.3.4.2.14": "HMAC-SHA3-256",
	"2.16.840.1.101.3.4.2.15": "HMAC-SHA3-384",
	"2.16.840.1.101.3.4.2.16": "HMAC-SHA3-512",
}

var keyCiphers = map[string]string{
	"2.16.840.1.101.3.4.1.2":  "AES-128-CBC",
	"2.16.840.1.101.3.4.1.22": "AES-192-CBC",
	"2.16.840.1.101.3.4.1.42": "AES-256-CBC",
	"2.16.840.1.101.3.4.1.6":  "AES-128-GCM",
	"2.16.840.1.101.3.4.1.26": "AES-192-GCM",
	"2.16.840.1.101.3.4.1.46": "AES-256-GCM",
	"1.2.840.113549.3.7":      "DES-EDE3-CBC",
	"1.3.14.3.2.7":            "DES-CBC",
	"1.2.840.113549.3.2":      "RC2-CBC",
}

// keyDescribePBE names a password-based encryption AlgorithmIdentifier as
// PKCS#8 and PKCS#12 use it: "PBES2 (PBKDF2-HMAC-SHA256, 2048 iterations,
// AES-256-CBC)", "PBES2 (scrypt N=16384 r=8 p=1, AES-256-CBC)",
// "pbeWithSHA1And3-KeyTripleDES-CBC (2048 iterations)". The salt and IV are
// read past, never reported. A keystore parser can use it for a PKCS#12
// SafeBag or MAC as well.
func keyDescribePBE(alg asn1.RawValue) string {
	oid, params, ok := keyAlgorithmID(alg)
	if !ok {
		return "unrecognised"
	}
	if name, ok := keyPBES1[oid]; ok {
		// PBEParameter / pkcs-12PbeParams: salt, iterations.
		if _, pe, ok := keySequence(params.FullBytes); ok && len(pe) == 2 && keyIsInt(pe[1]) {
			if it, ok := keySmallInt(pe[1]); ok {
				return fmt.Sprintf("%s (%d iterations)", name, it)
			}
		}
		return name
	}
	if oid != keyOIDPBES2 {
		return "unrecognised scheme " + oid
	}
	_, pe, ok := keySequence(params.FullBytes)
	if !ok || len(pe) != 2 {
		return "PBES2 (unreadable parameters)"
	}
	kdf := keyDescribeKDF(pe[0])
	cipher := "unrecognised cipher"
	if cOID, _, ok := keyAlgorithmID(pe[1]); ok {
		if c, ok := keyCiphers[cOID]; ok {
			cipher = c
		} else {
			cipher = "cipher " + cOID
		}
	}
	return fmt.Sprintf("PBES2 (%s, %s)", kdf, cipher)
}

func keyDescribeKDF(alg asn1.RawValue) string {
	oid, params, ok := keyAlgorithmID(alg)
	if !ok {
		return "unrecognised KDF"
	}
	_, pe, seqOK := keySequence(params.FullBytes)
	switch oid {
	case keyOIDPBKDF2:
		// salt, iterationCount, keyLength OPTIONAL, prf DEFAULT hmacWithSHA1
		prf := "HMAC-SHA1"
		iters := ""
		if seqOK && len(pe) >= 2 {
			if it, ok := keySmallInt(pe[1]); ok {
				iters = fmt.Sprintf(", %d iterations", it)
			}
			for _, e := range pe[2:] {
				if keyIsSeq(e) {
					if pOID, _, ok := keyAlgorithmID(e); ok {
						if name, ok := keyPRFs[pOID]; ok {
							prf = name
						} else {
							prf = "PRF " + pOID
						}
					}
				}
			}
		}
		return "PBKDF2-" + prf + iters
	case keyOIDScrypt:
		// salt, costParameter, blockSize, parallelizationParameter, keyLength OPTIONAL
		if seqOK && len(pe) >= 4 {
			n, ok1 := keySmallInt(pe[1])
			r, ok2 := keySmallInt(pe[2])
			p, ok3 := keySmallInt(pe[3])
			if ok1 && ok2 && ok3 {
				return fmt.Sprintf("scrypt N=%d r=%d p=%d", n, r, p)
			}
		}
		return "scrypt"
	}
	return "KDF " + oid
}

// keySPKIInfo reads a DER SubjectPublicKeyInfo: algorithm, size and curve in
// the catalogue's spelling, and the hex SHA-256 of the structure, which is
// [Certificate.PublicKeySHA256] and [PrivateKey.PublicKeySHA256]. An
// unrecognised algorithm OID leaves Algorithm empty but still hashes.
func keySPKIInfo(spki []byte) (PublicKeyInfo, bool) {
	outer, el, ok := keySequence(spki)
	if !ok || len(el) != 2 || !keyIsSeq(el[0]) || el[1].Tag != asn1.TagBitString {
		return PublicKeyInfo{}, false
	}
	sum := sha256.Sum256(outer.FullBytes)
	out := PublicKeyInfo{PublicKeySHA256: hex.EncodeToString(sum[:])}
	oid, params, ok := keyAlgorithmID(el[0])
	if !ok {
		return PublicKeyInfo{}, false
	}
	info, known := keyAlgorithms[oid]
	if !known {
		return out, true
	}
	out.Algorithm, out.SizeBits = info.name, info.bits
	var bs asn1.BitString
	if _, err := asn1.Unmarshal(el[1].FullBytes, &bs); err != nil {
		return out, true
	}
	switch oid {
	case keyOIDRSA, keyOIDRSAPSS:
		if _, re, ok := keySequence(bs.Bytes); ok && len(re) >= 1 {
			if n, ok := keyBigInt(re[0]); ok && n.Sign() > 0 {
				out.SizeBits = n.BitLen()
			}
		}
	case keyOIDEC:
		var c asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(params.FullBytes, &c); err == nil {
			if ci, ok := keyCurves[c.String()]; ok {
				out.Curve, out.SizeBits = ci.name, ci.bits
			}
		}
	case keyOIDDSA:
		if _, pe, ok := keySequence(params.FullBytes); ok && len(pe) >= 1 {
			if p, ok := keyBigInt(pe[0]); ok && p.Sign() > 0 {
				out.SizeBits = p.BitLen()
			}
		}
	}
	return out, true
}

// keyApplySPKI fills a PrivateKey's public fields from its derived SPKI.
func keyApplySPKI(k *PrivateKey, spki []byte) bool {
	info, ok := keySPKIInfo(spki)
	if !ok {
		return false
	}
	if info.Algorithm != "" {
		k.Algorithm = info.Algorithm
	}
	if info.SizeBits != 0 {
		k.SizeBits = info.SizeBits
	}
	if info.Curve != "" {
		k.Curve = info.Curve
	}
	k.PublicKeySHA256 = info.PublicKeySHA256
	return true
}

// keyBuildSPKI assembles SubjectPublicKeyInfo from a DER AlgorithmIdentifier
// and the public key's bytes.
func keyBuildSPKI(algID, pub []byte) []byte {
	b, err := asn1.Marshal(struct {
		Alg asn1.RawValue
		Pub asn1.BitString
	}{asn1.RawValue{FullBytes: algID}, asn1.BitString{Bytes: pub, BitLength: 8 * len(pub)}})
	if err != nil {
		return nil
	}
	return b
}

// keySequence parses the DER SEQUENCE at the start of der into its elements,
// at most keyMaxElements of them. Trailing bytes after the SEQUENCE are
// ignored: whether they matter is the caller's question.
func keySequence(der []byte) (asn1.RawValue, []asn1.RawValue, bool) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return outer, nil, false
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return outer, nil, false
	}
	var out []asn1.RawValue
	rest := outer.Bytes
	for len(rest) > 0 {
		if len(out) >= keyMaxElements {
			return outer, nil, false
		}
		var rv asn1.RawValue
		r, err := asn1.Unmarshal(rest, &rv)
		if err != nil {
			return outer, nil, false
		}
		out = append(out, rv)
		rest = r
	}
	return outer, out, true
}

// keyAlgorithmID reads an AlgorithmIdentifier: an OID and optional
// parameters (zero RawValue when absent).
func keyAlgorithmID(rv asn1.RawValue) (string, asn1.RawValue, bool) {
	if !keyIsSeq(rv) {
		return "", asn1.RawValue{}, false
	}
	_, el, ok := keySequence(rv.FullBytes)
	if !ok || len(el) < 1 || el[0].Class != asn1.ClassUniversal || el[0].Tag != asn1.TagOID {
		return "", asn1.RawValue{}, false
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(el[0].FullBytes, &oid); err != nil {
		return "", asn1.RawValue{}, false
	}
	var params asn1.RawValue
	if len(el) > 1 {
		params = el[1]
	}
	return oid.String(), params, true
}

func keyIsSeq(rv asn1.RawValue) bool {
	return rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence && rv.IsCompound
}

func keyIsOctet(rv asn1.RawValue) bool {
	return rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagOctetString && !rv.IsCompound
}

func keyIsInt(rv asn1.RawValue) bool {
	return rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagInteger && !rv.IsCompound
}

func keyAllInts(el []asn1.RawValue) bool {
	for _, e := range el {
		if !keyIsInt(e) {
			return false
		}
	}
	return true
}

func keyBigInt(rv asn1.RawValue) (*big.Int, bool) {
	if !keyIsInt(rv) {
		return nil, false
	}
	n := new(big.Int)
	if _, err := asn1.Unmarshal(rv.FullBytes, &n); err != nil {
		return nil, false
	}
	return n, true
}

// keySmallInt reads an INTEGER that should be a modest count (iterations, a
// cost parameter). A value beyond int64 or negative is not reported.
func keySmallInt(rv asn1.RawValue) (int64, bool) {
	n, ok := keyBigInt(rv)
	if !ok || n.Sign() < 0 || !n.IsInt64() {
		return 0, false
	}
	return n.Int64(), true
}

// keyMustOID parses a dotted OID this file defines; it cannot fail for them.
func keyMustOID(s string) asn1.ObjectIdentifier {
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		v := 0
		for _, c := range part {
			v = v*10 + int(c-'0')
		}
		oid = append(oid, v)
	}
	return oid
}
