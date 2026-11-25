package hostcrypto

import (
	"encoding/asn1"
	"errors"
	"strconv"
	"strings"
)

// Bouncy Castle's keystores: identification and protection only. Their
// contents are not listed; that needs the password (BCFKS) or a parser of
// BC's own entry encoding this package does not carry (BKS).
//
// What is recognised how:
//
//   - BCFKS is recognised BY STRUCTURE: a DER SEQUENCE of the store data and
//     an integrity check, as Bouncy Castle's ObjectStore ASN.1 module defines
//     it. When it parses, its key derivation, cipher and MAC are named.
//     Nothing in the file says "BCFKS"; a DER file that happens to have this
//     shape would be reported as one, which is why the collector calls this
//     only for a file its name or configuration already says is BCFKS.
//   - BKS and UBER have NO magic number. A file is taken for one by its name
//     (.bks, .ubr, or a configuration naming the BKS type) and checked here
//     only for a plausible header: a version, a salt length and an iteration
//     count. The two formats share that header and differ after it (BKS
//     entries in the clear with each key sealed; UBER the whole body
//     encrypted), which the header does not say, so both are reported as
//     KeystoreBKS.

type ksBCFKSPbkdMac struct {
	MacAlgorithm  ksAlgorithmIdentifier
	PbkdAlgorithm ksAlgorithmIdentifier
	Mac           []byte
}

// ParseBCFKS describes a BCFKS keystore's protection. It returns an error
// when the bytes are not shaped like one; Type is set either way.
func ParseBCFKS(b []byte) (KeystoreContents, error) {
	out := KeystoreContents{Keystore: Keystore{Type: KeystoreBCFKS, Opened: OpenedNot}}
	var outer []asn1.RawValue
	if ksUnmarshalAll(b, &outer) != nil || len(outer) != 2 {
		return out, errors.New("bcfks: not an object store")
	}
	data, check := outer[0], outer[1]
	if data.Class != asn1.ClassUniversal || data.Tag != asn1.TagSequence {
		return out, errors.New("bcfks: not an object store")
	}
	var fields []asn1.RawValue
	if ksUnmarshalAll(data.FullBytes, &fields) != nil || len(fields) == 0 {
		return out, errors.New("bcfks: not an object store")
	}
	var parts []string
	switch {
	case fields[0].Class == asn1.ClassUniversal && fields[0].Tag == asn1.TagSequence:
		// EncryptedObjectStoreData: an algorithm and the encrypted content.
		var alg ksAlgorithmIdentifier
		if len(fields) != 2 || ksUnmarshalAll(fields[0].FullBytes, &alg) != nil {
			return out, errors.New("bcfks: bad encrypted store")
		}
		parts = append(parts, ksDescribeEncryption(alg))
	case fields[0].Class == asn1.ClassUniversal && fields[0].Tag == asn1.TagInteger:
		// ObjectStoreData in the clear: each entry carries its own protection.
		parts = append(parts, "store not encrypted (entries protected individually)")
	default:
		return out, errors.New("bcfks: not an object store")
	}
	switch {
	case check.Class == asn1.ClassUniversal && check.Tag == asn1.TagSequence:
		var mac ksBCFKSPbkdMac
		if ksUnmarshalAll(check.FullBytes, &mac) != nil {
			return out, errors.New("bcfks: bad integrity check")
		}
		parts = append(parts, "MAC: "+ksAlgName(mac.MacAlgorithm.Algorithm)+" ("+ksDescribeKDF(mac.PbkdAlgorithm)+")")
	case check.Class == asn1.ClassContextSpecific && check.Tag == 0:
		parts = append(parts, "integrity: signature")
	default:
		return out, errors.New("bcfks: bad integrity check")
	}
	out.Keystore.Protection = strings.Join(parts, "; ")
	return out, nil
}

// ParseBKS checks a BKS or UBER header and reports its iteration count.
func ParseBKS(b []byte) (KeystoreContents, error) {
	out := KeystoreContents{Keystore: Keystore{Type: KeystoreBKS, Opened: OpenedNot}}
	r := &ksReader{b: b}
	version := r.u32()
	saltLen := r.u32()
	if r.bad || version < 1 || version > 2 || saltLen == 0 || saltLen > 256 {
		return out, errors.New("bks: not a BKS or UBER header")
	}
	r.skip(int(saltLen))
	iterations := r.u32()
	if r.bad || iterations == 0 || iterations > 1<<24 {
		return out, errors.New("bks: not a BKS or UBER header")
	}
	// The header is the same in BKS and UBER; the collector sets KeystoreUBER
	// from the file name (.ubr), which is the only thing that tells them apart.
	out.Keystore.Protection = "BKS or UBER (version " + strconv.Itoa(int(version)) + ", " +
		ksIterations(int(iterations)) + ")"
	return out, nil
}
