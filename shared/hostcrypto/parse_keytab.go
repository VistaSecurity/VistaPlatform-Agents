package hostcrypto

import (
	"errors"
	"strconv"
	"strings"
)

// The MIT Kerberos keytab, version 0x0502 (what MIT, Heimdal, Samba and
// Windows ktpass write), big-endian:
//
//	version   u16  0x0502
//	records:
//	  length  i32  negative: a hole of -length bytes left by a deleted entry
//	  num_components   u16 (excluding the realm)
//	  realm            u16 length + bytes
//	  components       u16 length + bytes, num_components times
//	  name_type        u32
//	  timestamp        u32
//	  vno8             u8
//	  keyblock         u16 enctype, u16 length + key bytes
//	  vno32            u32, optional: present when the record has room; overrides vno8 when non-zero
//
// A keytab has no password: whoever can read the file holds the service's
// long-term keys. That is why it is reported, and why the listing is
// [OpenedWithoutPassword]. The key bytes are stepped over by length and never
// copied out.
//
// Version 0x0501 wrote integers in the writing host's native byte order,
// which the file does not record; it is reported as an unsupported legacy
// version rather than guessed at.

const (
	ksKeytabV2 = 0x0502
	ksKeytabV1 = 0x0501
)

var errKsNotKeytab = errors.New("not a keytab")

// ksKerberosEnctypes are the encryption type numbers of RFC 3961, 3962, 4757,
// 6803 and 8009 by their registered names.
var ksKerberosEnctypes = map[uint16]string{
	1:  "des-cbc-crc",
	2:  "des-cbc-md4",
	3:  "des-cbc-md5",
	16: "des3-cbc-sha1",
	17: "aes128-cts-hmac-sha1-96",
	18: "aes256-cts-hmac-sha1-96",
	19: "aes128-cts-hmac-sha256-128",
	20: "aes256-cts-hmac-sha384-192",
	23: "rc4-hmac",
	24: "rc4-hmac-exp",
	25: "camellia128-cts-cmac",
	26: "camellia256-cts-cmac",
}

// ksKerberosEnctypeName names an encryption type, or "etype-N".
func ksKerberosEnctypeName(n uint16) string {
	if s, ok := ksKerberosEnctypes[n]; ok {
		return s
	}
	return "etype-" + strconv.Itoa(int(n))
}

// ParseKeytab lists a keytab's entries: principal, key version and encryption
// type for each. It never reads a key.
//
// On a malformed file it returns the entries before the fault and an error;
// EntryCount is then nil.
func ParseKeytab(b []byte) (KeystoreContents, error) {
	return ksParseKeytab(b, DefaultMaxKeystoreEntries)
}

func ksParseKeytab(b []byte, maxEntries int) (KeystoreContents, error) {
	out := KeystoreContents{Keystore: Keystore{Type: KeystoreKeytab, Opened: OpenedWithoutPassword}}
	r := &ksReader{b: b}
	version := r.u16()
	switch {
	case r.bad:
		return KeystoreContents{}, errKsNotKeytab
	case version == ksKeytabV1:
		out.Keystore.Opened = OpenedNot
		out.Keystore.Protection = "keytab version 0x0501 (native byte order); unsupported legacy version"
		return out, errors.New("keytab: unsupported legacy version")
	case version != ksKeytabV2:
		return KeystoreContents{}, errKsNotKeytab
	}
	out.Keystore.Protection = "none (keys stored unencrypted; readable by anyone who can read the file)"

	count := 0
	for r.remaining() > 0 {
		if r.remaining() < 4 {
			// Too short to be a record length: the file was cut short.
			return out, errors.New("keytab: truncated")
		}
		length := int32(r.u32())
		if length == 0 {
			// A zero length marks the end of what was written.
			break
		}
		if length < 0 {
			// A hole: a deleted entry's space, -length bytes long.
			hole := -int64(length)
			if hole > int64(r.remaining()) {
				return out, errors.New("keytab: hole runs past the end")
			}
			r.skip(int(hole))
			continue
		}
		rec := r.take(int(length))
		if rec == nil {
			return out, errors.New("keytab: record runs past the end")
		}
		if count >= maxEntries {
			// Keep counting so EntryCount is honest; stop keeping entries.
			out.Truncated = true
			count++
			continue
		}
		entry, ok := ksKeytabRecord(rec)
		if !ok {
			return out, errors.New("keytab: malformed record")
		}
		out.Keystore.Entries = append(out.Keystore.Entries, entry)
		count++
	}
	out.Keystore.EntryCount = ksIntPtr(count)
	return out, nil
}

// ksKeytabRecord decodes one record. The key bytes are skipped.
func ksKeytabRecord(rec []byte) (KeystoreEntry, bool) {
	r := &ksReader{b: rec}
	n := int(r.u16())
	realm := string(r.take(int(r.u16())))
	if r.bad || n*2 > r.remaining() {
		return KeystoreEntry{}, false
	}
	comps := make([]string, 0, n)
	for i := 0; i < n; i++ {
		comps = append(comps, string(r.take(int(r.u16()))))
	}
	r.u32() // name_type
	r.u32() // timestamp
	kvno := int(r.u8())
	enctype := r.u16()
	r.skip(int(r.u16())) // the key: stepped over, never copied
	if r.bad {
		return KeystoreEntry{}, false
	}
	if r.remaining() >= 4 {
		if v := r.u32(); v != 0 {
			kvno = int(v)
		}
	}
	principal := strings.ToValidUTF8(strings.Join(comps, "/"), "�")
	if realm != "" {
		principal += "@" + strings.ToValidUTF8(realm, "�")
	}
	return KeystoreEntry{
		Kind:           "kerberos_key",
		Principal:      principal,
		KVNO:           kvno,
		EncryptionType: ksKerberosEnctypeName(enctype),
	}, true
}
