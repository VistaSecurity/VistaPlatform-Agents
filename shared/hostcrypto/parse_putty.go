package hostcrypto

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PuTTY private key files (.ppk), versions 2 and 3, as PuTTY's manual
// (appendix C, "PPK file format") describes them:
//
//	PuTTY-User-Key-File-3: ssh-ed25519
//	Encryption: aes256-cbc
//	Comment: ...
//	Public-Lines: 2
//	<base64 SSH public key blob>
//	Key-Derivation: Argon2id          (v3, encrypted only)
//	Argon2-Memory: 8192
//	Argon2-Passes: 13
//	Argon2-Parallelism: 1
//	Argon2-Salt: ...
//	Private-Lines: 1
//	<base64, encrypted or not>
//	Private-MAC: ...
//
// The public key is stored in the clear, so algorithm, size and fingerprint
// are readable without the passphrase. Reading stops at "Private-Lines:": the
// private lines are never decoded, and the comment is never kept.

const (
	keyPuTTYPrefix = "PuTTY-User-Key-File-"
	// keyPuTTYMaxHeaderLines bounds how many lines are read before giving up
	// on finding Private-Lines.
	keyPuTTYMaxHeaderLines = 64
	// keyPuTTYMaxPublicLines bounds Public-Lines. A 16384-bit RSA key is 47
	// lines of 64 characters.
	keyPuTTYMaxPublicLines = 256
)

// ParsePuTTYKey describes a PuTTY-User-Key-File-2 or -3. It reports false for
// anything else.
func ParsePuTTYKey(b []byte) (PrivateKey, bool) {
	if !bytes.HasPrefix(b, []byte(keyPuTTYPrefix)) {
		return PrivateKey{}, false
	}
	next := func() (string, bool) {
		if len(b) == 0 {
			return "", false
		}
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		return strings.TrimRight(string(line), "\r"), true
	}

	first, _ := next()
	ver, alg, ok := strings.Cut(strings.TrimPrefix(first, keyPuTTYPrefix), ": ")
	if !ok || (ver != "2" && ver != "3") {
		return PrivateKey{}, false
	}
	headers := map[string]string{}
	var publicBlob []byte
	publicRead := false
	for i := 0; i < keyPuTTYMaxHeaderLines; i++ {
		line, ok := next()
		if !ok {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return PrivateKey{}, false
		}
		value = strings.TrimSpace(value)
		if name == "Private-Lines" {
			break
		}
		if name == "Comment" {
			continue // a person's words; not kept
		}
		if name == "Public-Lines" {
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 || n > keyPuTTYMaxPublicLines || publicRead {
				return PrivateKey{}, false
			}
			var enc strings.Builder
			for j := 0; j < n; j++ {
				l, ok := next()
				if !ok {
					return PrivateKey{}, false
				}
				enc.WriteString(strings.TrimSpace(l))
			}
			blob, err := base64.StdEncoding.DecodeString(enc.String())
			if err != nil {
				return PrivateKey{}, false
			}
			publicBlob, publicRead = blob, true
			continue
		}
		if len(value) <= 64 {
			headers[name] = value
		}
	}
	enc, ok := headers["Encryption"]
	if !ok {
		return PrivateKey{}, false
	}

	k := keyNew(KeyFormatPuTTY, enc != "none")
	if enc != "none" {
		cipher := keySafeName([]byte(enc))
		if ver == "3" {
			k.Encryption = keyPuTTYKDF(headers) + " + " + cipher
		} else {
			// Version 2 derives the key with SHA-1 over the passphrase,
			// without salt or iterations; the cipher is all it names.
			k.Encryption = cipher
		}
	}
	if publicBlob == nil {
		k.Algorithm = keySSHCatalogueName(alg)
		k.Unknown = "the public key lines could not be read"
		return k, true
	}
	d, ok := keyDescribeSSHBlob(publicBlob)
	if !ok {
		k.Algorithm = keySSHCatalogueName(alg)
		k.Unknown = "the public key lines could not be read"
		return k, true
	}
	k.Algorithm, k.SizeBits, k.Curve = d.algorithm, d.size, d.curve
	k.SSHFingerprint = d.fingerprint
	k.PublicKeySHA256 = d.spkiSHA256
	k.Unknown = d.unknown
	return k, true
}

// keyPuTTYKDF names a version 3 file's key derivation with its cost
// parameters, which are not secret: "Argon2id (8192 KiB, 13 passes,
// parallelism 1)".
func keyPuTTYKDF(h map[string]string) string {
	kdf := keySafeName([]byte(h["Key-Derivation"]))
	if _, ok := h["Key-Derivation"]; !ok {
		return "unrecognised"
	}
	mem, err1 := strconv.Atoi(h["Argon2-Memory"])
	passes, err2 := strconv.Atoi(h["Argon2-Passes"])
	par, err3 := strconv.Atoi(h["Argon2-Parallelism"])
	if err1 != nil || err2 != nil || err3 != nil {
		return kdf
	}
	return kdf + " (" + strconv.Itoa(mem) + " KiB, " + strconv.Itoa(passes) + " passes, parallelism " + strconv.Itoa(par) + ")"
}

// keySSHCatalogueName maps an SSH key type name to the catalogue's algorithm
// name, for when only the name is known.
func keySSHCatalogueName(t string) string {
	switch {
	case t == ssh.KeyAlgoRSA:
		return "RSA"
	case t == keySSHDSS:
		return "DSA"
	case strings.HasPrefix(t, "ecdsa-sha2-"), strings.HasPrefix(t, "sk-ecdsa-sha2-"):
		return "ECDSA"
	case t == ssh.KeyAlgoED25519, t == ssh.KeyAlgoSKED25519:
		return "Ed25519"
	}
	return ""
}
