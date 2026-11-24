package hostcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSH keys: the openssh-key-v1 private key container, public key lines,
// authorized_keys and known_hosts.

const (
	keyOpenSSHMagic = "openssh-key-v1\x00"
	// keyOpenSSHMaxKeys bounds the key count a container may claim. OpenSSH
	// itself writes exactly one.
	keyOpenSSHMaxKeys = 16
	// keySSHDSS is the DSA key type. x/crypto/ssh deprecates its constant
	// because OpenSSH no longer accepts DSA; hosts still carry such keys, and
	// they are exactly what an inventory must find.
	keySSHDSS = "ssh-dss"
)

// ParseOpenSSHPrivateKey describes the keys in an openssh-key-v1 container
// (the base64-decoded body of an "OPENSSH PRIVATE KEY" PEM block; PROTOCOL.key
// in the OpenSSH sources).
//
// It is parsed by hand rather than with ssh.ParseRawPrivateKey because the
// container stores each PUBLIC key in the clear ahead of the private section:
// algorithm, size and both fingerprints are readable from an encrypted key
// without its passphrase, and without decoding a byte of the private section,
// which this function never reads. Every length is checked against what is
// left of the input before it is used, so a hostile length cannot cause an
// allocation or a read past the end.
func ParseOpenSSHPrivateKey(blob []byte) ([]PrivateKey, bool) {
	if !bytes.HasPrefix(blob, []byte(keyOpenSSHMagic)) {
		return nil, false
	}
	r := keySSHReader{b: blob[len(keyOpenSSHMagic):]}
	cipher := r.str()
	kdf := r.str()
	kdfOpts := r.str()
	n := r.u32()
	if r.bad || n == 0 || n > keyOpenSSHMaxKeys {
		return nil, false
	}
	pubs := make([][]byte, 0, n)
	for i := uint32(0); i < n; i++ {
		p := r.str()
		if r.bad {
			return nil, false
		}
		pubs = append(pubs, p)
	}
	// The private section follows. It is deliberately not read.

	encrypted := string(cipher) != "none"
	encryption := ""
	if encrypted {
		encryption = keyDescribeOpenSSHKDF(kdf, kdfOpts) + " + " + keySafeName(cipher)
	}
	out := make([]PrivateKey, 0, n)
	for _, p := range pubs {
		k := keyNew(KeyFormatOpenSSH, encrypted)
		k.Encryption = encryption
		d, ok := keyDescribeSSHBlob(p)
		if !ok {
			k.Unknown = "the public key in the container could not be read"
			out = append(out, k)
			continue
		}
		k.Algorithm, k.SizeBits, k.Curve = d.algorithm, d.size, d.curve
		k.SSHFingerprint = d.fingerprint
		k.PublicKeySHA256 = d.spkiSHA256
		k.Unknown = d.unknown
		out = append(out, k)
	}
	return out, true
}

func keyDescribeOpenSSHKDF(kdf, opts []byte) string {
	if string(kdf) != "bcrypt" {
		return keySafeName(kdf)
	}
	r := keySSHReader{b: opts}
	_ = r.str() // salt
	rounds := r.u32()
	if r.bad {
		return "bcrypt"
	}
	return fmt.Sprintf("bcrypt (%d rounds)", rounds)
}

// keySafeName returns an algorithm name from a file only when it looks like
// one: short and from the characters algorithm names use. Anything else is
// not repeated into the report.
func keySafeName(b []byte) string {
	if len(b) == 0 || len(b) > 64 {
		return "unrecognised"
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '@', c == '+':
		default:
			return "unrecognised"
		}
	}
	return string(b)
}

// keySSHReader reads the SSH wire encoding (RFC 4251 section 5). A short read
// sets bad and every later read returns zero values.
type keySSHReader struct {
	b   []byte
	bad bool
}

func (r *keySSHReader) u32() uint32 {
	if r.bad || len(r.b) < 4 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *keySSHReader) str() []byte {
	n := r.u32()
	if r.bad || uint64(n) > uint64(len(r.b)) {
		r.bad = true
		return nil
	}
	s := r.b[:n:n]
	r.b = r.b[n:]
	return s
}

func (r *keySSHReader) mpint() *big.Int {
	s := r.str()
	if r.bad {
		return nil
	}
	return new(big.Int).SetBytes(s)
}

type keySSHDescription struct {
	// typ is the key type as the wire form names it ("ssh-ed25519").
	typ         string
	fingerprint string
	algorithm   string
	size        int
	curve       string
	spkiSHA256  string
	unknown     string
}

// keyDescribeSSHPublic gives an SSH public key's catalogue algorithm, size,
// curve and SubjectPublicKeyInfo hash. An SSH certificate is described by the
// key it certifies.
func keyDescribeSSHPublic(pub ssh.PublicKey) keySSHDescription {
	outer := pub
	if c, ok := pub.(*ssh.Certificate); ok {
		pub = c.Key
	}
	d := keySSHDescription{typ: outer.Type(), fingerprint: ssh.FingerprintSHA256(outer)}
	t := pub.Type()
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		d.unknown = "unrecognised SSH key type"
		return d
	}
	cp := cpk.CryptoPublicKey()
	switch k := cp.(type) {
	case *rsa.PublicKey:
		d.algorithm, d.size = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		d.algorithm = "ECDSA"
		if k.Curve != nil {
			d.curve, d.size = k.Curve.Params().Name, k.Curve.Params().BitSize
		}
	case ed25519.PublicKey:
		d.algorithm, d.size = "Ed25519", 256
	default:
		d.unknown = "unrecognised SSH key type"
		return d
	}
	if strings.HasPrefix(t, "sk-") {
		// A FIDO security-key public key is bound to an application string
		// ("ssh:") that has no place in a SubjectPublicKeyInfo; hashing the
		// bare point would pair it with keys it is not.
		d.unknown = "security-key (FIDO) key: no SubjectPublicKeyInfo form"
		return d
	}
	spki, err := x509.MarshalPKIXPublicKey(cp)
	if err != nil {
		return d
	}
	if info, ok := keySPKIInfo(spki); ok {
		d.spkiSHA256 = info.PublicKeySHA256
	}
	return d
}

// keyDescribeSSHBlob describes an SSH public key in its wire form. ssh-dss
// is read here by hand: x/crypto/ssh no longer parses DSA keys at all, and a
// host's leftover DSA key is exactly what an inventory must still report.
func keyDescribeSSHBlob(blob []byte) (keySSHDescription, bool) {
	r := keySSHReader{b: blob}
	if t := r.str(); !r.bad && string(t) == keySSHDSS {
		p, q, g, y := r.mpint(), r.mpint(), r.mpint(), r.mpint()
		if r.bad || p.Sign() <= 0 {
			return keySSHDescription{}, false
		}
		sum := sha256.Sum256(blob)
		d := keySSHDescription{
			typ:         keySSHDSS,
			fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
			algorithm:   "DSA",
			size:        p.BitLen(),
		}
		if info, ok := keySPKIInfo(keyDSASPKI(p, q, g, y)); ok {
			d.spkiSHA256 = info.PublicKeySHA256
		}
		return d, true
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return keySSHDescription{}, false
	}
	return keyDescribeSSHPublic(pub), true
}

// keySSHPublicKey projects an ssh.PublicKey onto the record. Algorithm is the
// type as the file spells it ("ssh-ed25519", "sk-ssh-ed25519@openssh.com",
// "ssh-rsa-cert-v01@openssh.com").
func keySSHPublicKey(d keySSHDescription) SSHPublicKey {
	return SSHPublicKey{Algorithm: d.typ, SizeBits: d.size, Fingerprint: d.fingerprint}
}

// keyParseKeyLine reads "[options] type base64 [comment]". x/crypto/ssh
// does it for every type it knows; a line it refuses is tried as ssh-dss,
// which it no longer knows.
func keyParseKeyLine(line []byte) (keySSHDescription, []string, bool) {
	if pub, _, options, _, err := ssh.ParseAuthorizedKey(line); err == nil {
		return keyDescribeSSHPublic(pub), options, true
	}
	s := string(line)
	var opts string
	switch {
	case strings.HasPrefix(s, keySSHDSS+" "):
	default:
		i := strings.Index(s, " "+keySSHDSS+" ")
		if i < 0 {
			return keySSHDescription{}, nil, false
		}
		opts, s = s[:i], s[i+1:]
	}
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return keySSHDescription{}, nil, false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return keySSHDescription{}, nil, false
	}
	d, ok := keyDescribeSSHBlob(blob)
	if !ok || d.typ != keySSHDSS {
		return keySSHDescription{}, nil, false
	}
	return d, keySplitOptions(opts), true
}

// keySplitOptions splits an authorized_keys option list on the commas that
// are outside double quotes.
func keySplitOptions(s string) []string {
	var out []string
	inQuote, start := false, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case '\\':
			i++
		case ',':
			if !inQuote {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// keyRestrictingOptions are the authorized_keys options (sshd(8),
// "AUTHORIZED_KEYS FILE FORMAT") that limit what a key may do. Options that
// only grant ("pty", "port-forwarding", "no-touch-required") or describe
// ("environment", "cert-authority") are not on it.
var keyRestrictingOptions = map[string]bool{
	"restrict":            true,
	"command":             true,
	"from":                true,
	"no-pty":              true,
	"no-port-forwarding":  true,
	"no-agent-forwarding": true,
	"no-x11-forwarding":   true,
	"no-user-rc":          true,
	"permitopen":          true,
	"permitlisten":        true,
	"expiry-time":         true,
	"principals":          true,
	"verify-required":     true,
}

// ParseSSHPublicKeyLine reads one authorized_keys line: optional options, the
// key type, the base64 key, an optional comment. The comment and the options'
// values are dropped: they are usually a person's address or a host name, and
// a command line can hold anything. Restricted records whether any option
// limits the key; cert-authority sets CertificateAuthority.
func ParseSSHPublicKeyLine(line []byte) (SSHPublicKey, bool) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] == '#' {
		return SSHPublicKey{}, false
	}
	d, options, ok := keyParseKeyLine(line)
	if !ok {
		return SSHPublicKey{}, false
	}
	out := keySSHPublicKey(d)
	restricted := false
	for _, o := range options {
		name := strings.ToLower(o)
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimSpace(name)
		if name == "cert-authority" {
			out.CertificateAuthority = true
		}
		if keyRestrictingOptions[name] {
			restricted = true
		}
	}
	out.Restricted = &restricted
	return out, true
}

// ParseAuthorizedKeys reads an authorized_keys file, at most max keys (0
// means the package's 2000). Blank lines and comments are skipped; a line that
// is neither and does not parse counts as malformed. When len(keys) == max
// the file may hold more.
func ParseAuthorizedKeys(b []byte, max int) (keys []SSHPublicKey, malformed int) {
	if max <= 0 {
		max = keyDefaultMaxRecords
	}
	for len(b) > 0 && len(keys) < max {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		t := bytes.TrimSpace(line)
		if len(t) == 0 || t[0] == '#' {
			continue
		}
		k, ok := ParseSSHPublicKeyLine(t)
		if !ok {
			malformed++
			continue
		}
		keys = append(keys, k)
	}
	return keys, malformed
}

// SummariseKnownHosts counts a known_hosts file's entries and says whether
// any is hashed (HashKnownHosts). Nothing else is read: the entries are
// other people's hosts.
func SummariseKnownHosts(b []byte) (entries int, hashed bool) {
	for len(b) > 0 {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		t := bytes.TrimSpace(line)
		if len(t) == 0 || t[0] == '#' {
			continue
		}
		entries++
		if t[0] == '@' { // @cert-authority / @revoked marker
			if i := bytes.IndexAny(t, " \t"); i >= 0 {
				t = bytes.TrimSpace(t[i:])
			}
		}
		if bytes.HasPrefix(t, []byte("|1|")) {
			hashed = true
		}
	}
	return entries, hashed
}

// ParseSSHPublicKeyFile reads a ".pub" file: a user key's or a host key's
// (ssh_host_*_key.pub) public half, one line. The comment is dropped and
// Restricted is left nil: it means something only in authorized_keys.
func ParseSSHPublicKeyFile(b []byte) (SSHPublicKey, bool) {
	for len(b) > 0 {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		t := bytes.TrimSpace(line)
		if len(t) == 0 || t[0] == '#' {
			continue
		}
		d, _, ok := keyParseKeyLine(t)
		if !ok {
			return SSHPublicKey{}, false
		}
		return keySSHPublicKey(d), true
	}
	return SSHPublicKey{}, false
}
