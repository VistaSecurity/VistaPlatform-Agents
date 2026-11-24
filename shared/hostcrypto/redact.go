package hostcrypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"regexp"
	"strings"
)

// The text rules: what a file's public content is (publicContent, the remote
// ReadFile), what a configuration read returns (FilterConfigText, ReadText),
// and what identification sees (inspect). They are defined HERE, once, in Go,
// and mirrored line for line by the programs that run on remote hosts (the awk
// program in target_remote_unix.go, the PowerShell in target_remote_win.go).
// Parity tests run the awk program for real and require identical bytes.
//
// Every comparison is on ASCII bytes, so the remote programs can work on a
// Latin-1 or C-locale view of any file and agree with Go byte for byte.
//
// A BEGIN line is any line containing "----BEGIN" or "---- BEGIN"; an END
// line, "----END" or "---- END". A BEGIN line is VALID when the whole line is
// "-----BEGIN <label>-----" or "---- BEGIN <label> ----" and the label is 1 to
// 64 characters of [A-Z0-9 -]. Public labels are an exact allowlist: anything
// not on it is not public, whatever it says.

// publicPEMLabels is the allowlist. A file whose every PEM block carries one
// of these labels may be public; one other label and it is not.
var publicPEMLabels = []string{
	"CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE",
	"PUBLIC KEY", "RSA PUBLIC KEY", "SSH2 PUBLIC KEY",
	"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST",
	"X509 CRL", "DH PARAMETERS", "EC PARAMETERS",
}

func isPublicLabel(l string) bool {
	for _, p := range publicPEMLabels {
		if l == p {
			return true
		}
	}
	return false
}

// maxConfigLines bounds a configuration read: more lines than this is
// ErrFileTooLarge.
const maxConfigLines = 200000

// maxPEMBodyLine is the longest body line a public block may have (RFC 7468
// generators write 64; 76 is the MIME limit).
const maxPEMBodyLine = 76

// redactClass reports the bytes a redacted run is made of: base64, which
// includes hexadecimal.
func redactClass(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

// isLabelByte is [A-Z0-9 -].
func isLabelByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '-'
}

// hasLongRun reports a run of RedactRunLength or more redactClass bytes.
func hasLongRun(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		if redactClass(s[i]) {
			n++
			if n >= RedactRunLength {
				return true
			}
		} else {
			n = 0
		}
	}
	return false
}

// redactRuns replaces every maximal run of RedactRunLength or more
// redactClass bytes with RedactedMarker and counts them.
func redactRuns(s string) (string, int) {
	if !hasLongRun(s) {
		return s, 0
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		if !redactClass(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && redactClass(s[j]) {
			j++
		}
		if j-i >= RedactRunLength {
			b.WriteString(RedactedMarker)
			n++
		} else {
			b.WriteString(s[i:j])
		}
		i = j
	}
	return b.String(), n
}

func isBeginLine(s string) bool {
	return strings.Contains(s, "----BEGIN") || strings.Contains(s, "---- BEGIN")
}

func isEndLine(s string) bool {
	return strings.Contains(s, "----END") || strings.Contains(s, "---- END")
}

// parseBeginLine returns the label of a valid BEGIN line.
func parseBeginLine(s string) (string, bool) {
	n := len(s)
	if n < 17 {
		return "", false
	}
	five := s[:11] == "-----BEGIN " && s[n-5:] == "-----"
	four := s[:11] == "---- BEGIN " && s[n-5:] == " ----"
	if !five && !four {
		return "", false
	}
	label := s[11 : n-5]
	if len(label) > maxPEMLabelLen {
		return "", false
	}
	for i := 0; i < len(label); i++ {
		if !isLabelByte(label[i]) {
			return "", false
		}
	}
	return label, true
}

// namesPrivate reports a BEGIN line that names private material: PRIVATE,
// SECRET or KEY anywhere in it, in any ASCII case. Only called for lines not
// exactly on the allowlist, so "PUBLIC KEY" is not caught.
func namesPrivate(s string) bool {
	u := asciiUpper(s)
	return strings.Contains(u, "PRIVATE") || strings.Contains(u, "SECRET") || strings.Contains(u, "KEY")
}

// asciiUpper upper-cases ASCII letters only. strings.ToUpper would fold
// non-ASCII letters into ASCII ones (U+017F to 'S'), which the remote
// programs, working on bytes, do not.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// pemLines splits b for the PEM rules: on "\n", with one trailing "\r"
// removed from each line and a leading UTF-8 byte-order mark removed. A final
// empty segment (b ends in "\n") is not a line.
func pemLines(b []byte) []string {
	b = bytes.TrimPrefix(b, utf8BOM)
	var out []string
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		var line []byte
		if i < 0 {
			line, b = b, nil
		} else {
			line, b = b[:i], b[i+1:]
		}
		out = append(out, strings.TrimSuffix(string(line), "\r"))
	}
	return out
}

// configLines splits b for the configuration rule: a leading UTF-8 BOM is
// removed, and "\r\n", "\n" and a lone "\r" all end a line. A final empty
// segment is not a line.
func configLines(b []byte) []string {
	b = bytes.TrimPrefix(b, utf8BOM)
	var out []string
	start := 0
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '\n':
			out = append(out, string(b[start:i]))
			start = i + 1
		case '\r':
			out = append(out, string(b[start:i]))
			if i+1 < len(b) && b[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

// sshKeyType is one OpenSSH public key type: its blob's base64 length bounds
// and the base64 of its fixed prefix (the length-prefixed type string, to
// the last whole base64 group).
type sshKeyType struct {
	name           string
	minLen, maxLen int
	prefix         string
}

// sshKeyTypes are the key types a public key line may declare. A blob must
// begin with its type's encoded name and be within the length bounds, which
// are as tight as each type allows, because the blob is the one part of a
// line that crosses whole and a loose bound is room for a payload:
//
//   - Ed25519 and each ECDSA curve: exact (the key is fixed-size);
//   - ssh-rsa: up to an 8192-bit modulus with an exponent of up to eight
//     bytes (1,400 characters; a 1024-bit key is about 200);
//   - security keys (sk-*): 300 characters, room for an application string
//     of about 100 bytes;
//   - certificates: 4,096 characters, which holds an 8192-bit RSA CA key,
//     a signature and a few dozen principals.
//
// ssh-dss is not listed: the parsers no longer read it, so its bytes would
// cross only to be refused.
var sshKeyTypes = func() []sshKeyType {
	types := []sshKeyType{
		{name: "ssh-ed25519", minLen: 68, maxLen: 68},
		{name: "ecdsa-sha2-nistp256", minLen: 140, maxLen: 140},
		{name: "ecdsa-sha2-nistp384", minLen: 184, maxLen: 184},
		{name: "ecdsa-sha2-nistp521", minLen: 232, maxLen: 232},
		{name: "ssh-rsa", minLen: 100, maxLen: 1400},
		{name: "sk-ssh-ed25519@openssh.com", minLen: 96, maxLen: 300},
		{name: "sk-ecdsa-sha2-nistp256@openssh.com", minLen: 160, maxLen: 300},
		{name: "ssh-ed25519-cert-v01@openssh.com", minLen: 100, maxLen: 4096},
		{name: "ssh-rsa-cert-v01@openssh.com", minLen: 100, maxLen: 4096},
		{name: "ecdsa-sha2-nistp256-cert-v01@openssh.com", minLen: 100, maxLen: 4096},
		{name: "ecdsa-sha2-nistp384-cert-v01@openssh.com", minLen: 100, maxLen: 4096},
		{name: "ecdsa-sha2-nistp521-cert-v01@openssh.com", minLen: 100, maxLen: 4096},
		{name: "sk-ssh-ed25519-cert-v01@openssh.com", minLen: 100, maxLen: 4096},
		{name: "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", minLen: 100, maxLen: 4096},
	}
	for i := range types {
		raw := binary.BigEndian.AppendUint32(nil, uint32(len(types[i].name)))
		raw = append(raw, types[i].name...)
		raw = raw[:len(raw)/3*3]
		types[i].prefix = base64.StdEncoding.EncodeToString(raw)
	}
	return types
}()

func findSSHKeyType(name string) (sshKeyType, bool) {
	for _, t := range sshKeyTypes {
		if t.name == name {
			return t, true
		}
	}
	return sshKeyType{}, false
}

// isSSHBlob is [A-Za-z0-9+/]+ followed by '=' padding.
func isSSHBlob(b string) bool {
	k := 0
	for k < len(b) && b[k] != '=' {
		if !redactClass(b[k]) {
			return false
		}
		k++
	}
	if k == 0 {
		return false
	}
	for ; k < len(b); k++ {
		if b[k] != '=' {
			return false
		}
	}
	return true
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

// sshKeyLine finds a genuine OpenSSH public key in a line: ".pub" form
// ("type blob [comment]") or authorized_keys form ("options type blob
// [comment]"). Leading blanks are skipped. When the first field is not a key
// type it is the options field, which runs to the first blank outside double
// quotes (a backslash escapes the next byte inside them); a key type must
// follow it. The blob must begin with that type's encoded name and fit its
// length bounds. It returns "type blob" only: options and comment never.
func sshKeyLine(s string) (string, bool) {
	// Every type name holds "ssh-" or "ecdsa-": a line with neither is not a
	// key line, decided without the option scan below.
	if !strings.Contains(s, "ssh-") && !strings.Contains(s, "ecdsa-") {
		return "", false
	}
	i := 0
	for i < len(s) && isBlank(s[i]) {
		i++
	}
	field := func() string {
		j := i
		for j < len(s) && !isBlank(s[j]) {
			j++
		}
		f := s[i:j]
		i = j
		for i < len(s) && isBlank(s[i]) {
			i++
		}
		return f
	}
	start := i
	typ := field()
	if _, ok := findSSHKeyType(typ); !ok {
		// The options field.
		i = start
		inQ := false
		for i < len(s) {
			c := s[i]
			if inQ {
				if c == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				if c == '"' {
					inQ = false
				}
			} else {
				if isBlank(c) {
					break
				}
				if c == '"' {
					inQ = true
				}
			}
			i++
		}
		if inQ {
			return "", false
		}
		for i < len(s) && isBlank(s[i]) {
			i++
		}
		typ = field()
	}
	t, ok := findSSHKeyType(typ)
	if !ok {
		return "", false
	}
	b := field()
	if isSSHBlob(b) && len(b) >= t.minLen && len(b) <= t.maxLen && strings.HasPrefix(b, t.prefix) {
		return t.name + " " + b, true
	}
	return "", false
}

// privateUnderPublicLabel reports a public block's FIRST body line that
// begins as an unencrypted private key does, whatever the label says. Every
// unencrypted DER private key encoding starts SEQUENCE, INTEGER of one byte
// (its version): PKCS#1 RSA and DSA (version 0, then an INTEGER), SEC1 EC
// (version 1, then an OCTET STRING), PKCS#8 and RFC 5958 (version 0 or 1,
// then the algorithm SEQUENCE), PKCS#12 (version 3). In base64 at offset 0,
// with the outer length in short form, in one byte (0x81) or in two (0x82),
// those are:
//
//	M..CAQ          30 LL 02 01 0v           (v < 16)
//	MI[EFGH].AgE    30 81 LL 02 01 vv        (vv < 64)
//	MII..[AQgw]IB   30 82 LL LL 02 01 vv
//
// and an OpenSSH private key's body begins with base64 "openssh-key-v1".
// Nothing public on the allowlist begins that way (a certificate, request
// or CRL starts SEQUENCE SEQUENCE; a SubjectPublicKeyInfo SEQUENCE SEQUENCE;
// an RSA PUBLIC KEY or DH PARAMETERS SEQUENCE INTEGER of 64 bytes or more;
// named EC PARAMETERS an OID; an SSH2 PUBLIC KEY a length and "ssh-") except
// explicit EC PARAMETERS, SEQUENCE { INTEGER 1, SEQUENCE { OID
// 1.2.840.10045.1.x (a field type) ... } }, which privateException lets
// through in each pair of outer and inner length forms that can occur (the
// inner SEQUENCE short or 0x81: a field of over 2,000 bits does not exist):
// no private key structure carries a field-type OID there. The pattern was
// checked against OpenSSL's explicit parameters for eight curves, prime and
// binary, and is held by TestPrivateUnderPublicLabel to generated objects.
//
// What still passes: an ENCRYPTED PKCS#8 key (SEQUENCE SEQUENCE, like a
// certificate) and a key whose outer length needs three bytes (over 64 KiB).
// An encrypted key under a public label crosses as ciphertext.
func privateUnderPublicLabel(first string) bool {
	return privateDeny.MatchString(first) && !privateException.MatchString(first)
}

// The patterns, as POSIX extended regular expressions without interval
// expressions, so the awk and PowerShell programs use these very strings.
const (
	privateDenyRegex      = `^(MII..[AQgw]IB|MI[EFGH].AgE|M..CAQ|b3BlbnNzaC1rZXktdjE)`
	privateExceptionRegex = `^(M..CAQEw.[AQgw]YHKoZIzj0B|MI[EFGH].AgEBM..GByqGSM49AQ|MI[EFGH].AgEBMI[GH].BgcqhkjOPQE|MII..[AQgw]IBAT..BgcqhkjOPQE|MII..[AQgw]IBATCB.[AQgw]YHKoZIzj0B)`
)

var (
	privateDeny      = regexp.MustCompile(privateDenyRegex)
	privateException = regexp.MustCompile(privateExceptionRegex)
)

// isPEMBodyLine is 1 to 76 characters of [A-Za-z0-9+/=].
func isPEMBodyLine(s string) bool {
	if len(s) == 0 || len(s) > maxPEMBodyLine {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !redactClass(s[i]) {
			return false
		}
	}
	return true
}

// publicContent is the remote ReadFile rule: the public PEM blocks and the
// genuine OpenSSH public key lines of b, and NOTHING else — no text before,
// between or after them, no options, no comments.
//
//   - A block runs from a valid BEGIN line with a label on the allowlist to
//     the matching END line; every body line must be 1 to 76 base64
//     characters, or the whole block is dropped. An unterminated block, or
//     one cut by another BEGIN or a different END, is dropped.
//   - A NUL byte anywhere, a BEGIN line that is not valid, or a valid label
//     off the allowlist refuses the whole file (ok false): such a file is not
//     one whose public parts can be told apart safely. (Other control bytes
//     are ordinary bytes: they can never be part of a printed line.)
//   - A public block whose first body line begins as a private key does
//     (privateUnderPublicLabel) refuses the whole file: a private key under
//     a certificate's label is still a private key.
//   - No public content at all refuses the file.
//
// A DER certificate is therefore never readable remotely: it has no PEM
// frame to cut public bytes out by, and eight bytes of magic cannot tell it
// from a DER private key. The local collector parses DER in memory.
//
// Each line is returned with "\n". A leading UTF-8 byte-order mark is
// tolerated.
func publicContent(b []byte) ([]byte, bool) {
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, false
	}
	var out []string
	var block []string
	inBlock, blockOK := false, false
	var endLine string
	for _, s := range pemLines(b) {
		if isBeginLine(s) {
			// A BEGIN line ends any open block (it is dropped, unterminated).
			label, ok := parseBeginLine(s)
			if !ok || !isPublicLabel(label) {
				return nil, false
			}
			inBlock, blockOK, block = true, true, []string{s}
			if strings.HasPrefix(s, "-----") {
				endLine = "-----END " + label + "-----"
			} else {
				endLine = "---- END " + label + " ----"
			}
			continue
		}
		if inBlock {
			if s == endLine {
				if blockOK {
					out = append(out, block...)
					out = append(out, s)
				}
				inBlock = false
				continue
			}
			if isEndLine(s) {
				inBlock = false
				continue
			}
			if len(block) == 1 && privateUnderPublicLabel(s) {
				return nil, false
			}
			if !isPEMBodyLine(s) {
				blockOK = false
			}
			block = append(block, s)
			continue
		}
		if k, ok := sshKeyLine(s); ok {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return []byte(strings.Join(out, "\n") + "\n"), true
}

// configStatus is why filterConfig refused.
type configStatus int

const (
	configOK configStatus = iota
	configNotText
	configTooManyLines
	configNoKeep
)

// The keep OPTIONS. A keep entry that begins with "@" is one of these, never
// a directive name, and any other "@" entry refuses the read. They say how
// the product's syntax continues a line or groups statements; without them
// a line is a line.
const (
	// KeepOptStatements reads brace-and-semicolon syntax (nginx) as
	// statements rather than lines.
	KeepOptStatements = "@statements"
	// KeepOptBackslash continues a KEPT line that ends in an odd number of
	// backslashes onto the next line.
	KeepOptBackslash = "@backslash"
	// KeepOptIndent continues a logical line onto every following line that
	// begins with a blank (Postfix).
	KeepOptIndent = "@indent"
	// KeepOptCR ends a line at a lone carriage return (Java properties).
	KeepOptCR = "@cr"
)

// Bounds of the rule. A statement or continuation past them is dropped, never
// returned in part.
const (
	// maxStatementBytes and maxStatementLines bound one @statements
	// statement; a longer one is dropped and scanning resumes at the next
	// ";" or brace.
	maxStatementBytes = 16 << 10
	maxStatementLines = 64
	// maxContinuation is how many continuation lines one logical line may
	// have; the rest of it is dropped.
	maxContinuation = 32
	// maxBlockDepth is how deep @statements blocks are followed: a block
	// opened deeper than this is dropped whole.
	maxBlockDepth = 64
)

// keepSet is the caller's keep list: directive names, lower-cased once, and
// options.
type keepSet struct {
	words                             map[string]bool
	statements, backslash, indent, cr bool
	badOption                         bool
}

func newKeepSet(keep []string) keepSet {
	k := keepSet{words: map[string]bool{}}
	for _, w := range keep {
		w = asciiLower(w)
		if w == "" {
			continue
		}
		if w[0] == '@' {
			switch w {
			case KeepOptStatements:
				k.statements = true
			case KeepOptBackslash:
				k.backslash = true
			case KeepOptIndent:
				k.indent = true
			case KeepOptCR:
				k.cr = true
			default:
				k.badOption = true
			}
			continue
		}
		if !isKeepWord(w) {
			k.badOption = true
			continue
		}
		k.words[w] = true
	}
	return k
}

// isKeepWord is a directive name as a keep list may hold one:
// [A-Za-z0-9._*+/-]+. keepArg refuses anything else before it is sent.
func isKeepWord(w string) bool {
	for i := 0; i < len(w); i++ {
		c := w[i]
		if (!redactClass(c) || c == '=') && c != '.' && c != '_' && c != '-' && c != '*' {
			return false
		}
	}
	return w != ""
}

// usable reports a keep list that names at least one directive and holds
// no unknown option and no entry that is not a directive name.
func (k keepSet) usable() bool { return len(k.words) > 0 && !k.badOption }

// firstWord is a configuration line's (or statement's) directive name:
// leading blanks removed, then a leading "<" (an opening tag), "-D" (a JVM
// option) and "@" (crypto-policies' "@SECLEVEL=") removed in that order,
// then the longest prefix without a blank, '=', ':', ';', '{' or '}', a
// trailing '>' removed, lower-cased.
func firstWord(t string) string {
	t = strings.TrimLeft(t, " \t")
	t = strings.TrimPrefix(t, "<")
	t = strings.TrimPrefix(t, "-D")
	t = strings.TrimPrefix(t, "@")
	i := 0
	for i < len(t) {
		c := t[i]
		if c == ' ' || c == '\t' || c == '=' || c == ':' || c == ';' || c == '{' || c == '}' {
			break
		}
		i++
	}
	return asciiLower(strings.TrimSuffix(t[:i], ">"))
}

// endsInOddBackslashes reports a line whose last bytes are an odd number of
// backslashes: one that escapes the line end. Trailing blanks are not
// skipped: "a \ " does not continue.
func endsInOddBackslashes(s string) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// What a lone "\r" (one not before "\n") does to a line.
type crMode int

const (
	crCut   crMode = iota // the line ends there and the rest of it is dropped
	crSplit               // it ends the line (@cr)
	crKeep                // it stays, as a blank (@statements: nginx reads it so)
)

// ruleLines splits a file for the rule: a leading UTF-8 byte-order mark is
// removed; "\n" ends a line, and one "\r" before it is part of the line end.
// A lone "\r" left inside a line is handled by mode: in line mode it ends
// the line when @cr is set (Java properties) and otherwise CUTS it, the rest
// dropped, so bytes some reader takes for two lines never cross as one; in
// @statements mode it is a blank, as it is to nginx, and the canonical
// output never holds one. A final empty segment (the file ends in "\n") is
// not a line. ok is false past maxConfigLines.
func ruleLines(b []byte, mode crMode) ([]string, bool) {
	b = bytes.TrimPrefix(b, utf8BOM)
	var out []string
	for len(b) > 0 {
		var seg []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			seg, b = b[:i], b[i+1:]
		} else {
			seg, b = b, nil
		}
		seg = bytes.TrimSuffix(seg, []byte{'\r'})
		for {
			i := bytes.IndexByte(seg, '\r')
			if i < 0 || mode == crKeep {
				out = append(out, string(seg))
				break
			}
			out = append(out, string(seg[:i]))
			if mode == crCut {
				break
			}
			seg = seg[i+1:]
		}
		if len(out) > maxConfigLines {
			return nil, false
		}
	}
	return out, true
}

// isCommentLine reports a line (left-trimmed) whose first bytes are "#", "!",
// ";" or "//".
func isCommentLine(t string) bool {
	return t != "" && (t[0] == '#' || t[0] == '!' || t[0] == ';' || strings.HasPrefix(t, "//"))
}

// isSectionHeader is ^\[[A-Za-z0-9 ._:/-]{1,128}\]$ on a trimmed line.
func isSectionHeader(tr string) bool {
	if len(tr) < 3 || len(tr) > 130 || tr[0] != '[' || tr[len(tr)-1] != ']' {
		return false
	}
	for i := 1; i < len(tr)-1; i++ {
		c := tr[i]
		if !isASCIIAlnum(c) && strings.IndexByte(" ._:/-", c) < 0 {
			return false
		}
	}
	return true
}

func isASCIIAlnum(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func isTagNameByte(c byte) bool {
	return isASCIIAlnum(c) || c == '_' || c == '.' || c == ':' || c == '-'
}

// closingTag returns the lower-cased name of a trimmed line that is exactly
// a closing tag, ^</[A-Za-z0-9_.:-]{1,64}>$.
func closingTag(tr string) (string, bool) {
	if len(tr) < 4 || len(tr) > 67 || !strings.HasPrefix(tr, "</") || tr[len(tr)-1] != '>' {
		return "", false
	}
	name := tr[2 : len(tr)-1]
	for i := 0; i < len(name); i++ {
		if !isTagNameByte(name[i]) {
			return "", false
		}
	}
	return asciiLower(name), true
}

// openingTag returns the lower-cased name of a trimmed line that opens a
// tag: "<", a letter, up to 64 name bytes in all, then ">" or a blank, and
// the line ends in ">".
func openingTag(tr string) (string, bool) {
	if len(tr) < 3 || tr[0] != '<' || tr[len(tr)-1] != '>' {
		return "", false
	}
	c := tr[1]
	if !isASCIIAlnum(c) || c >= '0' && c <= '9' {
		return "", false
	}
	i := 1
	for i < len(tr) && isTagNameByte(tr[i]) {
		i++
	}
	if i-1 > 64 || (tr[i] != '>' && tr[i] != ' ' && tr[i] != '\t') {
		return "", false
	}
	return asciiLower(tr[1:i]), true
}

// FilterConfigText is [Target.ReadText]'s rule, applied by every target (on
// the host, for a remote one, by programs that mirror this function: the
// awk in target_remote_unix.go, the PowerShell in target_remote_win.go). It
// returns the parts of b a parser asked for, redacted, and how many
// redactions it made; ok is false when the file must be refused (not text,
// an unusable keep, or more than 200,000 lines; the targets turn the last
// into ErrFileTooLarge).
//
// keep holds lower-case ASCII directive names, compared with a line's first
// word without regard to ASCII case, and options, which begin with "@":
// [KeepOptStatements], [KeepOptBackslash], [KeepOptIndent], [KeepOptCR]. A
// keep with no name, or with an unknown option, is refused.
//
//  1. Not text — a NUL or 0x01 byte anywhere, a UTF-16 byte-order mark, or a
//     keystore's magic (at the start, or after a UTF-8 byte-order mark) — is
//     refused. A UTF-8 byte-order mark is removed; a file that is only one
//     yields nothing.
//  2. Lines end at "\n" and "\r\n". A lone "\r" ends a line with @cr, is a
//     blank with @statements, and otherwise cuts its line there, the rest of
//     the line dropped (ruleLines).
//  3. Line mode (no @statements). Comment lines (first non-blank "#", "!",
//     ";" or "//") are dropped. Structure is kept and is strict: a blank
//     line; a section header ^\[[A-Za-z0-9 ._:/-]{1,128}\]$; a closing tag
//     ^</[A-Za-z0-9_.:-]{1,64}>$; a lone "}" or "};"; a lone "{" only
//     directly after a kept line (blank and comment lines between do not
//     count). Any other line is KEPT when its first word (firstWord) is in
//     keep, else DROPPED. A dropped line that ends in "{" drops everything
//     to its matching "}" (a line starting with "}" closes one level, one
//     ending in "{" opens one, comment lines do not count); a dropped
//     opening tag ("<Name ...>") drops everything to its matching "</Name>".
//     There is no continuation without an option. With @backslash a kept
//     line ending in an odd number of backslashes continues onto the next
//     line; with @indent a line beginning with a blank continues the
//     previous logical line, kept iff that was kept, and blank and comment
//     lines between do not end it. Inside a continuation only "#" starts a
//     comment line (a Postfix value may begin with "!"); it is dropped. A
//     logical line has at most 32 continuation lines; the rest are dropped.
//  4. @statements: the text is read as statements, honouring single and
//     double quotes (a backslash escapes the quote or a backslash inside
//     them) and "#" comments, exactly as the nginx parser tokenises: a
//     statement ends at ";", or at "{" (it opens a block), and "}" closes a
//     block. A statement is kept iff its first word is in keep; a block
//     opener likewise, and a dropped opener drops its whole block. A
//     statement over 16 KiB or 64 lines is dropped. The output is
//     canonical: one statement per line, its words joined by one blank
//     (comments and line ends between them gone, a line end inside quotes
//     a blank), ending in ";"; an opener as "<words> {"; a closer as "}".
//  5. Of what is kept, every PEM block is dropped and every run of
//     [RedactRunLength] or more [A-Za-z0-9+/=] is replaced by
//     [RedactedMarker]; each counts one redaction. Every returned line ends
//     in "\n".
//
// What this does NOT do, stated plainly: a KEPT line's value crosses as
// written unless it holds a 40-character run. A 24-character password, a
// JWT (its dots break the runs), a "ghp_" token or colon-separated hex on a
// directive the parser listed would cross. Which directives a parser lists
// is therefore the parser's responsibility, and a parser lists only the
// directives whose values are names, paths and policy, never credentials.
func FilterConfigText(b []byte, keep []string) (out []byte, redactions int, ok bool) {
	out, redactions, st := filterConfig(b, keep)
	return out, redactions, st == configOK
}

// filterConfig is FilterConfigText with the reason for a refusal.
func filterConfig(b []byte, keep []string) ([]byte, int, configStatus) {
	ks := newKeepSet(keep)
	if !ks.usable() {
		return nil, 0, configNoKeep
	}
	if textRefused(b) {
		return nil, 0, configNotText
	}
	mode := crCut
	switch {
	case ks.statements:
		mode = crKeep
	case ks.cr:
		mode = crSplit
	}
	lines, ok := ruleLines(b, mode)
	if !ok {
		return nil, 0, configTooManyLines
	}
	out := make([]byte, 0, len(b)/4)
	n := 0
	drop := false
	emit := func(s string) {
		if drop {
			if isEndLine(s) {
				drop = false
			}
			return
		}
		if isBeginLine(s) {
			n++
			drop = !isEndLine(s)
			return
		}
		red, k := redactRuns(s)
		n += k
		out = append(out, red...)
		out = append(out, '\n')
	}
	if ks.statements {
		filterStatements(lines, ks, emit)
	} else {
		filterLines(lines, ks, emit)
	}
	return out, n, configOK
}

// filterLines is the line mode of filterConfig (rule 3).
func filterLines(lines []string, ks keepSet, emit func(string)) {
	var (
		dropTag     string // the tag of a dropped tag block
		dropBrace   bool   // a dropped brace block is open
		dropDepth   int
		prevKept    bool // the last line that was neither blank nor a comment was kept by its word
		bsCont      bool // @backslash: this line continues a kept line
		contN       int  // continuation lines of the current logical line
		haveLogical bool // @indent: a logical line has started
		logicalKept bool
	)
	for _, s := range lines {
		t := strings.TrimLeft(s, " \t")
		if dropBrace || dropTag != "" {
			if t == "" || isCommentLine(t) {
				continue
			}
			tr := strings.TrimRight(t, " \t")
			if dropBrace {
				if tr[0] == '}' {
					dropDepth--
				}
				if tr[len(tr)-1] == '{' {
					dropDepth++
				}
			} else if name, ok := openingTag(tr); ok && name == dropTag {
				dropDepth++
			} else if name, ok := closingTag(tr); ok && name == dropTag {
				dropDepth--
			}
			if dropDepth <= 0 {
				dropBrace, dropTag = false, ""
			}
			continue
		}
		if bsCont {
			contN++
			bsCont = endsInOddBackslashes(s)
			if contN <= maxContinuation && !strings.HasPrefix(t, "#") {
				emit(s)
			}
			continue
		}
		if ks.indent && haveLogical && t != "" && (s[0] == ' ' || s[0] == '\t') {
			if t[0] == '#' {
				continue
			}
			contN++
			if logicalKept && contN <= maxContinuation {
				emit(s)
			}
			continue
		}
		if t == "" {
			emit(s)
			continue
		}
		if isCommentLine(t) {
			continue
		}
		haveLogical, logicalKept, contN = true, false, 0
		tr := strings.TrimRight(t, " \t")
		if _, closing := closingTag(tr); closing || isSectionHeader(tr) || tr == "}" || tr == "};" || (tr == "{" && prevKept) {
			emit(s)
			prevKept = false
			continue
		}
		if w := firstWord(t); w != "" && ks.words[w] {
			emit(s)
			prevKept, logicalKept = true, true
			bsCont = ks.backslash && endsInOddBackslashes(s)
			continue
		}
		prevKept = false
		if tr[len(tr)-1] == '{' {
			dropBrace, dropDepth = true, 1
		} else if name, ok := openingTag(tr); ok {
			dropTag, dropDepth = name, 1
		}
	}
}

// filterStatements is the @statements mode of filterConfig (rule 4). The
// tokens are those of the nginx parser (cfgNgxTokens): blanks (a lone "\r"
// among them) and line ends
// separate words; "#" at the start of a token comments to the end of the
// line; a quote at the start of a token opens a quoted word, in which a
// backslash before the quote or a backslash is an escape; inside a word, "{"
// after "$" opens a "${...}" that runs to "}" or the line end.
func filterStatements(lines []string, ks keepSet, emit func(string)) {
	text := strings.Join(lines, "\n") + "\n"
	var buf []byte
	started, sep, overlong := false, false, false
	nl, depth, dropAt := 0, 0, 0
	reset := func() {
		buf = buf[:0]
		started, sep, overlong, nl = false, false, false, 0
	}
	add := func(tok string, lineEnds int) {
		if overlong {
			return
		}
		if started && sep {
			buf = append(buf, ' ')
		}
		buf = append(buf, tok...)
		started, sep = true, false
		nl += lineEnds
		if len(buf) > maxStatementBytes || nl >= maxStatementLines {
			overlong, buf = true, buf[:0]
		}
	}
	kept := func() bool {
		if overlong || !started || dropAt != 0 {
			return false
		}
		w := firstWord(string(buf))
		return w != "" && ks.words[w]
	}
	for i := 0; i < len(text); {
		c := text[i]
		switch c {
		case ' ', '\t', '\f', '\v', '\r':
			sep = true
			i++
		case '\n':
			sep = true
			if started && !overlong {
				nl++
				if nl >= maxStatementLines {
					overlong, buf = true, buf[:0]
				}
			}
			i++
		case ';':
			if kept() {
				emit(string(buf) + ";")
			}
			reset()
			i++
		case '{':
			depth++
			switch {
			case kept() && depth <= maxBlockDepth:
				emit(string(buf) + " {")
			case dropAt == 0:
				dropAt = depth
			}
			reset()
			i++
		case '}':
			reset()
			if depth == 0 {
				emit("}")
			} else {
				if dropAt == 0 {
					emit("}")
				}
				if dropAt == depth {
					dropAt = 0
				}
				depth--
			}
			i++
		case '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
			sep = true
		case '"', '\'':
			j := i + 1
			for j < len(text) && text[j] != c {
				if text[j] == '\\' && j+1 < len(text) && (text[j+1] == c || text[j+1] == '\\') {
					j++
				}
				j++
			}
			if j < len(text) {
				j++
			}
			tok := text[i:j]
			ends := strings.Count(tok, "\n")
			add(strings.NewReplacer("\n", " ", "\r", " ").Replace(tok), ends)
			i = j
		default:
			j := i
			for j < len(text) {
				d := text[j]
				if d == ' ' || d == '\t' || d == '\f' || d == '\v' || d == '\r' || d == '\n' || d == ';' || d == '}' {
					break
				}
				if d == '{' {
					if j > i && text[j-1] == '$' {
						for j < len(text) && text[j] != '}' && text[j] != '\n' {
							j++
						}
						if j < len(text) && text[j] == '}' {
							j++
						}
						continue
					}
					break
				}
				j++
			}
			add(text[i:j], 0)
			i = j
		}
	}
}

// inspection is what the public rule learns from a window of a file. The
// remote programs compute the same fields on the host and return them.
type inspection struct {
	magic  []byte
	labels []string // valid labels in order, at most maxPEMLabels kept
	nLabel int      // how many valid labels there were in all
	// size is the whole file's size; truncated is size > the window.
	size      int64
	truncated bool

	nul          bool // a NUL byte anywhere in the window
	bad          bool // a BEGIN line that is not valid
	nonPublic    bool // a valid label not on the allowlist
	unterminated bool // a public block with no END before EOF or the next BEGIN
	private      bool // a BEGIN line not on the allowlist names private material
	outsideRun   bool // a long run outside every public block
	sshBad       bool // a non-blank, non-comment line outside blocks that is not a genuine SSH key line
	sshLines     int  // genuine SSH public key lines
	// utf16 is a UTF-16 byte-order mark; utf16Private a line of the file,
	// with NUL, 0xFE and 0xFF bytes removed, holding both BEGIN and PRIVATE.
	utf16, utf16Private bool
}

func isBlankOrComment(s string) bool {
	if strings.HasPrefix(s, "#") {
		return true
	}
	return strings.Trim(s, " \t") == ""
}

// utf16Scan decides utf16Private: remove the bytes a UTF-16 encoding of
// ASCII adds (NUL, and the BOM's 0xFE and 0xFF) and look for BEGIN and
// PRIVATE on one line, in any ASCII case.
func utf16Scan(b []byte) bool {
	clean := make([]byte, 0, len(b))
	for _, c := range b {
		if c != 0 && c != 0xFE && c != 0xFF {
			clean = append(clean, c)
		}
	}
	for _, line := range bytes.Split(clean, []byte{'\n'}) {
		u := asciiUpper(string(line))
		if strings.Contains(u, "BEGIN") && strings.Contains(u, "PRIVATE") {
			return true
		}
	}
	return false
}

// inspect applies the identification rule to b, a window of a file. size is
// the file's whole size.
func inspect(b []byte, size int64) inspection {
	in := inspection{size: size, truncated: size > int64(len(b))}
	if len(b) > 0 {
		in.magic = cloneBytes(b[:min(len(b), MagicBytes)])
	}
	in.nul = bytes.IndexByte(b, 0) >= 0
	if bytes.HasPrefix(b, []byte{0xFF, 0xFE}) || bytes.HasPrefix(b, []byte{0xFE, 0xFF}) {
		in.utf16 = true
		in.utf16Private = utf16Scan(b)
	}
	inPub := false
	for _, s := range pemLines(b) {
		if isBeginLine(s) {
			if inPub {
				in.unterminated = true
			}
			inPub = false
			label, ok := parseBeginLine(s)
			pub := ok && isPublicLabel(label)
			if !pub && namesPrivate(s) {
				in.private = true
			}
			if !ok {
				in.bad = true
				continue
			}
			in.nLabel++
			if len(in.labels) < maxPEMLabels {
				in.labels = append(in.labels, label)
			}
			if pub {
				inPub = true
			} else {
				in.nonPublic = true
			}
			continue
		}
		if inPub {
			if isEndLine(s) {
				inPub = false
			}
			continue
		}
		if hasLongRun(s) {
			in.outsideRun = true
		}
		if isBlankOrComment(s) {
			continue
		}
		if _, ok := sshKeyLine(s); ok {
			in.sshLines++
		} else {
			in.sshBad = true
		}
	}
	if inPub {
		in.unterminated = true
	}
	return in
}

// keystoreMagic reports the magic numbers that refuse a file as text whatever
// else it looks like.
func keystoreMagic(m []byte) bool {
	return bytes.HasPrefix(m, magicJKS) || bytes.HasPrefix(m, magicJCEKS) ||
		bytes.HasPrefix(m, magicKeytab2) || bytes.HasPrefix(m, magicKeytab1) || bytes.HasPrefix(m, magicSQLite)
}

// textRefused reports a file that is not text: a NUL or 0x01 byte anywhere
// (0x01 because the remote programs see a NUL as 0x01: `tr` maps it so that
// every awk sees it the same way), a UTF-16 byte-order mark, or a keystore's
// magic at the start or after a UTF-8 byte-order mark.
func textRefused(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 || bytes.IndexByte(b, 1) >= 0 {
		return true
	}
	if bytes.HasPrefix(b, []byte{0xFF, 0xFE}) || bytes.HasPrefix(b, []byte{0xFE, 0xFF}) {
		return true
	}
	if keystoreMagic(b[:min(len(b), MagicBytes)]) {
		return true
	}
	if r, ok := bytes.CutPrefix(b, utf8BOM); ok && keystoreMagic(r[:min(len(r), MagicBytes)]) {
		return true
	}
	return false
}
