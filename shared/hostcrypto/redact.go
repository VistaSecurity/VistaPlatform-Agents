package hostcrypto

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
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

// certificateLabels are the labels whose blocks may cross a remote
// connection, and then only as a host parser's re-encoding of the
// certificate they hold. Every other public label (a public key, a request,
// a revocation list, parameters) is allowed in a file, but its block never
// crosses.
var certificateLabels = []string{"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"}

func isCertificateLabel(l string) bool {
	for _, c := range certificateLabels {
		if l == c {
			return true
		}
	}
	return false
}

// derFirstElement returns the length of the first DER element of b: a
// SEQUENCE (0x30) with a definite length in short form or in one to four
// length bytes. ok is false for anything else, or when b is shorter.
func derFirstElement(b []byte) (int, bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return 0, false
	}
	l, hdr := int(b[1]), 2
	if l >= 0x80 {
		n := l - 0x80
		if n < 1 || n > 4 || len(b) < 2+n {
			return 0, false
		}
		l = 0
		for _, c := range b[2 : 2+n] {
			l = l<<8 | int(c)
		}
		hdr += n
	}
	if l < 0 || hdr+l > len(b) {
		return 0, false
	}
	return hdr + l, true
}

// certificateDER is the parser step of the public rule: the DER a block's
// body decodes to, parsed as ONE certificate and re-encoded. A TRUSTED
// CERTIFICATE carries OpenSSL's trust settings after the certificate, so its
// first element is taken; any other label must be exactly one certificate.
// What is returned is cert.Raw, the parser's certificate, never the block.
func certificateDER(label string, body []string) ([]byte, bool) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(body, ""))
	if err != nil {
		return nil, false
	}
	if label == "TRUSTED CERTIFICATE" {
		n, ok := derFirstElement(der)
		if !ok {
			return nil, false
		}
		der = der[:n]
	}
	if !certEnvelope(der) {
		return nil, false
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}
	// The envelope, rebuilt from the parser's own TBS and the algorithm and
	// signature that follow it, must be the input exactly: nothing beside
	// the three elements, nothing hidden in a length.
	in := cryptobyte.String(der)
	var outer cryptobyte.String
	var alg, sig []byte
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) || !outer.Skip(len(c.RawTBSCertificate)) {
		return nil, false
	}
	alg, sig = derNext(&outer), derNext(&outer)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(c.RawTBSCertificate)
		b.AddBytes(alg)
		b.AddBytes(sig)
	})
	rebuilt, err := b.Bytes()
	if err != nil || !bytes.Equal(rebuilt, der) || !bytes.Equal(c.Raw, der) {
		return nil, false
	}
	return c.Raw, true
}

// derNext reads the next whole DER element of s, or nil.
func derNext(s *cryptobyte.String) []byte {
	var e cryptobyte.String
	if !s.ReadAnyASN1Element(&e, nil) {
		return nil
	}
	return e
}

// certEnvelope is the strict DER envelope of a certificate, checked before
// any parser sees it, the same on every host (vDer in the PowerShell): a
// SEQUENCE with a definite, minimal length equal to the rest of the input,
// holding exactly a SEQUENCE (the TBS), a SEQUENCE (the algorithm) and a BIT
// STRING (the signature), each with a definite, minimal length, and nothing
// after them. A fourth element, a long-form or indefinite length, or a
// trailing byte is refused: .NET hands back its input verbatim as RawData,
// and Go's parser takes the certificate's Raw as the outer element, so
// either would let a key appended inside the envelope cross.
// cryptobyte's ReadASN1 refuses any length that is not minimal DER.
func certEnvelope(der []byte) bool {
	in := cryptobyte.String(der)
	var outer, tbs, alg cryptobyte.String
	var sig cryptobyte.String
	if !in.ReadASN1(&outer, cbasn1.SEQUENCE) || !in.Empty() {
		return false
	}
	return outer.ReadASN1Element(&tbs, cbasn1.SEQUENCE) && outer.ReadASN1Element(&alg, cbasn1.SEQUENCE) &&
		outer.ReadASN1Element(&sig, cbasn1.BIT_STRING) && outer.Empty()
}

// certificatePEM is the canonical PEM of a certificate's DER: the label
// CERTIFICATE and 64-character lines, as openssl, PowerShell and Go all
// write it.
func certificatePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

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

// publicContent is the remote ReadFile rule: the CERTIFICATES of b, each as
// a parser's re-encoding (certificateDER), and its genuine OpenSSH public
// key lines, and NOTHING else: no text before, between or after them, no
// options, no comments, no other block.
//
// No pattern over a block's bytes can tell a certificate from a private key
// written under a certificate's label (a first body line of a few
// characters, an unencrypted PKCS#12, a long-form length all defeated one),
// so a block crosses only after a certificate parser on the host has parsed
// it, and what crosses is the parser's output. On a remote host the parser
// is openssl (Unix) or .NET's X509Certificate2 after GetCertContentType says
// Cert (Windows); here it is crypto/x509.
//
//   - A block runs from a valid BEGIN line with a label on the allowlist to
//     the matching END line; every body line must be 1 to 76 base64
//     characters, or the whole block is dropped. An unterminated block, or
//     one cut by another BEGIN or a different END, is dropped.
//   - Only a five-dash block labelled CERTIFICATE, X509 CERTIFICATE or
//     TRUSTED CERTIFICATE can cross, and only when it parses; one that does not is
//     dropped. Every other allowlisted block is dropped.
//   - A NUL byte anywhere, a BEGIN line that is not valid, or a valid label
//     off the allowlist refuses the whole file (ok false).
//   - No certificate and no key line refuses the file.
//
// A DER certificate file is not readable remotely: it has no PEM frame. The
// local collector parses DER in memory.
//
// Each certificate is returned as CERTIFICATE PEM with 64-character lines,
// each key line as "type blob\n". A leading UTF-8 byte-order mark is
// tolerated.
func publicContent(b []byte) ([]byte, bool) {
	out, _, ok := publicContentCount(b)
	return out, ok
}

// publicContentCount is publicContent with the number of certificate blocks
// the parser refused.
func publicContentCount(b []byte) ([]byte, int, bool) {
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, 0, false
	}
	var out strings.Builder
	var body []string
	inBlock, blockOK := false, false
	var endLine, label string
	refused := 0
	for _, s := range pemLines(b) {
		if isBeginLine(s) {
			// A BEGIN line ends any open block (it is dropped, unterminated).
			l, ok := parseBeginLine(s)
			if !ok || !isPublicLabel(l) {
				return nil, 0, false
			}
			inBlock, blockOK, body, label = true, true, nil, l
			if strings.HasPrefix(s, "-----") {
				endLine = "-----END " + l + "-----"
			} else {
				endLine = "---- END " + l + " ----"
			}
			continue
		}
		if inBlock {
			if s == endLine {
				inBlock = false
				if !blockOK || !isCertificateLabel(label) || !strings.HasPrefix(endLine, "-----") {
					continue
				}
				if der, ok := certificateDER(label, body); ok {
					out.WriteString(certificatePEM(der))
				} else {
					refused++
				}
				continue
			}
			if isEndLine(s) {
				inBlock = false
				continue
			}
			if !isPEMBodyLine(s) {
				blockOK = false
			}
			body = append(body, s)
			continue
		}
		if k, ok := sshKeyLine(s); ok {
			out.WriteString(k + "\n")
		}
	}
	if out.Len() == 0 {
		return nil, refused, false
	}
	return []byte(out.String()), refused, true
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
	// KeepOptSections makes a "[name]" header structure when name is in
	// keep (krb5, GnuTLS); KeepOptAnySections does for any name of the
	// header shape (OpenSSL, whose section names the file chooses). With
	// either, a header that does not cross drops its whole section.
	KeepOptSections    = "@sections"
	KeepOptAnySections = "@anysections"
	// KeepOptTags makes "</Name>" structure when Name is in keep, and drops
	// a dropped "<Name ...>" through its matching "</Name>" (Apache).
	KeepOptTags = "@tags"
)

// maxConfigOutput bounds what a configuration read returns: over it the
// read is ErrFileTooLarge. 6,000,000 bytes is what fits the runner's 8 MiB
// output once a Windows host base64-encodes it; @statements output can be
// larger than its input ("a;" becomes "a;\n").
const maxConfigOutput = 6000000

// maxPhysicalLine bounds one physical line (the bytes between two line
// feeds, after a leading byte-order mark): a longer one makes the read
// ErrFileTooLarge before anything is tokenised. busybox and macOS awk took
// past the 90-second command timeout over a 5.9 MB one-line nginx file; at
// this bound every awk answers in seconds. No parser reads a logical line
// past 64 KiB.
const maxPhysicalLine = 256 << 10

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
	words                                  map[string]bool
	statements, backslash, indent, cr      bool
	sections, anySections, tags, badOption bool
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
			case KeepOptSections:
				k.sections = true
			case KeepOptAnySections:
				k.anySections = true
			case KeepOptTags:
				k.tags = true
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

// endsInBackslash reports a line whose last byte is a backslash.
func endsInBackslash(s string) bool { return strings.HasSuffix(s, `\`) }

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

// ruleLines splits a file for the rule: a leading UTF-8 byte-order mark is
// removed; "\n" ends a line, and one "\r" before it is part of the line end.
// A lone "\r" left inside a line ends it when split is set (@cr, Java
// properties); otherwise it stays in the line, for the mode to deal with: a
// line-mode line holding one is dropped whole, and to @statements it is a
// blank, as it is to nginx. A final empty segment (the file ends in "\n") is
// not a line. ok is false past maxConfigLines.
func ruleLines(b []byte, split bool) ([]string, bool) {
	b = bytes.TrimPrefix(b, utf8BOM)
	var out []string
	for len(b) > 0 {
		var seg []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			seg, b = b[:i], b[i+1:]
		} else {
			seg, b = b, nil
		}
		if len(seg) > maxPhysicalLine {
			return nil, false
		}
		seg = bytes.TrimSuffix(seg, []byte{'\r'})
		if split {
			for _, p := range bytes.Split(seg, []byte{'\r'}) {
				out = append(out, string(p))
			}
		} else {
			out = append(out, string(seg))
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

// sectionName returns the name of a trimmed line of the header shape
// ^\[[ \t]*[A-Za-z0-9_.-]{1,64}[ \t]*\]$, lower-cased.
func sectionName(tr string) (string, bool) {
	if len(tr) < 3 || tr[0] != '[' || tr[len(tr)-1] != ']' {
		return "", false
	}
	name := strings.Trim(tr[1:len(tr)-1], " \t")
	if name == "" || len(name) > 64 {
		return "", false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !isASCIIAlnum(c) && c != '_' && c != '.' && c != '-' {
			return "", false
		}
	}
	return asciiLower(name), true
}

// isHeaderLike is a trimmed line that a section syntax would read as a
// header: "[" ... "]".
func isHeaderLike(tr string) bool {
	return len(tr) >= 2 && tr[0] == '[' && tr[len(tr)-1] == ']'
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
// an unusable keep, more than 200,000 lines or more than 6,000,000 bytes of
// output; the targets turn the last two into ErrFileTooLarge).
//
// keep holds lower-case ASCII directive names, compared with a line's first
// word without regard to ASCII case, and options, which begin with "@":
// [KeepOptStatements], [KeepOptBackslash], [KeepOptIndent], [KeepOptCR],
// [KeepOptSections], [KeepOptAnySections], [KeepOptTags]. A keep with no
// name, or with an unknown option, is refused.
//
//  1. Not text — a NUL or 0x01 byte anywhere, a UTF-16 byte-order mark, or a
//     keystore's magic (at the start, or after a UTF-8 byte-order mark) — is
//     refused. A UTF-8 byte-order mark is removed; a file that is only one
//     yields nothing.
//  2. Lines end at "\n" and "\r\n". A lone "\r" ends a line with @cr and
//     is a blank to @statements; in any other line it DROPS THE LINE WHOLE,
//     and that line neither starts nor continues a continuation (it is a
//     dropped logical line), so what follows the "\r" never crosses and a
//     backslash before it continues nothing.
//  3. Line mode (no @statements). Comment lines (first non-blank "#", "!",
//     ";" or "//") are dropped. Structure is kept and is strict: a blank
//     line; a lone "}" or "};"; a lone "{" only directly after a kept line
//     (blank and comment lines between do not count); with @sections a
//     header "[name]" (name [A-Za-z0-9_.-]{1,64}, blanks around it) whose
//     name is in keep, with @anysections any such header; with @tags a
//     closing tag "</Name>" whose Name is in keep. A header-like line ("["
//     ... "]") under a section option that does not cross drops its whole
//     section, to the next header that does. Any other line is KEPT when
//     its first word (firstWord) is in keep, else DROPPED. A dropped line
//     that ends in "{" drops everything to its matching "}" (a line starting
//     with "}" closes one level, one ending in "{" opens one, comment lines
//     do not count); with @tags a dropped opening tag ("<Name ...>") drops
//     everything to its matching "</Name>". There is no continuation without
//     an option. With @backslash a kept line ending in an odd number of
//     backslashes continues onto the next line, and a DROPPED line ending in
//     any backslash drops the lines that continue it (a dropped line's
//     continuation is never read as a line of its own); with @indent a line
//     beginning with a blank continues the previous logical line, kept iff
//     that was kept, and blank and comment lines between do not end it.
//     Inside a continuation only "#" starts a comment line (a Postfix value
//     may begin with "!"); it is dropped. A kept logical line has at most 32
//     continuation lines; the rest are dropped.
//  4. @statements: the text is read as statements, honouring single and
//     double quotes (a backslash escapes the quote or a backslash inside
//     them), a backslash outside quotes (it makes the next byte part of the
//     word, so "\;" and "\}" end nothing, as in nginx), "${name}" variables
//     (any other "${" is a "$" and a block opener) and "#" comments,
//     as the nginx parser tokenises: a statement ends at ";", or at "{" (it
//     opens a block), and "}" closes a block. A statement is kept iff its
//     first word is in keep; a block opener likewise, and a dropped opener
//     drops its whole block. A statement over 16 KiB or 64 lines is dropped.
//     The output is canonical: one statement per line, its words joined by
//     one blank (comments and line ends between them gone, a line end
//     inside quotes a blank), ending in ";"; an opener as "<words> {"; a
//     closer as "}".
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
	lines, ok := ruleLines(b, ks.cr && !ks.statements)
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
	if len(out) > maxConfigOutput {
		return nil, 0, configTooManyLines
	}
	return out, n, configOK
}

// filterLines is the line mode of filterConfig (rule 3).
func filterLines(lines []string, ks keepSet, emit func(string)) {
	var (
		dropTag     string // the tag of a dropped tag block
		dropBrace   bool   // a dropped brace block is open
		dropDepth   int
		dropSection bool // inside a section whose header did not cross
		prevKept    bool // the last line that was neither blank nor a comment was kept by its word
		bsCont      bool // @backslash: this line continues a kept line
		dropCont    bool // @backslash: this line continues a dropped line
		contN       int  // continuation lines of the current logical line
		haveLogical bool // @indent: a logical line has started
		logicalKept bool
	)
	withSections := ks.sections || ks.anySections
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
		tr := strings.TrimRight(t, " \t")
		header := withSections && isHeaderLike(tr) && !strings.Contains(s, "\r")
		if dropSection && !header {
			continue
		}
		if strings.IndexByte(s, '\r') >= 0 {
			// A lone CR: the line is dropped whole, ends any continuation and
			// starts none; it is a dropped logical line.
			bsCont, dropCont, prevKept = false, false, false
			haveLogical, logicalKept, contN = true, false, 0
			if withSections && strings.HasPrefix(tr, "[") {
				dropSection = true // an unlisted header: drop its section
				continue
			}
			if tr != "" && tr[len(tr)-1] == '{' {
				dropBrace, dropDepth = true, 1
			} else if name, ok := openingTag(tr); ok && ks.tags {
				dropTag, dropDepth = name, 1
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
		if dropCont {
			dropCont = endsInBackslash(s)
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
		if header {
			name, ok := sectionName(tr)
			dropSection = !ok || (!ks.anySections && !ks.words[name])
			if !dropSection {
				emit(s)
			}
			prevKept = false
			continue
		}
		if name, ok := closingTag(tr); ok && ks.tags && ks.words[name] {
			emit(s)
			prevKept = false
			continue
		}
		if tr == "}" || tr == "};" || (tr == "{" && prevKept) {
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
		switch {
		case ks.backslash && endsInBackslash(s):
			dropCont = true
		case tr[len(tr)-1] == '{':
			dropBrace, dropDepth = true, 1
		default:
			if name, ok := openingTag(tr); ok && ks.tags {
				dropTag, dropDepth = name, 1
			}
		}
	}
}

// filterStatements is the @statements mode of filterConfig (rule 4). The
// tokens are those of the nginx parser (cfgNgxTokens), with nginx's escapes:
// blanks (a lone "\r" among them) and line ends separate words; "#" at the
// start of a token comments to the end of the line; a quote at the start of
// a token opens a quoted word, in which a backslash before the quote or a
// backslash is an escape; outside quotes a backslash makes the next byte
// part of the word; inside a word, "${name}" (name [A-Za-z0-9_]+) is a
// variable and part of the word, and any other "{" opens a block, so a ";"
// inside "${...}" still ends its statement.
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
				if d == '\\' && j+1 < len(text) && text[j+1] != '\n' {
					j += 2 // an escaped byte is part of the word, whatever it is
					continue
				}
				if d == ' ' || d == '\t' || d == '\f' || d == '\v' || d == '\r' || d == '\n' || d == ';' || d == '}' {
					break
				}
				if d == '{' {
					// "${name}" is a variable, part of the word; any other
					// "{" opens a block, so "${x;}" cannot hide a ";".
					if j > i && text[j-1] == '$' {
						k := j + 1
						for k < len(text) && (isASCIIAlnum(text[k]) || text[k] == '_') {
							k++
						}
						if k > j+1 && k < len(text) && text[k] == '}' {
							j = k + 1
							continue
						}
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
