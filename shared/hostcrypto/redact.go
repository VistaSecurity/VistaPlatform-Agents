package hostcrypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
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
// begin with its type's encoded name and be within the length bounds:
// exact for Ed25519 and each ECDSA curve, a 16384-bit modulus for RSA, and
// generous but finite for security keys and certificates.
var sshKeyTypes = func() []sshKeyType {
	types := []sshKeyType{
		{name: "ssh-ed25519", minLen: 68, maxLen: 68},
		{name: "ecdsa-sha2-nistp256", minLen: 140, maxLen: 140},
		{name: "ecdsa-sha2-nistp384", minLen: 184, maxLen: 184},
		{name: "ecdsa-sha2-nistp521", minLen: 232, maxLen: 232},
		{name: "ssh-rsa", minLen: 100, maxLen: 2844},
		{name: "ssh-dss", minLen: 100, maxLen: 2000},
		{name: "sk-ssh-ed25519@openssh.com", minLen: 96, maxLen: 600},
		{name: "sk-ecdsa-sha2-nistp256@openssh.com", minLen: 160, maxLen: 700},
		{name: "ssh-ed25519-cert-v01@openssh.com", minLen: 100, maxLen: 16384},
		{name: "ssh-rsa-cert-v01@openssh.com", minLen: 100, maxLen: 16384},
		{name: "ecdsa-sha2-nistp256-cert-v01@openssh.com", minLen: 100, maxLen: 16384},
		{name: "ecdsa-sha2-nistp384-cert-v01@openssh.com", minLen: 100, maxLen: 16384},
		{name: "ecdsa-sha2-nistp521-cert-v01@openssh.com", minLen: 100, maxLen: 16384},
		{name: "sk-ssh-ed25519-cert-v01@openssh.com", minLen: 100, maxLen: 16384},
		{name: "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", minLen: 100, maxLen: 16384},
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

// sshKeyLine finds a genuine OpenSSH public key in a line ("[options] type
// blob [comment]", authorized_keys or .pub): the first token that names a
// known type, and the token after it, whose base64 must begin with that
// type's encoded name and fit its length bounds. It returns "type blob" only:
// options and comment never.
func sshKeyLine(s string) (string, bool) {
	tok := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
	for i := 0; i+1 < len(tok); i++ {
		t, ok := findSSHKeyType(tok[i])
		if !ok {
			continue
		}
		b := tok[i+1]
		if isSSHBlob(b) && len(b) >= t.minLen && len(b) <= t.maxLen && strings.HasPrefix(b, t.prefix) {
			return t.name + " " + b, true
		}
		return "", false
	}
	return "", false
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

// keepSet is the caller's directive allowlist, lower-cased once. A word
// written with a trailing ";" ("ssl_protocols;") is a directive that runs to
// the next ";", across lines.
type keepSet struct {
	words map[string]bool
	semi  map[string]bool
}

func newKeepSet(keep []string) keepSet {
	k := keepSet{words: map[string]bool{}, semi: map[string]bool{}}
	for _, w := range keep {
		w = asciiLower(w)
		semi := strings.HasSuffix(w, ";")
		w = strings.TrimSuffix(w, ";")
		if w == "" {
			continue
		}
		k.words[w] = true
		if semi {
			k.semi[w] = true
		}
	}
	return k
}

// firstWord is a configuration line's directive name: leading blanks
// removed, a leading "<" (an opening tag) and a leading "-D" (a JVM option)
// removed, then the longest prefix without a blank, '=', ':', ';', '{' or
// '}', a trailing '>' removed, lower-cased.
func firstWord(t string) string {
	t = strings.TrimPrefix(t, "<")
	t = strings.TrimPrefix(t, "-D")
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

// endsWithBackslash reports a line whose last non-blank byte is '\'.
func endsWithBackslash(s string) bool {
	s = strings.TrimRight(s, " \t")
	return strings.HasSuffix(s, `\`)
}

// FilterConfigText is [Target.ReadText]'s rule, applied by every target (on
// the host, for a remote one, by a program that mirrors this function line
// for line). It returns the lines of b a parser asked for, redacted, and how
// many redactions it made; ok is false when the file must be refused (not
// text, an empty keep, or more than 200,000 lines; the targets turn the last
// into ErrFileTooLarge).
//
//  1. Not text — a NUL or 0x01 byte anywhere, or a keystore's magic — is
//     refused. A leading UTF-8 byte-order mark is removed. "\r\n", "\n" and a
//     lone "\r" all end a line; every returned line ends in "\n".
//  2. keep is lower-cased; an entry with a trailing ";" names a directive
//     that runs to the next ";" (nginx). An empty keep is refused.
//  3. A line is KEPT when its first word (see firstWord) is in keep; when it
//     is structure — blank, a "[section]" header, only "{", "}" or "};", or
//     a closing tag "</...>"; or when it continues a kept line (the kept
//     line ended with "\", or its directive runs to ";" and the line had
//     none yet). Comment lines (first non-blank "#", "!", ";" or "//") are
//     dropped, as is every other line. Opening tags and block openers
//     ("<VirtualHost ...>", "server {", "Match ...") are ordinary words the
//     caller must list.
//  4. Of the kept lines, every PEM block (any label) is dropped and every run
//     of [RedactRunLength] or more [A-Za-z0-9+/=] is replaced by
//     [RedactedMarker]; each counts one redaction.
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
	if len(ks.words) == 0 {
		return nil, 0, configNoKeep
	}
	if textRefused(b) {
		return nil, 0, configNotText
	}
	lines := configLines(b)
	if len(lines) > maxConfigLines {
		return nil, 0, configTooManyLines
	}
	out := make([]byte, 0, len(b)/4)
	n := 0
	cont, contSemi := false, false
	drop := false
	keepLine := func(s string) {
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
	for _, s := range lines {
		if cont {
			keepLine(s)
			if contSemi {
				cont = !strings.Contains(s, ";")
			} else {
				cont = endsWithBackslash(s)
			}
			continue
		}
		t := strings.TrimLeft(s, " \t")
		if t == "" {
			keepLine(s)
			continue
		}
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "!") || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "//") {
			continue
		}
		tr := strings.TrimRight(t, " \t")
		if strings.HasPrefix(tr, "[") && strings.HasSuffix(tr, "]") || tr == "{" || tr == "}" || tr == "};" || strings.HasPrefix(t, "</") {
			keepLine(s)
			continue
		}
		w := firstWord(t)
		if w == "" || !ks.words[w] {
			continue
		}
		keepLine(s)
		switch {
		case endsWithBackslash(s):
			cont, contSemi = true, false
		case ks.semi[w] && !strings.Contains(s, ";"):
			cont, contSemi = true, true
		}
	}
	return out, n, configOK
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
// every awk sees it the same way), or a keystore's magic.
func textRefused(b []byte) bool {
	return bytes.IndexByte(b, 0) >= 0 || bytes.IndexByte(b, 1) >= 0 || keystoreMagic(b[:min(len(b), MagicBytes)])
}
