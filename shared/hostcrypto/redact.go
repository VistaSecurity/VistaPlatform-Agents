package hostcrypto

import (
	"bytes"
	"strings"
)

// The text rules: what makes a file public, and how a configuration file is
// redacted. They are defined HERE, once, in Go, and mirrored line for line by
// the programs that run on remote hosts (the awk program in
// target_remote_unix.go, the PowerShell in target_remote_win.go). Parity
// tests run the awk program for real over a corpus and require identical
// answers; change one side and they fail.
//
// Both rules are line rules. A line is the bytes up to "\n"; one trailing
// "\r" is ignored for matching (CRLF files) but kept in the output. Every
// comparison is on ASCII bytes, so the remote programs can work on a Latin-1
// or C-locale view of any file and agree with Go byte for byte.
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

// redactClass reports the bytes a redacted run is made of: base64, which
// includes hexadecimal.
func redactClass(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
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

// isLabelByte is [A-Z0-9 -].
func isLabelByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '-'
}

// isKeyTypeByte is [a-z0-9@.-].
func isKeyTypeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '@' || c == '.' || c == '-'
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
		c := label[i]
		if !isLabelByte(c) {
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

// forEachLine calls fn for every line of b: content without "\n", and whether
// a "\n" ended it. A final empty segment (b ends in "\n") is not a line.
func forEachLine(b []byte, fn func(line []byte, nl bool)) {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			fn(b, false)
			return
		}
		fn(b[:i], true)
		b = b[i+1:]
	}
}

// isSSHPublicKeyLine reports an OpenSSH public key line: a key type
// ("ssh-...", "ecdsa-sha2-...", "sk-..." of [a-z0-9@.-]), one space, a base64
// blob, and optionally one space and a comment without a long run.
func isSSHPublicKeyLine(s string) bool {
	i := strings.IndexByte(s, ' ')
	if i < 1 {
		return false
	}
	typ := s[:i]
	if !strings.HasPrefix(typ, "ssh-") && !strings.HasPrefix(typ, "ecdsa-sha2-") && !strings.HasPrefix(typ, "sk-") {
		return false
	}
	for j := 0; j < len(typ); j++ {
		c := typ[j]
		if !isKeyTypeByte(c) {
			return false
		}
	}
	rest := s[i+1:]
	blob, comment := rest, ""
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		blob, comment = rest[:j], rest[j+1:]
	}
	k := 0
	for k < len(blob) && blob[k] != '=' {
		if c := blob[k]; c == '=' || !redactClass(c) {
			return false
		}
		k++
	}
	if k == 0 {
		return false
	}
	for ; k < len(blob); k++ {
		if blob[k] != '=' {
			return false
		}
	}
	return !hasLongRun(comment)
}

// isBlankOrComment is a line the SSH public key rule skips.
func isBlankOrComment(s string) bool {
	if strings.HasPrefix(s, "#") {
		return true
	}
	return strings.Trim(s, " \t") == ""
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
	sshBad       bool // a non-blank, non-comment line that is not an SSH public key line
	sshLines     int  // SSH public key lines
}

// inspect applies the public rule to b, a window of a file. size is the
// file's whole size.
func inspect(b []byte, size int64) inspection {
	in := inspection{size: size, truncated: size > int64(len(b))}
	if len(b) > 0 {
		in.magic = cloneBytes(b[:min(len(b), MagicBytes)])
	}
	in.nul = bytes.IndexByte(b, 0) >= 0
	inPub := false
	forEachLine(b, func(line []byte, _ bool) {
		s := strings.TrimSuffix(string(line), "\r")
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
				return
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
			return
		}
		if inPub {
			if isEndLine(s) {
				inPub = false
			}
			return
		}
		if hasLongRun(s) {
			in.outsideRun = true
		}
		if isBlankOrComment(s) {
			return
		}
		if isSSHPublicKeyLine(s) {
			in.sshLines++
		} else {
			in.sshBad = true
		}
	})
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

// textRefused reports a file ReadText must refuse as not text: a NUL byte
// anywhere (stricter than the first 8 KiB, so every implementation can treat
// the rest of the file as lines), or a keystore's magic.
func textRefused(b []byte) bool {
	return bytes.IndexByte(b, 0) >= 0 || keystoreMagic(b[:min(len(b), MagicBytes)])
}

// RedactText applies [Target.ReadText]'s redaction to b and counts what it
// removed: every PEM block whose BEGIN line is not a valid line with a label
// on the public allowlist is dropped, BEGIN to END inclusive (an unterminated
// one to the end of the file; one counted per block), and every run of
// [RedactRunLength] or more characters of [A-Za-z0-9+/=] is replaced by
// [RedactedMarker] (one counted per run). Line endings, including a missing
// final newline, are kept. It is pure; refusing a file that is not text is
// the caller's.
//
// Applying it to its own output changes nothing and counts nothing, which is
// how a target checks a host's redaction after the bytes arrive.
func RedactText(b []byte) ([]byte, int) {
	out := make([]byte, 0, len(b))
	n := 0
	inDrop := false
	forEachLine(b, func(line []byte, nl bool) {
		s := strings.TrimSuffix(string(line), "\r")
		if inDrop {
			if isEndLine(s) {
				inDrop = false
			}
			return
		}
		if isBeginLine(s) {
			if label, ok := parseBeginLine(s); !ok || !isPublicLabel(label) {
				n++
				// A one-line block (BEGIN and END on one line) ends here.
				inDrop = !isEndLine(s)
				return
			}
		}
		red, k := redactRuns(string(line))
		n += k
		out = append(out, red...)
		if nl {
			out = append(out, '\n')
		}
	})
	return out, n
}
