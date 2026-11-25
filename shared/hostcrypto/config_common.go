package hostcrypto

import (
	"bytes"
	"sort"
	"strings"
	"unicode/utf8"
)

// Configuration parsers: one pure function per product, bytes in,
// []CryptoConfig out. The rules every one of them follows, and why:
//
//   - ALLOWLIST, NEVER PATTERN. A parser keeps a fixed, named set of
//     directives and drops everything else. A directive whose value is a
//     secret (a password, a pre-shared key, a passphrase, a token, a PKCS#11
//     PIN) is never on the list, whatever its name says: `ssl_password_file`,
//     `SSLPassPhraseDialog`, `javax.net.ssl.keyStorePassword`, `ca-sign-pass`
//     are all dropped, not "kept in redacted form". A reader of a report must
//     never be able to ask whether a secret is in it.
//   - No file is opened, no command run, no include followed. An include
//     becomes a [ConfigReference] of Kind "include" and the collector reads
//     it, so every file the collector touches goes through its Target.
//   - Everything is bounded: a value is cut at 4096 characters, a list at 256
//     items, a file at 200,000 lines, and a logical line at 64 KiB before it
//     is parsed, so a hostile file costs a bounded amount and cannot make the
//     report unbounded.
//   - Location is left zero; the caller knows the path.
//   - A directive is reported as the file says it. Nothing is invented: a
//     default the product would apply is not filled in, so an absent field
//     means "not stated here", never "off".

// IncludedFile is one file an include directive named.
type IncludedFile struct {
	Path string
	Text []byte
}

// IncludeResolver returns the files an include pattern names, in the order
// the product reads them (sorted for a glob). A nil resolver means "do not
// follow includes": the parser then only records each include as a
// ConfigReference of Kind "include". The parser never opens a file itself;
// the collector's resolver reads through its Target.
//
// maxBytes is how much the parser can still take of the 16 MiB budget for this
// root file: a resolver that reads through a Target should refuse to read
// more than that in total. What a resolver returns beyond the budget is
// dropped and counted, so a resolver that ignores maxBytes still cannot make
// the parser hold more.
type IncludeResolver func(pattern string, maxBytes int64) []IncludedFile

// ConfigParser parses one product's configuration file. include may be nil.
type ConfigParser func(b []byte, include IncludeResolver) []CryptoConfig

// cfgParsers is the registry, by the product name the caller selects on.
var cfgParsers = map[string]ConfigParser{
	"openssl":         cfgParseOpenSSL,
	"java":            cfgParseJava,
	"java-options":    cfgParseJavaOptions,
	"sshd":            cfgParseSSHD,
	"ssh":             cfgParseSSHClient,
	"nginx":           cfgParseNginx,
	"apache":          cfgParseApache,
	"haproxy":         cfgParseHAProxy,
	"crypto-policies": cfgParseCryptoPoliciesConfig,
	"krb5":            cfgParseKrb5,
	"gnutls":          cfgParseGnuTLS,
	"postfix":         cfgParsePostfix,
}

// ConfigParserFor returns the parser for a product name ("openssl", "java",
// "sshd", "ssh", "nginx", "apache", "haproxy", "crypto-policies", "krb5",
// "gnutls", "postfix", and "java-options" for a JVM command line), or nil.
func ConfigParserFor(product string) ConfigParser {
	return cfgParsers[product]
}

// ConfigProducts lists the products with a parser, sorted.
func ConfigProducts() []string {
	out := make([]string, 0, len(cfgParsers))
	for k := range cfgParsers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Bounds. See the comment at the top of the file.
const (
	cfgMaxValue       = 4096
	cfgMaxList        = 256
	cfgMaxLines       = 200000
	cfgMaxLogicalLine = 64 << 10
	cfgMaxSettings    = 256
	cfgMaxRefs        = 256
	cfgMaxFields      = 1024
)

// cfgLine is one logical line and the 1-based number of its first physical
// line.
type cfgLine struct {
	n    int
	text string
}

// cfgLogicalLines splits b into logical lines: a UTF-8 byte order mark is
// dropped, CRLF and LF both end a line, NUL bytes are removed, and at most
// cfgMaxLines physical lines are read. With continuation set, a line ending
// in an odd number of backslashes continues on the next, whose leading blanks
// are dropped. A comment line (first non-blank byte in comments) never
// continues, so a "# see \" does not swallow the directive after it.
func cfgLogicalLines(b []byte, comments string, continuation bool) []cfgLine {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	var out []cfgLine
	var cur []byte
	startN := 0
	continuing := false
	n := 0
	for pos := 0; pos <= len(b) && n < cfgMaxLines; n++ {
		var raw []byte
		if i := bytes.IndexByte(b[pos:], '\n'); i >= 0 {
			raw, pos = b[pos:pos+i], pos+i+1
		} else {
			raw, pos = b[pos:], len(b)+1
		}
		raw = bytes.TrimRight(raw, "\r")
		if len(raw) > cfgMaxLogicalLine {
			raw = raw[:cfgMaxLogicalLine]
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			raw = bytes.ReplaceAll(raw, []byte{0}, nil)
		}
		if continuing {
			raw = bytes.TrimLeft(raw, " \t")
		} else {
			startN = n + 1
			cur = cur[:0]
		}
		if continuation && endsInContinuation(raw) && (continuing || !cfgIsCommentLine(raw, comments)) {
			raw = raw[:len(raw)-1]
			if len(cur)+len(raw) <= cfgMaxLogicalLine {
				cur = append(cur, raw...)
			}
			continuing = true
			continue
		}
		if len(cur)+len(raw) <= cfgMaxLogicalLine {
			cur = append(cur, raw...)
		}
		continuing = false
		out = append(out, cfgLine{n: startN, text: string(cur)})
	}
	if continuing {
		out = append(out, cfgLine{n: startN, text: string(cur)})
	}
	return out
}

func endsInContinuation(raw []byte) bool {
	k := 0
	for i := len(raw) - 1; i >= 0 && raw[i] == '\\'; i-- {
		k++
	}
	return k%2 == 1
}

func cfgIsCommentLine(raw []byte, comments string) bool {
	t := bytes.TrimLeft(raw, " \t")
	return len(t) > 0 && strings.IndexByte(comments, t[0]) >= 0
}

// cfgStripHash cuts a trailing "#" comment that is outside quotes.
func cfgStripHash(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#':
			return s[:i]
		}
	}
	return s
}

// cfgUnquote trims blanks and one pair of matching quotes. An unterminated
// quote loses only its opening mark.
func cfgUnquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 1 && (s[0] == '"' || s[0] == '\'') {
		if len(s) >= 2 && s[len(s)-1] == s[0] {
			return s[1 : len(s)-1]
		}
		return s[1:]
	}
	return s
}

// cfgFields splits a line into words on blanks, honouring single and double
// quotes (a quote closes only its own kind; inside double quotes \" and \\
// are escapes). An unterminated quote runs to the end of the line. With hash
// set, a "#" that starts a word ends the line.
func cfgFields(s string, hash bool) []string {
	var out []string
	var cur []byte
	in := false
	var q byte
	flush := func() {
		if in {
			out = append(out, string(cur))
			cur = cur[:0]
			in = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == '\\' && q == '"' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				cur = append(cur, s[i+1])
				i++
				continue
			}
			if c == q {
				q = 0
				continue
			}
			cur = append(cur, c)
			continue
		}
		switch {
		case c == '"' || c == '\'':
			q = c
			in = true
		case c == ' ' || c == '\t' || c == '\f' || c == '\v' || c == '\r':
			flush()
		case c == '#' && hash && !in:
			flush()
			return out
		default:
			cur = append(cur, c)
			in = true
		}
		if len(out) >= cfgMaxFields {
			return out
		}
	}
	flush()
	return out
}

// cfgClip bounds a value: valid UTF-8, at most cfgMaxValue bytes, and ending
// at the first control character other than a tab. A "\r" or a "\x01" inside
// a value is a line end for some reader, so what follows it is not this
// value's to keep.
func cfgClip(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			s = s[:i]
			break
		}
	}
	if len(s) > cfgMaxValue {
		s = s[:cfgMaxValue]
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

// cfgSplitList splits on any byte in seps, trims blanks, drops empties and
// bounds the list and every item.
func cfgSplitList(s, seps string) []string {
	var out []string
	for len(s) > 0 && len(out) < cfgMaxList {
		i := strings.IndexAny(s, seps)
		var item string
		if i < 0 {
			item, s = s, ""
		} else {
			item, s = s[:i], s[i+1:]
		}
		item = cfgClip(strings.TrimSpace(item))
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// cfgAppend adds items, skipping empties and duplicates, within the list
// bound.
func cfgAppend(list *[]string, items ...string) {
	for _, it := range items {
		it = cfgClip(it)
		if it == "" || len(*list) >= cfgMaxList {
			continue
		}
		dup := false
		for _, have := range *list {
			if have == it {
				dup = true
				break
			}
		}
		if !dup {
			*list = append(*list, it)
		}
	}
}

// cfgSet records an allowlisted directive in Settings, last write wins.
func cfgSet(c *CryptoConfig, name, val string) {
	name = cfgClip(name)
	if name == "" {
		return
	}
	if c.Settings == nil {
		c.Settings = map[string]string{}
	}
	if _, have := c.Settings[name]; !have && len(c.Settings) >= cfgMaxSettings {
		return
	}
	c.Settings[name] = cfgClip(val)
}

// cfgRef records a file the configuration names; it is THE path every
// reference goes through. A value that carries a URI scheme
// ("store:pkcs11:token=t;pin-value=S", "engine:pkcs11:...", "data:...",
// "https://u:p@h/") is not a file and can hold a PIN, so only the lower-cased
// scheme is kept, as Settings "<directive>_source". A value that is not
// plausibly a filesystem path (a control character, a quote, ";" or "=", a
// colon that is not a Windows drive letter) is dropped. An empty path and an
// exact repeat are dropped too.
func cfgRef(c *CryptoConfig, kind, directive, path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if scheme, ok := cfgURIScheme(path); ok {
		cfgSet(c, directive+"_source", scheme)
		return
	}
	if !cfgIsFSPath(path, kind == "include") || len(c.References) >= cfgMaxRefs {
		return
	}
	r := ConfigReference{Kind: kind, Directive: cfgClip(directive), Path: cfgClip(path)}
	for _, have := range c.References {
		if have == r {
			return
		}
	}
	c.References = append(c.References, r)
}

// cfgURIScheme reports a leading URI scheme: ^[A-Za-z][A-Za-z0-9+.-]+: . A
// Windows drive letter ("C:\x") is one character and so never matches; an
// IPv6 group ("fe80::1") is all hex and at most four characters, and "host:443"
// ends in a port; neither is taken for a scheme. The scheme is returned lower-cased, without the colon.
func cfgURIScheme(v string) (string, bool) {
	if len(v) < 3 || !cfgIsLetter(v[0]) {
		return "", false
	}
	i := 1
	for i < len(v) {
		c := v[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-' {
			i++
			continue
		}
		break
	}
	if i < 2 || i >= len(v) || v[i] != ':' {
		return "", false
	}
	// "host:443" is a host and a port, not a scheme.
	if port := v[i+1:]; len(port) <= 5 && strings.Trim(port, "0123456789") == "" {
		return "", false
	}
	scheme := strings.ToLower(v[:i])
	if len(scheme) <= 4 && strings.Trim(scheme, "0123456789abcdef") == "" {
		return "", false
	}
	return scheme, true
}

// cfgIsFSPath says whether v is plausibly a file path, absolute or relative.
// Globs are allowed for an include; "?" is not allowed elsewhere because a
// URL query is how a PIN gets in.
func cfgIsFSPath(v string, include bool) bool {
	if v == "" || len(v) > cfgMaxValue {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if strings.ContainsAny(v, ";=\"'`|<>") || (!include && strings.Contains(v, "?")) {
		return false
	}
	if len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') &&
		(v[0] >= 'a' && v[0] <= 'z' || v[0] >= 'A' && v[0] <= 'Z') {
		v = v[2:]
	}
	return !strings.Contains(v, ":")
}

// cfgSimple says whether a value is the kind a switch takes: letters, digits,
// blanks and a few separators, short, and in particular no colon or slash,
// so a URL or a path cannot ride in a Setting that should be "on".
func cfgSimple(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !cfgIsAlnum(c) && !strings.ContainsRune(" ._+,-=@*^", rune(c)) {
			return false
		}
	}
	return true
}

// cfgSetSimple records a Setting whose value must be simple (see cfgSimple);
// anything else is dropped, not shortened.
func cfgSetSimple(c *CryptoConfig, name, val string) {
	if cfgSimple(val) {
		cfgSet(c, name, val)
	}
}

// cfgContext builds a bounded, sanitised Context: words with a URI scheme
// keep only the scheme, and the whole is cut at 256 characters.
func cfgContext(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if scheme, ok := cfgURIScheme(w); ok {
			words[i] = scheme + ":"
		}
	}
	out := strings.Join(words, " ")
	if len(out) > 256 {
		out = out[:256]
	}
	return cfgClip(out)
}

// The include budget of one root file.
const (
	cfgMaxIncludeDepth = 8
	cfgMaxIncludeFiles = 256
	cfgMaxIncludeBytes = 16 << 20
)

// cfgIncl enforces the budget while a parser follows includes: depth 8, at
// most 256 files and 16 MiB in all, and no file that is already being read
// (a cycle).
type cfgIncl struct {
	resolve IncludeResolver
	files   int
	bytes   int
	active  []string
}

func newCfgIncl(r IncludeResolver) *cfgIncl { return &cfgIncl{resolve: r} }

// get returns the files to read for pattern, or none when the resolver is
// nil, the depth is spent, or the budget is: all three are checked BEFORE the
// resolver is called, and the resolver is told how many bytes remain. The
// caller reads each file in turn with enter and leave around it.
func (in *cfgIncl) get(pattern string, depth int) []IncludedFile {
	if in == nil || in.resolve == nil || depth >= cfgMaxIncludeDepth ||
		in.files >= cfgMaxIncludeFiles || in.bytes >= cfgMaxIncludeBytes {
		return nil
	}
	res := in.resolve(pattern, int64(cfgMaxIncludeBytes-in.bytes))
	var out []IncludedFile
	for _, f := range res {
		if in.files >= cfgMaxIncludeFiles || in.bytes+len(f.Text) > cfgMaxIncludeBytes {
			break
		}
		cycle := false
		for _, a := range in.active {
			if a == f.Path {
				cycle = true
			}
		}
		if cycle {
			continue
		}
		in.files++
		in.bytes += len(f.Text)
		out = append(out, f)
	}
	return out
}

func (in *cfgIncl) enter(path string) { in.active = append(in.active, path) }
func (in *cfgIncl) leave()            { in.active = in.active[:len(in.active)-1] }

// cfgProtocolNames maps the spellings products use onto the catalogue's.
var cfgProtocolNames = map[string]string{
	"sslv2": "SSLv2", "ssl2": "SSLv2",
	"sslv3": "SSLv3", "ssl3": "SSLv3",
	"tlsv1": "TLSv1.0", "tls1": "TLSv1.0", "tlsv1.0": "TLSv1.0", "tls1.0": "TLSv1.0",
	"tlsv1.1": "TLSv1.1", "tls1.1": "TLSv1.1",
	"tlsv1.2": "TLSv1.2", "tls1.2": "TLSv1.2",
	"tlsv1.3": "TLSv1.3", "tls1.3": "TLSv1.3",
	"dtlsv1": "DTLSv1.0", "dtls1": "DTLSv1.0", "dtlsv1.0": "DTLSv1.0", "dtls1.0": "DTLSv1.0",
	"dtlsv1.2": "DTLSv1.2", "dtls1.2": "DTLSv1.2",
	"sshv1": "SSHv1", "ssh1": "SSHv1",
	"sshv2": "SSHv2", "ssh2": "SSHv2",
}

// cfgNormaliseProtocol maps a product's protocol spelling ("TLSv1", "TLS 1.2",
// "tls1_2", "SSLv3") to the catalogue's ("TLSv1.0", "TLSv1.2", "SSLv3"). The
// second result is false for a name it does not know ("SSLv2Hello", "ALL").
func cfgNormaliseProtocol(s string) (string, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.NewReplacer(" ", "", "-", "", "_", ".").Replace(k)
	v, ok := cfgProtocolNames[k]
	return v, ok
}

// cfgProtocolList normalises each name, keeping an unknown one as written.
func cfgProtocolList(names []string) []string {
	var out []string
	for _, n := range names {
		if v, ok := cfgNormaliseProtocol(n); ok {
			cfgAppend(&out, v)
		} else {
			cfgAppend(&out, n)
		}
	}
	return out
}

// cfgBoolWord reads the on/off spellings products use.
func cfgBoolWord(s string) (val, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "yes", "true", "1", "enabled", "enable":
		return true, true
	case "off", "no", "false", "0", "disabled", "disable":
		return false, true
	}
	return false, false
}

func cfgBoolPtr(b bool) *bool { return &b }

// cfgHasContent says whether a configuration holds anything worth reporting.
func cfgHasContent(c *CryptoConfig) bool {
	return len(c.Protocols)+len(c.DisabledProtocols)+len(c.CipherSuites)+len(c.KeyExchanges)+len(c.Groups)+
		len(c.MACs)+len(c.SignatureAlgorithms)+len(c.HostKeyAlgorithms)+
		len(c.DisabledAlgorithms)+len(c.Settings)+len(c.References) > 0 ||
		c.MinProtocol != "" || c.MaxProtocol != "" || c.CipherString != "" ||
		c.Policy != "" || c.FIPS != nil
}

// cfgInherit fills the typed fields and Settings that own leaves unset from
// parent: how an nginx server block or an Apache VirtualHost sees the policy
// of the level above. References are never inherited: the file that names a
// path is the one that holds it.
func cfgInherit(own, parent *CryptoConfig) {
	// Protocols and DisabledProtocols are two statements about one thing: a
	// level that makes either statement replaces both of the level above.
	if len(own.Protocols) == 0 && len(own.DisabledProtocols) == 0 {
		own.Protocols = append([]string(nil), parent.Protocols...)
		own.DisabledProtocols = append([]string(nil), parent.DisabledProtocols...)
	}
	if own.MinProtocol == "" {
		own.MinProtocol = parent.MinProtocol
	}
	if own.MaxProtocol == "" {
		own.MaxProtocol = parent.MaxProtocol
	}
	if own.CipherString == "" {
		own.CipherString = parent.CipherString
	}
	if len(own.CipherSuites) == 0 {
		own.CipherSuites = append([]string(nil), parent.CipherSuites...)
	}
	if len(own.KeyExchanges) == 0 {
		own.KeyExchanges = append([]string(nil), parent.KeyExchanges...)
	}
	if len(own.Groups) == 0 {
		own.Groups = append([]string(nil), parent.Groups...)
	}
	if len(own.MACs) == 0 {
		own.MACs = append([]string(nil), parent.MACs...)
	}
	if len(own.SignatureAlgorithms) == 0 {
		own.SignatureAlgorithms = append([]string(nil), parent.SignatureAlgorithms...)
	}
	if len(own.HostKeyAlgorithms) == 0 {
		own.HostKeyAlgorithms = append([]string(nil), parent.HostKeyAlgorithms...)
	}
	if len(own.DisabledAlgorithms) == 0 {
		own.DisabledAlgorithms = append([]string(nil), parent.DisabledAlgorithms...)
	}
	if own.Policy == "" {
		own.Policy = parent.Policy
	}
	if own.FIPS == nil && parent.FIPS != nil {
		own.FIPS = cfgBoolPtr(*parent.FIPS)
	}
	if len(parent.Settings) > 0 {
		merged := make(map[string]string, len(parent.Settings)+len(own.Settings))
		for k, v := range parent.Settings {
			merged[k] = v
		}
		for k, v := range own.Settings {
			merged[k] = v
		}
		own.Settings = merged
	}
}

// cfgCut returns the first blank-separated word of s and the rest.
func cfgCut(s string) (word, rest string) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}

func cfgIsLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func cfgIsAlnum(c byte) bool  { return cfgIsLetter(c) || c >= '0' && c <= '9' }
