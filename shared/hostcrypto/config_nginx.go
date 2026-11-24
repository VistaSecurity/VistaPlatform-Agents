package hostcrypto

import (
	"bytes"
	"strings"
)

// nginx.conf. Brace syntax, tokenised properly (quotes, "#" comments, ";"),
// then folded into a tree, then read per scope:
//
//   - one CryptoConfig for each of the http, stream and mail levels that sets
//     anything (and for a bare top level, "main", which also carries the
//     file's includes, so the collector follows them);
//   - one for each server block that sets a TLS directive or listens with
//     "ssl" or "quic". Its typed fields and Settings INHERIT from the level
//     above when the server does not set them, as nginx does, so a reader of
//     one server's entry sees the policy that server actually has. References
//     are not inherited: the level that names a path is the one that holds it.
//
// Nothing is defaulted. nginx's own defaults (ssl_protocols, ssl_ciphers)
// differ between versions, so a directive that is absent is reported absent.
//
// location and if blocks are not read: the TLS directives are not valid
// there, and the proxy_ssl_* ones are read at server level and above only.
//
// Includes are recorded and, when the caller supplies a resolver, spliced in
// at the include's position, so an included server block inherits the http
// level of the file that includes it.
//
// ssl_conf_command at a lower level REPLACES the set the level above gave, as
// nginx does: a server that sets any ssl_conf_command does not also carry the
// http level's.
//
// Never kept: ssl_password_file (it names a file of passphrases),
// ssl_session_ticket_key (a file of ticket keys), and the contents of any
// value that is not a path: a `data:`, `engine:`, `store:` or `pkcs11:` key
// can carry a PIN, so cfgRef keeps only its scheme, as
// ssl_certificate_key_source.

type cfgNgxTok struct {
	kind byte // 'w' word, '{', '}', ';'
	text string
}

const (
	cfgNgxMaxTokens = 500000
	cfgNgxMaxNodes  = 300000
	cfgNgxMaxDepth  = 64
	cfgNgxMaxWord   = 8192
)

func cfgNgxTokens(b []byte) []cfgNgxTok {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	var toks []cfgNgxTok
	lines := 0
	for i := 0; i < len(b) && len(toks) < cfgNgxMaxTokens; {
		c := b[i]
		switch c {
		case '\n':
			lines++
			if lines >= cfgMaxLines {
				return toks
			}
			i++
		case ' ', '\t', '\r', '\f', '\v', 0:
			i++
		case '#':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case ';', '{', '}':
			toks = append(toks, cfgNgxTok{kind: c})
			i++
		case '"', '\'':
			q := c
			i++
			var w []byte
			for i < len(b) && b[i] != q {
				if b[i] == '\\' && i+1 < len(b) {
					if b[i+1] == q || b[i+1] == '\\' {
						i++
					}
				}
				if b[i] == '\n' {
					lines++
				}
				if len(w) < cfgNgxMaxWord {
					w = append(w, b[i])
				}
				i++
			}
			i++ // closing quote; past the end when unterminated
			toks = append(toks, cfgNgxTok{kind: 'w', text: string(w)})
		default:
			start := i
			for i < len(b) {
				d := b[i]
				if d == ' ' || d == '\t' || d == '\r' || d == '\n' || d == '\f' || d == '\v' || d == 0 || d == ';' || d == '}' {
					break
				}
				if d == '{' {
					if i > start && b[i-1] == '$' { // ${var}
						for i < len(b) && b[i] != '}' && b[i] != '\n' {
							i++
						}
						if i < len(b) && b[i] == '}' {
							i++
						}
						continue
					}
					break
				}
				i++
			}
			end := i
			if end-start > cfgNgxMaxWord {
				end = start + cfgNgxMaxWord
			}
			toks = append(toks, cfgNgxTok{kind: 'w', text: string(b[start:end])})
		}
	}
	return toks
}

type cfgNgxNode struct {
	name  string
	args  []string
	kids  []*cfgNgxNode
	block bool
}

// cfgNgxTree folds tokens into directives. Unbalanced braces are tolerated: a
// stray "}" is ignored and an unclosed block ends at the end of the file.
func cfgNgxTree(toks []cfgNgxTok, inc *cfgIncl, depth int) *cfgNgxNode {
	root := &cfgNgxNode{block: true}
	stack := []*cfgNgxNode{root}
	var words []string
	nodes := 0
	for _, t := range toks {
		parent := stack[len(stack)-1]
		switch t.kind {
		case 'w':
			words = append(words, t.text)
		case ';':
			if len(words) > 0 && nodes < cfgNgxMaxNodes {
				nodes++
				n := &cfgNgxNode{name: strings.ToLower(words[0]), args: words[1:]}
				parent.kids = append(parent.kids, n)
				if n.name == "include" && len(n.args) > 0 {
					for _, f := range inc.get(n.args[0], depth) {
						inc.enter(f.Path)
						sub := cfgNgxTree(cfgNgxTokens(f.Text), inc, depth+1)
						inc.leave()
						if nodes+len(sub.kids) < cfgNgxMaxNodes {
							nodes += len(sub.kids)
							parent.kids = append(parent.kids, sub.kids...)
						}
					}
				}
			}
			words = nil
		case '{':
			n := &cfgNgxNode{block: true}
			if len(words) > 0 {
				n.name, n.args = strings.ToLower(words[0]), words[1:]
			}
			if len(stack) < cfgNgxMaxDepth && nodes < cfgNgxMaxNodes {
				nodes++
				parent.kids = append(parent.kids, n)
			}
			stack = append(stack, n)
			words = nil
		case '}':
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			words = nil
		}
	}
	return root
}

// cfgNgxScope is what one level sets itself.
type cfgNgxScope struct {
	cfg       CryptoConfig
	tls       bool // some TLS directive other than include
	sslListen bool
	listens   []string
	names     string
	confCmd   bool // some ssl_conf_command at this level
}

// cfgNgxProxy is the exact set of upstream TLS directives kept: the same ten
// for proxy_, grpc_ and uwsgi_, spelled out by building the names, never by
// matching a prefix.
var cfgNgxProxy = func() map[string]struct{ kind string } {
	m := map[string]struct{ kind string }{}
	for _, p := range []string{"proxy", "grpc", "uwsgi"} {
		m[p+"_ssl_protocols"] = struct{ kind string }{"list"}
		m[p+"_ssl_ciphers"] = struct{ kind string }{"list"}
		m[p+"_ssl_verify"] = struct{ kind string }{"setting"}
		m[p+"_ssl_verify_depth"] = struct{ kind string }{"setting"}
		m[p+"_ssl_server_name"] = struct{ kind string }{"setting"}
		m[p+"_ssl_session_reuse"] = struct{ kind string }{"setting"}
		m[p+"_ssl_certificate"] = struct{ kind string }{"certificate"}
		m[p+"_ssl_certificate_key"] = struct{ kind string }{"private_key"}
		m[p+"_ssl_trusted_certificate"] = struct{ kind string }{"trust_store"}
		m[p+"_ssl_crl"] = struct{ kind string }{"crl"}
	}
	return m
}()

func cfgNgxApply(sc *cfgNgxScope, kids []*cfgNgxNode) {
	c := &sc.cfg
	for _, n := range kids {
		if n.block {
			continue
		}
		a := n.args
		switch n.name {
		case "include":
			for _, p := range a {
				cfgRef(c, "include", "include", p)
			}
		case "server_name":
			sc.names = strings.Join(a, " ")
		case "listen":
			if len(a) > 0 {
				sc.listens = append(sc.listens, strings.Join(a, " "))
				for _, w := range a[1:] {
					if lw := strings.ToLower(w); lw == "ssl" || lw == "quic" {
						sc.sslListen = true
					}
				}
			}
		case "ssl_protocols":
			// A repeated ssl_protocols is OR-ed by nginx: the union.
			sc.tls = true
			cfgAppend(&c.Protocols, cfgProtocolList(a)...)
		case "ssl_ciphers":
			if len(a) > 0 {
				sc.tls = true
				c.CipherString = cfgClip(a[0])
			}
		case "ssl_ecdh_curve":
			if len(a) > 0 {
				sc.tls = true
				c.Groups = cfgSplitList(a[0], ":")
			}
		case "ssl_conf_command":
			if len(a) >= 2 {
				cfgNgxConfCommand(sc, a[0], a[1])
			}
		case "ssl_prefer_server_ciphers", "ssl_session_tickets", "ssl_session_timeout",
			"ssl_stapling", "ssl_stapling_verify", "ssl_verify_client", "ssl_verify_depth",
			"ssl_early_data", "ssl_reject_handshake", "ssl":
			if len(a) > 0 {
				sc.tls = true
				cfgSetSimple(c, n.name, a[0])
			}
		case "add_header":
			if len(a) >= 2 && strings.EqualFold(a[0], "Strict-Transport-Security") {
				sc.tls = true
				if cfgSimple(strings.ReplaceAll(a[1], ";", " ")) {
					cfgSet(c, "Strict-Transport-Security", a[1])
				}
			}
		case "ssl_certificate":
			sc.tls = true
			cfgNgxPath(c, "certificate", n.name, a)
		case "ssl_certificate_key":
			sc.tls = true
			cfgNgxPath(c, "private_key", n.name, a)
		case "ssl_trusted_certificate", "ssl_client_certificate":
			sc.tls = true
			cfgNgxPath(c, "trust_store", n.name, a)
		case "ssl_dhparam":
			sc.tls = true
			cfgNgxPath(c, "dh_params", n.name, a)
		case "ssl_crl":
			sc.tls = true
			cfgNgxPath(c, "crl", n.name, a)
		default:
			if p, ok := cfgNgxProxy[n.name]; ok {
				sc.tls = true
				switch p.kind {
				case "setting":
					cfgSetSimple(c, n.name, strings.Join(a, " "))
				case "list":
					if len(a) > 0 {
						v := strings.Join(a, " ")
						if strings.HasSuffix(n.name, "_protocols") && c.Settings[n.name] != "" {
							v = cfgUnionWords(c.Settings[n.name], v) // OR-ed, like ssl_protocols
						}
						cfgSet(c, n.name, v)
					}
				default:
					cfgNgxPath(c, p.kind, n.name, a)
				}
			}
		}
	}
}

// cfgNgxConfCommand applies one `ssl_conf_command <Name> <value>`.
func cfgNgxConfCommand(sc *cfgNgxScope, name, value string) {
	c := &sc.cfg
	canon := map[string]string{
		"ciphersuites": "Ciphersuites", "options": "Options", "minprotocol": "MinProtocol",
		"maxprotocol": "MaxProtocol", "groups": "Groups", "curves": "Curves",
		"signaturealgorithms": "SignatureAlgorithms", "ciphersuite": "CipherString",
		"cipherstring": "CipherString",
	}[strings.ToLower(name)]
	if canon == "" {
		return
	}
	sc.tls = true
	sc.confCmd = true
	cfgSet(c, "ssl_conf_command "+canon, value)
	switch canon {
	case "Ciphersuites":
		c.CipherSuites = cfgSplitList(value, ":")
	case "MinProtocol":
		c.MinProtocol = cfgProtocolOne(value)
	case "MaxProtocol":
		c.MaxProtocol = cfgProtocolOne(value)
	case "SignatureAlgorithms":
		c.SignatureAlgorithms = cfgSplitList(value, ":")
	}
}

// cfgNgxPath records a path directive. A value that is not a path (data:,
// engine:, store:, pkcs11:, a URL) is handled by cfgRef: only its scheme is
// kept.
func cfgNgxPath(c *CryptoConfig, kind, directive string, args []string) {
	if len(args) == 0 {
		return
	}
	cfgRef(c, kind, directive, args[0])
}

// cfgNgxInherit completes own from parent. When own has its own
// ssl_conf_command, what the parent's ssl_conf_command set (its Settings, and
// the typed fields only it sets) is not inherited.
func cfgNgxInherit(own *CryptoConfig, ownConfCmd bool, parent *CryptoConfig) {
	p := *parent
	if ownConfCmd {
		p.Settings = map[string]string{}
		for k, v := range parent.Settings {
			if !strings.HasPrefix(k, "ssl_conf_command ") {
				p.Settings[k] = v
			}
		}
		p.CipherSuites, p.SignatureAlgorithms = nil, nil
		if _, ok := parent.Settings["ssl_conf_command MinProtocol"]; ok {
			p.MinProtocol = ""
		}
		if _, ok := parent.Settings["ssl_conf_command MaxProtocol"]; ok {
			p.MaxProtocol = ""
		}
	}
	cfgInherit(own, &p)
}

func cfgParseNginx(b []byte, include IncludeResolver) []CryptoConfig {
	root := cfgNgxTree(cfgNgxTokens(b), newCfgIncl(include), 0)
	var out []CryptoConfig
	emit := func(c CryptoConfig) {
		if len(out) < cfgMaxList*4 {
			out = append(out, c)
		}
	}

	var level func(kids []*cfgNgxNode, parent *CryptoConfig, kind string)
	level = func(kids []*cfgNgxNode, parent *CryptoConfig, kind string) {
		sc := cfgNgxScope{cfg: CryptoConfig{Product: "nginx"}}
		cfgNgxApply(&sc, kids)
		eff := sc.cfg
		if parent != nil {
			cfgNgxInherit(&eff, sc.confCmd, parent)
		}
		if sc.tls || len(sc.cfg.References) > 0 {
			c := eff
			c.References = sc.cfg.References
			c.Context = cfgContext(kind)
			if cfgHasContent(&c) {
				emit(c)
			}
		}
		for _, n := range kids {
			if !n.block {
				continue
			}
			switch n.name {
			case "http", "stream", "mail":
				if kind == "main" {
					level(n.kids, &eff, n.name)
				}
			case "server":
				cfgNgxServer(n, &eff, kind, emit)
			}
		}
	}
	level(root.kids, nil, "main")
	return out
}

func cfgNgxServer(n *cfgNgxNode, parent *CryptoConfig, kind string, emit func(CryptoConfig)) {
	sc := cfgNgxScope{cfg: CryptoConfig{Product: "nginx"}}
	cfgNgxApply(&sc, n.kids)
	if !sc.tls && !sc.sslListen {
		return
	}
	c := sc.cfg
	cfgNgxInherit(&c, sc.confCmd, parent)
	c.References = sc.cfg.References

	var parts []string
	if sc.names != "" {
		parts = append(parts, "server_name "+sc.names)
	}
	for _, l := range sc.listens {
		parts = append(parts, "listen "+l)
	}
	ctx := strings.Join(parts, "; ")
	if kind == "stream" || kind == "mail" {
		ctx = kind + ": " + ctx
	}
	c.Context = cfgContext(ctx)
	// Reported even when it sets nothing: a server that listens with ssl and
	// names no policy is serving TLS on the product's defaults, which the
	// Context alone says.
	emit(c)
}

// cfgUnionWords joins two blank-separated word lists without repeats.
func cfgUnionWords(a, b string) string {
	var out []string
	cfgAppend(&out, strings.Fields(a)...)
	cfgAppend(&out, strings.Fields(b)...)
	return strings.Join(out, " ")
}
