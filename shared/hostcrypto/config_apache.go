package hostcrypto

import (
	"strings"
)

// Apache httpd (mod_ssl, and mod_gnutls where present).
//
// Directives are lines; sections are <Name args> ... </Name>; a backslash ends
// a line's continuation. The parser keeps a stack of open sections:
//
//   - <VirtualHost> opens a scope of its own;
//   - <IfModule> and <IfDefine> (not negated) are transparent: their body is
//     read as part of the enclosing scope, since which module is loaded and
//     which -D was given are not known from the file, and mod_ssl's own
//     config is almost always inside <IfModule mod_ssl.c>;
//   - everything else (<Directory>, <Location>, <If>, <IfVersion>, a negated
//     <IfModule !x>...) is skipped, bodies and all.
//
// One CryptoConfig for the server level (when it sets anything or names an
// Include) and one per VirtualHost that sets a TLS directive; the virtual
// host inherits the typed fields and Settings of the server level, as Apache
// does.
//
// SSLProtocol is resolved by mod_ssl's rules (+X adds, -X removes, a bare X
// replaces), but only as far as the file decides: "all" means every protocol
// the OpenSSL build has, which the file does not say. "all -SSLv3 -TLSv1"
// therefore reports DisabledProtocols (SSLv3, TLSv1.0) and no Protocols;
// "-all +TLSv1.2 +TLSv1.3" and a bare "TLSv1.2" pin the set and report
// Protocols. The text as written stays in Settings["SSLProtocol"].
//
// Includes are recorded and, with a resolver, read in place; a virtual host
// in an included file inherits the server level of the including file.
//
// Never kept: SSLPassPhraseDialog (a program that prints a passphrase),
// GnuTLSP12Password, and any file-valued directive whose value is not a path
// (pkcs11: and engine: URIs carry PINs; cfgRef records only the scheme).

var cfgApacheSettings = map[string]string{
	"sslengine": "SSLEngine", "sslhonorcipherorder": "SSLHonorCipherOrder",
	"sslcompression": "SSLCompression", "sslsessiontickets": "SSLSessionTickets",
	"sslusestapling":  "SSLUseStapling",
	"sslverifyclient": "SSLVerifyClient", "sslverifydepth": "SSLVerifyDepth",
	"sslinsecurerenegotiation": "SSLInsecureRenegotiation",
	"sslstrictsnivhostcheck":   "SSLStrictSNIVHostCheck",
	"sslproxyprotocol":         "SSLProxyProtocol",
	"sslproxyciphersuite":      "SSLProxyCipherSuite", "sslproxyverify": "SSLProxyVerify",
	"sslproxyverifydepth": "SSLProxyVerifyDepth", "sslproxyengine": "SSLProxyEngine",
	"sslproxycheckpeercn": "SSLProxyCheckPeerCN", "sslproxycheckpeername": "SSLProxyCheckPeerName",
	"sslproxycheckpeerexpire": "SSLProxyCheckPeerExpire",
	"gnutlsenable":            "GnuTLSEnable",
}

var cfgApacheRefs = map[string][2]string{
	"sslcertificatefile":             {"certificate", "SSLCertificateFile"},
	"sslcertificatekeyfile":          {"private_key", "SSLCertificateKeyFile"},
	"sslcertificatechainfile":        {"certificate", "SSLCertificateChainFile"},
	"sslcacertificatefile":           {"trust_store", "SSLCACertificateFile"},
	"sslcacertificatepath":           {"trust_store", "SSLCACertificatePath"},
	"sslcarevocationfile":            {"crl", "SSLCARevocationFile"},
	"sslcarevocationpath":            {"crl", "SSLCARevocationPath"},
	"sslproxymachinecertificatefile": {"certificate", "SSLProxyMachineCertificateFile"},
	"sslproxycacertificatefile":      {"trust_store", "SSLProxyCACertificateFile"},
	"sslproxycacertificatepath":      {"trust_store", "SSLProxyCACertificatePath"},
	"sslproxycarevocationfile":       {"crl", "SSLProxyCARevocationFile"},
	"gnutlscertificatefile":          {"certificate", "GnuTLSCertificateFile"},
	"gnutlskeyfile":                  {"private_key", "GnuTLSKeyFile"},
	"gnutlsp12file":                  {"keystore", "GnuTLSP12File"},
}

type cfgApacheScope struct {
	cfg        CryptoConfig
	tls        bool
	args       []string // the <VirtualHost ...> arguments
	serverName string
	vhost      bool
}

// cfgApacheSection is one open section on the stack.
type cfgApacheSection struct {
	name  string
	scope *cfgApacheScope // the scope its body belongs to; nil when skipped
}

func cfgParseApache(b []byte, include IncludeResolver) []CryptoConfig {
	inc := newCfgIncl(include)
	server := &cfgApacheScope{cfg: CryptoConfig{Product: "apache"}}
	scopes := []*cfgApacheScope{server}
	stack := []cfgApacheSection{}
	over := 0 // sections opened past the depth limit: counted, not pushed
	current := func() *cfgApacheScope {
		if over > 0 {
			return nil
		}
		if len(stack) == 0 {
			return server
		}
		return stack[len(stack)-1].scope
	}

	var process func(b []byte, depth int)
	process = func(b []byte, depth int) {
		base, overBase := len(stack), over // sections must balance within one file
		for _, ln := range cfgLogicalLines(b, "#", true) {
			s := strings.TrimSpace(ln.text)
			if s == "" || s[0] == '#' {
				continue
			}
			if s[0] == '<' {
				end := strings.LastIndexByte(s, '>')
				if end < 0 {
					continue
				}
				inner := strings.TrimSpace(s[1:end])
				if strings.HasPrefix(inner, "/") {
					// Apache needs a close tag to match the section that is
					// open, so only the innermost one is compared: O(1), and
					// a stray close tag changes nothing.
					switch {
					case over > overBase:
						over--
					case len(stack) > base && stack[len(stack)-1].name == strings.ToLower(strings.TrimSpace(inner[1:])):
						stack = stack[:len(stack)-1]
					}
					continue
				}
				word, rest := cfgCut(inner)
				name := strings.ToLower(word)
				parent := current()
				sec := cfgApacheSection{name: name}
				args := cfgFields(rest, false)
				if len(stack) >= 64 || over > 0 {
					over++ // too deep to be real: skip the body, push nothing
					continue
				}
				switch {
				case parent == nil:
					// inside a skipped section
				case name == "virtualhost":
					if len(scopes) < cfgMaxList {
						v := &cfgApacheScope{cfg: CryptoConfig{Product: "apache"}, vhost: true, args: cfgVHostArgs(args)}
						scopes = append(scopes, v)
						sec.scope = v
					}
				case (name == "ifmodule" || name == "ifdefine") && len(args) > 0 && !strings.HasPrefix(args[0], "!"):
					sec.scope = parent
				}
				stack = append(stack, sec)
				continue
			}
			sc := current()
			if sc == nil {
				continue
			}
			word, rest := cfgCut(s)
			d, args := strings.ToLower(word), cfgFields(rest, false)
			cfgApacheDirective(sc, d, args)
			if (d == "include" || d == "includeoptional") && len(args) > 0 {
				for _, f := range inc.get(args[0], depth) {
					inc.enter(f.Path)
					process(f.Text, depth+1)
					inc.leave()
				}
			}
		}
		stack, over = stack[:base], overBase
	}
	process(b, 0)

	var out []CryptoConfig
	for _, sc := range scopes {
		c := sc.cfg
		if sc.vhost {
			if !sc.tls {
				continue
			}
			cfgInherit(&c, &server.cfg)
			c.References = sc.cfg.References
			ctx := "VirtualHost " + strings.Join(sc.args, " ")
			if sc.serverName != "" {
				ctx += " ServerName " + sc.serverName
			}
			c.Context = cfgContext(ctx)
		}
		if cfgHasContent(&c) {
			out = append(out, c)
		}
	}
	return out
}

// cfgVHostArgs keeps the words of a <VirtualHost ...> line that look like
// addresses (a "*", "_default_", or something with a colon or a dot). The
// directive takes nothing else, so any other word is not part of the
// address and is not repeated.
func cfgVHostArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "*" || a == "_default_" || strings.ContainsAny(a, ":.") {
			out = append(out, a)
		}
	}
	return out
}

func cfgApacheDirective(sc *cfgApacheScope, d string, a []string) {
	c := &sc.cfg
	if len(a) == 0 {
		return
	}
	switch d {
	case "servername":
		if sc.vhost && sc.serverName == "" {
			sc.serverName = a[0]
		}
		return
	case "include", "includeoptional":
		name := "Include"
		if d == "includeoptional" {
			name = "IncludeOptional"
		}
		cfgRef(c, "include", name, a[0])
		return
	case "sslprotocol":
		// Every argument must be an SSLProtocol term; Apache refuses to start
		// on anything else, so a line with a stray word is not a policy.
		for _, w := range a {
			if _, ok := cfgNormaliseProtocol(strings.TrimLeft(w, "+-")); !ok && !strings.EqualFold(strings.TrimLeft(w, "+-"), "all") {
				return
			}
		}
		sc.tls = true
		c.Protocols, c.DisabledProtocols = cfgApacheProtocols(a)
		cfgSet(c, "SSLProtocol", strings.Join(a, " "))
	case "sslciphersuite":
		sc.tls = true
		switch {
		case len(a) >= 2 && strings.EqualFold(a[0], "TLSv1.3"):
			c.CipherSuites = cfgSplitList(a[1], ":")
		case len(a) >= 2 && strings.EqualFold(a[0], "SSL"):
			c.CipherString = cfgClip(a[1])
		default:
			c.CipherString = cfgClip(a[0])
		}
	case "sslopensslconfcmd":
		if len(a) >= 2 {
			cfgApacheConfCmd(sc, a[0], a[1])
		}
	case "sslfips":
		if on, ok := cfgBoolWord(a[0]); ok {
			sc.tls = true
			c.FIPS = cfgBoolPtr(on)
		}
	case "gnutlspriorities":
		sc.tls = true
		c.Policy = cfgClip(a[0])
	case "header":
		for i, w := range a {
			if strings.EqualFold(w, "Strict-Transport-Security") && i+1 < len(a) {
				sc.tls = true
				if cfgSimple(strings.ReplaceAll(a[i+1], ";", " ")) {
					cfgSet(c, "Strict-Transport-Security", a[i+1])
				}
				break
			}
		}
	default:
		if r, ok := cfgApacheRefs[d]; ok {
			sc.tls = true
			cfgRef(c, r[0], r[1], a[0])
		} else if name, ok := cfgApacheSettings[d]; ok {
			sc.tls = true
			if d == "sslproxyprotocol" || d == "sslproxyciphersuite" {
				cfgSet(c, name, strings.Join(a, " "))
			} else {
				cfgSetSimple(c, name, strings.Join(a, " "))
			}
		}
	}
}

func cfgApacheConfCmd(sc *cfgApacheScope, name, value string) {
	c := &sc.cfg
	switch strings.ToLower(name) {
	case "dhparameters":
		sc.tls = true
		cfgRef(c, "dh_params", "SSLOpenSSLConfCmd DHParameters", value)
		return
	}
	canon := map[string]string{
		"ciphersuites": "Ciphersuites", "options": "Options", "minprotocol": "MinProtocol",
		"maxprotocol": "MaxProtocol", "groups": "Groups", "curves": "Curves",
		"signaturealgorithms": "SignatureAlgorithms",
	}[strings.ToLower(name)]
	if canon == "" {
		return
	}
	sc.tls = true
	cfgSet(c, "SSLOpenSSLConfCmd "+canon, value)
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

// cfgApacheProtocols models mod_ssl's SSLProtocol exactly. The set starts
// empty and the arguments are applied left to right: a bare name sets the set
// to that one protocol, a bare "all" sets it to every protocol the OpenSSL
// build has, "+X" adds, "-X" removes, "-all" empties it. So "-TLSv1.2 all"
// disables nothing, and "TLSv1.2 TLSv1.3" is TLSv1.3.
//
// What "all" covers is not in the file. So when the final set was never
// touched by "all" it is reported (allowed); when "all" is in force, only what
// was removed AFTER the last "all" is certain, and that is the second result.
func cfgApacheProtocols(args []string) (allowed, removed []string) {
	order := []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
	set := map[string]bool{}
	allUsed := false
	var minus []string
	for _, a := range args {
		action := byte(0)
		if a != "" && (a[0] == '+' || a[0] == '-') {
			action, a = a[0], a[1:]
		}
		if strings.EqualFold(a, "all") {
			switch action {
			case '-':
				set, allUsed, minus = map[string]bool{}, false, nil
			default: // bare or "+all"
				set, allUsed, minus = map[string]bool{}, true, nil
			}
			continue
		}
		p, ok := cfgNormaliseProtocol(a)
		if !ok {
			continue
		}
		switch action {
		case '-':
			if allUsed {
				cfgAppend(&minus, p)
			} else {
				delete(set, p)
			}
		case '+':
			if allUsed {
				kept := minus[:0]
				for _, m := range minus {
					if m != p {
						kept = append(kept, m)
					}
				}
				minus = kept
			} else {
				set[p] = true
			}
		default: // a bare name sets the set
			set, allUsed, minus = map[string]bool{p: true}, false, nil
		}
	}
	if allUsed {
		if len(minus) == 0 {
			minus = nil
		}
		return nil, minus
	}
	for _, p := range order {
		if set[p] {
			allowed = append(allowed, p)
		}
	}
	return allowed, nil
}
