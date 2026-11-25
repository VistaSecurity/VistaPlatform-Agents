package hostcrypto

import (
	"path"
	"strconv"
	"strings"
)

// HAProxy's haproxy.cfg. Sections: global, defaults, frontend, listen,
// backend (others are skipped). What is kept:
//
//   - global: the ssl-default-bind-* and ssl-default-server-* defaults,
//     tune.ssl.default-dh-param, ssl-dh-param-file, ca-base and crt-base (the
//     last two resolve relative crt and ca-file paths);
//   - one CryptoConfig per `bind` line that says `ssl`, in a frontend or
//     listen section, Context "frontend web bind :443". The spec says one per
//     section; two bind lines of one frontend may differ (a public listener
//     and an admin one with a client-CA), so one entry per TLS listener is
//     what keeps each one's protocols and files true. It starts from the
//     global ssl-default-bind-* values and applies the bind line's own over
//     them;
//   - one CryptoConfig per backend (and per listen section with `server ...
//     ssl` lines, Context "listen x servers") whose servers use TLS to the
//     origin: the server options (verify, ca-file, crt, ssl-min-ver...) as
//     Settings named "server <name> <option>".
//
// A `crt` is a combined PEM that usually holds the private key too, so it is
// reported twice, as "certificate" and as "private_key", the second so that
// pass 2 and the permission findings reach the key file.
//
// Protocols are never invented. With only exclusions stated (no-tlsv10,
// no-sslv3) the allowed set depends on HAProxy's and the library's defaults,
// so only DisabledProtocols is filled; Protocols is filled when the file
// states the set: both ssl-min-ver and ssl-max-ver, or a force-tlsvXX.
// MinProtocol and MaxProtocol are filled whenever stated.
//
// A default-server line sets defaults for the servers after it; a later one
// replaces an option by name, so the defaults stay as small as the options
// are many, and a `defaults` section's default-server applies to the
// backends after it.
//
// Never kept: ca-sign-file and ca-sign-pass, tls-ticket-keys (a file of
// session-ticket keys), crt-ignore-err and any option not named below.

type cfgHAOpt struct{ name, val string }

const (
	cfgHAMaxTokens  = 128 // tokens read from one line
	cfgHAMaxOptions = 256 // options kept per section
)

// Options that take one argument, and are kept.
var cfgHAArgOpts = map[string]bool{
	"crt": true, "crt-list": true, "ca-file": true, "ca-verify-file": true,
	"crl-file": true, "ciphers": true, "ciphersuites": true, "curves": true,
	"sigalgs": true, "client-sigalgs": true, "ssl-min-ver": true, "ssl-max-ver": true,
	"alpn": true, "verify": true, "verifyhost": true,
}

// Options that take one argument and are NOT kept (some are secrets), from
// HAProxy's bind and server keyword lists. They are consumed so their
// argument is never read as an option. Any token NOT in this table or the kept
// tables is taken to have no argument (send-proxy-v2-ssl, accept-proxy,
// defer-accept, check, backup...), so a `crt` after such a flag is not lost.
var cfgHASkipArgOpts = map[string]bool{
	"ca-sign-file": true, "ca-sign-pass": true, "tls-ticket-keys": true,
	"crt-ignore-err": true, "ca-ignore-err": true, "npn": true, "sni": true,
	"name": true, "id": true, "maxconn": true, "interface": true, "user": true,
	"group": true, "mode": true, "process": true, "thread": true, "namespace": true,
	"backlog": true, "tcp-ut": true, "mss": true, "ocsp-update": true,
	"ssl-load-extra-files": true, "check-sni": true, "ca-sign-pass-file": true,
	"quic-cc-algo": true, "quic-socket": true, "weight": true, "port": true, "addr": true,
	"inter": true, "fastinter": true, "downinter": true, "rise": true, "fall": true,
	"slowstart": true, "minconn": true, "check-proto": true, "agent-port": true,
	"agent-inter": true, "agent-addr": true, "agent-send": true, "agent-check-proto": true,
	"observe": true, "on-error": true, "on-marked-down": true, "on-marked-up": true,
	"pool-max-conn": true, "pool-purge-delay": true, "pool-low-conn": true,
	"pool-conn-name": true, "resolvers": true, "resolve-prefer": true, "resolve-opts": true,
	"resolve-net": true, "source": true, "usesrc": true, "proxy-v2-options": true,
	"redir": true, "cookie": true, "track": true, "init-addr": true, "tos": true,
	"set-proxy-v2-tlv-fmt": true, "shutdown-sessions": false, "stick": false,
	"idle-ping": true, "max-reuse": true, "log-bufsize": true, "socks4": true,
	"cc": true, "tls-tickets": false, "guid": true, "curves-file": true,
}

// Flags that are kept.
var cfgHAFlags = map[string]bool{
	"ssl": true, "no-sslv3": true, "no-tlsv10": true, "no-tlsv11": true,
	"no-tlsv12": true, "no-tlsv13": true, "force-sslv3": true, "force-tlsv10": true,
	"force-tlsv11": true, "force-tlsv12": true, "force-tlsv13": true,
	"strict-sni": true, "no-tls-tickets": true, "prefer-client-ciphers": true,
	"allow-0rtt": true, "no-ca-names": true,
}

// cfgHAVersion maps the dotless version names of the no-* and force-* flags.
var cfgHAVersion = map[string]int{"sslv3": 0, "tlsv10": 1, "tlsv11": 2, "tlsv12": 3, "tlsv13": 4}

func cfgHAOptions(tokens []string) []cfgHAOpt {
	var out []cfgHAOpt
	for i := 0; i < len(tokens) && len(out) < cfgHAMaxOptions; i++ {
		t := strings.ToLower(tokens[i])
		switch {
		case cfgHAArgOpts[t] && i+1 < len(tokens):
			out = append(out, cfgHAOpt{t, tokens[i+1]})
			i++
		case cfgHAArgOpts[t]:
		case cfgHASkipArgOpts[t]:
			i++
		case cfgHAFlags[t]:
			out = append(out, cfgHAOpt{t, ""})
		}
		// anything else takes no argument and is not kept
	}
	return out
}

var cfgHAProtoOrder = []string{"SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

// cfgHAProtocols reads what a set of options says about protocols: the
// bounds, the exclusions, and (only when the set is pinned) the allowed list.
func cfgHAProtocols(opts []cfgHAOpt) (allowed, disabled []string, minP, maxP string) {
	lo, hi := 0, len(cfgHAProtoOrder)-1
	haveMin, haveMax, forced := false, false, false
	removed := map[int]bool{}
	idx := func(name string) int {
		p, ok := cfgNormaliseProtocol(name)
		if !ok {
			return -1
		}
		for i, q := range cfgHAProtoOrder {
			if q == p {
				return i
			}
		}
		return -1
	}
	for _, o := range opts {
		switch o.name {
		case "ssl-min-ver":
			if i := idx(o.val); i >= 0 {
				lo, minP, haveMin = i, cfgHAProtoOrder[i], true
			}
		case "ssl-max-ver":
			if i := idx(o.val); i >= 0 {
				hi, maxP, haveMax = i, cfgHAProtoOrder[i], true
			}
		case "no-sslv3", "no-tlsv10", "no-tlsv11", "no-tlsv12", "no-tlsv13":
			removed[cfgHAVersion[strings.TrimPrefix(o.name, "no-")]] = true
		case "force-sslv3", "force-tlsv10", "force-tlsv11", "force-tlsv12", "force-tlsv13":
			i := cfgHAVersion[strings.TrimPrefix(o.name, "force-")]
			lo, hi, forced = i, i, true
			minP, maxP = cfgHAProtoOrder[i], cfgHAProtoOrder[i]
		}
	}
	// With a bound or a force in force, HAProxy ignores no-sslv3 and no-tlsvXX
	// altogether: they narrow nothing and disable nothing.
	if haveMin || haveMax || forced {
		removed = map[int]bool{}
	}
	for i, p := range cfgHAProtoOrder {
		if removed[i] {
			disabled = append(disabled, p)
		}
	}
	if forced || (haveMin && haveMax) {
		for i := lo; i <= hi; i++ {
			if !removed[i] {
				allowed = append(allowed, cfgHAProtoOrder[i])
			}
		}
	}
	return allowed, disabled, minP, maxP
}

type cfgHASection struct {
	kind  string
	name  string
	lines [][]string
}

var cfgHASectionKinds = map[string]bool{
	"global": true, "defaults": true, "frontend": true, "listen": true, "backend": true,
	"userlist": true, "peers": true, "resolvers": true, "mailers": true, "cache": true,
	"program": true, "http-errors": true, "ring": true, "fcgi-app": true,
	"log-forward": true, "crt-store": true, "traces": true,
}

// cfgHAALPN says whether v is a protocol list ("h2,http/1.1").
func cfgHAALPN(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !cfgIsAlnum(c) && !strings.ContainsRune(",./-", rune(c)) {
			return false
		}
	}
	return true
}

func cfgParseHAProxy(b []byte, _ IncludeResolver) []CryptoConfig {
	var secs []*cfgHASection
	var cur *cfgHASection
	for _, ln := range cfgLogicalLines(b, "#", false) {
		f := cfgFields(ln.text, true)
		if len(f) == 0 {
			continue
		}
		if len(f) > cfgHAMaxTokens {
			f = f[:cfgHAMaxTokens]
		}
		kw := strings.ToLower(f[0])
		if cfgHASectionKinds[kw] {
			if len(secs) >= 4096 {
				cur = &cfgHASection{kind: "skip"}
				continue
			}
			cur = &cfgHASection{kind: kw}
			if len(f) > 1 {
				cur.name = f[1]
			}
			secs = append(secs, cur)
			continue
		}
		if cur != nil && cur.kind != "skip" && len(cur.lines) < cfgMaxLines {
			f[0] = kw
			cur.lines = append(cur.lines, f)
		}
	}

	// Pass one: global, which holds the defaults and the base directories.
	g := CryptoConfig{Product: "haproxy", Context: "global"}
	var bindDefaults []cfgHAOpt
	bindCiphers, bindSuites, bindCurves, bindSig := "", "", "", ""
	caBase, crtBase := "", ""
	for _, s := range secs {
		if s.kind != "global" {
			continue
		}
		for _, f := range s.lines {
			if len(f) < 2 {
				continue
			}
			v := f[1]
			switch f[0] {
			case "ca-base":
				if cfgIsFSPath(v, false) {
					caBase = v
					cfgSet(&g, "ca-base", v)
				}
			case "crt-base":
				if cfgIsFSPath(v, false) {
					crtBase = v
					cfgSet(&g, "crt-base", v)
				}
			case "ssl-default-bind-ciphers":
				bindCiphers = v
			case "ssl-default-bind-ciphersuites":
				bindSuites = v
			case "ssl-default-bind-curves":
				bindCurves = v
			case "ssl-default-bind-sigalgs":
				bindSig = v
			case "ssl-default-bind-options":
				bindDefaults = append(bindDefaults, cfgHAOptions(f[1:])...)
				if len(bindDefaults) > cfgHAMaxOptions {
					bindDefaults = bindDefaults[len(bindDefaults)-cfgHAMaxOptions:]
				}
				cfgSet(&g, "ssl-default-bind-options", strings.Join(cfgHAOptNames(cfgHAOptions(f[1:])), " "))
			case "ssl-default-server-options":
				cfgSet(&g, f[0], strings.Join(cfgHAOptNames(cfgHAOptions(f[1:])), " "))
			case "ssl-default-server-ciphers", "ssl-default-server-ciphersuites",
				"ssl-default-server-curves", "ssl-default-server-sigalgs":
				cfgSet(&g, f[0], v)
			case "tune.ssl.default-dh-param":
				cfgSetSimple(&g, f[0], v)
			case "ssl-server-verify":
				cfgSetSimple(&g, f[0], v)
			case "ssl-dh-param-file":
				cfgRef(&g, "dh_params", "ssl-dh-param-file", v)
			}
		}
	}
	// The global entry reports the bind defaults in the typed fields.
	g.CipherString = cfgClip(bindCiphers)
	g.CipherSuites = cfgSplitList(bindSuites, ":")
	g.Groups = cfgSplitList(bindCurves, ":")
	g.SignatureAlgorithms = cfgSplitList(bindSig, ":")
	g.Protocols, g.DisabledProtocols, g.MinProtocol, g.MaxProtocol = cfgHAProtocols(bindDefaults)
	g.Policy = cfgSecLevel(g.CipherString)

	resolve := func(base, p string) string {
		if base != "" && !strings.HasPrefix(p, "/") && !strings.Contains(p, "@") {
			return path.Join(base, p)
		}
		return p
	}
	r := cfgHAResolver{resolve: resolve, caBase: caBase, crtBase: crtBase}

	var out []CryptoConfig
	add := func(c CryptoConfig) {
		if cfgHasContent(&c) && len(out) < cfgMaxList*4 {
			out = append(out, c)
		}
	}
	add(g)

	// A defaults section's default-server options apply to the sections
	// after it, until the next defaults section.
	var defaults cfgHAServerDefaults
	for _, s := range secs {
		switch s.kind {
		case "defaults":
			defaults = cfgHAServerDefaults{}
			defaults.add(s.lines)
			c := CryptoConfig{Product: "haproxy", Context: cfgContext("defaults " + s.name)}
			defaults.record(&c, "default-server", r)
			add(c)
		case "frontend", "listen":
			for _, f := range s.lines {
				if f[0] != "bind" || len(f) < 2 {
					continue
				}
				opts := cfgHAOptions(f[2:])
				hasSSL := false
				for _, o := range opts {
					if o.name == "ssl" {
						hasSSL = true
					}
				}
				if hasSSL {
					add(cfgHABind(s, f[1], opts, bindDefaults, [4]string{bindCiphers, bindSuites, bindCurves, bindSig}, r))
				}
			}
			if s.kind == "listen" {
				add(cfgHAServers(s, "listen "+s.name+" servers", defaults, r))
			}
		case "backend":
			add(cfgHAServers(s, "backend "+s.name, defaults, r))
		}
	}
	return out
}

func cfgHAOptNames(opts []cfgHAOpt) []string {
	var out []string
	for _, o := range opts {
		out = append(out, o.name)
		if o.val != "" {
			out = append(out, o.val)
		}
	}
	return out
}

type cfgHAResolver struct {
	resolve         func(base, p string) string
	caBase, crtBase string
}

func cfgHABind(s *cfgHASection, addr string, opts, defaults []cfgHAOpt, d [4]string, r cfgHAResolver) CryptoConfig {
	c := CryptoConfig{Product: "haproxy", Context: cfgContext(s.kind + " " + s.name + " bind " + addr)}
	if cfgIsBindAddr(addr) {
		cfgSet(&c, "bind", addr)
	}
	ciphers, suites, curves, sig := d[0], d[1], d[2], d[3]
	for _, o := range opts {
		switch o.name {
		case "ciphers":
			ciphers = o.val
		case "ciphersuites":
			suites = o.val
		case "curves":
			curves = o.val
		case "sigalgs":
			sig = o.val
		case "crt":
			p := r.resolve(r.crtBase, o.val)
			cfgRef(&c, "certificate", "bind crt", p)
			cfgRef(&c, "private_key", "bind crt", p)
		case "crt-list":
			cfgRef(&c, "include", "bind crt-list", r.resolve(r.crtBase, o.val))
		case "ca-file", "ca-verify-file":
			cfgRef(&c, "trust_store", "bind "+o.name, r.resolve(r.caBase, o.val))
		case "crl-file":
			cfgRef(&c, "crl", "bind crl-file", r.resolve(r.caBase, o.val))
		case "alpn":
			if cfgHAALPN(o.val) {
				cfgSet(&c, "alpn", o.val)
			}
		case "verify":
			cfgSetSimple(&c, "verify", o.val)
		case "strict-sni", "no-tls-tickets", "prefer-client-ciphers", "allow-0rtt":
			cfgSet(&c, o.name, "true")
		}
	}
	var protoText []cfgHAOpt
	for _, o := range opts {
		if strings.HasPrefix(o.name, "no-tlsv") || strings.HasPrefix(o.name, "no-sslv") ||
			strings.HasPrefix(o.name, "force-") || o.name == "ssl-min-ver" || o.name == "ssl-max-ver" {
			protoText = append(protoText, o)
		}
	}
	if len(protoText) > 0 {
		// The flags as written, since they may be ignored (no-* beside a bound).
		cfgSet(&c, "bind ssl-options", strings.Join(cfgHAOptNames(protoText), " "))
	}
	c.CipherString = cfgClip(ciphers)
	c.CipherSuites = cfgSplitList(suites, ":")
	c.Groups = cfgSplitList(curves, ":")
	c.SignatureAlgorithms = cfgSplitList(sig, ":")
	c.Policy = cfgSecLevel(ciphers)
	all := append(append([]cfgHAOpt(nil), defaults...), opts...)
	c.Protocols, c.DisabledProtocols, c.MinProtocol, c.MaxProtocol = cfgHAProtocols(all)
	return c
}

// cfgIsBindAddr says whether a bind address is the shape of one: no blanks
// or quotes, and no URI scheme.
func cfgIsBindAddr(a string) bool {
	if a == "" || len(a) > 128 || strings.ContainsAny(a, " \t\"'") {
		return false
	}
	_, scheme := cfgURIScheme(a)
	return !scheme
}

// cfgHAServerDefaults is the set of default-server options in force: a later
// one replaces an earlier one of the same name.
type cfgHAServerDefaults struct {
	byName map[string]cfgHAOpt
	order  []string
}

func (d *cfgHAServerDefaults) add(lines [][]string) {
	for _, f := range lines {
		if f[0] != "default-server" {
			continue
		}
		for _, o := range cfgHAOptions(f[1:]) {
			if d.byName == nil {
				d.byName = map[string]cfgHAOpt{}
			}
			if _, have := d.byName[o.name]; !have {
				if len(d.order) >= cfgHAMaxOptions {
					continue
				}
				d.order = append(d.order, o.name)
			}
			d.byName[o.name] = o
		}
	}
}

func (d cfgHAServerDefaults) opts() []cfgHAOpt {
	out := make([]cfgHAOpt, 0, len(d.order))
	for _, n := range d.order {
		out = append(out, d.byName[n])
	}
	return out
}

func (d cfgHAServerDefaults) record(c *CryptoConfig, who string, r cfgHAResolver) {
	cfgHAServer(c, who, d.opts(), r)
}

// cfgHAServers reads the `server`, `server-template` and `default-server`
// lines of a section. Defaults from an earlier defaults section start it; a
// default-server line in the section itself replaces by name.
func cfgHAServers(s *cfgHASection, context string, in cfgHAServerDefaults, r cfgHAResolver) CryptoConfig {
	c := CryptoConfig{Product: "haproxy", Context: cfgContext(context)}
	defs := cfgHAServerDefaults{order: append([]string(nil), in.order...), byName: map[string]cfgHAOpt{}}
	for k, v := range in.byName {
		defs.byName[k] = v
	}
	n := 0
	server := func(name string, own []cfgHAOpt) {
		n++
		who := "server." + strconv.Itoa(n)
		cfgHAServer(&c, who, cfgHAMerge(defs, own), r)
		if c.Settings[who+" ssl"] != "" {
			cfgSetSimple(&c, who+" name", name)
		}
	}
	for _, f := range s.lines {
		switch f[0] {
		case "default-server":
			defs.add([][]string{f})
			defs.record(&c, "default-server", r)
		case "server":
			// server <name> <addr> [options]
			if len(f) >= 3 {
				server(f[1], cfgHAOptions(f[3:]))
			}
		case "server-template":
			// server-template <prefix> <num> <addr> [options]
			if len(f) >= 4 {
				server(f[1], cfgHAOptions(f[4:]))
			}
		}
	}
	return c
}

// cfgHAMerge puts a server's own options over the defaults, by name.
func cfgHAMerge(d cfgHAServerDefaults, own []cfgHAOpt) []cfgHAOpt {
	if len(own) == 0 {
		return d.opts()
	}
	m := map[string]cfgHAOpt{}
	var order []string
	for _, n := range d.order {
		m[n] = d.byName[n]
		order = append(order, n)
	}
	for _, o := range own {
		if _, have := m[o.name]; !have {
			order = append(order, o.name)
		}
		m[o.name] = o
	}
	out := make([]cfgHAOpt, 0, len(order))
	for _, n := range order {
		out = append(out, m[n])
	}
	return out
}

// cfgHAServer records the TLS options of one server line, when it uses TLS.
func cfgHAServer(c *CryptoConfig, who string, opts []cfgHAOpt, r cfgHAResolver) {
	ssl := false
	for _, o := range opts {
		if o.name == "ssl" {
			ssl = true
		}
	}
	if !ssl {
		return
	}
	// who names the Settings ("server.3 verify"); the directive of a Reference
	// is the fixed word before the dot. A server's own name is a value, never
	// part of a key or a directive.
	kind := who
	if i := strings.IndexByte(who, '.'); i >= 0 {
		kind = who[:i]
	}
	cfgSet(c, who+" ssl", "true")
	for _, o := range opts {
		switch o.name {
		case "ssl":
		case "crt":
			p := r.resolve(r.crtBase, o.val)
			cfgRef(c, "certificate", kind+" crt", p)
			cfgRef(c, "private_key", kind+" crt", p)
		case "ca-file", "ca-verify-file":
			p := r.resolve(r.caBase, o.val)
			cfgRef(c, "trust_store", kind+" "+o.name, p)
			if cfgIsFSPath(p, false) {
				cfgSet(c, who+" "+o.name, p)
			}
		case "crl-file":
			cfgRef(c, "crl", kind+" crl-file", r.resolve(r.caBase, o.val))
		case "crt-list":
			cfgRef(c, "include", kind+" crt-list", r.resolve(r.crtBase, o.val))
		case "alpn":
			if cfgHAALPN(o.val) {
				cfgSet(c, who+" alpn", o.val)
			}
		case "ciphers", "ciphersuites", "curves", "sigalgs", "client-sigalgs":
			cfgSet(c, who+" "+o.name, o.val)
		default:
			v := o.val
			if v == "" {
				v = "true"
			}
			cfgSetSimple(c, who+" "+o.name, v)
		}
	}
}
