package hostcrypto

import (
	"strings"
)

// OpenSSL's configuration file (openssl.cnf): INI-like sections and
// ".include". What a host's OpenSSL clients and servers negotiate by default
// is decided in one place, reached by a chain: the default section's
// openssl_conf names an init section; its ssl_conf names a section of named
// SSL configurations; ONLY `system_default` is host-wide (any other name is an
// application's own, which a host report must not mistake for the host's);
// and the section it names holds MinProtocol, CipherString and the rest.
// With no such chain there is no typed policy, but the providers (and so
// FIPS) are still reported.
//
// Values are reported AS WRITTEN. "$var" and "${section::var}" are NOT
// expanded: an expansion can pull any value of the file, [req]
// input_password included, into a field that is kept. The one cost is that a
// path written "$dir/ca.pem" stays that way.
//
// Includes are recorded and, when the caller supplies a resolver, read in
// place: the included keys join the section the include stands in.
//
// The allowlist: the SSL_CONF keys below; the section names that reach them;
// the providers section, whose activated members matter only when the name
// is a known provider (a key is a name the file's author chose, so an
// unknown one is not repeated); the engines section's known names;
// ".include". [req] and [ca] hold passwords and private-key paths and are
// never read.

type cfgOSSLSection struct {
	name string
	keys []string
	vals map[string]string
}

func (s *cfgOSSLSection) set(k, v string) {
	if _, have := s.vals[k]; !have {
		if len(s.keys) >= 1024 {
			return
		}
		s.keys = append(s.keys, k)
	}
	s.vals[k] = v
}

// ci reads a key case-insensitively (SSL_CONF command names are).
func (s *cfgOSSLSection) ci(names ...string) (string, bool) {
	for _, want := range names {
		if v, ok := s.vals[want]; ok {
			return v, true
		}
	}
	for _, want := range names {
		for _, k := range s.keys {
			if strings.EqualFold(k, want) {
				return s.vals[k], true
			}
		}
	}
	return "", false
}

var cfgOSSLProviders = map[string]bool{
	"default": true, "base": true, "legacy": true, "fips": true, "null": true,
	"pkcs11": true, "tpm2": true, "oqsprovider": true, "oqs": true, "gost": true,
	"ibmca": true, "gmssl": true,
}

var cfgOSSLEngines = map[string]bool{
	"pkcs11": true, "capi": true, "afalg": true, "dasync": true, "padlock": true,
	"devcrypto": true, "gost": true, "ibmca": true, "qat": true, "qatengine": true,
	"tpm2tss": true, "tpm2": true,
}

// cfgOSSLFile is a loaded file: its sections and its include patterns.
type cfgOSSLFile struct {
	secs     map[string]*cfgOSSLSection
	global   *cfgOSSLSection
	includes []string
}

func cfgOSSLLoad(b []byte, inc *cfgIncl) *cfgOSSLFile {
	f := &cfgOSSLFile{secs: map[string]*cfgOSSLSection{}}
	get := func(name string) *cfgOSSLSection {
		if strings.EqualFold(name, "default") {
			name = "" // an explicit [default] is the default section
		}
		if s, ok := f.secs[name]; ok {
			return s
		}
		s := &cfgOSSLSection{name: name, vals: map[string]string{}}
		if len(f.secs) < 4096 {
			f.secs[name] = s
		}
		return s
	}
	f.global = get("")
	cur := f.global

	var load func(b []byte, depth int)
	load = func(b []byte, depth int) {
		for _, ln := range cfgLogicalLines(b, "#", true) {
			s := strings.TrimSpace(cfgStripHash(ln.text))
			if s == "" {
				continue
			}
			if s[0] == '[' {
				if end := strings.IndexByte(s, ']'); end > 0 {
					cur = get(strings.TrimSpace(s[1:end]))
				}
				continue
			}
			if s[0] == '.' {
				name, rest := cfgCut(s[1:])
				if i := strings.IndexByte(name, '='); i >= 0 {
					name, rest = name[:i], name[i:]+" "+rest
				}
				if strings.EqualFold(name, "include") {
					rest = strings.TrimSpace(rest)
					rest = cfgUnquote(strings.TrimSpace(strings.TrimPrefix(rest, "=")))
					if len(f.includes) < cfgMaxRefs {
						f.includes = append(f.includes, rest)
					}
					// An included file is read as if its text stood here, so
					// the section it leaves current stays current after it.
					for _, inf := range inc.get(rest, depth) {
						inc.enter(inf.Path)
						load(inf.Text, depth+1)
						inc.leave()
					}
				}
				continue
			}
			k, v, ok := strings.Cut(s, "=")
			k = strings.TrimSpace(k)
			if !ok || k == "" {
				continue
			}
			cur.set(k, cfgUnquote(v))
		}
	}
	load(b, 0)
	return f
}

// cfgOSSLInit finds the init section, the one openssl_conf names.
func (f *cfgOSSLFile) init() *cfgOSSLSection {
	if name, ok := f.global.ci("openssl_conf"); ok {
		if s := f.secs[name]; s != nil {
			return s
		}
	}
	return f.global
}

func cfgParseOpenSSL(b []byte, include IncludeResolver) []CryptoConfig {
	f := cfgOSSLLoad(b, newCfgIncl(include))
	holder := f.init()

	// The SSL section that applies to every application: system_default only.
	var eff *cfgOSSLSection
	if name, ok := holder.ci("ssl_conf"); ok {
		if ssl := f.secs[name]; ssl != nil {
			if sd, ok := ssl.vals["system_default"]; ok {
				eff = f.secs[sd]
			}
		}
	}

	c := CryptoConfig{Product: "openssl"}
	if eff != nil {
		c.Context = cfgContext(eff.name)
		cfgOSSLApplySSL(&c, eff)
	}
	cfgOSSLProvidersAndEngines(&c, f, holder)
	for _, inc := range f.includes {
		cfgRef(&c, "include", ".include", inc)
	}
	if !cfgHasContent(&c) {
		return nil
	}
	return []CryptoConfig{c}
}

// cfgOSSLFragment reads a file that is only the SSL keys (the
// crypto-policies back-ends/opensslcnf.config), where the default section IS
// the system_default section.
func cfgOSSLFragment(b []byte, include IncludeResolver) []CryptoConfig {
	f := cfgOSSLLoad(b, newCfgIncl(include))
	c := CryptoConfig{Product: "openssl"}
	cfgOSSLApplySSL(&c, f.global)
	// openssl_fips.config says "activate = 1" but exists on every host and is
	// read only once FIPS mode is on, so it never sets FIPS: the value is kept
	// as written, and what turns FIPS on is Protection.FIPSMode.
	if s := f.secs["fips_sect"]; s != nil {
		if a, ok := s.ci("activate"); ok {
			cfgSetSimple(&c, "fips_sect activate", a)
		}
	}
	for _, inc := range f.includes {
		cfgRef(&c, "include", ".include", inc)
	}
	if !cfgHasContent(&c) {
		return nil
	}
	return []CryptoConfig{c}
}

func cfgOSSLApplySSL(c *CryptoConfig, eff *cfgOSSLSection) {
	val := func(names ...string) (string, bool) {
		v, ok := eff.ci(names...)
		return cfgClip(v), ok
	}
	minP, maxP := "", ""
	if v, ok := val("TLS.MinProtocol"); ok {
		minP = v
	} else if v, ok := val("MinProtocol"); ok {
		minP = v
	}
	if v, ok := val("TLS.MaxProtocol"); ok {
		maxP = v
	} else if v, ok := val("MaxProtocol"); ok {
		maxP = v
	}
	c.MinProtocol = cfgProtocolOne(minP)
	c.MaxProtocol = cfgProtocolOne(maxP)
	if v, ok := val("DTLS.MinProtocol"); ok {
		cfgSet(c, "DTLS.MinProtocol", cfgProtocolOne(v))
	}
	if v, ok := val("DTLS.MaxProtocol"); ok {
		cfgSet(c, "DTLS.MaxProtocol", cfgProtocolOne(v))
	}
	if v, ok := val("CipherString"); ok {
		c.CipherString = v
		c.Policy = cfgSecLevel(v)
	}
	if v, ok := val("Ciphersuites"); ok {
		c.CipherSuites = cfgSplitList(v, ":")
	}
	if v, ok := val("Groups", "Curves"); ok {
		c.Groups = cfgSplitList(v, ":")
	}
	if v, ok := val("SignatureAlgorithms"); ok {
		c.SignatureAlgorithms = cfgSplitList(v, ":")
	}
	for _, n := range []string{"ClientSignatureAlgorithms", "Options", "Protocol", "VerifyMode"} {
		if v, ok := val(n); ok {
			cfgSet(c, n, v)
		}
	}
	for _, r := range []struct{ key, kind string }{
		{"Certificate", "certificate"}, {"PrivateKey", "private_key"},
		{"ChainCAFile", "trust_store"}, {"ChainCAPath", "trust_store"},
		{"VerifyCAFile", "trust_store"}, {"VerifyCAPath", "trust_store"},
		{"RequestCAFile", "trust_store"}, {"RequestCAPath", "trust_store"},
		{"DHParameters", "dh_params"},
	} {
		if v, ok := val(r.key); ok {
			cfgRef(c, r.kind, r.key, v)
		}
	}
}

func cfgOSSLProvidersAndEngines(c *CryptoConfig, f *cfgOSSLFile, holder *cfgOSSLSection) {
	if pn, ok := holder.ci("providers"); ok {
		if ps := f.secs[pn]; ps != nil {
			var active []string
			for _, name := range ps.keys {
				s := f.secs[ps.vals[name]]
				if s == nil || !cfgOSSLProviders[strings.ToLower(name)] {
					continue
				}
				if a, ok := s.ci("activate"); ok {
					if on, ok := cfgBoolWord(a); ok && on {
						cfgAppend(&active, name)
						if strings.EqualFold(name, "fips") {
							c.FIPS = cfgBoolPtr(true)
						}
					}
				}
			}
			if len(active) > 0 {
				cfgSet(c, "providers", strings.Join(active, ","))
			}
		}
	}
	if an, ok := holder.ci("alg_section"); ok {
		if as := f.secs[an]; as != nil {
			if dp, ok := as.ci("default_properties"); ok && cfgPropertiesRequireFIPS(dp) {
				c.FIPS = cfgBoolPtr(true)
			}
		}
	}
	if en, ok := holder.ci("engines"); ok {
		if es := f.secs[en]; es != nil {
			var names []string
			for _, k := range es.keys {
				if cfgOSSLEngines[strings.ToLower(k)] {
					cfgAppend(&names, k)
				}
			}
			if len(names) > 0 {
				cfgSet(c, "engines", strings.Join(names, ","))
			}
		}
	}
}

// cfgProtocolOne normalises one protocol name, keeping an unknown one.
func cfgProtocolOne(s string) string {
	s = strings.TrimSpace(s)
	if v, ok := cfgNormaliseProtocol(s); ok {
		return v
	}
	return cfgClip(s)
}

// cfgSecLevel finds "@SECLEVEL=n" in a cipher string.
func cfgSecLevel(cipherString string) string {
	i := strings.Index(strings.ToUpper(cipherString), "@SECLEVEL=")
	if i < 0 {
		return ""
	}
	j := i + len("@SECLEVEL=")
	k := j
	for k < len(cipherString) && cipherString[k] >= '0' && cipherString[k] <= '9' {
		k++
	}
	if k == j {
		return ""
	}
	return "SECLEVEL=" + cipherString[j:k]
}

// cfgPropertiesRequireFIPS reads an OpenSSL property query. "fips=yes" is a
// requirement; "?fips=yes" is only a preference and does not turn FIPS on.
func cfgPropertiesRequireFIPS(q string) bool {
	for _, p := range strings.Split(q, ",") {
		p = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(p)), " ", "")
		if p == "fips=yes" || p == "fips=1" || p == "fips=true" {
			return true
		}
	}
	return false
}
