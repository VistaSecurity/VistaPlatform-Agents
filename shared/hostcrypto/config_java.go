package hostcrypto

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
)

// java.security (the JDK's security properties file) and, as a second entry,
// the -D options of a JVM command line. Properties format: "#" and "!"
// comment lines, backslash continuations, key and value split by the first
// unescaped "=", ":" or blank. The last definition of a property wins, as in
// java.util.Properties.
//
// The allowlist is the exactly named properties below, "security.provider.N"
// and "fips.provider.N" (N one to three digits). Everything else, including every keystore or truststore
// password property, is dropped: a java.security file does not normally
// carry one, a JVM command line often does, and neither may reach a report.

// jdk.tls.disabledAlgorithms is the ONLY property that feeds
// DisabledAlgorithms: it is the TLS deny list. The certificate-path, jar and
// legacy lists mean something else (a certificate chain check; a jar check;
// "allowed but discouraged") and stay in Settings under their own names, so a
// reader cannot mistake "legacy" for "disabled".
//
// An entry "include jdk.disabled.namedCurves" inside a list is resolved to
// the items of that property, which is how JDK 17+ ships the curve deny list.
var cfgJavaSettingProps = []string{
	"jdk.certpath.disabledAlgorithms", "jdk.jar.disabledAlgorithms",
	"jdk.security.legacyAlgorithms", "jdk.tls.legacyAlgorithms",
	"jdk.disabled.namedCurves", "jdk.tls.keyLimits", "keystore.type", "keystore.type.compat",
	"securerandom.strongAlgorithms", "jdk.tls.namedGroups",
	"jdk.tls.client.protocols", "jdk.tls.server.protocols", "crypto.policy",
	"security.useSystemPropertiesFile", "security.overridePropertiesFile",
	"jdk.tls.ephemeralDHKeySize", "jdk.tls.server.defaultDHEParameters",
	"fips.keystore.type",
}

// The numbered provider families: a prefix followed by 1 to 3 digits.
const (
	cfgJavaProviderPrefix     = "security.provider."
	cfgJavaFIPSProviderPrefix = "fips.provider."
)

// cfgNumbered reports whether name is prefix followed by 1 to 3 digits and
// nothing else: the strict anchored form of a numbered family
// ("security.provider.12").
func cfgNumbered(name, prefix string) (int, bool) {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || rest == "" || len(rest) > 3 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return 0, false
		}
		n = n*10 + int(rest[i]-'0')
	}
	return n, true
}

// cfgJavaProvider keeps the provider's name and drops its arguments: a
// SunPKCS11 line can carry an inline configuration, with a PIN.
func cfgJavaProvider(v string) string {
	w := strings.Fields(v)
	if len(w) == 0 {
		return ""
	}
	for i := 0; i < len(w[0]); i++ {
		c := w[0][i]
		if !cfgIsAlnum(c) && !strings.ContainsRune("._$-", rune(c)) {
			return ""
		}
	}
	return w[0]
}

// cfgJavaFileURL accepts the securerandom.source forms: a file: URL naming a
// path, or a plain word (an egd: URL is cut to its scheme by the caller).
func cfgJavaSource(v string) string {
	if rest, ok := strings.CutPrefix(v, "file:"); ok {
		if cfgIsFSPath(rest, false) {
			return v
		}
		return ""
	}
	if scheme, ok := cfgURIScheme(v); ok {
		return scheme + ":"
	}
	return ""
}

func cfgPropSplit(s string) (k, v string, ok bool) {
	s = strings.TrimLeft(s, " \t\f")
	if s == "" {
		return "", "", false
	}
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if c == '=' || c == ':' || c == ' ' || c == '\t' || c == '\f' {
			break
		}
		i++
	}
	k = s[:i]
	rest := strings.TrimLeft(s[i:], " \t\f")
	if rest != "" && (rest[0] == '=' || rest[0] == ':') {
		rest = strings.TrimLeft(rest[1:], " \t\f")
	}
	return k, strings.TrimSpace(rest), true
}

// cfgJavaLines splits properties text the way java.util.Properties does: a
// line ends at "\n", "\r" or "\r\n", each by itself. cfgLogicalLines knows
// only "\n" (a "\r" it keeps is stripped at the end of a line), so a lone "\r"
// would otherwise hide a following property inside the value of the previous
// one, and a reader that splits there would then keep what we dropped.
func cfgJavaLines(b []byte) []cfgLine {
	if bytes.IndexByte(b, '\r') >= 0 {
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		b = bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
	}
	return cfgLogicalLines(b, "#!", true)
}

func cfgParseJava(b []byte, include IncludeResolver) []CryptoConfig {
	props := map[string]string{}
	inc := newCfgIncl(include)
	var includes []string
	var load func(b []byte, depth int)
	load = func(b []byte, depth int) {
		for _, ln := range cfgJavaLines(b) {
			t := strings.TrimLeft(ln.text, " \t\f")
			if t == "" || t[0] == '#' || t[0] == '!' {
				continue
			}
			k, v, ok := cfgPropSplit(t)
			if !ok || k == "" {
				continue
			}
			// JDK 24 and later: "include <file>" reads another security file
			// at this point, so a later definition still wins.
			if k == "include" {
				if len(includes) < cfgMaxRefs {
					includes = append(includes, v)
				}
				for _, f := range inc.get(v, depth) {
					inc.enter(f.Path)
					load(f.Text, depth+1)
					inc.leave()
				}
				continue
			}
			props[k] = v
		}
	}
	load(b, 0)
	c := CryptoConfig{Product: "java"}
	for _, p := range includes {
		cfgRef(&c, "include", "include", p)
	}

	if v, ok := props["jdk.tls.disabledAlgorithms"]; ok {
		cfgAppend(&c.DisabledAlgorithms, cfgJavaExpandIncludes(cfgSplitList(v, ","), props)...)
		cfgSet(&c, "jdk.tls.disabledAlgorithms", v)
	}
	for _, name := range cfgJavaSettingProps {
		if v, ok := props[name]; ok {
			cfgSet(&c, name, v)
		}
	}
	if v, ok := props["securerandom.source"]; ok {
		if src := cfgJavaSource(v); src != "" {
			cfgSet(&c, "securerandom.source", src)
		}
	}
	if v, ok := props["jdk.tls.namedGroups"]; ok {
		cfgAppend(&c.Groups, cfgSplitList(v, ",")...)
	}
	for _, name := range []string{"jdk.tls.client.protocols", "jdk.tls.server.protocols"} {
		if v, ok := props[name]; ok {
			cfgAppend(&c.Protocols, cfgProtocolList(cfgSplitList(v, ","))...)
		}
	}
	if v, ok := props["crypto.policy"]; ok {
		c.Policy = cfgClip(v)
	}
	if v, ok := props["com.redhat.fips"]; ok {
		if on, ok := cfgBoolWord(v); ok {
			c.FIPS = cfgBoolPtr(on)
			cfgSet(&c, "com.redhat.fips", strconv.FormatBool(on))
		}
	}

	// The provider lists are ordered by their number, not by the file.
	type prov struct {
		n int
		v string
	}
	var provs, fipsProvs []prov
	for k, v := range props {
		if n, ok := cfgNumbered(k, cfgJavaProviderPrefix); ok {
			provs = append(provs, prov{n, v})
		}
		if n, ok := cfgNumbered(k, cfgJavaFIPSProviderPrefix); ok {
			fipsProvs = append(fipsProvs, prov{n, v})
		}
	}
	for _, g := range []struct {
		list []prov
		name string
	}{{provs, "providers"}, {fipsProvs, "fips.providers"}} {
		sort.Slice(g.list, func(i, j int) bool { return g.list[i].n < g.list[j].n })
		var names []string
		for _, p := range g.list {
			if w := cfgJavaProvider(p.v); w != "" && len(names) < cfgMaxList {
				names = append(names, w)
			}
		}
		if len(names) > 0 {
			cfgSet(&c, g.name, strings.Join(names, ","))
		}
	}

	if !cfgHasContent(&c) {
		return nil
	}
	return []CryptoConfig{c}
}

// cfgJavaExpandIncludes replaces "include jdk.disabled.namedCurves" by the
// items of that property. Only that property is resolved, and not
// recursively.
func cfgJavaExpandIncludes(items []string, props map[string]string) []string {
	var out []string
	for _, it := range items {
		if name, ok := strings.CutPrefix(it, "include "); ok && strings.TrimSpace(name) == "jdk.disabled.namedCurves" {
			if curves, have := props["jdk.disabled.namedCurves"]; have {
				out = append(out, cfgSplitList(curves, ",")...)
				continue
			}
		}
		out = append(out, it)
	}
	return out
}

// cfgParseJavaOptions reads the -D options of a JVM command line, a
// jvm.options file or a JAVA_OPTS="..." shell line. A value containing a
// blank is not supported (the option is cut at the blank), which loses a path
// with a space but never mis-reads a neighbouring option.
func cfgParseJavaOptions(b []byte, _ IncludeResolver) []CryptoConfig {
	c := CryptoConfig{Product: "java", Context: "jvm-options"}
	for _, ln := range cfgLogicalLines(b, "#", true) {
		t := strings.TrimSpace(ln.text)
		if t == "" || t[0] == '#' {
			continue
		}
		t = strings.NewReplacer(`"`, " ", `'`, " ").Replace(t)
		for _, tok := range strings.Fields(t) {
			if !strings.HasPrefix(tok, "-D") {
				i := strings.Index(tok, "=-D")
				if i < 0 {
					continue
				}
				tok = tok[i+1:]
			}
			name, val, ok := strings.Cut(tok[2:], "=")
			if !ok {
				continue
			}
			cfgJavaOption(&c, name, val)
		}
	}
	if !cfgHasContent(&c) {
		return nil
	}
	return []CryptoConfig{c}
}

// cfgJavaOption applies one allowlisted -D property.
func cfgJavaOption(c *CryptoConfig, name, val string) {
	switch name {
	case "javax.net.ssl.keyStore":
		cfgRef(c, "keystore", "-D"+name, val)
	case "javax.net.ssl.trustStore":
		cfgRef(c, "trust_store", "-D"+name, val)
	case "java.security.properties":
		cfgRef(c, "include", "-D"+name, strings.TrimPrefix(val, "="))
	case "javax.net.ssl.keyStoreType", "javax.net.ssl.trustStoreType",
		"javax.net.ssl.keyStoreProvider", "javax.net.ssl.trustStoreProvider",
		"com.sun.net.ssl.checkRevocation", "com.sun.security.enableCRLDP",
		"jdk.tls.rejectClientInitiatedRenegotiation", "jdk.tls.allowLegacyResumption":
		cfgSetSimple(c, name, val)
	case "https.protocols", "jdk.tls.client.protocols", "jdk.tls.server.protocols":
		cfgSet(c, name, val)
		cfgAppend(&c.Protocols, cfgProtocolList(cfgSplitList(val, ","))...)
	case "jdk.tls.client.cipherSuites", "jdk.tls.server.cipherSuites":
		cfgSet(c, name, val)
		cfgAppend(&c.CipherSuites, cfgSplitList(val, ",")...)
	case "jdk.tls.namedGroups":
		cfgAppend(&c.Groups, cfgSplitList(val, ",")...)
	case "jdk.tls.disabledAlgorithms":
		cfgSet(c, name, val)
		cfgAppend(&c.DisabledAlgorithms, cfgSplitList(val, ",")...)
	case "com.redhat.fips":
		if on, ok := cfgBoolWord(val); ok {
			c.FIPS = cfgBoolPtr(on)
		}
	}
}
