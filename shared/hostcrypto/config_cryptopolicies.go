package hostcrypto

import (
	"path"
	"strings"
)

// RHEL, Fedora and derivatives set one cryptographic policy for the whole
// host with crypto-policies: /etc/crypto-policies/config names it ("DEFAULT",
// "FIPS", "DEFAULT:SHA1"), and `update-crypto-policies` generates one file per
// consumer under /etc/crypto-policies/back-ends/ which OpenSSL, OpenSSH,
// GnuTLS, the JDK, NSS and Kerberos then read. The generated files are the
// policy as it takes effect; the name is only its label.
//
// Debian and Ubuntu have no equivalent: each package carries its own
// settings, and the parsers for those files cover them.
//
// The Policy field reports the name as written. FIPS is NOT set from a policy
// named "FIPS": the policy selects FIPS-compatible algorithms, it does not
// turn the kernel's FIPS mode on, and a report that said otherwise would
// overstate it. The kernel's switch is Protection.FIPSMode.

// cfgParseCryptoPoliciesConfig reads /etc/crypto-policies/config (or
// state/current): the first line that is not a comment is the policy.
func cfgParseCryptoPoliciesConfig(b []byte, _ IncludeResolver) []CryptoConfig {
	for _, ln := range cfgLogicalLines(b, "#", false) {
		s := strings.TrimSpace(cfgStripHash(ln.text))
		if s == "" {
			continue
		}
		// A policy name is letters, digits and ":_+.-"; anything else is not one.
		if len(s) > 256 || strings.Trim(s, ":_+.-") == "" {
			return nil
		}
		for i := 0; i < len(s); i++ {
			if !cfgIsAlnum(s[i]) && !strings.ContainsRune(":_+.-", rune(s[i])) {
				return nil
			}
		}
		return []CryptoConfig{{Product: "crypto-policies", Policy: s}}
	}
	return nil
}

// ParseCryptoPolicyBackend parses one generated back-end file of
// crypto-policies, chosen by its file name ("opensslcnf.config",
// "opensshserver.config", "openssh", "libssh", "openssl", "openssl_fips",
// "gnutls.config", "java.config", "javasystem", "nss.config", "krb5.config";
// a directory part and the ".config" suffix are ignored). The result carries Product "crypto-policies" and the Context
// "back-end <name>" (followed by the parser's own context, if it has one), so
// a reader sees both what set the policy and which consumer it is for. A name
// with no parser returns nil.
func ParseCryptoPolicyBackend(name string, b []byte) []CryptoConfig {
	base := strings.TrimSuffix(path.Base(strings.ReplaceAll(name, "\\", "/")), ".config")
	var cfgs []CryptoConfig
	switch base {
	case "opensslcnf", "openssl_fips":
		cfgs = cfgOSSLFragment(b, nil)
	case "openssl":
		// The whole file is one bare cipher string: "@SECLEVEL=2:kEECDH:...".
		cfgs = cfgBareCipherString(b)
	case "openssh", "libssh":
		cfgs = cfgParseSSH(cfgCPOpenSSHOptions(b), "ssh", true, nil)
	case "opensshserver":
		cfgs = cfgParseSSH(cfgCPOpenSSHOptions(b), "sshd", false, nil)
	case "gnutls":
		cfgs = cfgParseGnuTLS(b, nil)
	case "java", "javasystem":
		cfgs = cfgParseJava(b, nil)
	case "nss":
		cfgs = cfgParseNSSPolicy(b)
	case "krb5":
		cfgs = cfgParseKrb5(b, nil)
	default:
		return nil
	}
	for i := range cfgs {
		ctx := "back-end " + base
		if cfgs[i].Context != "" {
			ctx += " " + cfgs[i].Context
		}
		cfgs[i].Product = "crypto-policies"
		cfgs[i].Context = cfgClip(ctx)
	}
	return cfgs
}

// cfgCPOpenSSHOptions turns the older back-end spelling
//
//	CRYPTO_POLICY='-oCiphers=a,b -oMACs=c'
//
// into the keyword lines the SSH parser reads. Other lines pass through.
func cfgCPOpenSSHOptions(b []byte) []byte {
	var out strings.Builder
	for _, ln := range cfgLogicalLines(b, "#", true) {
		t := strings.TrimSpace(ln.text)
		rest, ok := strings.CutPrefix(t, "CRYPTO_POLICY=")
		if !ok {
			out.WriteString(t)
			out.WriteByte('\n')
			continue
		}
		for _, f := range strings.Fields(cfgUnquote(rest)) {
			if o, ok := strings.CutPrefix(f, "-o"); ok {
				if k, v, ok := strings.Cut(o, "="); ok {
					out.WriteString(k + " " + v + "\n")
				}
			}
		}
	}
	return []byte(out.String())
}

// cfgParseNSSPolicy reads nss.config: key=value lines, of which `config` is
// the policy string ("disallow=ALL allow=HMAC-SHA256:..:tls-version-min=tls1.2").
func cfgParseNSSPolicy(b []byte) []CryptoConfig {
	c := CryptoConfig{Product: "nss"}
	for _, ln := range cfgLogicalLines(b, "#", false) {
		k, v, ok := strings.Cut(strings.TrimSpace(ln.text), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "config") {
			continue
		}
		v = cfgUnquote(v)
		cfgSet(&c, "config", v)
		for _, f := range strings.Fields(v) {
			for _, part := range strings.Split(f, ":") {
				name, val, ok := strings.Cut(part, "=")
				if !ok {
					continue
				}
				switch strings.ToLower(name) {
				case "tls-version-min":
					c.MinProtocol = cfgProtocolOne(val)
				case "tls-version-max":
					c.MaxProtocol = cfgProtocolOne(val)
				case "dtls-version-min":
					cfgSet(&c, "dtls-version-min", cfgProtocolOne(val))
				case "dtls-version-max":
					cfgSet(&c, "dtls-version-max", cfgProtocolOne(val))
				}
			}
		}
	}
	if !cfgHasContent(&c) {
		return nil
	}
	return []CryptoConfig{c}
}

// cfgBareCipherString reads a file that holds one OpenSSL cipher string and
// nothing else (crypto-policies' back-ends/openssl.config).
func cfgBareCipherString(b []byte) []CryptoConfig {
	for _, ln := range cfgLogicalLines(b, "#", false) {
		t := strings.TrimSpace(ln.text)
		if t == "" || t[0] == '#' {
			continue
		}
		if strings.ContainsAny(t, " \t\"'`;|&$") {
			return nil
		}
		c := CryptoConfig{Product: "openssl", CipherString: cfgClip(t), Policy: cfgSecLevel(t)}
		return []CryptoConfig{c}
	}
	return nil
}
