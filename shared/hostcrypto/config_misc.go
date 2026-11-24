package hostcrypto

import (
	"strings"
)

// Two small parsers: the system-wide GnuTLS configuration and Postfix's
// main.cf.

// cfgGnuTLSDeny are the [overrides] keys that name algorithms the library is
// told to refuse or to treat as insecure; their values feed
// DisabledAlgorithms.
var cfgGnuTLSDeny = map[string]bool{
	"insecure-sig": true, "insecure-sig-for-cert": true, "insecure-hash": true,
	"disabled-version": true, "disabled-curve": true, "disabled-sig": true,
	"disabled-hash": true, "tls-disabled-cipher": true, "tls-disabled-mac": true,
	"tls-disabled-group": true, "tls-disabled-kx": true,
}

// cfgGnuTLSAllow are the keys that name what is ENABLED, as RHEL 9's
// allowlist mode writes them (`override-mode = allowlist`): they fill the
// typed lists. secure-hash has no typed list (a hash is not a MAC) and stays
// in Settings.
var cfgGnuTLSAllow = map[string]bool{
	"tls-enabled-cipher": true, "tls-enabled-mac": true, "tls-enabled-group": true,
	"tls-enabled-kx": true, "enabled-version": true, "secure-sig": true,
	"secure-sig-for-cert": true, "secure-hash": true, "enabled-curve": true,
}

var cfgGnuTLSOther = map[string]bool{
	"tls-session-hash": true, "min-verification-profile": true, "allowlisting": true,
	"default-priority-string": true, "override-mode": true,
}

// cfgParseGnuTLS reads /etc/gnutls/config and the GnuTLS back-end of
// crypto-policies. Three layouts exist: a bare `SYSTEM=...` priority string
// with no section header (RHEL 8), `[priorities]` SYSTEM=, and `[overrides]`
// with deny lists or, in allowlist mode, the enabled lists. `[global]`
// override-mode says which.
func cfgParseGnuTLS(b []byte, _ IncludeResolver) []CryptoConfig {
	c := CryptoConfig{Product: "gnutls"}
	section := ""
	for _, ln := range cfgLogicalLines(b, "#", false) {
		s := strings.TrimSpace(cfgStripHash(ln.text))
		if s == "" {
			continue
		}
		if s[0] == '[' {
			if end := strings.IndexByte(s, ']'); end > 0 {
				section = strings.ToLower(strings.TrimSpace(s[1:end]))
			}
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		k, v = strings.TrimSpace(k), cfgUnquote(v)
		if !ok || k == "" {
			continue
		}
		switch section {
		case "", "priorities":
			if k == "SYSTEM" {
				c.Policy = cfgClip(v)
			}
		case "overrides", "global":
			lk := strings.ToLower(k)
			switch {
			case cfgGnuTLSDeny[lk]:
				cfgAppend(&c.DisabledAlgorithms, cfgSplitList(v, ", \t")...)
				cfgGnuTLSAccumulate(&c, lk, v)
			case cfgGnuTLSAllow[lk]:
				cfgGnuTLSAllowed(&c, lk, v)
				cfgGnuTLSAccumulate(&c, lk, v)
			case cfgGnuTLSOther[lk]:
				cfgGnuTLSAccumulate(&c, lk, v)
			}
		}
	}
	if !cfgHasContent(&c) {
		return nil
	}
	return []CryptoConfig{c}
}

func cfgGnuTLSAllowed(c *CryptoConfig, key, v string) {
	items := cfgSplitList(v, ", \t")
	switch key {
	case "tls-enabled-cipher":
		cfgAppend(&c.CipherSuites, items...)
	case "tls-enabled-mac":
		cfgAppend(&c.MACs, items...)
	case "tls-enabled-group", "enabled-curve":
		cfgAppend(&c.Groups, items...)
	case "tls-enabled-kx":
		cfgAppend(&c.KeyExchanges, items...)
	case "enabled-version":
		cfgAppend(&c.Protocols, cfgProtocolList(items)...)
	case "secure-sig", "secure-sig-for-cert":
		cfgAppend(&c.SignatureAlgorithms, items...)
	}
}

// cfgGnuTLSAccumulate keeps a repeatable key in Settings as a comma list,
// bounded: a key repeated 20,000 times must not copy a growing string 20,000
// times.
func cfgGnuTLSAccumulate(c *CryptoConfig, key, v string) {
	have := c.Settings[key]
	if len(have) >= cfgMaxValue {
		return
	}
	cfgSet(c, key, joinSetting(have, v))
}

// joinSetting accumulates a key that may be repeated (each line adds to it).
func joinSetting(have, add string) string {
	if have == "" {
		return add
	}
	return have + "," + add
}

// cfgParsePostfix reads main.cf. Postfix continues a line by indenting the
// next, "$name" refers to another parameter of the file, and the last
// definition wins.
//
// The server side (smtpd_*) and the client side (smtp_*) are separate
// entries, Context "smtpd" and "smtp". Within one side Postfix has an
// opportunistic setting (smtpd_tls_protocols) and a mandatory one
// (smtpd_tls_mandatory_protocols); the typed fields report the opportunistic
// one when it is set and the mandatory one otherwise, and Settings keeps both
// as written, so a reader can see the weaker of the two applies to sessions
// that are not required to be encrypted.
//
// Protocol lists come in two syntaxes: "!SSLv2, !SSLv3" (exclusions: they go
// to DisabledAlgorithms, since what remains depends on the library) and
// ">=TLSv1.2" / "<=TLSv1.3" (bounds: MinProtocol / MaxProtocol); a plain
// "TLSv1.2" is a protocol to allow.
func cfgParsePostfix(b []byte, _ IncludeResolver) []CryptoConfig {
	vals := map[string]string{}
	var order []string
	var pendKey string
	var pend []byte // the value being continued: appended to, then committed once
	commit := func() {
		if pendKey != "" {
			vals[pendKey] = string(pend)
		}
		pendKey, pend = "", pend[:0]
	}
	for _, ln := range cfgLogicalLines(b, "#", false) {
		t := ln.text
		trimmed := strings.TrimSpace(t)
		// Blank lines and comment lines do not end a continued value: a
		// later line that starts with whitespace still continues it.
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		if (t[0] == ' ' || t[0] == '\t') && pendKey != "" {
			if len(pend) < cfgMaxLogicalLine {
				pend = append(pend, ' ')
				pend = append(pend, strings.TrimSpace(t)...)
			}
			continue
		}
		commit()
		k, v, ok := strings.Cut(t, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			continue
		}
		if _, have := vals[k]; !have {
			if len(order) >= 4096 {
				continue
			}
			order = append(order, k)
		}
		pendKey = k
		pend = append(pend[:0], strings.TrimSpace(v)...)
	}
	commit()

	// Values are reported as written: "$name" is NOT expanded, because an
	// expansion could pull any parameter of the file (a relay password
	// included) into a field that is kept.
	val := func(name string) (string, bool) {
		v, ok := vals[name]
		return cfgClip(v), ok
	}

	globals := CryptoConfig{}
	for _, k := range cfgPostfixGlobals {
		if v, ok := val(k); ok {
			cfgSet(&globals, k, v)
		}
	}

	var out []CryptoConfig
	for _, side := range cfgPostfixSides {
		c := CryptoConfig{Product: "postfix", Context: side}
		protoKey := ""
		for _, suffix := range cfgPostfixProtocolSuffixes {
			k := side + suffix
			if v, ok := val(k); ok {
				cfgSet(&c, k, v)
				if protoKey == "" {
					protoKey = k
				}
			}
		}
		if protoKey != "" {
			cfgPostfixProtocols(&c, c.Settings[protoKey])
		}
		cipherSet := false
		for _, suffix := range cfgPostfixCipherSuffixes {
			k := side + suffix
			if v, ok := val(k); ok {
				cfgSet(&c, k, v)
				if !cipherSet {
					c.CipherString = v
					cipherSet = true
				}
			}
		}
		for _, suffix := range cfgPostfixExcludeSuffixes {
			k := side + suffix
			if v, ok := val(k); ok {
				cfgSet(&c, k, v)
				cfgAppend(&c.DisabledAlgorithms, cfgSplitList(v, ", \t:")...)
			}
		}
		for _, suffix := range cfgPostfixSimpleSuffixes {
			k := side + suffix
			if v, ok := val(k); ok {
				cfgSetSimple(&c, k, v)
			}
		}
		for _, r := range cfgPostfixRefSuffixes {
			if v, ok := val(side + r.suffix); ok {
				cfgRef(&c, r.kind, side+r.suffix, v)
			}
		}
		if cfgHasContent(&c) {
			for k, v := range globals.Settings {
				cfgSet(&c, k, v)
			}
			out = append(out, c)
		}
	}
	if len(out) == 0 && len(globals.Settings) > 0 {
		globals.Product, globals.Context = "postfix", "global"
		out = append(out, globals)
	}
	return out
}

// The parameters cfgParsePostfix reads: the global ones by name, the
// per-side ones as a side ("smtpd", "smtp") followed by a suffix. Each list
// is read in its order: the first of a pair that is set fills the typed
// field.
var (
	cfgPostfixGlobals = []string{"tls_high_cipherlist", "tls_medium_cipherlist", "tls_low_cipherlist",
		"tls_export_cipherlist", "tls_null_cipherlist", "tls_ssl_options", "tls_preempt_cipherlist",
		"tls_eecdh_strong_curve", "tls_eecdh_ultra_curve"}
	cfgPostfixSides            = []string{"smtpd", "smtp"}
	cfgPostfixProtocolSuffixes = []string{"_tls_protocols", "_tls_mandatory_protocols"}
	cfgPostfixCipherSuffixes   = []string{"_tls_ciphers", "_tls_mandatory_ciphers"}
	cfgPostfixExcludeSuffixes  = []string{"_tls_exclude_ciphers", "_tls_mandatory_exclude_ciphers"}
	cfgPostfixSimpleSuffixes   = []string{"_tls_security_level", "_tls_eecdh_grade", "_tls_fingerprint_digest"}
	cfgPostfixRefSuffixes      = []struct{ suffix, kind string }{
		{"_tls_cert_file", "certificate"}, {"_tls_key_file", "private_key"},
		{"_tls_eccert_file", "certificate"}, {"_tls_eckey_file", "private_key"},
		{"_tls_dcert_file", "certificate"}, {"_tls_dkey_file", "private_key"},
		{"_tls_CAfile", "trust_store"}, {"_tls_CApath", "trust_store"},
		{"_tls_dh1024_param_file", "dh_params"}, {"_tls_dh512_param_file", "dh_params"},
	}
)

func cfgPostfixProtocols(c *CryptoConfig, v string) {
	for _, item := range cfgSplitList(v, ", \t:") {
		switch {
		case strings.HasPrefix(item, "!"):
			cfgAppend(&c.DisabledProtocols, cfgProtocolOne(item[1:]))
		case strings.HasPrefix(item, ">="):
			c.MinProtocol = cfgProtocolOne(item[2:])
		case strings.HasPrefix(item, "<="):
			c.MaxProtocol = cfgProtocolOne(item[2:])
		default:
			cfgAppend(&c.Protocols, cfgProtocolOne(item))
		}
	}
}
