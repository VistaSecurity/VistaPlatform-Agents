package hostcrypto

import (
	"strings"
)

// MIT Kerberos krb5.conf, [libdefaults] only. [realms], [domain_realm],
// [capaths], [appdefaults] and the rest are dropped: they name hosts and
// principals, not cryptographic policy. A "REALM = { ... }" subsection INSIDE
// [libdefaults] is a per-realm override, not a global one, and is skipped.
//
// The first value of a relation wins, which is how MIT's profile library
// answers a lookup (profile_get_* returns the first match). I could not reach
// the MIT documentation from here to confirm it; it is the behaviour as I
// remember it, so a duplicate later in the file is ignored.
//
// Kept: the enctype lists (permitted_enctypes, default_tgs_enctypes,
// default_tkt_enctypes; the union goes to CipherSuites as enctype names, in
// that order, and each list is also kept as written in Settings),
// allow_weak_crypto, spake_preauth_groups (Groups), the credential-cache and
// keytab names (a FILE: keytab is a "keystore" reference; any other keytab or
// cache name is reduced to its type, such as KEYRING), the PKINIT anchors and
// identities when they are files, and include/includedir.
//
// With a resolver, include FILE and includedir DIR are read at their
// position (an includedir is passed as "DIR/*"). Each included file starts
// with no section, as MIT reads it, and the section in force before the
// include is restored after.
//
// Never kept: a PKINIT identity of the form PKCS11: or ENV: (a token PIN can
// ride in them), passwords of any kind, and anything under [realms].
//
// MIT Kerberos separates enctypes with blanks or commas.

func cfgParseKrb5(b []byte, include IncludeResolver) []CryptoConfig {
	c := CryptoConfig{Product: "krb5"}
	inc := newCfgIncl(include)
	seen := map[string]bool{}
	first := func(k string) bool {
		if seen[k] {
			return false
		}
		seen[k] = true
		return true
	}

	var load func(b []byte, depth int)
	load = func(b []byte, depth int) {
		section := ""
		sub := 0 // depth of a "REALM = {" subsection inside the section
		for _, ln := range cfgLogicalLines(b, "#;", false) {
			s := strings.TrimSpace(ln.text)
			if s == "" || s[0] == '#' || s[0] == ';' {
				continue
			}
			// include and includedir are directives of their own, valid anywhere.
			if kw, rest := cfgCut(s); strings.EqualFold(kw, "include") || strings.EqualFold(kw, "includedir") {
				kw = strings.ToLower(kw)
				target := cfgUnquote(rest)
				cfgRef(&c, "include", kw, target)
				pattern := target
				if kw == "includedir" {
					pattern = strings.TrimSuffix(target, "/") + "/*"
				}
				for _, f := range inc.get(pattern, depth) {
					if kw == "includedir" && !cfgKrb5DirFile(f.Path) {
						continue
					}
					inc.enter(f.Path)
					load(f.Text, depth+1)
					inc.leave()
				}
				continue
			}
			if s[0] == '[' {
				if end := strings.IndexByte(s, ']'); end > 0 {
					section = strings.ToLower(strings.TrimSpace(s[1:end]))
					sub = 0
				}
				continue
			}
			if section != "libdefaults" {
				continue
			}
			if s == "}" {
				if sub > 0 {
					sub--
				}
				continue
			}
			k, v, ok := strings.Cut(s, "=")
			k = strings.ToLower(strings.TrimSpace(k))
			if !ok {
				continue
			}
			v = cfgUnquote(v)
			if strings.HasSuffix(s, "{") {
				sub++
				continue
			}
			if sub > 0 {
				continue
			}
			cfgKrb5Relation(&c, k, v, first)
		}
	}
	load(b, 0)

	if !cfgHasContent(&c) {
		return nil
	}
	return []CryptoConfig{c}
}

func cfgKrb5Relation(c *CryptoConfig, k, v string, first func(string) bool) {
	switch k {
	case "permitted_enctypes", "default_tgs_enctypes", "default_tkt_enctypes":
		if first(k) {
			cfgAppend(&c.CipherSuites, cfgSplitList(v, " \t,")...)
			cfgSet(c, k, v)
		}
	case "allow_weak_crypto", "pkinit_eku_checking":
		if first(k) {
			cfgSetSimple(c, k, v)
		}
	case "spake_preauth_groups":
		if first(k) {
			cfgAppend(&c.Groups, cfgSplitList(v, " \t,")...)
		}
	case "default_ccache_name":
		if first(k) {
			if scheme, ok := cfgURIScheme(v); ok {
				cfgSet(c, k, scheme)
			}
		}
	case "default_keytab_name", "default_client_keytab_name":
		if first(k) {
			if p, ok := cfgKrb5File(v); ok {
				cfgRef(c, "keystore", k, p)
			} else {
				cfgRef(c, "keystore", k, v) // a non-FILE type: only its scheme survives
			}
		}
	case "pkinit_anchors":
		if first(k) {
			if kind, p, ok := cfgKrb5PKINIT(v); ok {
				cfgRef(c, kind, k, p)
			}
		}
	case "pkinit_identities":
		// FILE:cert,key or PKCS12:file; PKCS11 and ENV forms are dropped.
		if !first(k) {
			return
		}
		if rest, ok := cutPrefixFold(v, "FILE:"); ok {
			cert, key, _ := strings.Cut(rest, ",")
			cfgRef(c, "certificate", k, cert)
			cfgRef(c, "private_key", k, key)
		} else if rest, ok := cutPrefixFold(v, "PKCS12:"); ok {
			cfgRef(c, "keystore", k, rest)
		}
	}
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// cfgKrb5File returns the path of a FILE:/WRFILE: credential name, or of a
// bare absolute path.
func cfgKrb5File(v string) (string, bool) {
	for _, p := range []string{"FILE:", "WRFILE:"} {
		if rest, ok := cutPrefixFold(v, p); ok {
			return rest, true
		}
	}
	if strings.HasPrefix(v, "/") {
		return v, true
	}
	return "", false
}

func cfgKrb5PKINIT(v string) (kind, p string, ok bool) {
	if rest, ok := cutPrefixFold(v, "FILE:"); ok {
		return "trust_store", rest, true
	}
	if rest, ok := cutPrefixFold(v, "DIR:"); ok {
		return "trust_store", rest, true
	}
	return "", "", false
}

// cfgKrb5DirFile applies MIT's rule for includedir: a name that is entirely
// letters, digits, dashes and underscores, or that ends in ".conf"; never a
// name that starts with a dot.
func cfgKrb5DirFile(p string) bool {
	name := p
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		name = p[i+1:]
	}
	if name == "" || name[0] == '.' {
		return false
	}
	if strings.HasSuffix(name, ".conf") {
		return true
	}
	for i := 0; i < len(name); i++ {
		if !cfgIsAlnum(name[i]) && name[i] != '-' && name[i] != '_' {
			return false
		}
	}
	return true
}
