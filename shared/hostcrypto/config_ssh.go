package hostcrypto

import (
	"strings"
)

// OpenSSH's sshd_config (product "sshd") and ssh_config (product "ssh").
//
// Keywords are case-insensitive, the value follows blanks or an "=", and the
// FIRST value of a keyword wins (both programs say so), except for the
// keywords that may repeat (HostKey, IdentityFile, Include...). A "Match"
// (both) or "Host" (ssh_config) line starts a block that runs to the next
// such line; each block becomes its own CryptoConfig with the criteria as its
// Context, the part before the first block (the global part) first.
//
// A "Match exec" criterion names a command, which can say anything, so the
// Context keeps the word "exec" and drops the command.
//
// The OpenSSH algorithm lists keep the "+", "-" and "^" prefixes as written:
// "+aes128-cbc" means "the default plus aes128-cbc", which is not the list
// "aes128-cbc", and a consumer must be able to tell.
//
// Not kept, by design: AuthorizedKeysCommand, ProxyCommand, LocalCommand,
// SetEnv, Banner, Subsystem and every keyword not named below.

var cfgSSHSettings = map[string]string{
	"requiredrsasize":                 "RequiredRSASize",
	"fingerprinthash":                 "FingerprintHash",
	"rekeylimit":                      "RekeyLimit",
	"passwordauthentication":          "PasswordAuthentication",
	"pubkeyauthentication":            "PubkeyAuthentication",
	"permitrootlogin":                 "PermitRootLogin",
	"kbdinteractiveauthentication":    "KbdInteractiveAuthentication",
	"challengeresponseauthentication": "ChallengeResponseAuthentication",
	"gssapiauthentication":            "GSSAPIAuthentication",
	"gssapikexalgorithms":             "GSSAPIKexAlgorithms",
	"stricthostkeychecking":           "StrictHostKeyChecking",
	"updatehostkeys":                  "UpdateHostKeys",
	"verifyhostkeydns":                "VerifyHostKeyDNS",
	"hostbasedacceptedalgorithms":     "HostbasedAcceptedAlgorithms",
	"hostbasedacceptedkeytypes":       "HostbasedAcceptedKeyTypes",
	"authorizedkeysfile":              "AuthorizedKeysFile",
	"userknownhostsfile":              "UserKnownHostsFile",
	"globalknownhostsfile":            "GlobalKnownHostsFile",
	"pkcs11provider":                  "PKCS11Provider",
	"securitykeyprovider":             "SecurityKeyProvider",
}

var cfgSSHPathSettings = map[string]bool{
	"authorizedkeysfile": true, "userknownhostsfile": true, "globalknownhostsfile": true,
	"pkcs11provider": true, "securitykeyprovider": true,
}

func cfgParseSSHD(b []byte, include IncludeResolver) []CryptoConfig {
	return cfgParseSSH(b, "sshd", false, include)
}
func cfgParseSSHClient(b []byte, include IncludeResolver) []CryptoConfig {
	return cfgParseSSH(b, "ssh", true, include)
}

// cfgSSHBlock is the global part, or one Match/Host block.
type cfgSSHBlock struct {
	cfg  CryptoConfig
	seen map[string]bool
	// restricted: a sshd Match block, which accepts only the keywords of
	// cfgSSHMatchKeywords.
	restricted bool
}

// The sshd keywords this parser reads that sshd_config(5) allows inside a
// Match block. Everything else it reads (Ciphers, MACs, KexAlgorithms,
// HostKeyAlgorithms, HostKey, HostCertificate, Protocol, FingerprintHash...)
// is global only: sshd refuses it in a Match block, so it is dropped there.
var cfgSSHMatchKeywords = map[string]bool{
	"casignaturealgorithms": true, "hostbasedacceptedalgorithms": true,
	"hostbasedacceptedkeytypes": true, "pubkeyacceptedalgorithms": true,
	"pubkeyacceptedkeytypes": true, "requiredrsasize": true, "passwordauthentication": true,
	"pubkeyauthentication": true, "permitrootlogin": true, "kbdinteractiveauthentication": true,
	"challengeresponseauthentication": true, "gssapiauthentication": true,
	"authorizedkeysfile": true, "trustedusercakeys": true, "revokedkeys": true,
	"rekeylimit": true, "include": true,
}

// cfgParseSSH reads one file and, through the resolver, the files it
// includes. Included text is read AT the include's position and in the block
// the Include stands in, so the first-value-wins rule sees the same order the
// program does, and an Include inside a Match block is scoped to it. A Match
// or Host line inside an included file opens a block that ends with that
// file: the line after the Include belongs to the block that was current
// before it.
func cfgParseSSH(b []byte, product string, client bool, include IncludeResolver) []CryptoConfig {
	inc := newCfgIncl(include)
	global := &cfgSSHBlock{cfg: CryptoConfig{Product: product}, seen: map[string]bool{}}
	blocks := []*cfgSSHBlock{global}

	var walk func(b []byte, blk *cfgSSHBlock, depth int)
	walk = func(b []byte, blk *cfgSSHBlock, depth int) {
		// What the block this file was included from asks for: a Match in an
		// included file applies only inside it, and says so in its Context.
		outer := blk.cfg.Context
		for _, ln := range cfgLogicalLines(b, "#", false) {
			s := strings.TrimSpace(ln.text)
			if s == "" || s[0] == '#' {
				continue
			}
			kw, rest := cfgCut(s)
			if i := strings.IndexByte(kw, '='); i >= 0 {
				kw, rest = kw[:i], kw[i:]+" "+rest
			}
			rest = strings.TrimLeft(rest, " \t")
			if strings.HasPrefix(rest, "=") {
				rest = strings.TrimLeft(rest[1:], " \t")
			}
			kw = strings.ToLower(kw)
			args := cfgFields(rest, true)

			if kw == "match" || (client && kw == "host") {
				if len(blocks) < cfgMaxList {
					ctx := cfgSSHContext(kw, args)
					if outer != "" {
						ctx = cfgContext(outer + " > " + ctx)
					}
					blk = &cfgSSHBlock{cfg: CryptoConfig{Product: product, Context: ctx}, seen: map[string]bool{}, restricted: !client}
					blocks = append(blocks, blk)
				}
				continue
			}
			if blk.restricted && !cfgSSHMatchKeywords[kw] {
				continue
			}
			cfgSSHKeyword(&blk.cfg, blk.seen, kw, args)
			if kw == "include" {
				for _, a := range args {
					for _, f := range inc.get(a, depth) {
						inc.enter(f.Path)
						walk(f.Text, blk, depth+1)
						inc.leave()
					}
				}
			}
		}
	}
	walk(b, global, 0)

	var out []CryptoConfig
	for _, blk := range blocks {
		if cfgHasContent(&blk.cfg) {
			out = append(out, blk.cfg)
		}
	}
	return out
}

// The Match criteria that are kept with their value. Anything else keeps its
// name only, and exec (in any spelling) keeps the word only: a command can say
// anything, and a criterion this parser does not know may carry anything.
var cfgSSHMatchCriteria = map[string]bool{
	"user": true, "group": true, "host": true, "originalhost": true, "localuser": true,
	"localaddress": true, "localport": true, "address": true, "rdomain": true,
	"tagged": true, "final": true, "canonical": true, "all": true,
}

// Criteria that take no value.
var cfgSSHMatchBare = map[string]bool{"final": true, "canonical": true, "all": true}

func cfgSSHContext(kw string, args []string) string {
	parts := []string{strings.ToUpper(kw[:1]) + kw[1:]}
	if kw == "host" {
		return cfgContext(strings.Join(append(parts, args...), " "))
	}
	for i := 0; i < len(args); i++ {
		w := args[i]
		hadEq := false
		if j := strings.IndexByte(w, '='); j >= 0 {
			w, hadEq = w[:j], true
		}
		name := strings.ToLower(strings.TrimPrefix(w, "!"))
		switch {
		case cfgSSHMatchCriteria[name]:
			parts = append(parts, args[i])
			if !cfgSSHMatchBare[name] && !hadEq && i+1 < len(args) {
				parts = append(parts, args[i+1])
				i++
			}
		default:
			// exec and every criterion not known: the name alone.
			if name == "exec" {
				parts = append(parts, w)
			} else {
				parts = append(parts, "(unrecognised criterion)")
			}
			if !hadEq && i+1 < len(args) {
				i++
			}
		}
	}
	return cfgContext(strings.Join(parts, " "))
}

func cfgSSHKeyword(c *CryptoConfig, seen map[string]bool, kw string, args []string) {
	if len(args) == 0 {
		return
	}
	first := func() bool {
		if seen[kw] {
			return false
		}
		seen[kw] = true
		return true
	}
	list := func() []string { return cfgSplitList(args[0], ",") }

	switch kw {
	case "ciphers":
		if first() {
			cfgAppend(&c.CipherSuites, list()...)
		}
	case "macs":
		if first() {
			cfgAppend(&c.MACs, list()...)
		}
	case "kexalgorithms":
		if first() {
			cfgAppend(&c.KeyExchanges, list()...)
		}
	case "hostkeyalgorithms":
		if first() {
			cfgAppend(&c.HostKeyAlgorithms, list()...)
		}
	case "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes", "casignaturealgorithms":
		if first() {
			cfgAppend(&c.SignatureAlgorithms, list()...)
			name := map[string]string{
				"pubkeyacceptedalgorithms": "PubkeyAcceptedAlgorithms",
				"pubkeyacceptedkeytypes":   "PubkeyAcceptedKeyTypes",
				"casignaturealgorithms":    "CASignatureAlgorithms",
			}[kw]
			cfgSetSimple(c, name, args[0])
		}
	case "protocol":
		if first() {
			var names []string
			for _, p := range cfgSplitList(args[0], ",") {
				switch p {
				case "1":
					names = append(names, "SSHv1")
				case "2":
					names = append(names, "SSHv2")
				default:
					names = append(names, p)
				}
			}
			cfgAppend(&c.Protocols, cfgProtocolList(names)...)
		}
	case "hostkey":
		cfgRef(c, "private_key", "HostKey", args[0])
	case "hostcertificate":
		cfgRef(c, "certificate", "HostCertificate", args[0])
	case "trustedusercakeys":
		if first() {
			cfgRef(c, "trust_store", "TrustedUserCAKeys", args[0])
		}
	case "revokedkeys":
		if first() {
			cfgRef(c, "crl", "RevokedKeys", args[0])
		}
	case "identityfile":
		if !strings.EqualFold(args[0], "none") {
			cfgRef(c, "private_key", "IdentityFile", args[0])
		}
	case "certificatefile":
		cfgRef(c, "certificate", "CertificateFile", args[0])
	case "include":
		for _, a := range args {
			cfgRef(c, "include", "Include", a)
		}
	default:
		name, ok := cfgSSHSettings[kw]
		if !ok || !first() {
			return
		}
		if cfgSSHPathSettings[kw] {
			// Paths and path patterns ("none", "%d/.ssh/authorized_keys"):
			// each must look like one, or the setting is dropped whole.
			for _, a := range args {
				if !strings.EqualFold(a, "none") && !cfgIsFSPath(a, true) {
					return
				}
			}
		} else if !cfgSimple(strings.Join(args, " ")) {
			return
		}
		cfgSet(c, name, strings.Join(args, " "))
	}
}
