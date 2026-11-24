package hostcrypto

import (
	"path"
	"sort"
	"strconv"
	"strings"
)

// Keep words: what [Target.ReadText] lets cross from a configuration file.
//
// The rule (FilterConfigText) keeps a line when its FIRST WORD is listed,
// when it is structure ("[section]", "{", "}", "};", "</...>"), or when it
// continues a kept line. So a product's list is exactly the first words of
// the lines its parser reads: every directive it admits, and every block
// opener or scoping word it needs to put those directives where they belong.
// A directive is never listed for being harmless; a word the parser does not
// need is a line that crosses for nothing.
//
// The lists are built from the parsers' own allowlist tables wherever a
// parser has one. Where a parser decides by a switch or a comparison, the
// words are written here once, in the keep* slices below, and
// config_keep_test.go reads the parser's source and fails when a slice and
// the switch disagree. The parity test there runs every configuration
// fixture of the package through the filter and requires the parser's result
// to be unchanged.
//
// Words of semicolon-terminated syntaxes (nginx) carry a trailing ";": the
// directive runs to the next ";", across lines. A block opener never does
// ("server {" has no ";", so a ";" word would swallow the block's first
// directive as its continuation).
//
// Kept lines whose value the parser must reduce. A kept line crosses whole
// (only runs of 40 or more base64 characters are redacted), so the following
// can carry a secret to the collector, where the parser, not the filter,
// keeps it out of the report. This is the residual the host-side filter
// cannot remove:
//
//   - every directive that names a key, certificate or keystore and goes
//     through cfgRef, whose value can be a "store:", "pkcs11:", "engine:" or
//     URL form holding a PIN or credentials, of which only the scheme is
//     kept: openssl PrivateKey, Certificate (and the CA and DH keys);
//     nginx ssl_certificate_key, ssl_certificate, proxy_/grpc_/uwsgi_
//     ssl_certificate[_key]; apache SSLCertificateKeyFile, SSLCertificateFile,
//     SSLProxyMachineCertificateFile, GnuTLSKeyFile, GnuTLSP12File; sshd/ssh
//     HostKey, IdentityFile, CertificateFile, PKCS11Provider,
//     SecurityKeyProvider; java-options -Djavax.net.ssl.keyStore,
//     -Djavax.net.ssl.trustStore, -Djava.security.properties; krb5
//     pkinit_identities (a PKCS11: form with a PIN), default_keytab_name,
//     default_client_keytab_name, default_ccache_name; postfix
//     *_tls_key_file, *_tls_eckey_file, *_tls_dkey_file;
//   - lines that carry more than the parser reads: an ssh/sshd Match line
//     ("Match exec <command>": the command can hold a token; the parser keeps
//     the word exec only) and a Host line; apache Header and nginx add_header
//     (only Strict-Transport-Security is read; any other header and its value
//     cross); haproxy bind, server, server-template, default-server and
//     ssl-default-{bind,server}-options lines, whose options the parser skips
//     include ca-sign-pass and sni expressions; java.security
//     security.provider.N (an inline SunPKCS11 configuration);
//   - any line holding several directives: a one-line nginx block
//     ("server { listen 443 ssl; ssl_password_file /p; }" crosses for its
//     first word), several -D options on one jvm.options line.
//
// What the rule cannot express, so the parser never sees it through
// ReadText (the parity test lists each case it meets):
//
//   - a value continued on a line of its own that does not end the previous
//     one with "\": Postfix's indented continuation lines are dropped (and
//     one starting with "!" is a comment to the rule);
//   - a block opened by a word no list can name: a krb5 "REALM = {"
//     subsection inside [libdefaults] (its relations then read as global), an
//     nginx or Apache block of a third-party module (its closing brace or tag
//     then closes the enclosing block early);
//   - a JVM command line or a JAVA_OPTS="..." shell line (several options
//     after one first word that is not an option): only jvm.options, one
//     option per line, is read;
//   - a crypto-policies config naming a custom policy: only the shipped
//     policy names are listed;
//   - a security.provider.N or fips.provider.N above 99, or written with a
//     leading zero;
//   - an nginx "}" followed by a comment on the same line (it is not
//     structure to the rule, so the block it closes stays open).

// ConfigKeepWords returns the first words of the lines a product's parser
// reads ([ConfigParserFor]'s names), or, for a generated crypto-policies
// back-end, of the lines [ParseCryptoPolicyBackend] reads for it: the key is
// "crypto-policies/" and the back-end's file name, such as
// "crypto-policies/opensslcnf.config" (see [ConfigBackendKeepWords]). A name
// with no parser returns nil, which [Target.ReadText] refuses.
func ConfigKeepWords(product string) []string {
	return append([]string(nil), configKeepWords[product]...)
}

// ConfigBackendKeepWords returns the keep words of a crypto-policies back-end
// named as [ParseCryptoPolicyBackend] takes it ("opensslcnf.config",
// "/etc/crypto-policies/back-ends/openssh.config", "libssh").
func ConfigBackendKeepWords(name string) []string {
	return ConfigKeepWords(cfgBackendKeepKey(name))
}

// cfgBackendKeepKey is the configKeepWords key of a back-end name, normalised
// the way ParseCryptoPolicyBackend normalises it.
func cfgBackendKeepKey(name string) string {
	base := strings.TrimSuffix(path.Base(strings.ReplaceAll(name, "\\", "/")), ".config")
	return "crypto-policies/" + base + ".config"
}

// The words read by a switch or a comparison in a parser, written once here
// and held to the parser's source by config_keep_test.go.
var (
	// cfgOSSLApplySSL's val() keys.
	keepOpenSSLSSLKeys = []string{"TLS.MinProtocol", "MinProtocol", "TLS.MaxProtocol", "MaxProtocol",
		"DTLS.MinProtocol", "DTLS.MaxProtocol", "CipherString", "Ciphersuites", "Groups", "Curves",
		"SignatureAlgorithms"}
	// The chain from the default section to the policy: ci() and vals[] keys
	// of cfgParseOpenSSL, init and cfgOSSLProvidersAndEngines.
	keepOpenSSLChain = []string{"openssl_conf", "ssl_conf", "system_default", "providers", "activate",
		"alg_section", "default_properties", "engines"}
	// cfgOSSLFragment's own ci() key.
	keepOpenSSLFragment = []string{"activate"}

	// cfgParseJava's props[] keys (and cfgJavaExpandIncludes').
	keepJavaProps = []string{"jdk.tls.disabledAlgorithms", "securerandom.source", "jdk.tls.namedGroups",
		"crypto.policy", "com.redhat.fips", "jdk.disabled.namedCurves"}
	// cfgParseJava's comparisons: "include <file>" (JDK 24 and later).
	keepJavaStructure = []string{"include"}
	// cfgJavaOption's cases.
	keepJavaOptions = []string{"javax.net.ssl.keyStore", "javax.net.ssl.trustStore", "java.security.properties",
		"javax.net.ssl.keyStoreType", "javax.net.ssl.trustStoreType",
		"javax.net.ssl.keyStoreProvider", "javax.net.ssl.trustStoreProvider",
		"com.sun.net.ssl.checkRevocation", "com.sun.security.enableCRLDP",
		"jdk.tls.rejectClientInitiatedRenegotiation", "jdk.tls.allowLegacyResumption",
		"https.protocols", "jdk.tls.client.protocols", "jdk.tls.server.protocols",
		"jdk.tls.client.cipherSuites", "jdk.tls.server.cipherSuites", "jdk.tls.namedGroups",
		"jdk.tls.disabledAlgorithms", "com.redhat.fips"}

	// cfgSSHKeyword's cases.
	keepSSHKeywords = []string{"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms",
		"pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes", "casignaturealgorithms", "protocol",
		"hostkey", "hostcertificate", "trustedusercakeys", "revokedkeys", "identityfile",
		"certificatefile", "include"}
	// cfgParseSSH's block openers: Match (both), Host (ssh_config only).
	keepSSHBlocks       = []string{"match", "host"}
	keepSSHServerBlocks = []string{"match"}
	// cfgCPOpenSSHOptions's older back-end spelling, CRYPTO_POLICY='-o...'.
	keepCPOpenSSHOptions = []string{"CRYPTO_POLICY"}

	// cfgNgxApply's cases.
	keepNginxDirectives = []string{"include", "server_name", "listen", "ssl_protocols", "ssl_ciphers",
		"ssl_ecdh_curve", "ssl_conf_command", "ssl_prefer_server_ciphers", "ssl_session_tickets",
		"ssl_session_timeout", "ssl_stapling", "ssl_stapling_verify", "ssl_verify_client",
		"ssl_verify_depth", "ssl_early_data", "ssl_reject_handshake", "ssl", "add_header",
		"ssl_certificate", "ssl_certificate_key", "ssl_trusted_certificate", "ssl_client_certificate",
		"ssl_dhparam", "ssl_crl"}
	// cfgParseNginx's levels and cfgNgxServer's block.
	keepNginxBlocks = []string{"http", "stream", "mail", "server"}

	// cfgApacheDirective's cases.
	keepApacheDirectives = []string{"servername", "include", "includeoptional", "sslprotocol",
		"sslciphersuite", "sslopensslconfcmd", "sslfips", "gnutlspriorities", "header"}
	// cfgParseApache's sections that are read: <VirtualHost>, and <IfModule>
	// and <IfDefine>, which are transparent.
	keepApacheSections = []string{"virtualhost", "ifmodule", "ifdefine"}

	// cfgParseHAProxy's global switch.
	keepHAProxyGlobal = []string{"ca-base", "crt-base", "ssl-default-bind-ciphers",
		"ssl-default-bind-ciphersuites", "ssl-default-bind-curves", "ssl-default-bind-sigalgs",
		"ssl-default-bind-options", "ssl-default-server-options", "ssl-default-server-ciphers",
		"ssl-default-server-ciphersuites", "ssl-default-server-curves", "ssl-default-server-sigalgs",
		"tune.ssl.default-dh-param", "ssl-server-verify", "ssl-dh-param-file"}
	// cfgHAServers' switch, and the bind lines of cfgParseHAProxy and the
	// default-server lines of cfgHAServerDefaults.add (comparisons).
	keepHAProxyServers = []string{"default-server", "server", "server-template"}
	keepHAProxyBind    = []string{"bind", "default-server"}

	// cfgKrb5Relation's cases.
	keepKrb5Relations = []string{"permitted_enctypes", "default_tgs_enctypes", "default_tkt_enctypes",
		"allow_weak_crypto", "pkinit_eku_checking", "spake_preauth_groups", "default_ccache_name",
		"default_keytab_name", "default_client_keytab_name", "pkinit_anchors", "pkinit_identities"}
	// cfgParseKrb5's directives valid anywhere.
	keepKrb5Includes = []string{"include", "includedir"}

	// cfgParseGnuTLS's comparison: the priority string.
	keepGnuTLSSystem = []string{"SYSTEM"}

	// cfgParseNSSPolicy's comparison.
	keepNSSPolicy = []string{"config"}
)

// Words the parsers need but do not spell as a directive name, so no table or
// switch can give them. Each is commented with why the parser needs it.
var (
	// OpenSSL's include directive: the parser tests for a leading "." and
	// then the word "include", in any case.
	keepOpenSSLInclude = []string{".include"}

	// nginx: every "}" is structure and always crosses, so every block opener
	// the parser can meet must cross too, or its "}" closes the enclosing
	// block early (a server's directives after a multi-line location would
	// then read as the http level's). These are the openers of the core and
	// the common modules; the parser reads none of their bodies.
	keepNginxBraceOpeners = []string{"events", "location", "if", "upstream", "map", "geo",
		"split_clients", "types", "limit_except", "charset_map", "match", "mgmt", "otel_exporter"}

	// Apache: every "</...>" is structure and always crosses, and the parser
	// SKIPS the body of every section other than <VirtualHost>, <IfModule>
	// and <IfDefine>. A skipped section whose opener did not cross would have
	// its body read in the enclosing scope (an SSLVerifyClient inside
	// <Location> read as the server's). These are the containers of httpd
	// and its bundled modules.
	keepApacheSkippedSections = []string{"directory", "directorymatch", "files", "filesmatch",
		"location", "locationmatch", "if", "elseif", "else", "ifversion", "ifdirective", "iffile",
		"ifsection", "proxy", "proxymatch", "limit", "limitexcept", "requireall", "requireany",
		"requirenone", "macro", "authnprovideralias", "authzprovideralias", "mdomainset", "mdomain"}

	// /etc/crypto-policies/config holds one line, the policy name with its
	// modules ("DEFAULT:SHA1"); the rule's first word stops at ":", so it is
	// the base policy. These are the policies crypto-policies ships.
	keepCryptoPolicyNames = []string{"DEFAULT", "LEGACY", "FUTURE", "FIPS", "EMPTY", "NEXT", "BSI"}

	// back-ends/openssl.config is one bare cipher string, which
	// update-crypto-policies starts with "@SECLEVEL=n"; the first word stops
	// at "=".
	keepBareCipherString = []string{"@SECLEVEL"}
)

// keepJavaNumbered is how many of each numbered provider family are listed:
// "security.provider.1" to "security.provider.99" and the same for
// "fips.provider.". cfgNumbered accepts three digits, but every word is sent
// to a remote host, and a JDK numbers its providers from 1 upwards.
const keepJavaNumbered = 99

func keepNumbered(prefix string) []string {
	out := make([]string, 0, keepJavaNumbered)
	for i := 1; i <= keepJavaNumbered; i++ {
		out = append(out, prefix+strconv.Itoa(i))
	}
	return out
}

func keepKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// keepWords lower-cases, de-duplicates and sorts its groups, adding ";" to
// every word when semi is set.
func keepWords(semi bool, groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, w := range g {
			w = asciiLower(w)
			if semi {
				w += ";"
			}
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	sort.Strings(out)
	return out
}

// configKeepWords is built once from the tables. Keys are the product names
// of cfgParsers and "crypto-policies/<back-end file name>".
var configKeepWords = func() map[string][]string {
	var osslRefs []string
	for _, r := range cfgOSSLRefKeys {
		osslRefs = append(osslRefs, r.key)
	}
	osslSSL := [][]string{keepOpenSSLSSLKeys, cfgOSSLSettingKeys, osslRefs}
	openssl := keepWords(false, append(osslSSL, keepOpenSSLChain, keepOpenSSLInclude,
		keepKeys(cfgOSSLProviders), keepKeys(cfgOSSLEngines))...)
	opensslFragment := keepWords(false, append(osslSSL, keepOpenSSLFragment, keepOpenSSLInclude)...)

	java := keepWords(false, cfgJavaSettingProps, keepJavaProps, keepJavaStructure,
		keepNumbered(cfgJavaProviderPrefix), keepNumbered(cfgJavaFIPSProviderPrefix))
	javaOptions := keepWords(false, keepJavaOptions)

	sshCommon := [][]string{keepSSHKeywords, keepKeys(cfgSSHSettings)}
	ssh := keepWords(false, append(sshCommon, keepSSHBlocks)...)
	sshd := keepWords(false, append(sshCommon, keepSSHServerBlocks)...)

	nginx := append(keepWords(true, keepNginxDirectives, keepKeys(cfgNgxProxy)),
		keepWords(false, keepNginxBlocks, keepNginxBraceOpeners)...)
	sort.Strings(nginx)

	apache := keepWords(false, keepApacheDirectives, keepKeys(cfgApacheSettings), keepKeys(cfgApacheRefs),
		keepApacheSections, keepApacheSkippedSections)

	haproxy := keepWords(false, keepKeys(cfgHASectionKinds), keepHAProxyGlobal, keepHAProxyServers, keepHAProxyBind)

	krb5 := keepWords(false, keepKrb5Relations, keepKrb5Includes)
	gnutls := keepWords(false, keepGnuTLSSystem, keepKeys(cfgGnuTLSDeny), keepKeys(cfgGnuTLSAllow), keepKeys(cfgGnuTLSOther))

	var postfixRefs []string
	for _, r := range cfgPostfixRefSuffixes {
		postfixRefs = append(postfixRefs, r.suffix)
	}
	var postfixSide []string
	for _, side := range cfgPostfixSides {
		for _, g := range [][]string{cfgPostfixProtocolSuffixes, cfgPostfixCipherSuffixes,
			cfgPostfixExcludeSuffixes, cfgPostfixSimpleSuffixes, postfixRefs} {
			for _, s := range g {
				postfixSide = append(postfixSide, side+s)
			}
		}
	}
	postfix := keepWords(false, cfgPostfixGlobals, postfixSide)

	m := map[string][]string{
		"openssl":         openssl,
		"java":            java,
		"java-options":    javaOptions,
		"sshd":            sshd,
		"ssh":             ssh,
		"nginx":           nginx,
		"apache":          apache,
		"haproxy":         haproxy,
		"crypto-policies": keepWords(false, keepCryptoPolicyNames),
		"krb5":            krb5,
		"gnutls":          gnutls,
		"postfix":         postfix,
	}
	// The back-ends, by the parser ParseCryptoPolicyBackend chooses for each.
	for name, words := range map[string][]string{
		"opensslcnf":    opensslFragment,
		"openssl_fips":  opensslFragment,
		"openssl":       keepWords(false, keepBareCipherString),
		"openssh":       keepWords(false, ssh, keepCPOpenSSHOptions),
		"libssh":        keepWords(false, ssh, keepCPOpenSSHOptions),
		"opensshserver": keepWords(false, sshd, keepCPOpenSSHOptions),
		"gnutls":        gnutls,
		"java":          java,
		"javasystem":    java,
		"nss":           keepWords(false, keepNSSPolicy),
		"krb5":          krb5,
	} {
		m[cfgBackendKeepKey(name)] = words
	}
	return m
}()
