package hostcrypto

// Where macOS keeps cryptographic material and its configuration, for pass 1.
//
// A table, not build-tagged code (see oslinux.go). macOS keeps its trust and
// most keys in keychains, which are platform stores and read elsewhere; what
// is here is the files: the keychain files themselves (as keystores), the
// LibreSSL and OpenSSH configuration the system ships, the JDKs, and the
// package managers' trees. Homebrew installs under /opt/homebrew on Apple
// silicon and /usr/local on Intel; MacPorts under /opt/local. /etc is a link
// to /private/etc, which the registry resolves, so each file is one item.
//
// root prefixes every path (tests); production passes "".

// locDarwinPrefixes are the package managers' prefixes.
var locDarwinPrefixes = []string{"/opt/homebrew", "/usr/local", "/opt/local"}

// locDarwinJVMRoots are where JDKs live: the system's JavaVirtualMachines,
// and Homebrew's openjdk formulae (reached through their opt links).
var locDarwinJVMRoots = []string{
	"/Library/Java/JavaVirtualMachines/*/Contents/Home",
	"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
	"/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
}

func locDarwinTable(r string) []locEntry {
	t := []locEntry{
		// The bundle LibreSSL and curl read.
		{Path: r + "/etc/ssl/cert.pem", Kind: locTrust},
		{Path: r + "/etc/ssl/certs", Dir: true, Kind: locMaterial, SkipLinks: true, Section: SectionCertificates},
		{Path: r + "/etc/ssl/private", Dir: true, Kind: locMaterial},

		// System keychain files: keystores here, their contents a platform
		// store's.
		{Path: r + "/Library/Keychains", Dir: true, Names: []string{"*.keychain", "*.keychain-db"}, Kind: locMaterial, Section: SectionKeystores},
		{Path: r + "/System/Library/Keychains", Dir: true, Names: []string{"*.keychain", "*.keychain-db"}, Kind: locTrust, Section: SectionKeystores},

		// SSH.
		{Path: r + "/etc/ssh", Dir: true, Names: []string{"ssh_host_*_key", "ssh_host_*_key.pub"}, Kind: locSSHHost, Role: "ssh_host_key"},
		{Path: r + "/etc/ssh/ssh_known_hosts", Kind: locKnownHosts},

		// Kerberos.
		{Path: r + "/etc", Dir: true, Names: []string{"*.keytab"}, Kind: locMaterial, Section: SectionKeystores},

		// The system's own configuration.
		{Path: r + "/etc/ssl/openssl.cnf", Kind: locConfig, Product: "openssl"},
		{Path: r + "/System/Library/OpenSSL/openssl.cnf", Kind: locConfig, Product: "openssl"},
		{Path: r + "/etc/ssh/sshd_config", Kind: locConfig, Product: "sshd"},
		{Path: r + "/etc/ssh/ssh_config", Kind: locConfig, Product: "ssh"},
		{Path: r + "/etc/krb5.conf", Kind: locConfig, Product: "krb5"},
		{Path: r + "/etc/apache2/httpd.conf", Kind: locConfig, Product: "apache"},
		{Path: r + "/etc/postfix/main.cf", Kind: locConfig, Product: "postfix"},
	}
	for _, p := range locDarwinPrefixes {
		t = append(t,
			// Homebrew's and MacPorts' trust bundles and OpenSSL trees.
			locEntry{Path: r + p + "/etc/ca-certificates/cert.pem", Kind: locTrust},
			locEntry{Path: r + p + "/etc/openssl@*/cert.pem", Kind: locTrust},
			locEntry{Path: r + p + "/etc/openssl/cert.pem", Kind: locTrust},
			locEntry{Path: r + p + "/etc/openssl@*/certs", Dir: true, Kind: locMaterial, SkipLinks: true, Section: SectionCertificates},
			locEntry{Path: r + p + "/etc/openssl@*/private", Dir: true, Kind: locMaterial},
			locEntry{Path: r + p + "/etc/openssl@*/openssl.cnf", Kind: locConfig, Product: "openssl"},
			locEntry{Path: r + p + "/etc/openssl/openssl.cnf", Kind: locConfig, Product: "openssl"},
			locEntry{Path: r + p + "/etc/nginx/nginx.conf", Kind: locConfig, Product: "nginx"},
			locEntry{Path: r + p + "/etc/nginx/ssl", Dir: true, Depth: 1, Kind: locMaterial},
			locEntry{Path: r + p + "/etc/httpd/httpd.conf", Kind: locConfig, Product: "apache"},
			locEntry{Path: r + p + "/etc/apache2/httpd.conf", Kind: locConfig, Product: "apache"},
			locEntry{Path: r + p + "/etc/haproxy.cfg", Kind: locConfig, Product: "haproxy"},
			locEntry{Path: r + p + "/etc/haproxy/haproxy.cfg", Kind: locConfig, Product: "haproxy"},
			locEntry{Path: r + p + "/etc/gnutls/config", Kind: locConfig, Product: "gnutls"},
			locEntry{Path: r + p + "/etc/krb5.conf", Kind: locConfig, Product: "krb5"},
			locEntry{Path: r + p + "/etc/postfix/main.cf", Kind: locConfig, Product: "postfix"},
		)
	}
	for _, j := range locDarwinJVMRoots {
		t = append(t, locJVMEntries(r+j, "/")...)
	}
	return t
}

// locDarwinHomeTable is what each account keeps: root's home (/var/root) and
// every directory under /Users. Run only when the operator opts in.
func locDarwinHomeTable(r string) []locEntry {
	var t []locEntry
	for _, h := range []struct{ dir, account string }{{r + "/var/root", "root"}, {r + "/Users/*", "*"}} {
		t = append(t, locUnixHomeEntries(h.dir, h.account)...)
		t = append(t,
			locEntry{Path: h.dir + "/Library/Keychains", Dir: true, Names: []string{"*.keychain", "*.keychain-db"}, Kind: locMaterial, Section: SectionKeystores},
			locEntry{Path: h.dir + "/Library/Application Support/Firefox/Profiles/*", Dir: true, Kind: locNSS, Names: locNSSNames},
		)
	}
	return t
}
