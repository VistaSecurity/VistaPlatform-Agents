package hostcrypto

// Where Linux keeps cryptographic material and its configuration, for pass 1.
//
// This is a table, not build-tagged code: an agent on any platform may
// collect a Linux host over SSH. Paths are written once here, from how the
// distributions lay their systems out (Debian and Ubuntu, the Red Hat family,
// SUSE, Arch, Alpine), and each row says what the file is for. A row that
// does not exist on a host costs one Stat or one listing and is not an error.
//
// root prefixes every path (tests build a host under a temporary directory;
// production passes "").

// locJVMRoots are the directories JDKs are installed under. Each is listed a
// few levels deep, never the whole tree.
var locLinuxJVMRoots = []string{"/usr/lib/jvm/*", "/usr/java/*", "/opt/java/*", "/opt/jdk*", "/usr/local/java/*"}

func locLinuxTable(r string) []locEntry {
	t := []locEntry{
		// System trust bundles, one per distribution family. Each is what
		// OpenSSL, GnuTLS and most runtimes read; the per-anchor links in
		// /etc/ssl/certs mirror them (see that row).
		{Path: r + "/etc/ssl/certs/ca-certificates.crt", Kind: locTrust},                  // Debian, Ubuntu, Alpine
		{Path: r + "/etc/pki/tls/certs/ca-bundle.crt", Kind: locTrust},                    // Red Hat family
		{Path: r + "/etc/pki/tls/certs/ca-bundle.trust.crt", Kind: locTrust},              // Red Hat family, with trust bits
		{Path: r + "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", Kind: locTrust},   // Red Hat family, generated
		{Path: r + "/etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem", Kind: locTrust}, // Red Hat family, S/MIME
		{Path: r + "/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt", Kind: locTrust},
		{Path: r + "/etc/ssl/ca-bundle.pem", Kind: locTrust},                           // SUSE
		{Path: r + "/var/lib/ca-certificates/ca-bundle.pem", Kind: locTrust},           // SUSE, generated
		{Path: r + "/etc/ssl/cert.pem", Kind: locTrust},                                // Alpine, Arch
		{Path: r + "/etc/ca-certificates/extracted/tls-ca-bundle.pem", Kind: locTrust}, // Arch, generated

		// Anchors an administrator added, before or after the bundle is
		// regenerated from them.
		{Path: r + "/usr/local/share/ca-certificates", Dir: true, Depth: 2, Kind: locTrust},
		{Path: r + "/etc/pki/ca-trust/source/anchors", Dir: true, Depth: 1, Kind: locTrust},
		{Path: r + "/etc/pki/ca-trust/source/blacklist", Dir: true, Depth: 1, Kind: locMaterial, Section: SectionCertificates},
		{Path: r + "/etc/pki/trust/anchors", Dir: true, Depth: 1, Kind: locTrust},
		{Path: r + "/etc/ca-certificates/trust-source/anchors", Dir: true, Depth: 1, Kind: locTrust},

		// Java trust stores the system maintains.
		{Path: r + "/etc/ssl/certs/java/cacerts", Kind: locTrust},
		{Path: r + "/etc/pki/java/cacerts", Kind: locTrust},
		{Path: r + "/etc/pki/ca-trust/extracted/java/cacerts", Kind: locTrust},

		// The system NSS database (Red Hat family; Chrome and others on any).
		{Path: r + "/etc/pki/nssdb", Dir: true, Kind: locNSS, Names: locNSSNames},

		// Certificates and keys an administrator keeps. In /etc/ssl/certs and
		// /etc/pki/tls/certs only regular files are read: the links there are
		// the trust anchors again.
		{Path: r + "/etc/ssl/certs", Dir: true, Kind: locMaterial, SkipLinks: true, Section: SectionCertificates},
		{Path: r + "/etc/ssl/private", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/pki/tls/certs", Dir: true, Kind: locMaterial, SkipLinks: true, Section: SectionCertificates},
		{Path: r + "/etc/pki/tls/private", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/pki/CA", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/pki/libvirt", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/pki/qemu", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/letsencrypt/live", Dir: true, Depth: 1, Names: []string{"*.pem"}, Kind: locMaterial, Role: "tls"},
		{Path: r + "/etc/letsencrypt/archive", Dir: true, Depth: 1, Names: []string{"*.pem"}, Kind: locMaterial, Role: "tls"},
		{Path: r + "/etc/nginx/ssl", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/nginx/certs", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/apache2/ssl", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/apache2/ssl.crt", Dir: true, Kind: locMaterial},
		{Path: r + "/etc/apache2/ssl.key", Dir: true, Kind: locMaterial},
		{Path: r + "/etc/httpd/ssl", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/httpd/conf/ssl.crt", Dir: true, Kind: locMaterial},
		{Path: r + "/etc/httpd/conf/ssl.key", Dir: true, Kind: locMaterial},
		{Path: r + "/etc/haproxy/certs", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/haproxy/ssl", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/postfix/ssl", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/dovecot/private", Dir: true, Kind: locMaterial},
		{Path: r + "/etc/ipsec.d", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/strongswan/ipsec.d", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/swanctl", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/etc/openvpn", Dir: true, Depth: 2, Kind: locMaterial},
		{Path: r + "/etc/kubernetes/pki", Dir: true, Depth: 1, Kind: locMaterial},
		{Path: r + "/var/lib/kubelet/pki", Dir: true, Kind: locMaterial},
		{Path: r + "/etc/docker/certs.d", Dir: true, Depth: 2, Kind: locMaterial},
		{Path: r + "/etc/containerd/certs.d", Dir: true, Depth: 2, Kind: locMaterial},
		{Path: r + "/etc/cockpit/ws-certs.d", Dir: true, Kind: locMaterial},

		// SSH: host keys and their public halves, the system known hosts, and
		// authorized_keys kept outside home directories (AuthorizedKeysFile
		// /etc/ssh/authorized_keys/%u).
		{Path: r + "/etc/ssh", Dir: true, Names: []string{"ssh_host_*_key", "ssh_host_*_key.pub"}, Kind: locSSHHost, Role: "ssh_host_key"},
		{Path: r + "/etc/ssh/ssh_known_hosts", Kind: locKnownHosts},
		{Path: r + "/etc/ssh/authorized_keys", Dir: true, Kind: locAuthorizedKeys, Account: "@base"},

		// Kerberos keytabs.
		{Path: r + "/etc", Dir: true, Names: []string{"*.keytab"}, Kind: locMaterial, Section: SectionKeystores},
		{Path: r + "/etc/krb5", Dir: true, Names: []string{"*.keytab"}, Kind: locMaterial, Section: SectionKeystores},
		{Path: r + "/etc/security/keytabs", Dir: true, Names: []string{"*.keytab"}, Kind: locMaterial, Section: SectionKeystores},
		{Path: r + "/var/kerberos/krb5kdc", Dir: true, Names: []string{"*.keytab"}, Kind: locMaterial, Section: SectionKeystores},

		// The system's OpenPGP keyrings: what the package manager trusts.
		{Path: r + "/etc/apt/trusted.gpg", Kind: locGnuPG},
		{Path: r + "/etc/apt/trusted.gpg.d", Dir: true, Names: []string{"*.gpg", "*.asc"}, Kind: locGnuPG},
		{Path: r + "/etc/apt/keyrings", Dir: true, Names: []string{"*.gpg", "*.asc"}, Kind: locGnuPG},
		{Path: r + "/usr/share/keyrings", Dir: true, Names: []string{"*.gpg", "*.asc", "*.kbx"}, Kind: locGnuPG},
		{Path: r + "/etc/pki/rpm-gpg", Dir: true, Kind: locGnuPG},

		// Configuration, read by pass 2. Only each product's root file is
		// listed: what it includes is read as part of it, and a drop-in it
		// does not include is not in effect.
		{Path: r + "/etc/ssl/openssl.cnf", Kind: locConfig, Product: "openssl"},
		{Path: r + "/usr/lib/ssl/openssl.cnf", Kind: locConfig, Product: "openssl"},
		{Path: r + "/etc/pki/tls/openssl.cnf", Kind: locConfig, Product: "openssl"},
		{Path: r + "/usr/local/ssl/openssl.cnf", Kind: locConfig, Product: "openssl"},
		{Path: r + "/etc/ssh/sshd_config", Kind: locConfig, Product: "sshd"},
		{Path: r + "/etc/ssh/ssh_config", Kind: locConfig, Product: "ssh"},
		{Path: r + "/etc/nginx/nginx.conf", Kind: locConfig, Product: "nginx"},
		{Path: r + "/usr/local/nginx/conf/nginx.conf", Kind: locConfig, Product: "nginx"},
		{Path: r + "/opt/nginx/conf/nginx.conf", Kind: locConfig, Product: "nginx"},
		{Path: r + "/etc/apache2/apache2.conf", Kind: locConfig, Product: "apache"},
		{Path: r + "/etc/apache2/httpd.conf", Kind: locConfig, Product: "apache"},
		{Path: r + "/etc/httpd/conf/httpd.conf", Kind: locConfig, Product: "apache", BaseUp: 1},
		{Path: r + "/usr/local/apache2/conf/httpd.conf", Kind: locConfig, Product: "apache", BaseUp: 1},
		{Path: r + "/etc/haproxy/haproxy.cfg", Kind: locConfig, Product: "haproxy"},
		{Path: r + "/etc/crypto-policies/config", Kind: locConfig, Product: "crypto-policies"},
		{Path: r + "/etc/crypto-policies/back-ends", Dir: true, Names: []string{"*.config"}, Kind: locConfig, Product: locBackendProduct},
		{Path: r + "/etc/krb5.conf", Kind: locConfig, Product: "krb5"},
		{Path: r + "/etc/gnutls/config", Kind: locConfig, Product: "gnutls"},
		{Path: r + "/etc/postfix/main.cf", Kind: locConfig, Product: "postfix"},
		{Path: r + "/etc/java-*/security/java.security", Kind: locConfig, Product: "java"},
		{Path: r + "/etc/java/*/*/conf/security/java.security", Kind: locConfig, Product: "java"},
		{Path: r + "/etc/elasticsearch/jvm.options", Kind: locConfig, Product: "java-options"},
		{Path: r + "/etc/elasticsearch/jvm.options.d", Dir: true, Names: []string{"*.options"}, Kind: locConfig, Product: "java-options"},
		{Path: r + "/etc/opensearch/jvm.options", Kind: locConfig, Product: "java-options"},
		{Path: r + "/etc/logstash/jvm.options", Kind: locConfig, Product: "java-options"},
	}
	for _, j := range locLinuxJVMRoots {
		t = append(t, locJVMEntries(r+j, "/")...)
	}
	return t
}

// locNSSNames are the files of an NSS database, both generations.
var locNSSNames = []string{"cert9.db", "key4.db", "cert8.db", "key3.db"}

// locJVMEntries are a JDK's trust store and security properties, for both
// layouts: JDK 9 and later (lib/security/cacerts, conf/security) and JDK 8
// (jre/lib/security). home may hold wildcards.
func locJVMEntries(home, sep string) []locEntry {
	j := func(parts ...string) string {
		out := home
		for _, p := range parts {
			out += sep + p
		}
		return out
	}
	return []locEntry{
		{Path: j("lib", "security", "cacerts"), Kind: locTrust},
		{Path: j("jre", "lib", "security", "cacerts"), Kind: locTrust},
		{Path: j("conf", "security", "java.security"), Kind: locConfig, Product: "java"},
		{Path: j("jre", "lib", "security", "java.security"), Kind: locConfig, Product: "java"},
	}
}

// locLinuxHomeTable is what each account keeps in its home directory: root's
// and every directory under /home. Run only when the operator opts in.
func locLinuxHomeTable(r string) []locEntry {
	var t []locEntry
	for _, h := range []struct{ dir, account string }{{r + "/root", "root"}, {r + "/home/*", "*"}} {
		t = append(t, locUnixHomeEntries(h.dir, h.account)...)
		t = append(t,
			locEntry{Path: h.dir + "/.pki/nssdb", Dir: true, Kind: locNSS, Names: locNSSNames},
			locEntry{Path: h.dir + "/.mozilla/firefox/*", Dir: true, Kind: locNSS, Names: locNSSNames},
			locEntry{Path: h.dir + "/snap/firefox/common/.mozilla/firefox/*", Dir: true, Kind: locNSS, Names: locNSSNames},
		)
	}
	return t
}

// locUnixHomeEntries are the per-user SSH, GnuPG and Java files every Unix
// home shares.
func locUnixHomeEntries(home, account string) []locEntry {
	return []locEntry{
		{Path: home + "/.ssh", Dir: true, Names: []string{"authorized_keys", "authorized_keys2"}, Kind: locAuthorizedKeys, Account: account},
		{Path: home + "/.ssh", Dir: true, Names: []string{"known_hosts"}, Kind: locKnownHosts},
		{Path: home + "/.ssh", Dir: true, Names: []string{"id_*", "identity", "*.pem", "*.key", "*.ppk"}, Kind: locMaterial, Role: "ssh_user_key"},
		{Path: home + "/.gnupg", Dir: true, Depth: 1, Names: []string{"pubring.kbx", "pubring.gpg", "secring.gpg", "*.key"}, Kind: locGnuPG},
		{Path: home + "/.keystore", Kind: locMaterial, Section: SectionKeystores},
	}
}
