package hostcrypto

// Where Windows keeps cryptographic material in FILES, for pass 1.
//
// A table, not build-tagged code: a Linux agent collects a Windows host over
// SSH, so the file is named oswindows.go, not os_windows.go. Windows keeps
// its trust anchors and most keys in the certificate stores and CNG, which
// are platform stores and read elsewhere (IIS's certificates are there too).
// What is here is what lives in files: OpenSSH for Windows under
// %ProgramData%\ssh, the JDKs, Apache, nginx and OpenSSL builds in their
// usual install directories, Git for Windows' bundle, MIT Kerberos, the ACME
// clients' certificate folders.
//
// drive is the system drive ("C:"). The usual install directories are
// assumed; one installed elsewhere is reached only through its configuration
// or the sweep.

// locWindowsJDKVendors are the directories under Program Files that JDK
// vendors install into, each holding one directory per JDK.
var locWindowsJDKVendors = []string{
	`Java`, `Eclipse Adoptium`, `Eclipse Foundation`, `AdoptOpenJDK`, `Microsoft`,
	`Amazon Corretto`, `Zulu`, `BellSoft`, `RedHat`, `Semeru`,
}

func locWindowsTable(d string) []locEntry {
	pd := d + `\ProgramData`
	pf := d + `\Program Files`
	pf86 := d + `\Program Files (x86)`
	t := []locEntry{
		// OpenSSH for Windows.
		{Path: pd + `\ssh`, Dir: true, Names: []string{"ssh_host_*_key", "ssh_host_*_key.pub"}, Kind: locSSHHost, Role: "ssh_host_key"},
		{Path: pd + `\ssh\administrators_authorized_keys`, Kind: locAuthorizedKeys, Account: "Administrators"},
		{Path: pd + `\ssh\ssh_known_hosts`, Kind: locKnownHosts},
		{Path: pd + `\ssh\sshd_config`, Kind: locConfig, Product: "sshd"},
		{Path: pd + `\ssh\ssh_config`, Kind: locConfig, Product: "ssh"},

		// Git for Windows carries its own trust bundle, OpenSSL and OpenSSH.
		{Path: pf + `\Git\mingw64\etc\ssl\certs\ca-bundle.crt`, Kind: locTrust},
		{Path: pf + `\Git\mingw64\ssl\certs\ca-bundle.crt`, Kind: locTrust},
		{Path: pf + `\Git\usr\ssl\certs\ca-bundle.crt`, Kind: locTrust},
		{Path: pf + `\Git\mingw64\etc\ssl\openssl.cnf`, Kind: locConfig, Product: "openssl"},
		{Path: pf + `\Git\usr\ssl\openssl.cnf`, Kind: locConfig, Product: "openssl"},
		{Path: pf + `\Git\etc\ssh\ssh_config`, Kind: locConfig, Product: "ssh"},

		// OpenSSL builds: the default OPENSSLDIR of OpenSSL 3 for Windows,
		// and the installers' own trees.
		{Path: pf + `\Common Files\SSL\openssl.cnf`, Kind: locConfig, Product: "openssl"},
		{Path: pf + `\Common Files\SSL\cert.pem`, Kind: locTrust},
		{Path: pf + `\Common Files\SSL\certs`, Dir: true, Kind: locMaterial, Section: SectionCertificates},
		{Path: pf + `\Common Files\SSL\private`, Dir: true, Kind: locMaterial},
		{Path: pf + `\OpenSSL-Win64\bin\cnf\openssl.cnf`, Kind: locConfig, Product: "openssl"},
		{Path: pf + `\OpenSSL-Win64\bin\openssl.cfg`, Kind: locConfig, Product: "openssl"},
		{Path: pf86 + `\OpenSSL-Win32\bin\cnf\openssl.cnf`, Kind: locConfig, Product: "openssl"},
		{Path: d + `\OpenSSL-Win64\bin\openssl.cfg`, Kind: locConfig, Product: "openssl"},

		// Apache (Apache Lounge, XAMPP, WampServer) and nginx. ServerRoot is
		// the parent of conf\; nginx resolves against conf\.
		{Path: d + `\Apache24\conf\httpd.conf`, Kind: locConfig, Product: "apache", BaseUp: 1},
		{Path: d + `\Apache24\conf\ssl`, Dir: true, Depth: 1, Kind: locMaterial},
		{Path: d + `\xampp\apache\conf\httpd.conf`, Kind: locConfig, Product: "apache", BaseUp: 1},
		{Path: d + `\xampp\apache\conf\ssl.crt`, Dir: true, Kind: locMaterial},
		{Path: d + `\xampp\apache\conf\ssl.key`, Dir: true, Kind: locMaterial},
		{Path: d + `\wamp64\bin\apache\*\conf\httpd.conf`, Kind: locConfig, Product: "apache", BaseUp: 1},
		{Path: d + `\nginx\conf\nginx.conf`, Kind: locConfig, Product: "nginx"},
		{Path: d + `\nginx-*\conf\nginx.conf`, Kind: locConfig, Product: "nginx"},
		{Path: d + `\nginx\conf\ssl`, Dir: true, Depth: 1, Kind: locMaterial},

		// MIT Kerberos for Windows.
		{Path: pd + `\MIT\Kerberos5\krb5.ini`, Kind: locConfig, Product: "krb5"},
		{Path: pd + `\MIT\Kerberos5`, Dir: true, Names: []string{"*.keytab"}, Kind: locMaterial, Section: SectionKeystores},

		// ACME clients keep issued certificates (often as PFX) on disk.
		{Path: pd + `\win-acme`, Dir: true, Depth: 3, Names: []string{"*.pfx", "*.pem", "*.crt", "*.key"}, Kind: locMaterial, Role: "tls"},
		{Path: pd + `\Certify\assets`, Dir: true, Depth: 2, Names: []string{"*.pfx"}, Kind: locMaterial, Role: "tls"},

		// OpenVPN.
		{Path: pf + `\OpenVPN\config`, Dir: true, Depth: 1, Kind: locMaterial},
		{Path: pf + `\OpenVPN\config-auto`, Dir: true, Depth: 1, Kind: locMaterial},
	}
	for _, v := range locWindowsJDKVendors {
		for _, base := range []string{pf, pf86} {
			t = append(t, locJVMEntries(base+`\`+v+`\*`, `\`)...)
		}
	}
	return t
}

// locWindowsHomeTable is what each account keeps under C:\Users. Run only when
// the operator opts in.
func locWindowsHomeTable(d string) []locEntry {
	h := d + `\Users\*`
	return []locEntry{
		{Path: h + `\.ssh`, Dir: true, Names: []string{"authorized_keys"}, Kind: locAuthorizedKeys, Account: "*"},
		{Path: h + `\.ssh`, Dir: true, Names: []string{"known_hosts"}, Kind: locKnownHosts},
		{Path: h + `\.ssh`, Dir: true, Names: []string{"id_*", "identity", "*.pem", "*.key", "*.ppk"}, Kind: locMaterial, Role: "ssh_user_key"},
		{Path: h + `\AppData\Roaming\gnupg`, Dir: true, Depth: 1, Names: []string{"pubring.kbx", "pubring.gpg", "secring.gpg", "*.key"}, Kind: locGnuPG},
		{Path: h + `\AppData\Roaming\Mozilla\Firefox\Profiles\*`, Dir: true, Kind: locNSS, Names: locNSSNames},
		{Path: h + `\.keystore`, Kind: locMaterial, Section: SectionKeystores},
	}
}
