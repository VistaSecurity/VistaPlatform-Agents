package hostcrypto

import (
	"context"
	"errors"
	"os"
	"strings"
)

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
// The system drive and the ProgramData and Program Files directories are the
// host's (locWindowsRoots): one PowerShell command over a remote connection,
// the environment on the host itself, C: with a note when neither answers.
// Below them the usual install directories are assumed; a product installed
// elsewhere is reached only through its configuration or the sweep.

// locWinRoots are a Windows host's system drive and the directories programs
// install into.
type locWinRoots struct {
	Drive, ProgramData, ProgramFiles, ProgramFiles86 string
}

// locDefaultWinRoots are the roots of a host installed on drive with the
// default directory names.
func locDefaultWinRoots(drive string) locWinRoots {
	return locWinRoots{Drive: drive, ProgramData: drive + `\ProgramData`,
		ProgramFiles: drive + `\Program Files`, ProgramFiles86: drive + `\Program Files (x86)`}
}

// locWinRootsScript prints the four roots separated by "|". It takes no
// input, so it is sent as a fixed -EncodedCommand.
const locWinRootsScript = `[Console]::Out.Write((@($env:SystemDrive, $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}) -join '|'))`

// locWinRootsArgv is the one command that asks a remote host for its roots.
var locWinRootsArgv = []string{"powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", psEncode(locWinRootsScript)}

// locLocalEnv reads the agent's own environment for a local Windows
// collection. A variable so a test does not depend on the machine it runs on.
var locLocalEnv = os.Getenv

// locWindowsRoots asks the host for its roots, once per collection (the
// caller caches the answer). Every value is checked: the drive must be a
// letter and a colon, each directory an absolute path; one that is not is
// taken from the drive's defaults. No answer at all means C:, with a note.
func (c *collection) locWindowsRoots(ctx context.Context) locWinRoots {
	var vals []string
	if c.target.Local() {
		vals = []string{locLocalEnv("SystemDrive"), locLocalEnv("ProgramData"), locLocalEnv("ProgramFiles"), locLocalEnv("ProgramFiles(x86)")}
	} else if out, _, code, err := c.target.Run(ctx, locWinRootsArgv); err == nil && code == 0 {
		vals = strings.Split(strings.TrimSpace(string(out)), "|")
	}
	return c.locParseWinRoots(vals)
}

// locParseWinRoots validates the four values (see locWindowsRoots).
func (c *collection) locParseWinRoots(vals []string) locWinRoots {
	for len(vals) < 4 {
		vals = append(vals, "")
	}
	drive := strings.TrimSpace(vals[0])
	if len(drive) != 2 || !cfgIsLetter(drive[0]) || drive[1] != ':' {
		c.note(SectionPlatform, errors.New("assuming C: as the system drive: the host did not say which it is"))
		return locDefaultWinRoots("C:")
	}
	drive = strings.ToUpper(drive)
	r := locDefaultWinRoots(drive)
	w := locStyle(true)
	for i, dst := range []*string{&r.ProgramData, &r.ProgramFiles, &r.ProgramFiles86} {
		v := strings.TrimRight(strings.TrimSpace(vals[i+1]), `\`)
		if w.isAbs(v) && !strings.ContainsAny(v, "\x00\r\n|*?\"<>") {
			*dst = v
		}
	}
	return r
}

// locWindowsJDKVendors are the directories under Program Files that JDK
// vendors install into, each holding one directory per JDK.
var locWindowsJDKVendors = []string{
	`Java`, `Eclipse Adoptium`, `Eclipse Foundation`, `AdoptOpenJDK`, `Microsoft`,
	`Amazon Corretto`, `Zulu`, `BellSoft`, `RedHat`, `Semeru`,
}

func locWindowsTable(r locWinRoots) []locEntry {
	d, pd, pf, pf86 := r.Drive, r.ProgramData, r.ProgramFiles, r.ProgramFiles86
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
func locWindowsHomeTable(r locWinRoots) []locEntry {
	h := r.Drive + `\Users\*`
	return []locEntry{
		{Path: h + `\.ssh`, Dir: true, Names: []string{"authorized_keys"}, Kind: locAuthorizedKeys, Account: "*"},
		{Path: h + `\.ssh`, Dir: true, Names: []string{"known_hosts"}, Kind: locKnownHosts},
		{Path: h + `\.ssh`, Dir: true, Names: []string{"id_*", "identity", "*.pem", "*.key", "*.ppk"}, Kind: locMaterial, Role: "ssh_user_key"},
		{Path: h + `\AppData\Roaming\gnupg`, Dir: true, Depth: 1, Names: []string{"pubring.kbx", "pubring.gpg", "secring.gpg", "*.key"}, Kind: locGnuPG},
		{Path: h + `\AppData\Roaming\Mozilla\Firefox\Profiles\*`, Dir: true, Kind: locNSS, Names: locNSSNames},
		{Path: h + `\.keystore`, Kind: locMaterial, Section: SectionKeystores},
	}
}
