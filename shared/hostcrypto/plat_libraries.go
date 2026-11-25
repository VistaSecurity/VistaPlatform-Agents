package hostcrypto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Cryptographic libraries present on the host, learned three ways and said
// which in CryptoLibrary.Source: the package database ("package"), a file
// found in the library directories or a binary's own version output
// ("file"), and pass 3's running processes ("process", pass_running.go).
// Every listing is bounded on the host (head, a count and a time budget)
// and again by the registry.

// platLibFileMax bounds the library files one listing returns.
const platLibFileMax = 1000

// platPkgScript queries whichever package database the host has for the
// crypto library packages, by name pattern, as "manager<TAB>name<TAB>
// version" lines (apk: "apk<TAB>name-version"). Only installed packages are
// printed. Exit 127 when the host has none of dpkg, rpm and apk.
const platPkgScript = `if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' openssl 'libssl*' 'libcrypto*' 'libgnutls*' 'libnss3*' 'libgcrypt*' 'libwolfssl*' 'libmbed*' 'libressl*' libbcprov-java 'openssl-provider-fips*' 'openssl-fips*' 2>/dev/null | awk -F'\t' '$1 ~ /^ii/ { print "dpkg\t" $2 "\t" $3 }'
  exit 0
fi
if command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 'openssl*' 'libopenssl*' 'gnutls*' 'libgnutls*' 'nss' 'nss-softokn*' 'mozilla-nss*' 'libgcrypt*' 'wolfssl*' 'mbedtls*' 'libmbed*' 'libressl*' 'bouncycastle*' 'bcprov*' 2>/dev/null | awk -F'\t' 'NF == 2 { print "rpm\t" $1 "\t" $2 }'
  exit 0
fi
if command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null | awk '/^(openssl|libssl|libcrypto|gnutls|nss|libgcrypt|wolfssl|mbedtls|libressl|bouncycastle)/ { print "apk\t" $0 }'
  exit 0
fi
exit 127`

// platOpenSSLScript runs the openssl on PATH for its own version: the
// version line and the two directory lines, filtered on the host (the rest
// of "version -a" is build flags). Exit 127 without an openssl.
const platOpenSSLScript = `p=$(command -v openssl 2>/dev/null) || exit 127
printf 'path %s\n' "$p"
"$p" version -a 2>/dev/null | grep -E '^(OpenSSL|LibreSSL|BoringSSL) |^(OPENSSLDIR|MODULESDIR):' | head -n 4
exit 0`

// platLinuxLibFilesScript lists the library files of the crypto libraries
// in the library directories, regular files only (a soname link is the same
// library), within one filesystem, four levels deep, at most
// platLibFileMax lines.
const platLinuxLibFilesScript = `for d in /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /usr/share/java /opt; do
  [ -d "$d" ] || continue
  find "$d" -xdev -maxdepth 4 -type f \( -name 'libssl.so*' -o -name 'libcrypto.so*' -o -name 'libgnutls.so*' -o -name 'libnss3.so' -o -name 'libsoftokn3.so' -o -name 'libgcrypt.so*' -o -name 'libwolfssl.so*' -o -name 'libmbedtls.so*' -o -name 'libmbedcrypto.so*' -o -name 'libtls.so*' -o -name 'fips.so' -o -name 'bcprov*.jar' -o -name 'bc-fips*.jar' \) 2>/dev/null
done | head -n 1000
exit 0`

// platBrewScript lists the Homebrew crypto formulae: each opt link and the
// Cellar directory it points at, which names the version.
const platBrewScript = `for d in /opt/homebrew/opt /usr/local/opt; do
  [ -d "$d" ] || continue
  for n in openssl@3 openssl@1.1 openssl libressl gnutls libgcrypt mbedtls wolfssl nss; do
    [ -L "$d/$n" ] && printf '%s %s\n' "$d/$n" "$(readlink "$d/$n")"
  done
done
exit 0`

var platSwVersArgv = []string{"sw_vers", "-productVersion"}

// platPkgNames maps a package name to a library, by prefix, first match
// wins. Development, documentation and debug packages are not libraries.
var platPkgNames = []struct{ prefix, name string }{
	{"openssl-provider-fips", "openssl"}, {"openssl-fips", "openssl"},
	{"libressl", "libressl"},
	{"openssl", "openssl"}, {"libopenssl", "openssl"}, {"libssl", "openssl"}, {"libcrypto", "openssl"},
	{"libgnutls", "gnutls"}, {"gnutls", "gnutls"},
	{"libnss3", "nss"}, {"nss-softokn", "nss"}, {"mozilla-nss", "nss"}, {"nss", "nss"},
	{"libgcrypt", "libgcrypt"},
	{"libwolfssl", "wolfssl"}, {"wolfssl", "wolfssl"},
	{"libmbed", "mbedtls"}, {"mbedtls", "mbedtls"},
	{"libbcprov-java", "bouncycastle"}, {"bouncycastle", "bouncycastle"}, {"bcprov", "bouncycastle"},
}

var platPkgSkipSuffixes = []string{"-dev", "-devel", "-doc", "-docs", "-dbg", "-dbgsym", "-static", "-debuginfo", "-debugsource", "-utils", "-tools", "-bin", "-perl", "-java-doc"}

// platPkgLibrary names the library a package is, or "".
func platPkgLibrary(pkg string) string {
	for _, s := range platPkgSkipSuffixes {
		if strings.HasSuffix(pkg, s) {
			return ""
		}
	}
	for _, p := range platPkgNames {
		if strings.HasPrefix(pkg, p.prefix) {
			// "nss" alone must not take "nss-pam-ldapd" and the like.
			if p.prefix == "nss" && pkg != "nss" && !strings.HasPrefix(pkg, "nss-softokn") {
				return ""
			}
			return p.name
		}
	}
	return ""
}

func platPkgFIPS(pkg string) bool {
	return strings.HasPrefix(pkg, "openssl-provider-fips") || strings.HasPrefix(pkg, "openssl-fips")
}

var platVersionRE = regexp.MustCompile(`^[A-Za-z0-9.+:~_-]{1,64}$`)

var platApkRE = regexp.MustCompile(`^([a-z0-9][a-z0-9+._-]*?)-([0-9][A-Za-z0-9._]*-r[0-9]+)$`)

// platParsePackages parses platPkgScript into package-sourced libraries.
// A FIPS provider package marks the openssl entries FIPSProvider.
func platParsePackages(b []byte) []CryptoLibrary {
	var libs []CryptoLibrary
	fips := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		var pkg, ver string
		switch {
		case len(f) == 3 && (f[0] == "dpkg" || f[0] == "rpm"):
			pkg, ver = f[1], f[2]
		case len(f) == 2 && f[0] == "apk":
			m := platApkRE.FindStringSubmatch(f[1])
			if m == nil {
				continue
			}
			pkg, ver = m[1], m[2]
		default:
			continue
		}
		if !platVersionRE.MatchString(ver) || len(pkg) > 128 {
			continue
		}
		name := platPkgLibrary(pkg)
		if name == "" {
			continue
		}
		if platPkgFIPS(pkg) {
			fips = true
			libs = append(libs, CryptoLibrary{Name: name, Version: ver, Source: "package", Package: pkg, FIPSProvider: platBoolPtr(true)})
			continue
		}
		libs = append(libs, CryptoLibrary{Name: name, Version: ver, Source: "package", Package: pkg})
	}
	if fips {
		for i := range libs {
			if libs[i].Name == "openssl" && libs[i].FIPSProvider == nil {
				libs[i].FIPSProvider = platBoolPtr(true)
			}
		}
	}
	return libs
}

// platOpenSSLVersion is what platOpenSSLScript said.
type platOpenSSLVersion struct {
	path, name, version, modulesDir string
	fips                            bool
}

var platOpenSSLLineRE = regexp.MustCompile(`^(OpenSSL|LibreSSL|BoringSSL) ([0-9][A-Za-z0-9.\-]{0,31})`)

// platParseOpenSSLVersion parses platOpenSSLScript.
func platParseOpenSSLVersion(b []byte) (platOpenSSLVersion, bool) {
	var v platOpenSSLVersion
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "path "):
			p := strings.TrimPrefix(line, "path ")
			if strings.HasPrefix(p, "/") && len(p) <= 4096 {
				v.path = p
			}
		case strings.HasPrefix(line, "MODULESDIR:"):
			d := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "MODULESDIR:")), `"`)
			if strings.HasPrefix(d, "/") && len(d) <= 4096 {
				v.modulesDir = d
			}
		default:
			if m := platOpenSSLLineRE.FindStringSubmatch(line); m != nil && v.name == "" {
				v.name = strings.ToLower(m[1])
				v.version = m[2]
				v.fips = strings.HasSuffix(strings.ToLower(m[2]), "-fips")
			}
		}
	}
	return v, v.name != ""
}

// platLibFileNames maps a library file's base name to a library, and says
// whether the file is a FIPS provider or module.
var platLibFileRules = []struct {
	re   *regexp.Regexp
	name string
	fips bool
}{
	{regexp.MustCompile(`(?i)^fips\.(so|dylib|dll)$`), "openssl", true},
	{regexp.MustCompile(`(?i)^bc-fips.*\.jar$`), "bouncycastle", true},
	{regexp.MustCompile(`(?i)^bcprov.*\.jar$`), "bouncycastle", false},
	{regexp.MustCompile(`(?i)^libtls[.-]`), "libressl", false},
	{regexp.MustCompile(`(?i)^(libssl|libcrypto)([.-]|\.so|\.dll|$)`), "openssl", false},
	{regexp.MustCompile(`(?i)^(libeay32|ssleay32)\.dll$`), "openssl", false},
	{regexp.MustCompile(`(?i)^libgnutls[.-]`), "gnutls", false},
	{regexp.MustCompile(`(?i)^(libnss3|nss3|libsoftokn3|softokn3|libfreebl3|libfreeblpriv3)[.]`), "nss", false},
	{regexp.MustCompile(`(?i)^libgcrypt[.-]`), "libgcrypt", false},
	{regexp.MustCompile(`(?i)^(lib)?wolfssl[.-]`), "wolfssl", false},
	{regexp.MustCompile(`(?i)^(lib)?mbed(tls|crypto|x509)[.-]`), "mbedtls", false},
	{regexp.MustCompile(`(?i)^libboringssl[.-]`), "boringssl", false},
	{regexp.MustCompile(`(?i)^schannel\.dll$`), "schannel", false},
}

var platJarVersionRE = regexp.MustCompile(`-([0-9]+(?:\.[0-9]+)+)\.jar$`)

// platLibraryFile names the library a file is ("" when none), whether it
// is a FIPS module, and the version its name states (jars only: a soname's
// number is an ABI, not a release).
func platLibraryFile(p string) (name string, fips bool, version string) {
	base := p
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	for _, r := range platLibFileRules {
		if r.re.MatchString(base) {
			name, fips = r.name, r.fips
			break
		}
	}
	if name == "" {
		return "", false, ""
	}
	if name == "openssl" && strings.Contains(strings.ToLower(p), "libressl") {
		name = "libressl"
	}
	if m := platJarVersionRE.FindStringSubmatch(base); m != nil {
		version = m[1]
	}
	return name, fips, version
}

// platParseLibFiles turns a list of paths into file-sourced libraries.
func platParseLibFiles(b []byte, windows bool) []CryptoLibrary {
	var libs []CryptoLibrary
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.TrimRight(line, "\r")
		if !platAbsPath(p, windows) {
			continue
		}
		name, fips, ver := platLibraryFile(p)
		if name == "" {
			continue
		}
		l := CryptoLibrary{Name: name, Version: ver, Path: p, Source: "file"}
		if fips {
			l.FIPSProvider = platBoolPtr(true)
		}
		libs = append(libs, l)
	}
	return libs
}

// platAbsPath reports whether p is an absolute path of the platform, of
// bounded length, with no control character.
func platAbsPath(p string, windows bool) bool {
	if p == "" || len(p) > 4096 || !platPrintableUTF8(p) {
		return false
	}
	if windows {
		return len(p) > 3 && (p[1] == ':' && p[2] == '\\' || strings.HasPrefix(p, `\\`))
	}
	return strings.HasPrefix(p, "/")
}

func platPrintableUTF8(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '�' {
			return false
		}
	}
	return true
}

var platBrewTargetRE = regexp.MustCompile(`Cellar/([A-Za-z0-9@._+-]+)/([0-9][A-Za-z0-9._+-]{0,63})/?$`)

// platParseBrew parses platBrewScript into package-sourced libraries.
func platParseBrew(b []byte) []CryptoLibrary {
	var libs []CryptoLibrary
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !strings.HasPrefix(f[0], "/") {
			continue
		}
		m := platBrewTargetRE.FindStringSubmatch(f[1])
		if m == nil {
			continue
		}
		formula, ver := m[1], m[2]
		if seen[formula+"/"+ver] {
			continue
		}
		seen[formula+"/"+ver] = true
		name := ""
		switch {
		case strings.HasPrefix(formula, "openssl"):
			name = "openssl"
		case formula == "libressl", formula == "gnutls", formula == "libgcrypt", formula == "mbedtls", formula == "wolfssl", formula == "nss":
			name = formula
		}
		if name == "" {
			continue
		}
		libs = append(libs, CryptoLibrary{Name: name, Version: ver, Path: f[0] + "/lib", Source: "package", Package: "homebrew:" + formula})
	}
	return libs
}

// platAddLibraries adds libraries to the registry.
func platAddLibraries(c *collection, libs []CryptoLibrary) {
	for _, l := range libs {
		c.registry.addLibrary(l)
	}
}

// platOpenSSLBinary runs platOpenSSLScript and adds what it says, with
// FIPSProvider from the FIPS provider's presence in MODULESDIR (OpenSSL 3).
func platOpenSSLBinary(ctx context.Context, c *collection, fipsFile string) error {
	out, stderr, exit, err := platRun(ctx, c.target, platSh(platOpenSSLScript))
	if err != nil {
		if errors.Is(err, errPlatNoTool) {
			return nil // no openssl binary is an answer
		}
		return err
	}
	if exit != 0 {
		return platStderr("openssl version", stderr, exit)
	}
	v, ok := platParseOpenSSLVersion(out)
	if !ok {
		return nil
	}
	l := CryptoLibrary{Name: v.name, Version: v.version, Path: v.path, Source: "file"}
	switch {
	case v.fips:
		l.FIPSProvider = platBoolPtr(true)
	case v.modulesDir != "":
		if _, err := c.target.Stat(ctx, v.modulesDir+"/"+fipsFile); err == nil {
			l.FIPSProvider = platBoolPtr(true)
		} else if errors.Is(err, ErrNotExist) {
			l.FIPSProvider = platBoolPtr(false)
		}
	}
	c.registry.addLibrary(l)
	return nil
}

// platLinuxLibraries runs the Linux library steps.
func platLinuxLibraries(ctx context.Context, c *collection) {
	var problems []error
	out, stderr, exit, err := platRun(ctx, c.target, platSh(platPkgScript))
	switch {
	case errors.Is(err, errPlatNoTool):
		c.note(SectionLibraries, errors.New("libraries: no package database (dpkg, rpm, apk) on the host"))
	case err != nil:
		problems = append(problems, fmt.Errorf("libraries: packages: %w", err))
	case exit != 0:
		problems = append(problems, platStderr("libraries: packages", stderr, exit))
	default:
		platAddLibraries(c, platParsePackages(out))
	}
	if err := platOpenSSLBinary(ctx, c, "fips.so"); err != nil {
		problems = append(problems, err)
	}
	out, stderr, exit, err = platRun(ctx, c.target, platSh(platLinuxLibFilesScript))
	switch {
	case err != nil:
		problems = append(problems, fmt.Errorf("libraries: files: %w", err))
	case exit != 0:
		problems = append(problems, platStderr("libraries: files", stderr, exit))
	default:
		libs := platParseLibFiles(out, false)
		if strings.Count(string(out), "\n") >= platLibFileMax {
			c.limit(SectionLibraries, "max_files", fmt.Sprintf("listed the first %d library files", platLibFileMax))
		}
		platAddLibraries(c, libs)
	}
	platLibrariesOutcome(c, problems)
}

func platLibrariesOutcome(c *collection, problems []error) {
	for _, p := range problems {
		c.partial(SectionLibraries, p)
	}
	c.mark(SectionLibraries, SectionOK)
}

// platDarwinLibraries runs the macOS library steps: corecrypto (part of
// the operating system, so its version is the system's), the openssl on
// PATH (LibreSSL on a stock system) and the Homebrew formulae.
func platDarwinLibraries(ctx context.Context, c *collection) {
	var problems []error
	out, stderr, exit, err := platRun(ctx, c.target, platSwVersArgv)
	switch {
	case err != nil:
		problems = append(problems, fmt.Errorf("libraries: sw_vers: %w", err))
	case exit != 0:
		problems = append(problems, platStderr("libraries: sw_vers", stderr, exit))
	default:
		ver := strings.TrimSpace(string(out))
		if !platVersionRE.MatchString(ver) {
			ver = ""
		}
		c.registry.addLibrary(CryptoLibrary{Name: "corecrypto", Version: ver, Source: "package", Package: "macOS"})
	}
	if err := platOpenSSLBinary(ctx, c, "fips.dylib"); err != nil {
		problems = append(problems, err)
	}
	out, stderr, exit, err = platRun(ctx, c.target, platSh(platBrewScript))
	switch {
	case err != nil:
		problems = append(problems, fmt.Errorf("libraries: homebrew: %w", err))
	case exit != 0:
		problems = append(problems, platStderr("libraries: homebrew", stderr, exit))
	default:
		platAddLibraries(c, platParseBrew(out))
	}
	platLibrariesOutcome(c, problems)
}

// platPSLibraries reports Schannel's version and searches Program Files,
// four levels deep, for the files of other crypto libraries, within a time
// budget and a count: names and file versions only.
const platPSLibraries = `$lbOut = New-Object 'System.Collections.Generic.List[object]'
$lbTrunc = $false
$lbSw = [System.Diagnostics.Stopwatch]::StartNew()
$lbRx = [regex]::new('^(?:(?:libcrypto|libssl)(?:-[0-9_]+)?(?:-x64|-arm64)?\.dll|libeay32\.dll|ssleay32\.dll|libgnutls(?:-[0-9]+)?\.dll|nss3\.dll|softokn3\.dll|libgcrypt(?:-[0-9]+)?\.dll|wolfssl\.dll|mbedcrypto\.dll|mbedtls\.dll|fips\.dll|bcprov[^\\]*\.jar|bc-fips[^\\]*\.jar)\z', 'IgnoreCase, CultureInvariant')
function lbVer([string]$lvP) {
  try { $lvI = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($lvP); if ($lvI.ProductVersion) { return [string]$lvI.ProductVersion }; return [string]$lvI.FileVersion } catch { return '' }
}
$lbSch = [System.IO.Path]::Combine([Environment]::GetFolderPath('System'), 'schannel.dll')
if ([System.IO.File]::Exists($lbSch)) { [void]$lbOut.Add([pscustomobject]@{ Path = $lbSch; Version = (lbVer $lbSch) }) }
$lbQ = New-Object 'System.Collections.Generic.Queue[object]'
$lbSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($lbR in @([Environment]::GetFolderPath('ProgramFiles'), [Environment]::GetFolderPath('ProgramFilesX86'))) {
  if ($lbR -and $lbSeen.Add($lbR)) { $lbQ.Enqueue(@($lbR, 0)) }
}
$lbDirs = 0
while ($lbQ.Count -gt 0) {
  if ($lbSw.Elapsed.TotalSeconds -gt [int]$a.Budget -or $lbDirs -ge 20000 -or $lbOut.Count -ge [int]$a.Max) { $lbTrunc = $true; break }
  $lbItem = $lbQ.Dequeue()
  $lbD = [string]$lbItem[0]
  $lbDepth = [int]$lbItem[1]
  $lbDirs++
  try {
    foreach ($lbF in [System.IO.Directory]::EnumerateFiles($lbD)) {
      if ($lbRx.IsMatch([System.IO.Path]::GetFileName($lbF))) { [void]$lbOut.Add([pscustomobject]@{ Path = $lbF; Version = (lbVer $lbF) }) }
    }
    if ($lbDepth -lt 4) {
      foreach ($lbS in [System.IO.Directory]::EnumerateDirectories($lbD)) {
        $lbAttr = [System.IO.File]::GetAttributes($lbS)
        if (($lbAttr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $lbQ.Enqueue(@($lbS, ($lbDepth + 1)))
      }
    }
  } catch { $lbE = (plErr $_.Exception) }
}
plOut ([pscustomobject]@{ Libs = $lbOut.ToArray(); Truncated = $lbTrunc })
`

type platWinLib struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
}

type platWinLibsAnswer struct {
	Libs      json.RawMessage `json:"Libs"`
	Truncated bool            `json:"Truncated"`
}

// platParseWindowsLibraries parses platPSLibraries' answer.
func platParseWindowsLibraries(b []byte) (libs []CryptoLibrary, truncated bool, err error) {
	var ans platWinLibsAnswer
	if err := json.Unmarshal(b, &ans); err != nil {
		return nil, false, errors.New("hostcrypto: unreadable library answer")
	}
	items, err := psArray[platWinLib](ans.Libs)
	if err != nil {
		return nil, false, errors.New("hostcrypto: unreadable library answer")
	}
	for _, it := range items {
		if !platAbsPath(it.Path, true) {
			continue
		}
		name, fips, ver := platLibraryFile(it.Path)
		if name == "" {
			continue
		}
		v := strings.TrimSpace(it.Version)
		if i := strings.IndexByte(v, ' '); i > 0 {
			v = v[:i] // "10.0.26100.1 (WinBuild...)"
		}
		if v != "" && platVersionRE.MatchString(v) {
			ver = v
		}
		l := CryptoLibrary{Name: name, Version: ver, Path: it.Path, Source: "file"}
		if fips {
			l.FIPSProvider = platBoolPtr(true)
		}
		libs = append(libs, l)
	}
	return libs, ans.Truncated, nil
}

type platLibArgs struct {
	Budget int `json:"Budget"`
	Max    int `json:"Max"`
}

// platWindowsLibraries runs the Windows library program.
func platWindowsLibraries(ctx context.Context, c *collection) {
	b, err := platPS(ctx, c.target, platPSLibraries, platLibArgs{Budget: 20, Max: 200})
	if err != nil {
		c.partial(SectionLibraries, fmt.Errorf("libraries: %w", err))
		return
	}
	libs, trunc, err := platParseWindowsLibraries(b)
	if err != nil {
		c.partial(SectionLibraries, err)
		return
	}
	platAddLibraries(c, libs)
	if trunc {
		c.limit(SectionLibraries, "max_duration", "the Program Files search stopped at its bound (20 s, 200 files or 20000 directories)")
	}
	c.mark(SectionLibraries, SectionOK)
}
