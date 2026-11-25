package hostcrypto

// The remote probes the design table promises: describing a private key or
// a keystore on a REMOTE host by a command that runs there and prints only
// public information, so that no byte of the file crosses the connection.
//
//   - A private key: `ssh-keygen -y` (the public key line) and, where that
//     cannot read the key, `openssl pkey -pubout` (the SubjectPublicKeyInfo).
//     Neither is ever given a way to prompt: ssh-keygen gets -P '' and
//     openssl -passin pass:, both with standard input closed, so an
//     encrypted key fails at once, and the failure is the answer
//     "encrypted". On Windows the same ssh-keygen.exe, where OpenSSH is
//     installed; openssl is not a Windows built-in and is not used there.
//   - A keystore: `openssl pkcs12 -nokeys -info` for PKCS#12 (keys are never
//     output) and `keytool -list` (never -v, never -rfc) for JKS and JCEKS.
//     The default-password opt-in sends the well-known passwords on the
//     command's STANDARD INPUT, one per line, read by the script into a
//     shell variable and handed to the tool through a pipe from the shell's
//     own printf: no password is ever in a process's arguments, so none is
//     in `ps`. Without the opt-in only the empty password is tried. No
//     Windows keystore probe: Windows has no built-in tool that lists a
//     keystore without being able to print its keys (certutil -dump prints
//     key material), so remote Windows keystores keep their markers-only
//     description.
//
// Every script prints a small token vocabulary and passes the tool's own
// output through an awk filter that keeps only the lines the parser reads;
// the parsers below (pure: bytes in, record fields out) take nothing else.
// Keytabs (klist -k) are not probed: neither host this was built against
// has an MIT klist to prove the command against.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// jobKeyProbeScript describes one private key file ($1). Its answer is one
// of: "PUB <type> <base64 blob>", "SPKI" then the base64 lines of a PUBLIC
// KEY block then "END", "ENCRYPTED", "DENIED", "NOTOOL", "FAILED".
const jobKeyProbeScript = `f=$1
st=FAILED
if command -v ssh-keygen >/dev/null 2>&1; then
  if o=$(ssh-keygen -y -P '' -f "$f" </dev/null 2>/dev/null); then
    l=$(printf '%s\n' "$o" | awk 'NR==1 && NF>=2 && $2 ~ /^[A-Za-z0-9+\/]+=*$/ {print "PUB " $1 " " $2}')
    if [ -n "$l" ]; then printf '%s\n' "$l"; exit 0; fi
  fi
  e=$(ssh-keygen -y -P '' -f "$f" </dev/null 2>&1 >/dev/null)
  case $e in
    *passphrase*) echo ENCRYPTED; exit 0;;
    *ermission\ denied*) st=DENIED;;
  esac
else
  st=NOTOOL
fi
if command -v openssl >/dev/null 2>&1; then
  s=$(openssl pkey -in "$f" -pubout -passin pass: </dev/null 2>/dev/null | awk '/^-----BEGIN PUBLIC KEY-----$/ {p=1; print "SPKI"; next} p && /^-----END PUBLIC KEY-----$/ {print "END"; exit} p && /^[A-Za-z0-9+\/=]+$/ {print}')
  if [ -n "$s" ]; then printf '%s\n' "$s"; exit 0; fi
  e=$(openssl pkey -in "$f" -pubout -passin pass: </dev/null 2>&1 >/dev/null)
  case $e in
    *"bad decrypt"*|*"bad password"*|*"maybe wrong password"*) echo ENCRYPTED; exit 0;;
    *ermission\ denied*) st=DENIED;;
  esac
  [ "$st" = NOTOOL ] && st=FAILED
fi
echo "$st"
`

// jobKeyProbeArgv runs jobKeyProbeScript on path, the path a positional
// argument and never script text.
func jobKeyProbeArgv(path string) []string {
	return []string{"env", "LC_ALL=C", "sh", "-c", jobKeyProbeScript, "sh", path}
}

// jobWinKeyProbe is the Windows key probe: ssh-keygen.exe from the
// system's OpenSSH, started directly (no shell), standard input closed,
// -P "" so it cannot prompt. It answers the same vocabulary, as JSON.
var jobWinKeyProbe = psPrelude + `$kpExe = [System.IO.Path]::Combine([Environment]::GetFolderPath('System'), 'OpenSSH', 'ssh-keygen.exe')
$kpPath = [string]$a.Path
if ($kpPath.StartsWith('\\?\')) { $kpPath = $kpPath.Substring(4) }
if (-not [System.IO.File]::Exists($kpExe)) { psOut ([pscustomobject]@{ T = 'NOTOOL' }); exit 0 }
if ($kpPath.Contains('"')) { psOut ([pscustomobject]@{ T = 'FAILED' }); exit 0 }
$kpPsi = New-Object System.Diagnostics.ProcessStartInfo
$kpPsi.FileName = $kpExe
$kpPsi.Arguments = '-y -P "" -f "' + $kpPath + '"'
$kpPsi.UseShellExecute = $false
$kpPsi.RedirectStandardOutput = $true
$kpPsi.RedirectStandardError = $true
$kpPsi.RedirectStandardInput = $true
$kpPsi.CreateNoWindow = $true
$kpP = [System.Diagnostics.Process]::Start($kpPsi)
$kpP.StandardInput.Close()
if (-not $kpP.WaitForExit(20000)) { try { $kpP.Kill() } catch { }; psOut ([pscustomobject]@{ T = 'FAILED' }); exit 0 }
$kpO = $kpP.StandardOutput.ReadToEnd()
$kpE = $kpP.StandardError.ReadToEnd()
if ($kpP.ExitCode -eq 0) {
  $kpF = (($kpO -split [string][char]10)[0]).Trim() -split ' '
  if ($kpF.Count -ge 2 -and $kpF[1] -match '^[A-Za-z0-9+/]+=*$') { psOut ([pscustomobject]@{ T = 'PUB'; L = ($kpF[0] + ' ' + $kpF[1]) }); exit 0 }
  psOut ([pscustomobject]@{ T = 'FAILED' }); exit 0
}
if ($kpE -match 'passphrase') { psOut ([pscustomobject]@{ T = 'ENCRYPTED' }); exit 0 }
if ($kpE -match 'ermission denied|ccess is denied') { psOut ([pscustomobject]@{ T = 'DENIED' }); exit 0 }
psOut ([pscustomobject]@{ T = 'FAILED' })
`

// jobProbeRemoteKey is locRemoteKeyProbe.
func jobProbeRemoteKey(ctx context.Context, t Target, path string, _ Identity, base PrivateKey) (PrivateKey, bool) {
	switch tt := t.(type) {
	case *RemoteUnixTarget:
		out, _, exit, err := tt.Run(ctx, jobKeyProbeArgv(path))
		if err != nil || exit != 0 {
			return base, false
		}
		return jobParseKeyProbe(out, base), true
	case *RemoteWindowsTarget:
		b, err := tt.psJSON(ctx, jobWinKeyProbe, psPathArgs{Path: path})
		if err != nil {
			return base, false
		}
		var r struct{ T, L string }
		if json.Unmarshal(b, &r) != nil {
			return base, false
		}
		line := r.T
		if r.T == "PUB" {
			line += " " + r.L
		}
		return jobParseKeyProbe([]byte(line+"\n"), base), true
	}
	return base, false
}

// jobMaxProbeBlob bounds a public key blob or SPKI from a probe: larger than
// any public key (an RSA-16384 SPKI is about 2 KiB).
const jobMaxProbeBlob = 16 << 10

// jobParseKeyProbe completes base from a key probe's answer. It keeps only
// what it derives from a public key it could parse (algorithm, size, curve,
// the SubjectPublicKeyInfo hash, the SSH fingerprint); the line or block
// itself is not kept, and an answer it cannot parse is "could not read".
func jobParseKeyProbe(out []byte, base PrivateKey) PrivateKey {
	k := base
	failed := func(why string) PrivateKey {
		k.Unknown = why
		return k
	}
	const cannot = "remote: ssh-keygen and openssl on the host could not read the key; size and public key not read"
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	if !sc.Scan() {
		return failed(cannot)
	}
	first := strings.Fields(sc.Text())
	if len(first) == 0 {
		return failed(cannot)
	}
	no := false
	switch first[0] {
	case "PUB":
		if len(first) != 3 || len(first[2]) > jobMaxProbeBlob {
			return failed(cannot)
		}
		blob, err := base64.StdEncoding.DecodeString(first[2])
		if err != nil {
			return failed(cannot)
		}
		d, ok := keyDescribeSSHBlob(blob)
		if !ok || d.typ != first[1] {
			return failed(cannot)
		}
		k.Algorithm, k.SizeBits, k.Curve = d.algorithm, d.size, d.curve
		k.PublicKeySHA256, k.SSHFingerprint = d.spkiSHA256, d.fingerprint
		k.Encrypted, k.Unknown = &no, d.unknown
		return k
	case "SPKI":
		var b64 strings.Builder
		ended := false
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "END" {
				ended = true
				break
			}
			if b64.Len()+len(l) > jobMaxProbeBlob {
				return failed(cannot)
			}
			b64.WriteString(l)
		}
		der, err := base64.StdEncoding.DecodeString(b64.String())
		if !ended || err != nil {
			return failed(cannot)
		}
		info, ok := keySPKIInfo(der)
		if !ok || info.Algorithm == "" {
			return failed(cannot)
		}
		k.Algorithm, k.SizeBits, k.Curve, k.PublicKeySHA256 = info.Algorithm, info.SizeBits, info.Curve, info.PublicKeySHA256
		k.Encrypted, k.Unknown = &no, ""
		return k
	case "ENCRYPTED":
		yes := true
		k.Encrypted = &yes
		k.Unknown = "remote: encrypted; size and public key are not read without the passphrase"
		return k
	case "DENIED":
		return failed("remote: the account may not read the key file; size and public key not read")
	case "NOTOOL":
		return failed("remote: neither ssh-keygen nor openssl is installed on the host; size and public key not read")
	}
	return failed(cannot)
}

// jobKeystoreProbeScript lists one keystore ($1, of type $2). With $3 = 1
// it first tries the passwords on its standard input, one per line. Its
// answer is "OPENED default" or "OPENED empty" with the filtered listing,
// or one of "LOCKED", "DENIED", "NOTOOL", "UNSUPPORTED".
//
// The filtered listing is, for openssl pkcs12: "I <line>" for its MAC,
// PKCS7 and bag lines, "N <friendlyName>", and "CERT" for each certificate
// it printed (never the certificate); for keytool: "V 1" when the listing
// was not verified (no password), "C <count>", "E <alias line>" and
// "F <SHA-256 fingerprint>".
const jobKeystoreProbeScript = `f=$1
typ=$2
tries=$3
fp12() { awk '/^MAC/ || /^PKCS7 / || /^Shrouded Keybag/ || /^Key bag/ || /^Certificate bag/ {print "I " $0; next} /^-----BEGIN CERTIFICATE-----$/ {print "CERT"; next} /^ *friendlyName: / {sub(/^ *friendlyName: /, ""); print "N " $0}'; }
fkt() { awk '/^Your keystore contains [0-9]+ entr/ {print "C " $4; next} /(PrivateKeyEntry|trustedCertEntry|SecretKeyEntry), *$/ {print "E " $0; next} /^Certificate fingerprint \(SHA-256\): / {print "F " $4}'; }
p12() {
  for leg in "" -legacy; do
    o=$(printf '%s\n' "$1" | openssl pkcs12 $leg -in "$f" -nokeys -info -passin stdin 2>&1)
    if [ $? -eq 0 ]; then printf '%s\n' "$o" | fp12; return 0; fi
    case $o in *nsupported*|*"RC2"*) continue;; esac
    return 1
  done
  return 1
}
kt() {
  o=$(printf '%s\n' "$1" | keytool -list -keystore "$f" 2>&1)
  r=$?
  case $o in *"locate a Java Runtime"*|*"No Java runtime"*) return 2;; esac
  [ $r -eq 0 ] || return 1
  case $o in *"NOT been verified"*) echo "V 1";; esac
  printf '%s\n' "$o" | fkt
  return 0
}
case $typ in
  pkcs12) tool=openssl;;
  jks|jceks) tool=keytool;;
  *) echo UNSUPPORTED; exit 0;;
esac
[ -r "$f" ] || { echo DENIED; exit 0; }
command -v "$tool" >/dev/null 2>&1 || { echo NOTOOL; exit 0; }
lst() { if [ "$tool" = openssl ]; then p12 "$1"; else kt "$1"; fi; }
if [ "$tries" = 1 ]; then
  while IFS= read -r pw; do
    [ -n "$pw" ] || continue
    lst "$pw"
    rc=$?
    [ $rc -eq 0 ] && { echo "OPENED default"; exit 0; }
    [ $rc -eq 2 ] && { echo NOTOOL; exit 0; }
  done
fi
lst ""
rc=$?
[ $rc -eq 0 ] && { echo "OPENED empty"; exit 0; }
[ $rc -eq 2 ] && { echo NOTOOL; exit 0; }
echo LOCKED
`

// jobKeystoreProbeArgv runs jobKeystoreProbeScript; path and type are
// positional arguments, and no password is ever among them.
func jobKeystoreProbeArgv(path, typ string, tries bool) []string {
	t := "0"
	if tries {
		t = "1"
	}
	return []string{"env", "LC_ALL=C", "sh", "-c", jobKeystoreProbeScript, "sh", path, typ, t}
}

// jobProbeRemoteKeystore is locRemoteKeystoreProbe. Only a POSIX host is
// probed (see the file comment for Windows).
func jobProbeRemoteKeystore(ctx context.Context, t Target, path, typ string, tryDefaults bool) (KeystoreContents, bool) {
	tt, ok := t.(*RemoteUnixTarget)
	if !ok || (typ != KeystorePKCS12 && typ != KeystoreJKS && typ != KeystoreJCEKS) {
		return KeystoreContents{}, false
	}
	var (
		out      []byte
		exit     int
		err      error
		notTried string
	)
	ir, canInput := tt.runner.(hostinventory.InputRunner)
	switch {
	case tryDefaults && canInput:
		var pw []string
		for _, p := range DefaultKeystorePasswords {
			if p != "" {
				pw = append(pw, p)
			}
		}
		out, _, exit, err = ir.RunInput(ctx, jobKeystoreProbeArgv(path, typ, true), []byte(strings.Join(pw, "\n")+"\n"))
	default:
		if tryDefaults {
			notTried = "the connection cannot pass a password on standard input"
		}
		out, _, exit, err = tt.Run(ctx, jobKeystoreProbeArgv(path, typ, false))
	}
	if err != nil || exit != 0 {
		return KeystoreContents{}, false
	}
	kc, ok := jobParseKeystoreProbe(out, typ, tryDefaults && notTried == "")
	if !ok {
		return KeystoreContents{}, false
	}
	kc.DefaultsNotTried = notTried
	return kc, true
}

// jobLongRun is a run a name has no business holding: forty or more base64
// or hexadecimal characters, the redaction rule of ReadText.
var jobLongRun = regexp.MustCompile(`[A-Za-z0-9+/=]{` + strconv.Itoa(RedactRunLength) + `,}`)

// jobProbeName keeps an alias or friendly name that is a name: printable,
// bounded, and without a long encoded run.
func jobProbeName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 128 || jobLongRun.MatchString(s) {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return s
}

// jobFingerprintRx is keytool's colon-separated SHA-256.
var jobFingerprintRx = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$`)

// jobParseKeystoreProbe builds a keystore from a keystore probe's answer.
// tried says the default passwords were sent. false when the answer is not
// one this parser knows (the caller keeps the markers' description).
func jobParseKeystoreProbe(out []byte, typ string, tried bool) (KeystoreContents, bool) {
	ks := Keystore{Type: typ, Opened: OpenedNot}
	var protection []string
	var opened string
	unverified := false
	count := -1
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	tag := func(s, p string) (string, bool) {
		if strings.HasPrefix(s, p) {
			return s[len(p):], true
		}
		return "", false
	}
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), " \r")
		switch l {
		case "LOCKED":
			opened = "locked"
		case "DENIED":
			ks.Unknown = "remote: the account may not read the keystore; entries not read"
			return KeystoreContents{Keystore: ks}, true
		case "NOTOOL":
			ks.Unknown = "remote: no openssl or keytool on the host; entries not read"
			return KeystoreContents{Keystore: ks}, true
		case "UNSUPPORTED":
			return KeystoreContents{}, false
		case "OPENED default", "OPENED empty":
			opened = l[len("OPENED "):]
		case "V 1":
			unverified = true
		case "CERT":
			// A certificate the listing printed: already counted by its bag.
		default:
			if v, ok := tag(l, "I "); ok {
				switch {
				case strings.Contains(v, "Shrouded Keybag") || strings.HasPrefix(v, "Key bag"):
					ks.Entries = append(ks.Entries, KeystoreEntry{Kind: "private_key"})
					if a, ok := tag(v, "Shrouded Keybag: "); ok && !strings.HasPrefix(a, "Bag Attributes") {
						protection = jobAppendOnce(protection, "keys "+a)
					}
				case strings.Contains(v, "Certificate bag"):
					ks.Entries = append(ks.Entries, KeystoreEntry{Kind: "certificate"})
					if a, ok := tag(v, "PKCS7 Encrypted data: "); ok && !strings.HasPrefix(a, "Certificate bag") {
						protection = jobAppendOnce(protection, "certificates "+a)
					}
				case strings.HasPrefix(v, "MAC"):
					if !strings.HasPrefix(v, "MAC length") && !strings.HasPrefix(v, "MAC verified") {
						protection = jobAppendOnce(protection, v)
					}
				case strings.HasPrefix(v, "PKCS7 Encrypted data: "):
					protection = jobAppendOnce(protection, "certificates "+strings.TrimPrefix(v, "PKCS7 Encrypted data: "))
				}
			} else if v, ok := tag(l, "N "); ok {
				if n := len(ks.Entries); n > 0 && ks.Entries[n-1].Alias == "" {
					ks.Entries[n-1].Alias = jobProbeName(v)
				}
			} else if v, ok := tag(l, "C "); ok {
				if n, err := strconv.Atoi(v); err == nil && n >= 0 {
					count = n
				}
			} else if v, ok := tag(l, "E "); ok {
				e := KeystoreEntry{}
				switch {
				case strings.Contains(v, "PrivateKeyEntry"):
					e.Kind = "private_key"
				case strings.Contains(v, "trustedCertEntry"):
					e.Kind = "certificate"
				default:
					e.Kind = "secret_key"
				}
				if i := strings.Index(v, ", "); i > 0 {
					e.Alias = jobProbeName(v[:i])
				}
				ks.Entries = append(ks.Entries, e)
			} else if v, ok := tag(l, "F "); ok {
				if n := len(ks.Entries); n > 0 && jobFingerprintRx.MatchString(v) {
					ks.Entries[n-1].CertificateFingerprint = strings.ToLower(strings.ReplaceAll(v, ":", ""))
				}
			}
		}
		if len(ks.Entries) > DefaultMaxKeystoreEntries {
			ks.Entries = ks.Entries[:DefaultMaxKeystoreEntries]
		}
	}
	yes, no := true, false
	switch opened {
	case "default":
		ks.Opened, ks.DefaultPassword = OpenedDefaultPassword, &yes
	case "empty":
		ks.Opened = OpenedWithoutPassword
		if tried {
			// The empty password is one of the well-known defaults; a
			// listing keytool did not verify proves no password at all.
			v := !unverified
			ks.DefaultPassword = &v
		}
	case "locked":
		ks.Unknown = "remote: the keystore needs a password; entries not read"
		ks.Entries = nil
		if tried {
			ks.DefaultPassword = &no
		}
		return KeystoreContents{Keystore: ks}, true
	default:
		return KeystoreContents{}, false
	}
	if count < 0 {
		count = len(ks.Entries)
	}
	ks.EntryCount = &count
	if len(protection) > 0 {
		ks.Protection = strings.Join(protection, "; ")
	}
	if unverified {
		ks.Unknown = "remote: listed without a password; the keystore's integrity was not checked"
	}
	return KeystoreContents{Keystore: ks}, true
}

// jobAppendOnce adds a protection phrase once. A phrase is the tool's
// description of an algorithm; one that is long or holds an encoded run is
// not one, and is not kept.
func jobAppendOnce(list []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 160 || jobLongRun.MatchString(s) {
		return list
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return list
		}
	}
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}

// jobProbeCommands are the probes' command texts, for the guard tests.
func jobProbeCommands() map[string]string {
	return map[string]string{
		"key-probe":      strings.Join(jobKeyProbeArgv("PATH"), " "),
		"keystore-probe": strings.Join(jobKeystoreProbeArgv("PATH", "TYPE", true), " "),
		"win-key-probe":  jobWinKeyProbe,
	}
}

// jobProbeForbiddenWords are tool options that would make a probe print
// private material or a password, on top of platForbiddenWords: OpenSSL's
// -text (private parameters), -nodes and -nocerts (keys out of a PKCS#12),
// -passout and -out (writing), PEM conversions; keytool's -v and -rfc and a
// password in arguments; ssh-keygen's key conversions; klist's -K.
var jobProbeForbiddenWords = []string{
	" -text", "-nodes", "-nocerts", "-passout", " -out ", "-outform", "-traditional", "pkcs8",
	"-list -v", "-v -list", " -rfc", "-storepass", "-keypass", "-exportcert", " -e ", " -K", "-dump", "pass:changeit",
}

// jobProbeForbidden returns the first forbidden word in s, or "".
func jobProbeForbidden(s string) string {
	if w := platForbidden(s); w != "" {
		return w
	}
	for _, w := range jobProbeForbiddenWords {
		if strings.Contains(s, w) {
			return w
		}
	}
	return ""
}
