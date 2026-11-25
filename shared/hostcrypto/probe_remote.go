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

// The key probe decides from the file's own public markers first, on the
// host, from its first 4 KiB, before any tool runs: an OpenSSH key's cipher
// name (in clear in its header), a PEM "ENCRYPTED PRIVATE KEY" label, or a
// "Proc-Type: 4,ENCRYPTED" header. An encrypted PEM key is reported
// encrypted and no tool is run on it, because a tool asked to read it could
// wait on a passphrase. Then, for an OpenSSH key (encrypted or not, whoever
// can read it) and an unencrypted PEM key, `ssh-keygen -e`, which prints the
// public key only (RFC 4716) and, for an OpenSSH key, reads only the clear
// public half; for a PEM key it cannot read (one others may read: ssh-keygen
// then refuses it; an Ed25519 PKCS#8), `openssl pkey -pubout`. Every tool
// run is bounded to 3 seconds where the host has `timeout` (Linux; not
// stock macOS, where the tools are only ever run on files that cannot make
// them wait), and on Windows always.
//
// One host program probes a batch of files; its answer, per file, is
// "=== <index>" then any of: "ENC 0|1" (the OpenSSH cipher says), "B <base64
// line>"... "BLOBEND" (the RFC 4716 public key), "SPKI" <base64 lines> "END"
// (openssl's PUBLIC KEY block), or one of "ENCRYPTED", "DENIED", "NOTOOL",
// "FAILED", "NOTKEY", "TIMEUP".

// jobKeyProbeScript probes every path in its arguments.
const jobKeyProbeScript = `tmo() { if command -v timeout >/dev/null 2>&1; then timeout 3 "$@"; else "$@"; fi; }
b64d() { base64 -d 2>/dev/null || base64 -D 2>/dev/null; }
skg=0; command -v ssh-keygen >/dev/null 2>&1 && skg=1
osl=0; command -v openssl >/dev/null 2>&1 && osl=1
rfc() { tmo ssh-keygen -e -f "$1" </dev/null 2>/dev/null | awk '/^---- BEGIN SSH2 PUBLIC KEY ----$/ {p=1; next} /^---- END SSH2 PUBLIC KEY ----$/ {if (p) print "BLOBEND"; exit} p && /^[A-Za-z0-9+\/=]+$/ {print "B " $0}'; }
spki() { tmo openssl pkey -in "$1" -pubout -passin pass: </dev/null 2>/dev/null | awk '/^-----BEGIN PUBLIC KEY-----$/ {p=1; print "SPKI"; next} p && /^-----END PUBLIC KEY-----$/ {print "END"; exit} p && /^[A-Za-z0-9+\/=]+$/ {print}'; }
n=0
for f in "$@"; do
  echo "=== $n"
  n=$((n+1))
  if [ ! -r "$f" ]; then echo DENIED; continue; fi
  h=$(head -c 4096 "$f" 2>/dev/null | tr -d '\r')
  case $h in
    *"-----BEGIN OPENSSH PRIVATE KEY-----"*)
      c=$(printf '%s\n' "$h" | sed -n '/^-----BEGIN OPENSSH PRIVATE KEY-----$/{n;p;q;}' | cut -c1-44 | b64d | tr -c 'a-z0-9-' ' ')
      case $c in
        *none*) echo "ENC 0";;
        *aes*|*chacha*|*3des*|*blowfish*|*cbc*|*ctr*) echo "ENC 1";;
      esac
      if [ $skg = 1 ]; then o=$(rfc "$f"); else o=; fi
      if [ -n "$o" ]; then printf '%s\n' "$o"; elif [ $skg = 1 ]; then echo FAILED; else echo NOTOOL; fi
      ;;
    *"-----BEGIN ENCRYPTED PRIVATE KEY-----"*|*"Proc-Type: 4,ENCRYPTED"*) echo ENCRYPTED;;
    *"PRIVATE KEY-----"*)
      o=
      [ $skg = 1 ] && o=$(rfc "$f")
      [ -z "$o" ] && [ $osl = 1 ] && o=$(spki "$f")
      if [ -n "$o" ]; then printf '%s\n' "$o"; elif [ $skg = 1 ] || [ $osl = 1 ]; then echo FAILED; else echo NOTOOL; fi
      ;;
    *) echo NOTKEY;;
  esac
done
`

// jobKeyProbeArgv runs jobKeyProbeScript on paths, each a positional
// argument and never script text.
func jobKeyProbeArgv(paths []string) []string {
	return append([]string{"env", "LC_ALL=C", "sh", "-c", jobKeyProbeScript, "sh"}, paths...)
}

// jobWinKeyProbe is the Windows key probe: ssh-keygen.exe from the
// system's OpenSSH, started directly (no shell), standard input closed,
// each run bounded to 3 seconds and the batch to 25, with the same
// marker-first rule. It answers the same vocabulary, as JSON lines.
var jobWinKeyProbe = psPrelude + `$kpExe = [System.IO.Path]::Combine([Environment]::GetFolderPath('System'), 'OpenSSH', 'ssh-keygen.exe')
$kpHave = [System.IO.File]::Exists($kpExe)
$kpOut = New-Object 'System.Collections.Generic.List[string]'
function kpRun([string]$kpArgs) {
  $kpPsi = New-Object System.Diagnostics.ProcessStartInfo
  $kpPsi.FileName = $kpExe
  $kpPsi.Arguments = $kpArgs
  $kpPsi.UseShellExecute = $false
  $kpPsi.RedirectStandardOutput = $true
  $kpPsi.RedirectStandardError = $true
  $kpPsi.RedirectStandardInput = $true
  $kpPsi.CreateNoWindow = $true
  $kpP = [System.Diagnostics.Process]::Start($kpPsi)
  $kpP.StandardInput.Close()
  $kpTask = $kpP.StandardOutput.ReadToEndAsync()
  if (-not $kpP.WaitForExit(3000)) { try { $kpP.Kill() } catch { }; return $null }
  return $kpTask.Result
}
function kpRfc([string]$kpPath) {
  $kpO = kpRun ('-e -f "' + $kpPath + '"')
  if ($null -eq $kpO) { return $false }
  $kpIn = $false; $kpAny = $false
  foreach ($kpL in ($kpO -split [string][char]10)) {
    $kpL = $kpL.TrimEnd([char]13)
    if ($kpL -ceq '---- BEGIN SSH2 PUBLIC KEY ----') { $kpIn = $true; continue }
    if ($kpL -ceq '---- END SSH2 PUBLIC KEY ----') { if ($kpIn -and $kpAny) { $kpOut.Add('BLOBEND') }; return $kpAny }
    if ($kpIn -and $kpL -match '^[A-Za-z0-9+/=]+$') { $kpOut.Add('B ' + $kpL); $kpAny = $true }
  }
  return $false
}
$kpN = 0
foreach ($kpRaw in $a.Paths) {
  $kpOut.Add('=== ' + $kpN); $kpN++
  if ($vSw.Elapsed.TotalSeconds -gt 25) { $kpOut.Add('TIMEUP'); continue }
  $kpPath = [string]$kpRaw
  if ($kpPath.StartsWith('\\?\')) { $kpPath = $kpPath.Substring(4) }
  if ($kpPath.Contains('"')) { $kpOut.Add('FAILED'); continue }
  try {
    $kpFs = [System.IO.File]::Open($kpPath, 'Open', 'Read', 'ReadWrite')
    $kpBuf = New-Object byte[] 4096
    $kpLen = $kpFs.Read($kpBuf, 0, 4096)
    $kpFs.Close()
  } catch { $kpOut.Add('DENIED'); continue }
  $kpH = $vL1.GetString($kpBuf, 0, $kpLen).Replace($vCR, '')
  if ($kpH.Contains('-----BEGIN OPENSSH PRIVATE KEY-----')) {
    $kpLines = $kpH -split [string][char]10
    $kpI = [Array]::IndexOf($kpLines, '-----BEGIN OPENSSH PRIVATE KEY-----')
    if ($kpI -ge 0 -and $kpI + 1 -lt $kpLines.Count) {
      $kpB = $kpLines[$kpI + 1]
      if ($kpB.Length -ge 44) { $kpB = $kpB.Substring(0, 44) }
      try { $kpC = $vL1.GetString([Convert]::FromBase64String($kpB)) } catch { $kpC = '' }
      if ($kpC.Contains('none')) { $kpOut.Add('ENC 0') } elseif ($kpC -match 'aes|chacha|3des|blowfish|cbc|ctr') { $kpOut.Add('ENC 1') }
    }
    if (-not $kpHave) { $kpOut.Add('NOTOOL') } elseif (-not (kpRfc $kpPath)) { $kpOut.Add('FAILED') }
  } elseif ($kpH.Contains('-----BEGIN ENCRYPTED PRIVATE KEY-----') -or $kpH.Contains('Proc-Type: 4,ENCRYPTED')) {
    $kpOut.Add('ENCRYPTED')
  } elseif ($kpH.Contains('PRIVATE KEY-----')) {
    if (-not $kpHave) { $kpOut.Add('NOTOOL') } elseif (-not (kpRfc $kpPath)) { $kpOut.Add('FAILED') }
  } else { $kpOut.Add('NOTKEY') }
}
psOut ([pscustomobject]@{ L = $kpOut.ToArray() })
`

// jobProbeBatch bounds one host program's paths: the argument list stays far
// below any command-line limit, and one slow host program costs one batch.
const jobProbeBatch = 48

// jobKeyProbeMany probes paths on a remote target and returns each path's
// answer. Paths the host did not answer for are missing from the map.
func jobKeyProbeMany(ctx context.Context, t Target, paths []string) map[string][]byte {
	out := map[string][]byte{}
	for len(paths) > 0 {
		n := min(len(paths), jobProbeBatch)
		chunk := paths[:n]
		paths = paths[n:]
		var raw []byte
		switch tt := t.(type) {
		case *RemoteUnixTarget:
			o, _, exit, err := tt.Run(ctx, jobKeyProbeArgv(chunk))
			if err != nil || exit != 0 {
				continue
			}
			raw = o
		case *RemoteWindowsTarget:
			b, err := tt.psJSON(ctx, jobWinKeyProbe, struct {
				Paths []string `json:"Paths"`
			}{chunk})
			if err != nil {
				continue
			}
			var r struct{ L []string }
			if json.Unmarshal(b, &r) != nil {
				continue
			}
			raw = []byte(strings.Join(r.L, "\n") + "\n")
		default:
			return out
		}
		for i, ans := range jobSplitProbeAnswers(raw, len(chunk)) {
			if ans != nil {
				out[chunk[i]] = ans
			}
		}
	}
	return out
}

// jobSplitProbeAnswers splits a batch answer at its "=== <index>" lines.
func jobSplitProbeAnswers(raw []byte, n int) [][]byte {
	out := make([][]byte, n)
	cur := -1
	for _, l := range strings.Split(string(raw), "\n") {
		if idx, ok := strings.CutPrefix(l, "=== "); ok {
			i, err := strconv.Atoi(strings.TrimSpace(idx))
			if err != nil || i < 0 || i >= n {
				cur = -1
				continue
			}
			cur = i
			out[i] = []byte{}
			continue
		}
		if cur >= 0 && len(out[cur]) < 64<<10 {
			out[cur] = append(append(out[cur], l...), '\n')
		}
	}
	return out
}

// jobPrefetchKeyProbes probes, in batches, the paths a pass is about to
// visit, so that each key costs a share of one host program rather than a
// program of its own. Paths already probed are not asked again.
func (c *collection) jobPrefetchKeyProbes(ctx context.Context, paths []string) {
	if c.target.Local() || locRemoteKeyProbe == nil {
		return
	}
	var want []string
	c.mu.Lock()
	for _, p := range paths {
		if _, done := c.jobKeyProbes[p]; !done {
			want = append(want, p)
		}
	}
	c.mu.Unlock()
	if len(want) == 0 {
		return
	}
	got := jobKeyProbeMany(ctx, c.target, want)
	c.mu.Lock()
	if c.jobKeyProbes == nil {
		c.jobKeyProbes = map[string][]byte{}
	}
	for p, a := range got {
		c.jobKeyProbes[p] = a
	}
	c.mu.Unlock()
}

// jobProbeRemoteKey is locRemoteKeyProbe: the prefetched answer, else a
// probe of this one file.
func jobProbeRemoteKey(ctx context.Context, c *collection, path string, _ Identity, base PrivateKey) (PrivateKey, bool) {
	c.mu.Lock()
	ans, ok := c.jobKeyProbes[path]
	c.mu.Unlock()
	if !ok {
		got := jobKeyProbeMany(ctx, c.target, []string{path})
		if ans, ok = got[path]; !ok {
			return base, false
		}
	}
	return jobParseKeyProbe(ans, base), true
}

// jobMaxProbeBlob bounds a public key blob or SPKI from a probe: larger than
// any public key (an RSA-16384 SPKI is about 2 KiB).
const jobMaxProbeBlob = 16 << 10

// jobParseKeyProbe completes base from one file's probe answer. It keeps
// only what it derives from a public key it could parse (algorithm, size,
// curve, the SubjectPublicKeyInfo hash, the SSH fingerprint) and whether the
// key is encrypted; the key's encoding itself is not kept, and an answer it
// cannot parse is "could not read".
func jobParseKeyProbe(out []byte, base PrivateKey) PrivateKey {
	k := base
	yes, no := true, false
	const cannot = "remote: the host's ssh-keygen and openssl cannot read this key; size and public key not read"
	var blob, spki strings.Builder
	inSPKI, blobEnd, spkiEnd := false, false, false
	enc := ""
	verdict := ""
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case inSPKI:
			if l == "END" {
				inSPKI, spkiEnd = false, true
			} else if spki.Len()+len(l) <= jobMaxProbeBlob {
				spki.WriteString(l)
			}
		case l == "SPKI":
			inSPKI = true
		case strings.HasPrefix(l, "B "):
			if blob.Len()+len(l) <= jobMaxProbeBlob {
				blob.WriteString(l[2:])
			}
		case l == "BLOBEND":
			blobEnd = true
		case l == "ENC 0" || l == "ENC 1":
			enc = l[4:]
		case l == "ENCRYPTED", l == "DENIED", l == "NOTOOL", l == "FAILED", l == "NOTKEY", l == "TIMEUP":
			verdict = l
		}
	}
	switch enc {
	case "0":
		k.Encrypted = &no
	case "1":
		k.Encrypted = &yes
	}
	described := false
	if blobEnd {
		if b, err := base64.StdEncoding.DecodeString(blob.String()); err == nil {
			if d, ok := keyDescribeSSHBlob(b); ok {
				k.Algorithm, k.SizeBits, k.Curve = d.algorithm, d.size, d.curve
				k.PublicKeySHA256, k.SSHFingerprint, k.Unknown = d.spkiSHA256, d.fingerprint, d.unknown
				described = true
			}
		}
	}
	if !described && spkiEnd {
		if der, err := base64.StdEncoding.DecodeString(spki.String()); err == nil {
			if info, ok := keySPKIInfo(der); ok && info.Algorithm != "" {
				k.Algorithm, k.SizeBits, k.Curve, k.PublicKeySHA256 = info.Algorithm, info.SizeBits, info.Curve, info.PublicKeySHA256
				k.Unknown = ""
				described = true
			}
		}
	}
	if described {
		if k.Encrypted == nil && k.Format != KeyFormatOpenSSH {
			// A PEM key is only ever probed when its markers say it is not
			// encrypted.
			k.Encrypted = &no
		}
		return k
	}
	switch verdict {
	case "ENCRYPTED":
		k.Encrypted = &yes
		k.Unknown = "remote: encrypted; size and public key are not read without the passphrase"
	case "DENIED":
		k.Unknown = "remote: the account may not read the key file; size and public key not read"
	case "NOTOOL":
		k.Unknown = "remote: no ssh-keygen or openssl on the host; size and public key not read"
	case "TIMEUP":
		k.Unknown = "remote: not probed: the host program's time bound ran out"
	case "NOTKEY":
		k.Unknown = "remote: the file's first bytes are not a key this probe reads"
	default:
		k.Unknown = cannot
	}
	return k
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
	if jobResemblesKey(s) || strings.Contains(s, "-----") {
		return WithheldName
	}
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
	pendingName := ""
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
			// A certificate the listing printed: its bag is counted already,
			// and the attributes printed just before it are its own (openssl
			// prints them with the certificate, after the key bags), so the
			// friendly name goes to the first certificate still unnamed.
			for i := range ks.Entries {
				if ks.Entries[i].Kind == "certificate" && ks.Entries[i].Alias == "" {
					ks.Entries[i].Alias = pendingName
					break
				}
			}
			pendingName = ""
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
				pendingName = jobProbeName(v)
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
		"key-probe":      strings.Join(jobKeyProbeArgv([]string{"PATH"}), " "),
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
	"-list -v", "-v -list", " -rfc", "-storepass", "-keypass", "-exportcert", " -K", "-dump", "pass:changeit", " -y ",
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
