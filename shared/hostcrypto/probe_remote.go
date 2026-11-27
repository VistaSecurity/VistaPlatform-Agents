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
//     The empty password is always tried first. For PKCS#12 a second try
//     with a random value no store can have tells whether anything in the
//     file checks a password at all (`openssl pkcs12 -nokeys` lists a file
//     with no MAC and clear certificates under any password); for JKS and
//     JCEKS, whose listing never needs the password, the host computes the
//     integrity digest for the empty password and prints only whether it
//     matches. The default-password opt-in then sends the well-known
//     passwords on the command's STANDARD INPUT, one per line, read by the
//     script into a shell variable and handed to the tool through a pipe
//     from the shell's own printf: no password is ever in a process's
//     arguments, so none is in `ps` (the random value is in the arguments;
//     it is the password of nothing). No
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
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
// eight at a time, each bounded to 3 seconds and the batch to 25, with the
// same marker-first rule. It runs ssh-keygen ONLY on OpenSSH-format keys,
// whose public half it reads without a passphrase: on a PEM key Windows'
// ssh-keygen waits on the console for a passphrase even when the key has
// none (measured on Windows 11, OpenSSH for Windows), and Windows has no
// openssl, so a PEM key's public half is not read there ("WINPEM").
var jobWinKeyProbe = psPrelude + `$kpExe = [System.IO.Path]::Combine([Environment]::GetFolderPath('System'), 'OpenSSH', 'ssh-keygen.exe')
$kpHave = [System.IO.File]::Exists($kpExe)
$kpAns = @{}
$kpJobs = New-Object 'System.Collections.Generic.List[object]'
$kpN = 0
foreach ($kpRaw in $a.Paths) {
  $kpI = $kpN; $kpN++
  $kpL = New-Object 'System.Collections.Generic.List[string]'
  $kpAns[$kpI] = $kpL
  $kpPath = [string]$kpRaw
  if ($kpPath.StartsWith('\\?\')) { $kpPath = $kpPath.Substring(4) }
  if ($kpPath.Contains('"')) { $kpL.Add('FAILED'); continue }
  try {
    $kpFs = [System.IO.File]::Open($kpPath, 'Open', 'Read', 'ReadWrite')
    $kpBuf = New-Object byte[] 4096
    $kpLen = $kpFs.Read($kpBuf, 0, 4096)
    $kpFs.Close()
  } catch { $kpL.Add('DENIED'); continue }
  $kpH = $vL1.GetString($kpBuf, 0, $kpLen).Replace($vCR, '')
  if ($kpH.Contains('-----BEGIN OPENSSH PRIVATE KEY-----')) {
    $kpLines = $kpH -split [string][char]10
    $kpX = [Array]::IndexOf($kpLines, '-----BEGIN OPENSSH PRIVATE KEY-----')
    if ($kpX -ge 0 -and $kpX + 1 -lt $kpLines.Count) {
      $kpB = $kpLines[$kpX + 1]
      if ($kpB.Length -ge 44) { $kpB = $kpB.Substring(0, 44) }
      try { $kpC = $vL1.GetString([Convert]::FromBase64String($kpB)) } catch { $kpC = '' }
      if ($kpC.Contains('none')) { $kpL.Add('ENC 0') } elseif ($kpC -match 'aes|chacha|3des|blowfish|cbc|ctr') { $kpL.Add('ENC 1') }
    }
    if ($kpHave) { $kpJobs.Add(@($kpI, $kpPath)) } else { $kpL.Add('NOTOOL') }
  } elseif ($kpH.Contains('-----BEGIN ENCRYPTED PRIVATE KEY-----') -or $kpH.Contains('Proc-Type: 4,ENCRYPTED')) {
    $kpL.Add('ENCRYPTED')
  } elseif ($kpH.Contains('PRIVATE KEY-----')) {
    $kpL.Add('WINPEM')
  } else { $kpL.Add('NOTKEY') }
}
for ($kpS = 0; $kpS -lt $kpJobs.Count; $kpS += 8) {
  $kpRun = @()
  foreach ($kpJ in $kpJobs.GetRange($kpS, [Math]::Min(8, $kpJobs.Count - $kpS))) {
    if ($vSw.Elapsed.TotalSeconds -gt 25) { $kpAns[$kpJ[0]].Add('TIMEUP'); continue }
    $kpPsi = New-Object System.Diagnostics.ProcessStartInfo
    $kpPsi.FileName = $kpExe
    $kpPsi.Arguments = '-e -f "' + $kpJ[1] + '"'
    $kpPsi.UseShellExecute = $false
    $kpPsi.RedirectStandardOutput = $true
    $kpPsi.RedirectStandardError = $true
    $kpPsi.RedirectStandardInput = $true
    $kpPsi.CreateNoWindow = $true
    $kpP = [System.Diagnostics.Process]::Start($kpPsi)
    $kpP.StandardInput.Close()
    $kpRun += ,@($kpJ[0], $kpP, $kpP.StandardOutput.ReadToEndAsync(), [DateTime]::UtcNow.AddSeconds(3))
  }
  foreach ($kpR in $kpRun) {
    $kpWait = [int][Math]::Max(0, ($kpR[3] - [DateTime]::UtcNow).TotalMilliseconds)
    $kpL = $kpAns[$kpR[0]]
    if (-not $kpR[1].WaitForExit($kpWait)) { try { $kpR[1].Kill() } catch { }; $kpL.Add('FAILED'); continue }
    $kpIn = $false; $kpAny = $false; $kpDone = $false
    foreach ($kpX in ($kpR[2].Result -split [string][char]10)) {
      $kpX = $kpX.TrimEnd([char]13)
      if ($kpX -ceq '---- BEGIN SSH2 PUBLIC KEY ----') { $kpIn = $true; continue }
      if ($kpX -ceq '---- END SSH2 PUBLIC KEY ----') { if ($kpIn -and $kpAny) { $kpL.Add('BLOBEND'); $kpDone = $true }; break }
      if ($kpIn -and $kpX -match '^[A-Za-z0-9+/=]+$') { $kpL.Add('B ' + $kpX); $kpAny = $true }
    }
    if (-not $kpDone) { $kpL.Add('FAILED') }
  }
}
$kpOut = New-Object 'System.Collections.Generic.List[string]'
for ($kpI = 0; $kpI -lt $kpN; $kpI++) { $kpOut.Add('=== ' + $kpI); foreach ($kpX in $kpAns[$kpI]) { $kpOut.Add($kpX) } }
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
		case l == "ENCRYPTED", l == "DENIED", l == "NOTOOL", l == "FAILED", l == "NOTKEY", l == "TIMEUP", l == "WINPEM":
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
	case "WINPEM":
		k.Unknown = "remote (Windows): a PEM key's size and public key are not read: Windows' ssh-keygen can wait on a passphrase for one, and Windows has no openssl"
	default:
		k.Unknown = cannot
	}
	return k
}

// jobKeystoreProbeScript lists one keystore ($1, of type $2). $4 is a
// random value made for this probe, a password no store has. The empty
// password is tried first; then, with $3 = 1, the passwords on its standard
// input, one per line. Its answer is the filtered listing and one of:
//
//   - "OPENED empty": the empty password opens it (PKCS#12: openssl accepts
//     it and refuses the random value; JKS/JCEKS: the empty password's
//     integrity digest matches, "JKSEMPTY" below);
//   - "OPENED nocheck" (PKCS#12): openssl accepts the random value too, so
//     nothing in the file checks a password;
//   - "OPENED default": a default opens it, verified by the tool;
//   - "LISTED" / "LISTED unchecked" (JKS/JCEKS): listed in clear, the
//     integrity password not empty (nor a default, with $3 = 1), or not
//     checked because the host has no SHA-1 tool;
//   - "LOCKED clear" (PKCS#12): no password opens it, and its clear parts
//     were listed without verifying the MAC (nothing in it is encrypted);
//   - "LOCKED", "DENIED", "NOTOOL", "UNSUPPORTED".
//
// The filtered listing is, for openssl pkcs12: "I <line>" for its MAC,
// PKCS7 and bag lines, "N <friendlyName>", and "CERT" for each certificate
// it printed (never the certificate); for keytool: "V 1" when the listing
// was not verified (no password), "C <count>", "E <alias line>" and
// "F <SHA-256 fingerprint>". Every openssl run has -nokeys: no key is
// decrypted or printed, so no private key byte crosses.
const jobKeystoreProbeScript = `f=$1
typ=$2
tries=$3
rnd=$4
fp12() { awk '/^MAC/ || /^PKCS7 / || /^Shrouded Keybag/ || /^Key bag/ || /^Certificate bag/ {print "I " $0; next} /^-----BEGIN CERTIFICATE-----$/ {print "CERT"; next} /^ *friendlyName: / {sub(/^ *friendlyName: /, ""); print "N " $0}'; }
fkt() { awk '/^Your keystore contains [0-9]+ entr/ {print "C " $4; next} /(PrivateKeyEntry|trustedCertEntry|SecretKeyEntry), *$/ {print "E " $0; next} /^Certificate fingerprint \(SHA-256\): / {print "F " $4}'; }
p12() {
  for leg in "" -legacy; do
    o=$(printf '%s\n' "$1" | openssl pkcs12 $leg $2 -in "$f" -nokeys -info -passin stdin 2>&1)
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
jdig() {
  n=$(wc -c < "$f" | tr -d ' ')
  [ "$n" -ge 32 ] 2>/dev/null || return 0
  if command -v sha1sum >/dev/null 2>&1; then h="sha1sum"
  elif command -v shasum >/dev/null 2>&1; then h="shasum -a 1"
  elif command -v openssl >/dev/null 2>&1; then h="openssl dgst -sha1 -r"
  else return 0; fi
  w=$(tail -c 20 "$f" | od -An -tx1 | tr -d ' \n')
  g=$({ printf 'Mighty Aphrodite'; head -c $((n-20)) "$f"; } | $h | cut -c1-40)
  [ ${#w} -eq 40 ] && [ ${#g} -eq 40 ] || return 0
  if [ "$g" = "$w" ]; then echo 1; else echo 0; fi
}
case $typ in
  pkcs12) tool=openssl;;
  jks|jceks) tool=keytool;;
  *) echo UNSUPPORTED; exit 0;;
esac
[ -r "$f" ] || { echo DENIED; exit 0; }
command -v "$tool" >/dev/null 2>&1 || { echo NOTOOL; exit 0; }
if [ "$tool" = openssl ]; then
  if p12 ""; then
    if p12 "$rnd" >/dev/null; then echo "OPENED nocheck"; else echo "OPENED empty"; fi
    exit 0
  fi
  if p12 "$rnd" >/dev/null; then p12 "$rnd"; echo "OPENED nocheck"; exit 0; fi
  if [ "$tries" = 1 ]; then
    while IFS= read -r pw; do
      [ -n "$pw" ] || continue
      p12 "$pw" && { echo "OPENED default"; exit 0; }
    done
  fi
  p12 "$rnd" -nomacver && { echo "LOCKED clear"; exit 0; }
  echo LOCKED
  exit 0
fi
kt ""
rc=$?
[ $rc -eq 2 ] && { echo NOTOOL; exit 0; }
if [ $rc -eq 0 ]; then
  d=$(jdig)
  [ "$d" = 1 ] && { echo "OPENED empty"; exit 0; }
  if [ "$tries" = 1 ]; then
    while IFS= read -r pw; do
      [ -n "$pw" ] || continue
      kt "$pw" >/dev/null && { echo "OPENED default"; exit 0; }
    done
  fi
  if [ "$d" = 0 ]; then echo LISTED; else echo "LISTED unchecked"; fi
  exit 0
fi
if [ "$tries" = 1 ]; then
  while IFS= read -r pw; do
    [ -n "$pw" ] || continue
    kt "$pw"
    rc=$?
    [ $rc -eq 0 ] && { echo "OPENED default"; exit 0; }
    [ $rc -eq 2 ] && { echo NOTOOL; exit 0; }
  done
fi
echo LOCKED
`

// jobKeystoreProbeArgv runs jobKeystoreProbeScript; path, type and the
// probe's random value are positional arguments, and no password is ever
// among them.
func jobKeystoreProbeArgv(path, typ string, tries bool, random string) []string {
	t := "0"
	if tries {
		t = "1"
	}
	return []string{"env", "LC_ALL=C", "sh", "-c", jobKeystoreProbeScript, "sh", path, typ, t, random}
}

// jobProbeRandom is a fresh value for one probe: 128 random bits, so no store
// has it as its password, in hexadecimal, so the shell passes it intact.
func jobProbeRandom() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "vista-probe-" + hex.EncodeToString(b[:])
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
		out, _, exit, err = ir.RunInput(ctx, jobKeystoreProbeArgv(path, typ, true, jobProbeRandom()), []byte(strings.Join(pw, "\n")+"\n"))
	default:
		if tryDefaults {
			notTried = "the connection cannot pass a password on standard input"
		}
		out, _, exit, err = tt.Run(ctx, jobKeystoreProbeArgv(path, typ, false, jobProbeRandom()))
	}
	if err != nil || exit != 0 {
		return KeystoreContents{}, false
	}
	kc, ok := jobParseKeystoreProbe(out, typ, tryDefaults && notTried == "")
	if !ok {
		return KeystoreContents{}, false
	}
	if notTried != "" {
		kc.DefaultsNotTried = notTried
	}
	return kc, true
}

// jobNotTriedRemoteParts is DefaultsNotTried for a remote PKCS#12 that no
// password opens and that has an encrypted part.
const jobNotTriedRemoteParts = "parts are not tried separately over a remote connection"

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
	var opened, notTried string
	shrouded := false
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
		case "LOCKED clear":
			opened = "locked clear"
		case "LISTED", "LISTED unchecked":
			opened = strings.ToLower(l)
		case "DENIED":
			ks.Unknown = "remote: the account may not read the keystore; entries not read"
			return KeystoreContents{Keystore: ks}, true
		case "NOTOOL":
			ks.Unknown = "remote: no openssl or keytool on the host; entries not read"
			return KeystoreContents{Keystore: ks}, true
		case "UNSUPPORTED":
			return KeystoreContents{}, false
		case "OPENED default", "OPENED empty", "OPENED nocheck":
			opened = l[len("OPENED "):]
		case "V 1":
			// keytool listed without verifying; the integrity answer is the
			// host's digest check (JKSEMPTY) or a default keytool verified.
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
					shrouded = shrouded || strings.Contains(v, "Shrouded Keybag")
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
	notEmpty := "not empty"
	if tried {
		notEmpty = "neither empty nor a well-known default"
	}
	switch opened {
	case "default":
		ks.Opened, ks.DefaultPassword = OpenedDefaultPassword, &yes
	case "empty":
		// The empty password opens it: openssl accepted it and refused a
		// random value, or the empty password's JKS digest matched. No
		// well-known default opened it.
		ks.Opened = OpenedWithoutPassword
		if tried {
			ks.DefaultPassword = &no
		}
	case "nocheck":
		// openssl accepted a random value: nothing in the file checks a
		// password, so no password was tried in any useful sense.
		if shrouded {
			ks.Unknown = "remote: nothing in the keystore verifies a password and its keys are encrypted; what it states in clear is listed"
			notTried = ksNotTriedNoCheck
		} else {
			ks.Opened = OpenedWithoutPassword
			notTried = ksNotTriedUnprotected
		}
	case "listed", "listed unchecked":
		// JKS/JCEKS: aliases and certificates in clear, the store not opened.
		ks.Unknown = "aliases and certificates are stated in clear; the store's integrity password is " + notEmpty
		if opened == "listed unchecked" {
			ks.Unknown = "aliases and certificates are stated in clear; whether the store's integrity password is empty was not checked (no SHA-1 tool on the host)"
		}
		if tried {
			ks.DefaultPassword = &no
		}
	case "locked clear":
		ks.Unknown = "remote: the keystore needs a password that is " + notEmpty + "; what its unencrypted parts state is listed, its integrity not checked"
		if tried {
			ks.DefaultPassword = &no
		}
	case "locked":
		ks.Unknown = "remote: the keystore needs a password that is " + notEmpty + "; entries not read (a locked keystore is listed remotely only when nothing in it is encrypted)"
		ks.Entries = nil
		kc := KeystoreContents{Keystore: ks}
		switch {
		case tried && typ == KeystorePKCS12:
			// openssl refused every default for the whole file, but it
			// cannot try a part apart from the MAC, and this file has an
			// encrypted part (its clear listing failed): whether a default
			// opens a part is not known.
			kc.DefaultsNotTried = jobNotTriedRemoteParts
		case tried:
			kc.Keystore.DefaultPassword = &no
		}
		return kc, true
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
	kc := KeystoreContents{Keystore: ks}
	if tried {
		kc.DefaultsNotTried = notTried
	}
	return kc, true
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
		"keystore-probe": strings.Join(jobKeystoreProbeArgv("PATH", "TYPE", true, "RANDOM"), " "),
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
