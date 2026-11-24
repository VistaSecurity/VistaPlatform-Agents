// This file is named target_remote_win.go, not target_remote_windows.go: Go
// reads a "_windows" suffix as a build constraint, and this code must build on
// every platform so a Linux or macOS agent can collect a Windows host.

package hostcrypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// RemoteWindowsTarget is a Windows host reached through a
// [hostinventory.Runner], running PowerShell.
//
// # How a script reaches the host
//
// The default shell of Windows OpenSSH is cmd.exe, whose command line stops
// at 8,191 characters; these scripts are longer than that once encoded. So
// when the runner implements [hostinventory.InputRunner] (the SSH and local
// runners do), the ONLY thing on the command line is the fixed argv
// `powershell -NoProfile -NonInteractive -Command -`, and the script travels
// on stdin as one line:
//
//	iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<script>')))
//
// Without InputRunner the script goes as -EncodedCommand, as host inventory
// sends its own, and a command that would exceed 8,000 characters is refused
// with a clear error rather than cut by cmd.exe.
//
// # Paths are never script text
//
// The arguments are a JSON object, base64 encoded into the first line of the
// script ($vistaArgs = '<b64>'), which the prelude decodes into $a. Base64
// holds no quote, so the literal cannot end early whatever the path is, and
// the path is used only with -LiteralPath and [System.IO.File] calls, which
// expand no wildcards.
//
// # One read per decision
//
// Identify, ReadFile and ReadText each read the file's bytes ONCE into a
// buffer ([System.IO.FileStream], bounded) and decide from a Latin-1 decoding
// of that buffer, byte for byte, as the awk rules see it on Unix. The
// file's length and last-write time are taken before and after the read; if
// either moved, the file changed while it was read and the script answers
// "changed" ([errChanged]) instead of anything decided from a buffer that may
// mix two versions. ReadFile prints the public content of the same buffer it
// decided on, so there is no window between the check and the output. Go
// re-checks everything that arrives.
type RemoteWindowsTarget struct {
	runner   hostinventory.Runner
	maxBytes int64
}

// remoteWindowsReadMax is the largest file the Windows target returns. Base64
// makes four characters of three bytes and the runner refuses more than
// 8 MiB of output, so 6,000,000 bytes is the most that fits. A larger file is
// ErrFileTooLarge, decided on the host before anything is printed.
const remoteWindowsReadMax = 6000000

// remoteWindowsListBudget is how long one Windows listing may run on the
// host before it stops and reports Truncated with what it has: below the
// runner's 90-second command timeout, so a long walk is a partial answer
// rather than a lost one.
var remoteWindowsListBudget = 60 * time.Second

// cmdLineLimit is the longest command this target sends without
// InputRunner: cmd.exe stops at 8,191 characters.
const cmdLineLimit = 8000

// NewRemoteWindowsTarget wraps r for a Windows host.
func NewRemoteWindowsTarget(r hostinventory.Runner) *RemoteWindowsTarget {
	return &RemoteWindowsTarget{runner: r, maxBytes: defaultMaxFileBytes}
}

// SetMaxFileBytes sets the read bound; n <= 0 restores 10 MiB. Reads are
// further capped at 6,000,000 bytes by the transport.
func (t *RemoteWindowsTarget) SetMaxFileBytes(n int64) {
	if n <= 0 {
		n = defaultMaxFileBytes
	}
	t.maxBytes = n
}

func (t *RemoteWindowsTarget) readCap() int64 { return min(t.maxBytes, remoteWindowsReadMax) }

// Run passes argv to the runner unchanged.
func (t *RemoteWindowsTarget) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return t.runner.Run(ctx, argv)
}

// Local is false: bytes read here cross a connection.
func (t *RemoteWindowsTarget) Local() bool { return false }

// psQuoteList renders Go strings as a PowerShell array of single-quoted
// literals. Only used for package constants (the label allowlist), which hold
// no quote; psArgv's template check would refuse one that did.
func psQuoteList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = "'" + s + "'"
	}
	return "@(" + strings.Join(q, ",") + ")"
}

// psSSHTable renders sshKeyTypes as a PowerShell array of
// @(name, min, max, prefix). Names and base64 prefixes hold no quote.
func psSSHTable() string {
	rows := make([]string, len(sshKeyTypes))
	for i, k := range sshKeyTypes {
		rows[i] = "@('" + k.name + "'," + strconv.Itoa(k.minLen) + "," + strconv.Itoa(k.maxLen) + ",'" + k.prefix + "')"
	}
	return "@(" + strings.Join(rows, ",") + ")"
}

// The PowerShell programs are the rules of redact.go a third time, so they
// are written against PowerShell's traps (fxPS* tests enforce the first
// three on every script):
//
//   - Variable names are case-insensitive: $S and $s are ONE variable, which
//     is how the previous filter returned unlisted lines on a real host. No
//     two names here differ only by case, and the prelude's names carry a
//     per-function prefix so a callee never reads a caller's variable
//     through dynamic scoping.
//   - -eq, -ne, -contains, -match, -like and -replace ignore case, and so do
//     @{} hashtables, while the Go rules do not. String and character
//     comparisons are -ceq / -cne or .NET methods with Ordinal comparison;
//     lookups use Dictionary/HashSet with an explicit comparer (OrdinalIgnoreCase
//     only for the keep words, which the rule compares without ASCII case:
//     on a Latin-1 view no non-ASCII character folds to an ASCII one).
//   - No automatic variable is assigned ($input, $args, $matches, $host,
//     $error, $foreach, $switch, $this, ...); $_ is read only in catch.
//   - A function returning an array is unrolled by the pipeline; none here
//     returns one (results travel as properties of an object).
//   - Speed: a call to a PowerShell function costs tens of microseconds and
//     a cmdlet or pipeline far more, so the per-line and per-token loops
//     call none: the shared fragments (psEmit, psFirstWord) are spliced in
//     by Go where they are used.

// psEmit is filterConfig's emit on the variable $fE: the PEM-dropping state
// $fDrop, the redaction count $fRed, the output $fSB.
var psEmit = `if ($fDrop) { if ($fE.Contains('----END') -or $fE.Contains('---- END')) { $fDrop = $false } }
      elseif ($fE.Contains('----BEGIN') -or $fE.Contains('---- BEGIN')) { $fRed++; $fDrop = -not ($fE.Contains('----END') -or $fE.Contains('---- END')) }
      else { if ($fE.Length -ge ` + strconv.Itoa(RedactRunLength) + `) { $fMc = $vRunRx.Matches($fE).Count; if ($fMc -gt 0) { $fRed += $fMc; $fE = $vRunRx.Replace($fE, '` + RedactedMarker + `') } }; [void]$fSB.Append($fE).Append($vNL) }`

// psFirstWord is firstWord on $fWd (already left-trimmed), in place.
const psFirstWord = `if ($fWd.StartsWith('<', [StringComparison]::Ordinal)) { $fWd = $fWd.Substring(1) }
      if ($fWd.StartsWith('-D', [StringComparison]::Ordinal)) { $fWd = $fWd.Substring(2) }
      if ($fWd.StartsWith('@', [StringComparison]::Ordinal)) { $fWd = $fWd.Substring(1) }
      $fK = $fWd.IndexOfAny($vStop)
      if ($fK -ge 0) { $fWd = $fWd.Substring(0, $fK) }
      if ($fWd.EndsWith('>', [StringComparison]::Ordinal)) { $fWd = $fWd.Substring(0, $fWd.Length - 1) }`

// psOddBackslashes sets $fOdd for the line $fS: does it end in an odd number
// of backslashes?
const psOddBackslashes = `$fK = $fS.Length - 1
      while ($fK -ge 0 -and $fS[$fK] -ceq '\') { $fK-- }
      $fOdd = ((($fS.Length - 1 - $fK) % 2) -eq 1)`

// psStatementToken is the nginx tokeniser (cfgNgxTokens, filterStatements)
// as one .NET pattern, matched repeatedly from the start: every byte belongs
// to exactly one alternative, so the matches are contiguous. Blanks (a lone
// CR among them), a line end, ";", "{", "}", a "#" comment, a double- or
// single-quoted word (a backslash escapes the quote or a backslash), and a
// word, in which "{" right after "$" opens a "${...}" running to "}" or the
// line end.
const psStatementToken = `[ \t\f\v\r]+|\n|[;{}]|#[^\n]*|"(?:\\["\\]|[^"])*"?|''(?:\\[''\\]|[^''])*''?|(?:\\[^\n]|[^ \t\f\v\r\n;{}]|(?<=\$)\{[^}\n]*\}?)+`

// psPrelude decodes the arguments and defines the helpers every script uses.
// psErr turns an exception into "not_found", "denied" or "other"; psAcl
// projects Get-Acl onto the owner and ONE boolean worked out on the host
// (read granted to Everyone, BUILTIN\Users or Authenticated Users); the v*
// functions are the text rules of redact.go, on a Latin-1 view of the bytes.
var psPrelude = `$ErrorActionPreference='Stop'
$vSw = [System.Diagnostics.Stopwatch]::StartNew()
$a = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($vistaArgs)) | ConvertFrom-Json
$vL1 = [Text.Encoding]::GetEncoding(28591)
$vNL = [string][char]10
$vCR = [string][char]13
$vBOM = [string][char]0xEF + [char]0xBB + [char]0xBF
$vWin = ([System.IO.Path]::DirectorySeparatorChar -ceq [char]92)
$vAllowSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($vLbl in ` + psQuoteList(publicPEMLabels) + `) { [void]$vAllowSet.Add($vLbl) }
$vKT = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
foreach ($vRow in ` + psSSHTable() + `) { $vKT[$vRow[0]] = $vRow }
$vRunRx = [regex]::new('[A-Za-z0-9+/=]{` + strconv.Itoa(RedactRunLength) + `,}')
$vCertSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($vLbl in ` + psQuoteList(certificateLabels) + `) { [void]$vCertSet.Add($vLbl) }
$vLabelRx = [regex]::new('^[A-Z0-9 -]+\z')
$vBlobRx = [regex]::new('^[A-Za-z0-9+/]+=*\z')
$vBodyRx = [regex]::new('^[A-Za-z0-9+/=]+\z')
$vBlankRx = [regex]::new('^[ \t]*\z')
$vSecRx = [regex]::new('^\[[ \t]*([A-Za-z0-9_.-]{1,64})[ \t]*\]\z')
$vCloseRx = [regex]::new('^</([A-Za-z0-9_.:-]{1,64})>\z')
$vOpenRx = [regex]::new('^<([A-Za-z][A-Za-z0-9_.:-]*)[> \t]')
$vPrivRx = [regex]::new('PRIVATE|SECRET|KEY', 'IgnoreCase, CultureInvariant')
$vU16Rx = [regex]::new('[\x00\xFE\xFF]')
$vU16PrivRx = [regex]::new('BEGIN[^\n]*PRIVATE|PRIVATE[^\n]*BEGIN', 'IgnoreCase, CultureInvariant')
$vTokRx = [regex]::new('` + psStatementToken + `')
$vStop = [char[]]@([char]32, [char]9, [char]61, [char]58, [char]59, [char]123, [char]125)
$vBlanks = [char[]]@([char]32, [char]9)
function psErr($peX) {
  while ($peX -is [System.Management.Automation.MethodInvocationException] -and $peX.InnerException) { $peX = $peX.InnerException }
  if ($peX -is [System.Management.Automation.ItemNotFoundException] -or $peX -is [System.IO.FileNotFoundException] -or $peX -is [System.IO.DirectoryNotFoundException]) { return 'not_found' }
  if ($peX -is [System.UnauthorizedAccessException] -or $peX -is [System.Security.SecurityException]) { return 'denied' }
  return 'other'
}
function psOut($poX) { [Console]::Out.Write('J:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -Depth 4 -InputObject $poX)))) }
function psAcl([string]$paPath) {
  try {
    $paAcl = Get-Acl -LiteralPath $paPath
    $paAllow = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $paDeny = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($paRule in $paAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
      $paSid = [string]$paRule.IdentityReference.Value
      if (-not ($paSid -ceq 'S-1-1-0' -or $paSid -ceq 'S-1-5-32-545' -or $paSid -ceq 'S-1-5-11')) { continue }
      if (($paRule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
      $paMask = ([int64]$paRule.FileSystemRights) -band 0xFFFFFFFFL
      if (($paMask -band 0x90000001L) -eq 0) { continue }
      if ($paRule.AccessControlType -ceq 'Allow') { [void]$paAllow.Add($paSid) } else { [void]$paDeny.Add($paSid) }
    }
    $paBroad = $false
    foreach ($paK in $paAllow) { if (-not $paDeny.Contains($paK)) { $paBroad = $true } }
    return [pscustomobject]@{ Owner = [string]$paAcl.Owner; Broad = $paBroad; Ok = $true }
  } catch {
    return [pscustomobject]@{ Owner = ''; Broad = $false; Ok = $false }
  }
}
function psLink($plI) { return ($plI.LinkType -ceq 'SymbolicLink' -or $plI.LinkType -ceq 'Junction') }
function psTime($ptI) { return $ptI.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') }
function vLong([string]$lpP) {
  if (-not $vWin -or $lpP.StartsWith('\\?\', [StringComparison]::Ordinal)) { return $lpP }
  if ($lpP.StartsWith('\\', [StringComparison]::Ordinal)) { return '\\?\UNC\' + $lpP.Substring(2) }
  return '\\?\' + $lpP
}
function vShort([string]$spP) {
  if ($spP.StartsWith('\\?\UNC\', [StringComparison]::Ordinal)) { return '\\' + $spP.Substring(8) }
  if ($spP.StartsWith('\\?\', [StringComparison]::Ordinal)) { return $spP.Substring(4) }
  return $spP
}
function vRead([string]$vrPath, [int64]$vrMax) {
  if ([System.IO.Directory]::Exists($vrPath)) { return [pscustomobject]@{ Error = 'directory' } }
  $vrT0 = [System.IO.File]::GetLastWriteTimeUtc($vrPath).Ticks
  $vrFs = [System.IO.File]::Open($vrPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $vrLen0 = $vrFs.Length
    $vrCount = [int][Math]::Min($vrLen0, $vrMax)
    $vrBuf = New-Object byte[] $vrCount
    $vrOff = 0
    while ($vrOff -lt $vrCount) { $vrGot = $vrFs.Read($vrBuf, $vrOff, $vrCount - $vrOff); if ($vrGot -le 0) { break }; $vrOff += $vrGot }
    $vrLen1 = $vrFs.Length
  } finally { $vrFs.Close() }
  $vrT1 = [System.IO.File]::GetLastWriteTimeUtc($vrPath).Ticks
  if ($vrLen1 -ne $vrLen0 -or $vrT1 -ne $vrT0) { return [pscustomobject]@{ Error = 'changed' } }
  if ($vQuiet -and [Math]::Abs([DateTime]::UtcNow.Ticks - $vrT1) -lt 30000000) { return [pscustomobject]@{ Error = 'changed' } }
  return [pscustomobject]@{ Error = ''; Size = [int64]$vrLen0; Buf = $vrBuf; N = $vrOff }
}
function vParse([string]$vpS) {
  $vpN = $vpS.Length
  if ($vpN -lt 17) { return $null }
  $vpFive = $vpS.StartsWith('-----BEGIN ', [StringComparison]::Ordinal) -and $vpS.EndsWith('-----', [StringComparison]::Ordinal)
  $vpFour = $vpS.StartsWith('---- BEGIN ', [StringComparison]::Ordinal) -and $vpS.EndsWith(' ----', [StringComparison]::Ordinal)
  if (-not ($vpFive -or $vpFour)) { return $null }
  $vpL = $vpS.Substring(11, $vpN - 16)
  if ($vpL.Length -gt 64 -or -not $vLabelRx.IsMatch($vpL)) { return $null }
  return $vpL
}
function vSshKey([string]$skS) {
  if (-not ($skS.Contains('ssh-') -or $skS.Contains('ecdsa-'))) { return '' }
  $skR = $skS.TrimStart($vBlanks)
  $skI = $skR.IndexOfAny($vBlanks)
  if ($skI -lt 0) { $skT = $skR } else { $skT = $skR.Substring(0, $skI) }
  if (-not $vKT.ContainsKey($skT)) {
    $skN = $skR.Length; $skQ = $false; $skJ = 0
    while ($skJ -lt $skN) {
      $skC = $skR[$skJ]
      if ($skQ) {
        if ($skC -ceq [char]92 -and $skJ + 1 -lt $skN) { $skJ += 2; continue }
        if ($skC -ceq [char]34) { $skQ = $false }
      } else {
        if ($skC -ceq [char]32 -or $skC -ceq [char]9) { break }
        if ($skC -ceq [char]34) { $skQ = $true }
      }
      $skJ++
    }
    if ($skQ) { return '' }
    $skR = $skR.Substring($skJ).TrimStart($vBlanks)
    $skI = $skR.IndexOfAny($vBlanks)
    if ($skI -lt 0) { $skT = $skR } else { $skT = $skR.Substring(0, $skI) }
    if (-not $vKT.ContainsKey($skT)) { return '' }
  }
  $skR = $skR.Substring($skT.Length).TrimStart($vBlanks)
  $skI = $skR.IndexOfAny($vBlanks)
  if ($skI -lt 0) { $skB = $skR } else { $skB = $skR.Substring(0, $skI) }
  $skE = $vKT[$skT]
  if ($vBlobRx.IsMatch($skB) -and $skB.Length -ge $skE[1] -and $skB.Length -le $skE[2] -and $skB.StartsWith([string]$skE[3], [StringComparison]::Ordinal)) { return ($skT + ' ' + $skB) }
  return ''
}
function vLines([string]$lnT) {
  if ($lnT.StartsWith($vBOM, [StringComparison]::Ordinal)) { $lnT = $lnT.Substring(3) }
  $lnParts = $lnT.Split([char]10)
  $lnCount = $lnParts.Length
  if ($lnCount -gt 0 -and $lnParts[$lnCount - 1].Length -eq 0) { $lnCount-- }
  return [pscustomobject]@{ Parts = $lnParts; Count = $lnCount }
}
function vPublic([byte[]]$pcB, [int]$pcN) {
  if ([Array]::IndexOf($pcB, [byte]0, 0, $pcN) -ge 0) { return $null }
  $pcL = vLines ($vL1.GetString($pcB, 0, $pcN))
  $pcOut = New-Object System.Text.StringBuilder
  $pcBlock = New-Object 'System.Collections.Generic.List[string]'
  $pcAny = $false; $pcIn = $false; $pcOk = $false; $pcEnd = ''
  for ($pcI = 0; $pcI -lt $pcL.Count; $pcI++) {
    $pcS = $pcL.Parts[$pcI]
    if ($pcS.EndsWith($vCR, [StringComparison]::Ordinal)) { $pcS = $pcS.Substring(0, $pcS.Length - 1) }
    if ($pcS.Contains('----BEGIN') -or $pcS.Contains('---- BEGIN')) {
      $pcIn = $false
      $pcLab = vParse $pcS
      if ($null -eq $pcLab -or -not $vAllowSet.Contains($pcLab)) { return $null }
      $pcIn = $true; $pcOk = $true; $pcBlock.Clear(); $pcBlock.Add($pcS)
      if ($pcS.StartsWith('-----', [StringComparison]::Ordinal)) { $pcEnd = '-----END ' + $pcLab + '-----' } else { $pcEnd = '---- END ' + $pcLab + ' ----' }
      continue
    }
    if ($pcIn) {
      if ([string]::Equals($pcS, $pcEnd, [StringComparison]::Ordinal)) {
        $pcIn = $false
        if (-not $pcOk -or -not $vCertSet.Contains($pcLab) -or -not $pcS.StartsWith('-----', [StringComparison]::Ordinal)) { continue }
        $pcPem = vCert $pcLab ([string]::Join('', $pcBlock.ToArray(), 1, $pcBlock.Count - 1))
        if ($pcPem.Length -gt 0) { [void]$pcOut.Append($pcPem); $pcAny = $true }
        continue
      }
      if ($pcS.Contains('----END') -or $pcS.Contains('---- END')) { $pcIn = $false; continue }
      if ($pcS.Length -lt 1 -or $pcS.Length -gt ` + strconv.Itoa(maxPEMBodyLine) + ` -or -not $vBodyRx.IsMatch($pcS)) { $pcOk = $false }
      $pcBlock.Add($pcS)
      continue
    }
    if ($pcS.Contains('ssh-') -or $pcS.Contains('ecdsa-')) {
      $pcK = vSshKey $pcS
      if ($pcK.Length -gt 0) { [void]$pcOut.Append($pcK).Append($vNL); $pcAny = $true }
    }
  }
  if (-not $pcAny) { return $null }
  return $pcOut.ToString()
}
function vCert([string]$ceLabel, [string]$ceBody) {
  try { $ceDer = [Convert]::FromBase64String($ceBody) } catch { return '' }
  if ($ceLabel -ceq 'TRUSTED CERTIFICATE') {
    if ($ceDer.Length -lt 2 -or $ceDer[0] -ne 0x30) { return '' }
    $ceLen = [int]$ceDer[1]; $ceHdr = 2
    if ($ceLen -ge 0x80) {
      $ceN = $ceLen - 0x80
      if ($ceN -lt 1 -or $ceN -gt 4 -or $ceDer.Length -lt 2 + $ceN) { return '' }
      $ceLen = [int64]0
      for ($ceK = 0; $ceK -lt $ceN; $ceK++) { $ceLen = $ceLen * 256 + $ceDer[2 + $ceK] }
      $ceHdr += $ceN
    }
    if ($ceHdr + $ceLen -gt $ceDer.Length) { return '' }
    $ceFirst = New-Object byte[] ($ceHdr + $ceLen)
    [Array]::Copy($ceDer, $ceFirst, $ceFirst.Length)
    $ceDer = $ceFirst
  }
  try {
    if ([System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($ceDer) -ne [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) { return '' }
    $ceCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$ceDer)
    $ceRaw = $ceCert.RawData
  } catch { return '' }
  $ceB64 = [Convert]::ToBase64String($ceRaw)
  if (-not [string]::Equals($ceB64, [Convert]::ToBase64String($ceDer), [StringComparison]::Ordinal)) { return '' }
  $ceSb = New-Object System.Text.StringBuilder
  [void]$ceSb.Append('-----BEGIN CERTIFICATE-----').Append($vNL)
  for ($ceK = 0; $ceK -lt $ceB64.Length; $ceK += 64) { [void]$ceSb.Append($ceB64.Substring($ceK, [Math]::Min(64, $ceB64.Length - $ceK))).Append($vNL) }
  [void]$ceSb.Append('-----END CERTIFICATE-----').Append($vNL)
  return $ceSb.ToString()
}
function vMagicAt([byte[]]$mgB, [int]$mgOff, [int]$mgN) {
  $mgH = ''
  for ($mgK = $mgOff; $mgK -lt [Math]::Min($mgN, $mgOff + 8); $mgK++) { $mgH += $mgB[$mgK].ToString('x2') }
  return ($mgH.StartsWith('feedfeed', [StringComparison]::Ordinal) -or $mgH.StartsWith('cececece', [StringComparison]::Ordinal) -or $mgH.StartsWith('0502', [StringComparison]::Ordinal) -or $mgH.StartsWith('0501', [StringComparison]::Ordinal) -or $mgH.StartsWith('53514c6974652066', [StringComparison]::Ordinal))
}
function vHex([byte[]]$hxB, [int]$hxN) { $hxH = ''; for ($hxK = 0; $hxK -lt [Math]::Min($hxN, 8); $hxK++) { $hxH += $hxB[$hxK].ToString('x2') }; return $hxH }
function vFilter([byte[]]$fB, [int]$fN, [string[]]$fKeep) {
  $fWords = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $fSt = $false; $fBs = $false; $fInd = $false; $fCrOpt = $false; $fBadOpt = $false; $fSec = $false; $fAnySec = $false; $fTags = $false
  foreach ($fW in $fKeep) {
    $fW = [string]$fW
    if ($fW.Length -eq 0) { continue }
    if ($fW.StartsWith('@', [StringComparison]::Ordinal)) {
      $fOpt = $fW.ToLowerInvariant()
      if ($fOpt -ceq '` + KeepOptStatements + `') { $fSt = $true }
      elseif ($fOpt -ceq '` + KeepOptBackslash + `') { $fBs = $true }
      elseif ($fOpt -ceq '` + KeepOptIndent + `') { $fInd = $true }
      elseif ($fOpt -ceq '` + KeepOptCR + `') { $fCrOpt = $true }
      elseif ($fOpt -ceq '` + KeepOptSections + `') { $fSec = $true }
      elseif ($fOpt -ceq '` + KeepOptAnySections + `') { $fAnySec = $true }
      elseif ($fOpt -ceq '` + KeepOptTags + `') { $fTags = $true }
      else { $fBadOpt = $true }
      continue
    }
    [void]$fWords.Add($fW)
  }
  if ($fWords.Count -eq 0 -or $fBadOpt) { return [pscustomobject]@{ Status = 'not_public' } }
  if ([Array]::IndexOf($fB, [byte]0, 0, $fN) -ge 0 -or [Array]::IndexOf($fB, [byte]1, 0, $fN) -ge 0) { return [pscustomobject]@{ Status = 'not_public' } }
  if ($fN -ge 2 -and (($fB[0] -eq 0xFF -and $fB[1] -eq 0xFE) -or ($fB[0] -eq 0xFE -and $fB[1] -eq 0xFF))) { return [pscustomobject]@{ Status = 'not_public' } }
  if ((vMagicAt $fB 0 $fN) -or ($fN -ge 3 -and $fB[0] -eq 0xEF -and $fB[1] -eq 0xBB -and $fB[2] -eq 0xBF -and (vMagicAt $fB 3 $fN))) { return [pscustomobject]@{ Status = 'not_public' } }
  $fL = vLines ($vL1.GetString($fB, 0, $fN))
  $fLines = New-Object 'System.Collections.Generic.List[string]'
  for ($fI = 0; $fI -lt $fL.Count; $fI++) {
    $fG = $fL.Parts[$fI]
    if ($fG.EndsWith($vCR, [StringComparison]::Ordinal)) { $fG = $fG.Substring(0, $fG.Length - 1) }
    if ($fCrOpt -and -not $fSt -and $fG.IndexOf([char]13) -ge 0) { $fLines.AddRange([string[]]$fG.Split([char]13)) }
    else { $fLines.Add($fG) }
    if ($fLines.Count -gt ` + strconv.Itoa(maxConfigLines) + `) { return [pscustomobject]@{ Status = 'too_large' } }
  }
  $fSB = New-Object System.Text.StringBuilder
  $fRed = 0; $fDrop = $false
  $fLC = $fLines.Count
  if ($fSt) {
    $sText = [string]::Join($vNL, $fLines.ToArray()) + $vNL
    $sBuf = New-Object System.Text.StringBuilder
    $sStarted = $false; $sSep = $false; $sOver = $false; $sNl = 0; $sDepth = 0; $sDropAt = 0; $sCount = 0
    $sM = $vTokRx.Match($sText)
    while ($sM.Success) {
      $sCount++
      if (($sCount -band 4095) -eq 0 -and $vSw.Elapsed.TotalSeconds -ge $vBudget) { return [pscustomobject]@{ Status = 'too_large' } }
      $sTok = $sM.Value
      $sC = $sTok[0]
      $sTerm = ''
      if ($sC -ceq [char]32 -or $sC -ceq [char]9 -or $sC -ceq [char]12 -or $sC -ceq [char]11 -or $sC -ceq [char]13 -or $sC -ceq [char]35) { $sSep = $true }
      elseif ($sC -ceq [char]10) { $sSep = $true; if ($sStarted -and -not $sOver) { $sNl++; if ($sNl -ge ` + strconv.Itoa(maxStatementLines) + `) { $sOver = $true; [void]$sBuf.Clear() } } }
      elseif ($sC -ceq [char]59 -or $sC -ceq [char]123 -or $sC -ceq [char]125) { $sTerm = $sTok }
      else {
        $sEnds = 0
        if ($sC -ceq [char]34 -or $sC -ceq [char]39) { $sEnds = $sTok.Length - $sTok.Replace($vNL, '').Length; $sTok = $sTok.Replace($vNL, ' ').Replace($vCR, ' ') }
        if (-not $sOver) {
          if ($sStarted -and $sSep) { [void]$sBuf.Append(' ') }
          [void]$sBuf.Append($sTok); $sStarted = $true; $sSep = $false; $sNl += $sEnds
          if ($sBuf.Length -gt ` + strconv.Itoa(maxStatementBytes) + ` -or $sNl -ge ` + strconv.Itoa(maxStatementLines) + `) { $sOver = $true; [void]$sBuf.Clear() }
        }
      }
      if ($sTerm.Length -gt 0) {
        $sKept = $false
        if (-not $sOver -and $sStarted -and $sDropAt -eq 0) {
          $fWd = $sBuf.ToString()
          ` + psFirstWord + `
          $sKept = ($fWd.Length -gt 0 -and $fWords.Contains($fWd))
        }
        $sStmt = $sBuf.ToString()
        [void]$sBuf.Clear(); $sStarted = $false; $sSep = $false; $sOver = $false; $sNl = 0
        if ($sTerm -ceq ';') {
          if ($sKept) { $fE = $sStmt + ';'; ` + psEmit + ` }
        } elseif ($sTerm -ceq '{') {
          $sDepth++
          if ($sKept -and $sDepth -le ` + strconv.Itoa(maxBlockDepth) + `) { $fE = $sStmt + ' {'; ` + psEmit + ` }
          elseif ($sDropAt -eq 0) { $sDropAt = $sDepth }
        } else {
          if ($sDepth -eq 0) { $fE = '}'; ` + psEmit + ` }
          else {
            if ($sDropAt -eq 0) { $fE = '}'; ` + psEmit + ` }
            if ($sDropAt -eq $sDepth) { $sDropAt = 0 }
            $sDepth--
          }
        }
      }
      $sM = $sM.NextMatch()
    }
    if ($fSB.Length -gt ` + strconv.Itoa(maxConfigOutput) + `) { return [pscustomobject]@{ Status = 'too_large' } }
    return [pscustomobject]@{ Status = 'ok'; Text = $fSB.ToString(); N = $fRed }
  }
  $fDropB = $false; $fDropT = ''; $fDepth = 0; $fPrevK = $false; $fBsc = $false; $fDropC = $false; $fDropSec = $false; $fContN = 0; $fHaveL = $false; $fLKept = $false
  $fWithSec = ($fSec -or $fAnySec)
  for ($fI = 0; $fI -lt $fLC; $fI++) {
    if (($fI -band 1023) -eq 0 -and $vSw.Elapsed.TotalSeconds -ge $vBudget) { return [pscustomobject]@{ Status = 'too_large' } }
    $fS = $fLines[$fI]
    $fT = $fS.TrimStart($vBlanks)
    if ($fDropB -or $fDropT.Length -gt 0) {
      if ($fT.Length -eq 0) { continue }
      $fC0 = $fT[0]
      if ($fC0 -ceq [char]35 -or $fC0 -ceq [char]33 -or $fC0 -ceq [char]59 -or $fT.StartsWith('//', [StringComparison]::Ordinal)) { continue }
      $fTr = $fT.TrimEnd($vBlanks)
      if ($fDropB) {
        if ($fTr[0] -ceq [char]125) { $fDepth-- }
        if ($fTr[$fTr.Length - 1] -ceq [char]123) { $fDepth++ }
      } else {
        $fOm = $vOpenRx.Match($fTr)
        if ($fOm.Success -and $fTr.EndsWith('>', [StringComparison]::Ordinal) -and $fOm.Groups[1].Length -le 64 -and [string]::Equals($fOm.Groups[1].Value, $fDropT, [StringComparison]::OrdinalIgnoreCase)) { $fDepth++ }
        else {
          $fCm = $vCloseRx.Match($fTr)
          if ($fCm.Success -and [string]::Equals($fCm.Groups[1].Value, $fDropT, [StringComparison]::OrdinalIgnoreCase)) { $fDepth-- }
        }
      }
      if ($fDepth -le 0) { $fDropB = $false; $fDropT = '' }
      continue
    }
    $fTr = $fT.TrimEnd($vBlanks)
    $fHasCR = ($fS.IndexOf([char]13) -ge 0)
    $fHdr = ($fWithSec -and -not $fHasCR -and $fTr.Length -ge 2 -and $fTr[0] -ceq [char]91 -and $fTr[$fTr.Length - 1] -ceq [char]93)
    if ($fDropSec -and -not $fHdr) { continue }
    if ($fHasCR) {
      $fBsc = $false; $fDropC = $false; $fPrevK = $false; $fHaveL = $true; $fLKept = $false; $fContN = 0
      if ($fTr.Length -gt 0 -and $fTr[$fTr.Length - 1] -ceq [char]123) { $fDropB = $true; $fDepth = 1 }
      elseif ($fTags) {
        $fOm = $vOpenRx.Match($fTr)
        if ($fOm.Success -and $fTr.EndsWith('>', [StringComparison]::Ordinal) -and $fOm.Groups[1].Length -le 64) { $fDropT = $fOm.Groups[1].Value; $fDepth = 1 }
      }
      continue
    }
    if ($fBsc) {
      $fContN++
      ` + psOddBackslashes + `
      $fBsc = $fOdd
      if ($fContN -le ` + strconv.Itoa(maxContinuation) + ` -and -not $fT.StartsWith('#', [StringComparison]::Ordinal)) { $fE = $fS; ` + psEmit + ` }
      continue
    }
    if ($fDropC) { $fDropC = $fS.EndsWith('\', [StringComparison]::Ordinal); continue }
    if ($fInd -and $fHaveL -and $fT.Length -gt 0 -and ($fS[0] -ceq [char]32 -or $fS[0] -ceq [char]9)) {
      if ($fT[0] -ceq [char]35) { continue }
      $fContN++
      if ($fLKept -and $fContN -le ` + strconv.Itoa(maxContinuation) + `) { $fE = $fS; ` + psEmit + ` }
      continue
    }
    if ($fT.Length -eq 0) { $fE = $fS; ` + psEmit + `; continue }
    $fC0 = $fT[0]
    if ($fC0 -ceq [char]35 -or $fC0 -ceq [char]33 -or $fC0 -ceq [char]59 -or $fT.StartsWith('//', [StringComparison]::Ordinal)) { continue }
    $fHaveL = $true; $fLKept = $false; $fContN = 0
    if ($fHdr) {
      $fSm = $vSecRx.Match($fTr)
      $fDropSec = (-not $fSm.Success -or (-not $fAnySec -and -not $fWords.Contains($fSm.Groups[1].Value)))
      if (-not $fDropSec) { $fE = $fS; ` + psEmit + ` }
      $fPrevK = $false
      continue
    }
    $fCm = $vCloseRx.Match($fTr)
    if (($fTags -and $fCm.Success -and $fWords.Contains($fCm.Groups[1].Value)) -or $fTr -ceq '}' -or $fTr -ceq '};' -or ($fTr -ceq '{' -and $fPrevK)) { $fE = $fS; ` + psEmit + `; $fPrevK = $false; continue }
    $fWd = $fT
    ` + psFirstWord + `
    if ($fWd.Length -gt 0 -and $fWords.Contains($fWd)) {
      $fE = $fS; ` + psEmit + `
      $fPrevK = $true; $fLKept = $true; $fBsc = $false
      if ($fBs) { ` + psOddBackslashes + `; $fBsc = $fOdd }
      continue
    }
    $fPrevK = $false
    if ($fBs -and $fS.EndsWith('\', [StringComparison]::Ordinal)) { $fDropC = $true }
    elseif ($fTr[$fTr.Length - 1] -ceq [char]123) { $fDropB = $true; $fDepth = 1 }
    elseif ($fTags) {
      $fOm = $vOpenRx.Match($fTr)
      if ($fOm.Success -and $fTr.EndsWith('>', [StringComparison]::Ordinal) -and $fOm.Groups[1].Length -le 64) { $fDropT = $fOm.Groups[1].Value; $fDepth = 1 }
    }
  }
  if ($fSB.Length -gt ` + strconv.Itoa(maxConfigOutput) + `) { return [pscustomobject]@{ Status = 'too_large' } }
  return [pscustomobject]@{ Status = 'ok'; Text = $fSB.ToString(); N = $fRed }
}
function vInspect([string]$isText) {
  $isF = [ordered]@{ bad = 0; nonpub = 0; unterm = 0; priv = 0; orun = 0; sshbad = 0; sshl = 0; nl = 0 }
  $isLabels = New-Object 'System.Collections.Generic.List[string]'
  $isPub = $false
  $isL = vLines $isText
  for ($isI = 0; $isI -lt $isL.Count; $isI++) {
    $isS = $isL.Parts[$isI]
    if ($isS.EndsWith($vCR, [StringComparison]::Ordinal)) { $isS = $isS.Substring(0, $isS.Length - 1) }
    if ($isS.Contains('----BEGIN') -or $isS.Contains('---- BEGIN')) {
      if ($isPub) { $isF.unterm = 1 }
      $isPub = $false
      $isLab = vParse $isS
      $isOkPub = ($null -ne $isLab) -and $vAllowSet.Contains($isLab)
      if (-not $isOkPub -and $vPrivRx.IsMatch($isS)) { $isF.priv = 1 }
      if ($null -eq $isLab) { $isF.bad = 1; continue }
      $isF.nl++
      if ($isLabels.Count -lt ` + strconv.Itoa(maxPEMLabels) + `) { $isLabels.Add($isLab) }
      if ($isOkPub) { $isPub = $true } else { $isF.nonpub = 1 }
      continue
    }
    if ($isPub) { if ($isS.Contains('----END') -or $isS.Contains('---- END')) { $isPub = $false }; continue }
    if ($isS.Length -ge ` + strconv.Itoa(RedactRunLength) + ` -and $vRunRx.IsMatch($isS)) { $isF.orun = 1 }
    if ($isS.StartsWith('#', [StringComparison]::Ordinal) -or $vBlankRx.IsMatch($isS)) { continue }
    $isK = ''
    if ($isS.Contains('ssh-') -or $isS.Contains('ecdsa-')) { $isK = vSshKey $isS }
    if ($isK.Length -gt 0) { $isF.sshl++ } else { $isF.sshbad = 1 }
  }
  if ($isPub) { $isF.unterm = 1 }
  return [pscustomobject]@{ Flags = $isF; Labels = $isLabels.ToArray() }
}
`

// psBudgetLine sets the host-side time budget of a script.
func psBudgetLine(seconds int) string {
	return "$vBudget = " + strconv.Itoa(seconds) + "\n"
}

// psQuietLine turns on the quiescence rule for a script that returns file
// content: a file last written within 3 seconds of the host's clock (or
// ahead of it) is refused as "changed", as on Unix (readQuiet).
const psQuietLine = "$vQuiet = $true\n"

// remoteWindowsTextBudget is how long psReadText may filter before it gives
// up with "too_large": below the runner's 90-second command timeout, so a
// huge file is refused with an answer, never lost to a timeout.
const remoteWindowsTextBudget = 45

// psStat describes one path: Get-Item, then psAcl.
var psStat = psPrelude + `try { $stItem = Get-Item -LiteralPath $a.Path -Force } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
$stAcl = psAcl $stItem.FullName
$stLink = psLink $stItem
$stTarget = ''
if ($stLink) { $stTarget = [string](@($stItem.Target)[0]) }
$stSize = 0
if (-not $stItem.PSIsContainer) { $stSize = [int64]$stItem.Length }
psOut ([pscustomobject]@{
  Path = $stItem.FullName; Size = $stSize; Modified = (psTime $stItem)
  IsDir = [bool]($stItem.PSIsContainer -and -not $stLink); IsLink = [bool]$stLink; Target = $stTarget
  Owner = $stAcl.Owner; AclOk = $stAcl.Ok; Broad = $stAcl.Broad
})`

// psIdentify returns ONLY markers from one bounded read: size, the first
// eight bytes in hex, whether the window holds a NUL, up to 64 valid labels
// and the rule flags.
var psIdentify = psPrelude + `try { $idR = vRead $a.Path ([int64]$a.Max) } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
if ($idR.Error) { psOut ([pscustomobject]@{ Error = $idR.Error }); exit 0 }
$idNul = ([Array]::IndexOf($idR.Buf, [byte]0, 0, $idR.N) -ge 0)
$idText = $vL1.GetString($idR.Buf, 0, $idR.N)
$idX = vInspect $idText
$idU16 = $false
$idHex = vHex $idR.Buf $idR.N
if ($idHex.StartsWith('fffe', [StringComparison]::Ordinal) -or $idHex.StartsWith('feff', [StringComparison]::Ordinal)) {
  $idU16 = $vU16PrivRx.IsMatch($vU16Rx.Replace($idText, ''))
}
psOut ([pscustomobject]@{ Size = $idR.Size; Magic = $idHex; Nul = $idNul; Utf16 = $idU16; Labels = $idX.Labels; Flags = $idX.Flags })`

// psRead reads the buffer once, decides on it with the host-side rule (as the
// awk "decide" mode does) and only then prints base64 of THAT buffer's public
// content.
var psRead = psQuietLine + psPrelude + `try { $rdR = vRead $a.Path (([int64]$a.Max) + 1) } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
if ($rdR.Error) { psOut ([pscustomobject]@{ Error = $rdR.Error }); exit 0 }
if ($rdR.Size -gt [int64]$a.Max -or $rdR.N -gt [int64]$a.Max) { psOut ([pscustomobject]@{ Error = 'too_large' }); exit 0 }
$rdPub = vPublic $rdR.Buf $rdR.N
if ($null -eq $rdPub) { psOut ([pscustomobject]@{ Error = 'not_public' }); exit 0 }
[Console]::Out.Write('D:' + [Convert]::ToBase64String($vL1.GetBytes($rdPub)))`

// psReadText reads the buffer once, filters it with the rules of
// FilterConfigText within the time budget and prints the result with the
// count.
var psReadText = psBudgetLine(remoteWindowsTextBudget) + psQuietLine + psPrelude + `try { $rtR = vRead $a.Path (([int64]$a.Max) + 1) } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
if ($rtR.Error) { psOut ([pscustomobject]@{ Error = $rtR.Error }); exit 0 }
if ($rtR.Size -gt [int64]$a.Max -or $rtR.N -gt [int64]$a.Max) { psOut ([pscustomobject]@{ Error = 'too_large' }); exit 0 }
$rtF = vFilter $rtR.Buf $rtR.N ([string[]]@($a.Keep))
if ($rtF.Status -cne 'ok') { psOut ([pscustomobject]@{ Error = $rtF.Status }); exit 0 }
[Console]::Out.Write('T:' + $rtF.N + ':' + [Convert]::ToBase64String($vL1.GetBytes($rtF.Text)))`

// psList walks a tree itself, with .NET's DirectoryInfo.GetFileSystemInfos on
// the \\?\ form of every directory, so that a directory deeper than 260
// characters is entered (Get-ChildItem on Windows PowerShell 5.1 stops at
// MAX_PATH), a directory link or junction is reported and never entered, an
// unreadable directory is counted rather than silently skipped, files over
// the size bound are counted, and the walk stops at the bounds ON THE HOST.
// A reparse point is asked what it is with Get-Item (rare); one it cannot
// name is treated as a link, never followed. ACLs are not read here (a
// Get-Acl per file is too slow for a sweep); the sweep Stats the files it
// keeps.
var psList = psPrelude + `$lsRoot = [string]$a.Root
$lsMaxDepth = [int]$a.Depth; $lsMax = [int]$a.Max; $lsMaxSize = [int64]$a.MaxSize; $lsCap = [int64]$a.ByteCap; $lsCross = [bool]$a.Cross
$lsExcl = @(); if ($a.Exclude) { $lsExcl = @($a.Exclude) }
$lsNames = @(); if ($a.Names) { $lsNames = @($a.Names) }
function lsIsExcl([string]$exP) {
  foreach ($exE in $lsExcl) { if ([string]::Equals($exP, [string]$exE, [StringComparison]::OrdinalIgnoreCase) -or $exP.StartsWith(([string]$exE).TrimEnd([char]92) + [char]92, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
  return $false
}
function lsNameOk([string]$noN) {
  if ($lsNames.Count -eq 0) { return $true }
  foreach ($noG in $lsNames) { if ($noN -ilike $noG) { return $true } }
  return $false
}
function lsLinkInfo([string]$liP) {
  try {
    $liI = Get-Item -LiteralPath (vLong $liP) -Force
    $liL = psLink $liI
    $liT = ''
    if ($liL) { $liT = [string](@($liI.Target)[0]) }
    return [pscustomobject]@{ Link = $liL; Target = $liT }
  } catch { return [pscustomobject]@{ Link = $true; Target = '' } }
}
$lsFiles = New-Object 'System.Collections.Generic.List[object]'
$lsDenied = New-Object 'System.Collections.Generic.List[string]'
$lsDeniedCount = 0; $lsUnreadable = 0; $lsOversize = 0; $lsTrunc = $false; $lsBytes = 0
$lsBudget = [double]$a.Budget
try { $lsRi = Get-Item -LiteralPath $lsRoot -Force } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
$lsRootFull = vShort $lsRi.FullName
$lsRootVol = [System.IO.Path]::GetPathRoot($lsRootFull)
if (-not $lsRi.PSIsContainer -or (psLink $lsRi)) {
  if (lsNameOk $lsRi.Name) {
    $lsRl = psLink $lsRi
    if ($lsRl -or $lsRi.Length -le $lsMaxSize) {
      $lsRt = ''; if ($lsRl) { $lsRt = [string](@($lsRi.Target)[0]) }
      $lsSz = 0; if (-not $lsRi.PSIsContainer) { $lsSz = [int64]$lsRi.Length }
      $lsFiles.Add([pscustomobject]@{ Path = $lsRootFull; Size = $lsSz; Modified = (psTime $lsRi); IsLink = [bool]$lsRl; Target = $lsRt })
    } else { $lsOversize++ }
  }
} else {
  $lsStack = New-Object 'System.Collections.Generic.Stack[object]'
  $lsStack.Push(@($lsRootFull, 0))
  while ($lsStack.Count -gt 0 -and -not $lsTrunc) {
    if ($vSw.Elapsed.TotalSeconds -ge $lsBudget) { $lsTrunc = $true; break }
    $lsItem = $lsStack.Pop(); $lsDir = [string]$lsItem[0]; $lsDepth = [int]$lsItem[1]
    try { $lsKids = ([System.IO.DirectoryInfo]::new((vLong $lsDir))).GetFileSystemInfos() } catch {
      if ((psErr $_.Exception) -ceq 'denied') {
        $lsDeniedCount++
        if ($lsDenied.Count -lt 100) { $lsDenied.Add($lsDir) }
      } else { $lsUnreadable++ }
      continue
    }
    foreach ($lsC in $lsKids) {
      try {
        $lsPath = vShort $lsC.FullName
        if (lsIsExcl $lsPath) { continue }
        $lsAttr = $lsC.Attributes
        $lsIsDir = (($lsAttr -band [System.IO.FileAttributes]::Directory) -ne 0)
        $lsLink = $false; $lsTarget = ''
        if (($lsAttr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $lsInfo = lsLinkInfo $lsPath; $lsLink = $lsInfo.Link; $lsTarget = $lsInfo.Target }
        if ($lsIsDir -and -not $lsLink) {
          if ($lsDepth -lt $lsMaxDepth -and ($lsCross -or [string]::Equals([System.IO.Path]::GetPathRoot($lsPath), $lsRootVol, [StringComparison]::OrdinalIgnoreCase))) { $lsStack.Push(@($lsPath, ($lsDepth + 1))) }
          continue
        }
        if (-not (lsNameOk $lsC.Name)) { continue }
        $lsSize = 0
        if (-not $lsIsDir) { $lsSize = [int64]$lsC.Length }
        if (-not $lsLink -and $lsSize -gt $lsMaxSize) { $lsOversize++; continue }
        if ($lsFiles.Count -ge $lsMax -or $lsBytes -ge $lsCap -or $vSw.Elapsed.TotalSeconds -ge $lsBudget) { $lsTrunc = $true; break }
        $lsFiles.Add([pscustomobject]@{ Path = $lsPath; Size = $lsSize; Modified = $lsC.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'); IsLink = [bool]$lsLink; Target = $lsTarget })
        $lsBytes += $lsPath.Length + $lsTarget.Length + 120
      } catch { $lsUnreadable++ }
    }
  }
}
psOut ([pscustomobject]@{ Files = $lsFiles.ToArray(); Denied = $lsDenied.ToArray(); DeniedCount = $lsDeniedCount; Unreadable = $lsUnreadable; OverSize = $lsOversize; Truncated = $lsTrunc })`

// base64Alphabet is what may be substituted into a script. It is checked,
// not assumed, so a future change to the encoding cannot open the literal.
var base64Alphabet = regexp.MustCompile(`^[A-Za-z0-9+/=]*$`)

// psScript prefixes script with its arguments.
func psScript(script string, args any) (string, error) {
	j, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(j)
	if !base64Alphabet.MatchString(b64) {
		return "", errors.New("hostcrypto: argument encoding produced unsafe characters")
	}
	if !strings.Contains(script, "$vistaArgs") {
		return "", errors.New("hostcrypto: script does not read its arguments")
	}
	return "$vistaArgs = '" + b64 + "'\n" + script, nil
}

// psArgv builds the -EncodedCommand invocation of a full script, for a runner
// without stdin. It refuses a command cmd.exe would cut.
func psArgv(full string) ([]string, error) {
	argv := []string{"powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", psEncode(full)}
	if n := len(strings.Join(argv, " ")); n > cmdLineLimit {
		return nil, fmt.Errorf("hostcrypto: the PowerShell command is %d characters, over the %d cmd.exe allows; the runner must implement hostinventory.InputRunner", n, cmdLineLimit)
	}
	return argv, nil
}

// psStdinArgv is the fixed argv of the stdin path.
var psStdinArgv = []string{"powershell", "-NoProfile", "-NonInteractive", "-Command", "-"}

// psStdin is the one line sent on stdin: the full script, base64 encoded,
// run with Invoke-Expression so `exit` sets the process's exit code.
func psStdin(full string) []byte {
	b64 := base64.StdEncoding.EncodeToString([]byte(full))
	return []byte("iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + b64 + "')))\r\n")
}

// psEncode renders a script as the UTF-16LE base64 that -EncodedCommand
// takes. (Host inventory has the same helper, unexported.)
func psEncode(script string) string {
	units := utf16.Encode([]rune(script))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// psRun runs a script and returns its answer, which is ASCII whatever the
// host's console code page is: "J:" and base64 of UTF-8 JSON, "D:" and base64
// of data, or "T:<count>:" and base64 of text. The kind letter is returned
// with the decoded payload. A non-zero exit is an error: every script here
// reports its own failures and exits 0.
func (t *RemoteWindowsTarget) psRun(ctx context.Context, script string, args any) (byte, []byte, error) {
	full, err := psScript(script, args)
	if err != nil {
		return 0, nil, err
	}
	var out []byte
	var exit int
	if ir, ok := t.runner.(hostinventory.InputRunner); ok {
		out, _, exit, err = ir.RunInput(ctx, psStdinArgv, psStdin(full))
	} else {
		argv, aerr := psArgv(full)
		if aerr != nil {
			return 0, nil, aerr
		}
		out, _, exit, err = t.runner.Run(ctx, argv)
	}
	if err != nil {
		return 0, nil, err
	}
	if exit != 0 {
		return 0, nil, fmt.Errorf("hostcrypto: powershell exited %d", exit)
	}
	return psDecode(out)
}

// psDecode reads one answer.
func psDecode(out []byte) (byte, []byte, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(out), "\ufeff"))
	if len(s) < 2 || s[1] != ':' {
		return 0, nil, errors.New("hostcrypto: unreadable answer from the host")
	}
	kind, body := s[0], s[2:]
	if kind == 'T' {
		// T:<count>:<base64>; the count is returned in front of the payload
		// by psText.
		i := strings.IndexByte(body, ':')
		if i < 0 {
			return 0, nil, errors.New("hostcrypto: unreadable answer from the host")
		}
		data, err := base64.StdEncoding.DecodeString(body[i+1:])
		if err != nil {
			return 0, nil, errors.New("hostcrypto: unreadable answer from the host")
		}
		return kind, append([]byte(body[:i+1]), data...), nil
	}
	if kind != 'J' && kind != 'D' {
		return 0, nil, errors.New("hostcrypto: unreadable answer from the host")
	}
	data, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return 0, nil, errors.New("hostcrypto: unreadable answer from the host")
	}
	return kind, data, nil
}

// psJSON runs a script whose only answer is JSON.
func (t *RemoteWindowsTarget) psJSON(ctx context.Context, script string, args any) ([]byte, error) {
	kind, b, err := t.psRun(ctx, script, args)
	if err != nil {
		return nil, err
	}
	if kind != 'J' {
		return nil, errors.New("hostcrypto: unexpected answer from the host")
	}
	return b, nil
}

// winLongPath gives every absolute path the \\?\ form, so the Windows API
// neither cuts it at MAX_PATH nor rewrites it: without the prefix "nul.conf",
// "COM1.conf" and "aux" name devices, and a trailing dot or space is
// stripped, so the file asked for is not the file read. A relative path is
// left alone (it cannot take the prefix).
func winLongPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + p[2:]
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') && isASCIIAlnum(p[0]) {
		return `\\?\` + strings.ReplaceAll(p, "/", `\`)
	}
	return p
}

// psError maps a script's Error word to the sentinels.
func psError(path, word string) error {
	switch word {
	case "not_found":
		return fmt.Errorf("%s: %w", path, ErrNotExist)
	case "denied":
		return fmt.Errorf("%s: %w", path, ErrPermission)
	case "directory":
		return fmt.Errorf("hostcrypto: %s is a directory", path)
	case "too_large":
		return fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	case "not_public":
		return fmt.Errorf("%s: %w", path, ErrNotPublic)
	case "changed":
		return fmt.Errorf("%s: %w", path, errChanged)
	}
	return fmt.Errorf("hostcrypto: %s: could not be read", path)
}

type psPathArgs struct {
	Path string   `json:"Path"`
	Max  int64    `json:"Max,omitempty"`
	Keep []string `json:"Keep,omitempty"`
}

type psStatResult struct {
	Error    string `json:"Error"`
	Path     string `json:"Path"`
	Size     int64  `json:"Size"`
	Modified string `json:"Modified"`
	IsDir    bool   `json:"IsDir"`
	IsLink   bool   `json:"IsLink"`
	Target   string `json:"Target"`
	Owner    string `json:"Owner"`
	AclOk    bool   `json:"AclOk"`
	Broad    bool   `json:"Broad"`
}

// Stat describes one path, with its owner and the host-computed answer to
// "can Everyone, Users or Authenticated Users read it?". Mode stays 0 and
// GroupReadable nil: Windows has no group permission class.
func (t *RemoteWindowsTarget) Stat(ctx context.Context, path string) (FileInfo, error) {
	out, err := t.psJSON(ctx, psStat, psPathArgs{Path: winLongPath(path)})
	if err != nil {
		return FileInfo{}, err
	}
	var r psStatResult
	if err := json.Unmarshal(out, &r); err != nil {
		return FileInfo{}, fmt.Errorf("hostcrypto: stat %s: unreadable answer", path)
	}
	if r.Error != "" {
		return FileInfo{}, psError(path, r.Error)
	}
	fi := FileInfo{
		Path:       path,
		Size:       r.Size,
		Owner:      r.Owner,
		ModifiedAt: normaliseRFC3339(r.Modified),
		IsDir:      r.IsDir,
		IsSymlink:  r.IsLink,
		LinkTarget: r.Target,
	}
	if r.AclOk {
		broad := r.Broad
		fi.WorldReadable = &broad
	}
	return fi, nil
}

type psFlags struct {
	Bad    *int `json:"bad"`
	NonPub *int `json:"nonpub"`
	Unterm *int `json:"unterm"`
	Priv   *int `json:"priv"`
	ORun   *int `json:"orun"`
	SSHBad *int `json:"sshbad"`
	SSHL   *int `json:"sshl"`
	NL     *int `json:"nl"`
}

type psIdentifyResult struct {
	Error  string          `json:"Error"`
	Size   *int64          `json:"Size"`
	Magic  string          `json:"Magic"`
	Nul    *bool           `json:"Nul"`
	Utf16  *bool           `json:"Utf16"`
	Labels json.RawMessage `json:"Labels"`
	Flags  *psFlags        `json:"Flags"`
}

// identify runs psIdentify and returns the host's inspection. A field the
// host did not return is an error, never a default that could make a file
// public.
func (t *RemoteWindowsTarget) identify(ctx context.Context, path string) (inspection, error) {
	out, err := t.psJSON(ctx, psIdentify, psPathArgs{Path: winLongPath(path), Max: t.maxBytes})
	if err != nil {
		return inspection{}, err
	}
	var r psIdentifyResult
	if err := json.Unmarshal(out, &r); err != nil {
		return inspection{}, fmt.Errorf("hostcrypto: identify %s: unreadable answer", path)
	}
	if r.Error != "" {
		return inspection{}, psError(path, r.Error)
	}
	f := r.Flags
	if r.Size == nil || r.Nul == nil || r.Utf16 == nil || f == nil || f.Bad == nil || f.NonPub == nil || f.Unterm == nil ||
		f.Priv == nil || f.ORun == nil || f.SSHBad == nil || f.SSHL == nil || f.NL == nil {
		return inspection{}, fmt.Errorf("hostcrypto: identify %s: incomplete answer", path)
	}
	magic, err := hex.DecodeString(r.Magic)
	if err != nil || len(magic) > MagicBytes {
		return inspection{}, fmt.Errorf("hostcrypto: identify %s: unreadable magic", path)
	}
	raw, err := psArray[string](r.Labels)
	if err != nil {
		return inspection{}, fmt.Errorf("hostcrypto: identify %s: unreadable labels", path)
	}
	if len(magic) == 0 {
		magic = nil
	}
	in := inspection{
		magic: magic, size: *r.Size, truncated: *r.Size > t.maxBytes, nul: *r.Nul,
		bad: *f.Bad != 0, nonPublic: *f.NonPub != 0, unterminated: *f.Unterm != 0, private: *f.Priv != 0,
		outsideRun: *f.ORun != 0, sshBad: *f.SSHBad != 0, sshLines: *f.SSHL, nLabel: *f.NL,
		utf16: bytes.HasPrefix(magic, []byte{0xFF, 0xFE}) || bytes.HasPrefix(magic, []byte{0xFE, 0xFF}), utf16Private: *r.Utf16,
	}
	if in.utf16Private && !in.utf16 {
		return inspection{}, fmt.Errorf("hostcrypto: identify %s: inconsistent answer", path)
	}
	for _, l := range raw {
		if _, ok := parseBeginLine("-----BEGIN " + l + "-----"); !ok {
			in.bad = true
			continue
		}
		if len(in.labels) < maxPEMLabels {
			in.labels = append(in.labels, l)
		}
	}
	if len(in.labels) > in.nLabel {
		return inspection{}, fmt.Errorf("hostcrypto: identify %s: inconsistent answer", path)
	}
	return in, nil
}

// Identify runs psIdentify and classifies what it returns.
func (t *RemoteWindowsTarget) Identify(ctx context.Context, path string) (Identity, error) {
	in, err := t.identify(ctx, path)
	if err != nil {
		return Identity{}, err
	}
	return identityFrom(path, in), nil
}

// ReadFile identifies path first and refuses, with [ErrNotPublic], anything
// not identified as public, and with [ErrFileTooLarge] anything over the
// cap; in either case no script that returns content is run. psRead then
// decides again on the host from the one buffer it prints, and the bytes that
// arrive are inspected once more here.
func (t *RemoteWindowsTarget) ReadFile(ctx context.Context, path string) ([]byte, error) {
	in, err := t.identify(ctx, path)
	if err != nil {
		return nil, err
	}
	readCap := t.readCap()
	if in.size > readCap {
		return nil, fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	}
	if !identityFrom(path, in).Public() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotPublic)
	}
	kind, out, err := t.psRun(ctx, psRead, psPathArgs{Path: winLongPath(path), Max: readCap})
	if err != nil {
		return nil, err
	}
	if kind == 'J' {
		return nil, psJSONError(path, out)
	}
	if kind != 'D' {
		return nil, fmt.Errorf("hostcrypto: read %s: unexpected answer", path)
	}
	return recheckPublic(path, out, readCap)
}

// psJSONError reads a script's {"Error": ...} answer.
func psJSONError(path string, out []byte) error {
	var r struct {
		Error string `json:"Error"`
	}
	if json.Unmarshal(out, &r) == nil && r.Error != "" {
		return psError(path, r.Error)
	}
	return fmt.Errorf("hostcrypto: %s: unreadable answer", path)
}

// ReadText returns the lines of a configuration file a parser asked for,
// narrowed and redacted on the host by psReadText (filterConfig's rule),
// checked here as on Unix (see [RemoteUnixTarget.ReadText]). An empty keep is
// refused before anything is sent.
func (t *RemoteWindowsTarget) ReadText(ctx context.Context, path string, keep []string) ([]byte, int, error) {
	words, err := keepArg(keep)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	kind, out, err := t.psRun(ctx, psReadText, psPathArgs{Path: winLongPath(path), Max: t.readCap(), Keep: strings.Fields(words)})
	if err != nil {
		return nil, 0, err
	}
	if kind == 'J' {
		return nil, 0, psJSONError(path, out)
	}
	if kind != 'T' {
		return nil, 0, fmt.Errorf("hostcrypto: read text %s: unexpected answer", path)
	}
	i := bytes.IndexByte(out, ':')
	n, err := strconv.Atoi(string(out[:i]))
	if err != nil || n < 0 {
		return nil, 0, fmt.Errorf("hostcrypto: read text %s: the host did not report its redactions", path)
	}
	return checkFiltered(path, out[i+1:], n)
}

type psListArgs struct {
	Root    string   `json:"Root"`
	Depth   int      `json:"Depth"`
	Max     int      `json:"Max"`
	MaxSize int64    `json:"MaxSize"`
	ByteCap int      `json:"ByteCap"`
	Budget  float64  `json:"Budget"`
	Cross   bool     `json:"Cross"`
	Exclude []string `json:"Exclude"`
	Names   []string `json:"Names"`
}

type psListFile struct {
	Path     string `json:"Path"`
	Size     int64  `json:"Size"`
	Modified string `json:"Modified"`
	IsLink   bool   `json:"IsLink"`
	Target   string `json:"Target"`
}

type psListResult struct {
	Error       string          `json:"Error"`
	Files       json.RawMessage `json:"Files"`
	Denied      json.RawMessage `json:"Denied"`
	DeniedCount int             `json:"DeniedCount"`
	Unreadable  int             `json:"Unreadable"`
	OverSize    int             `json:"OverSize"`
	Truncated   bool            `json:"Truncated"`
}

// List runs psList. The walk and every bound run on the host; the answer is
// sorted by path here so it does not depend on the host's traversal order.
// WorldReadable is left nil (the sweep Stats each hit).
func (t *RemoteWindowsTarget) List(ctx context.Context, root string, opts ListOptions) ([]FileInfo, error) {
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}
	maxSize := opts.MaxSizeBytes
	if maxSize <= 0 {
		maxSize = defaultMaxFileBytes
	}
	args := psListArgs{
		Root: root, Depth: opts.MaxDepth, Max: maxFiles, MaxSize: maxSize,
		// Each record is about 120 bytes of JSON beyond its path, so the cap
		// keeps the answer under the runner's 8 MiB bound.
		ByteCap: remoteListByteCap - (1 << 20),
		Cross:   opts.CrossFilesystems,
		Budget:  remoteWindowsListBudget.Seconds(),
		Exclude: nonNil(opts.Exclude), Names: nonNil(opts.Names),
	}
	out, err := t.psJSON(ctx, psList, args)
	if err != nil {
		return nil, err
	}
	var r psListResult
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("hostcrypto: list %s: unreadable answer", root)
	}
	if r.Error != "" {
		return nil, psError(root, r.Error)
	}
	files, err := psArray[psListFile](r.Files)
	if err != nil {
		return nil, fmt.Errorf("hostcrypto: list %s: unreadable answer", root)
	}
	denied, err := psArray[string](r.Denied)
	if err != nil {
		return nil, fmt.Errorf("hostcrypto: list %s: unreadable answer", root)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	infos := make([]FileInfo, 0, len(files))
	for _, f := range files {
		if len(infos) >= maxFiles {
			r.Truncated = true
			break
		}
		infos = append(infos, FileInfo{
			Path: f.Path, Size: f.Size, ModifiedAt: normaliseRFC3339(f.Modified),
			IsSymlink: f.IsLink, LinkTarget: f.Target,
		})
	}
	lerr := &ListError{Truncated: r.Truncated, DeniedCount: r.DeniedCount, Unreadable: r.Unreadable, OverSize: r.OverSize}
	if len(denied) > maxDeniedListed {
		denied = denied[:maxDeniedListed]
	}
	lerr.Denied = denied
	if lerr.DeniedCount < len(denied) {
		lerr.DeniedCount = len(denied)
	}
	return infos, lerr.orNil()
}

// psArray reads a JSON array that PowerShell may have rendered as a bare
// value (one element), null or nothing.
func psArray[T any](raw json.RawMessage) ([]T, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil, nil
	}
	var arr []T
	if err := json.Unmarshal([]byte(s), &arr); err == nil {
		return arr, nil
	}
	var one T
	if err := json.Unmarshal([]byte(s), &one); err != nil {
		return nil, err
	}
	return []T{one}, nil
}

// normaliseRFC3339 returns t as RFC 3339 UTC, or "" when it is not a time.
func normaliseRFC3339(s string) string {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
