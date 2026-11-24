// This file is named target_remote_win.go, not target_remote_windows.go: Go
// reads a "_windows" suffix as a build constraint, and this code must build on
// every platform so a Linux or macOS agent can collect a Windows host.

package hostcrypto

import (
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
// of that buffer, byte for byte, as `grep -a` and the awk rules see it on
// Unix. ReadFile prints base64 of the same buffer it decided on, so there is
// no window between the check and the output on Windows. Go re-checks
// everything that arrives.
type RemoteWindowsTarget struct {
	runner   hostinventory.Runner
	maxBytes int64
}

// remoteWindowsReadMax is the largest file the Windows target returns. Base64
// makes four characters of three bytes and the runner refuses more than
// 8 MiB of output, so 6,000,000 bytes is the most that fits. A larger file is
// ErrFileTooLarge, decided on the host before anything is printed.
const remoteWindowsReadMax = 6000000

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

// psPrelude decodes the arguments and defines the helpers every script uses.
// psErr turns an exception into "not_found", "denied" or "other"; psAcl
// projects Get-Acl onto the owner and ONE boolean worked out on the host
// (read granted to Everyone, BUILTIN\Users or Authenticated Users); the v*
// functions are the text rules of redact.go, on a Latin-1 view of the bytes.
var psPrelude = `$ErrorActionPreference='Stop'
$a = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($vistaArgs)) | ConvertFrom-Json
$vL1 = [Text.Encoding]::GetEncoding(28591)
$vAllow = ` + psQuoteList(publicPEMLabels) + `
$vRun = '[A-Za-z0-9+/=]{` + strconv.Itoa(RedactRunLength) + `,}'
function psErr($e) {
  while ($e -is [System.Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
  if ($e -is [System.Management.Automation.ItemNotFoundException] -or $e -is [System.IO.FileNotFoundException] -or $e -is [System.IO.DirectoryNotFoundException]) { return 'not_found' }
  if ($e -is [System.UnauthorizedAccessException] -or $e -is [System.Security.SecurityException]) { return 'denied' }
  return 'other'
}
function psOut($o) { [Console]::Out.Write((ConvertTo-Json -Compress -Depth 4 -InputObject $o)) }
function psAcl([string]$p) {
  try {
    $acl = Get-Acl -LiteralPath $p
    $allow = @{}; $deny = @{}
    foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
      $sid = $r.IdentityReference.Value
      if (@('S-1-1-0','S-1-5-32-545','S-1-5-11') -notcontains $sid) { continue }
      if (($r.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
      $m = ([int64]$r.FileSystemRights) -band 0xFFFFFFFFL
      if (($m -band 0x90000001L) -eq 0) { continue }
      if ($r.AccessControlType -eq 'Allow') { $allow[$sid] = $true } else { $deny[$sid] = $true }
    }
    $broad = $false
    foreach ($k in $allow.Keys) { if (-not $deny.ContainsKey($k)) { $broad = $true } }
    return [pscustomobject]@{ Owner = [string]$acl.Owner; Broad = $broad; Ok = $true }
  } catch {
    return [pscustomobject]@{ Owner = ''; Broad = $false; Ok = $false }
  }
}
function psLink($i) { return ($i.LinkType -eq 'SymbolicLink' -or $i.LinkType -eq 'Junction') }
function psTime($i) { return $i.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') }
function vRead([string]$p, [int64]$max) {
  $i = Get-Item -LiteralPath $p -Force
  if ($i.PSIsContainer) { return [pscustomobject]@{ Error = 'directory' } }
  $fs = [System.IO.File]::Open($i.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $size = $fs.Length
    $n = [int][Math]::Min($size, $max)
    $buf = New-Object byte[] $n
    $off = 0
    while ($off -lt $n) { $r = $fs.Read($buf, $off, $n - $off); if ($r -le 0) { break }; $off += $r }
  } finally { $fs.Close() }
  return [pscustomobject]@{ Error = ''; Size = [int64]$size; Buf = $buf; N = $off }
}
function vIsBegin([string]$s) { return ($s.Contains('----BEGIN') -or $s.Contains('---- BEGIN')) }
function vIsEnd([string]$s) { return ($s.Contains('----END') -or $s.Contains('---- END')) }
function vParse([string]$s) {
  $n = $s.Length
  if ($n -lt 17) { return $null }
  $five = $s.StartsWith('-----BEGIN ', [StringComparison]::Ordinal) -and $s.EndsWith('-----', [StringComparison]::Ordinal)
  $four = $s.StartsWith('---- BEGIN ', [StringComparison]::Ordinal) -and $s.EndsWith(' ----', [StringComparison]::Ordinal)
  if (-not ($five -or $four)) { return $null }
  $l = $s.Substring(11, $n - 16)
  if ($l.Length -gt 64 -or -not [regex]::IsMatch($l, '^[A-Z0-9 -]+\z')) { return $null }
  return $l
}
function vStrip([string]$s) { if ($s.EndsWith([string][char]13, [StringComparison]::Ordinal)) { return $s.Substring(0, $s.Length - 1) }; return $s }
function vSsh([string]$s) {
  $i = $s.IndexOf(' ')
  if ($i -lt 1) { return $false }
  $t = $s.Substring(0, $i)
  if (-not ($t.StartsWith('ssh-', [StringComparison]::Ordinal) -or $t.StartsWith('ecdsa-sha2-', [StringComparison]::Ordinal) -or $t.StartsWith('sk-', [StringComparison]::Ordinal))) { return $false }
  if (-not [regex]::IsMatch($t, '^[a-z0-9@.-]+\z')) { return $false }
  $r = $s.Substring($i + 1); $j = $r.IndexOf(' ')
  if ($j -lt 0) { $b = $r; $c = '' } else { $b = $r.Substring(0, $j); $c = $r.Substring($j + 1) }
  if (-not [regex]::IsMatch($b, '^[A-Za-z0-9+/]+=*\z')) { return $false }
  return (-not [regex]::IsMatch($c, $vRun))
}
function vInspect([string]$t) {
  $f = [ordered]@{ bad = 0; nonpub = 0; unterm = 0; priv = 0; orun = 0; sshbad = 0; sshl = 0; nl = 0 }
  $labels = New-Object System.Collections.Generic.List[string]
  $inpub = $false
  foreach ($line in $t.Split([char]10)) {
    $s = vStrip $line
    if (vIsBegin $s) {
      if ($inpub) { $f.unterm = 1 }
      $inpub = $false
      $l = vParse $s
      $pub = ($null -ne $l) -and ($vAllow -ccontains $l)
      if (-not $pub -and [regex]::IsMatch($s, 'PRIVATE|SECRET|KEY', 'IgnoreCase, CultureInvariant')) { $f.priv = 1 }
      if ($null -eq $l) { $f.bad = 1; continue }
      $f.nl++
      if ($labels.Count -lt 64) { $labels.Add($l) }
      if ($pub) { $inpub = $true } else { $f.nonpub = 1 }
      continue
    }
    if ($inpub) { if (vIsEnd $s) { $inpub = $false }; continue }
    if ([regex]::IsMatch($s, $vRun)) { $f.orun = 1 }
    if ($s.StartsWith('#', [StringComparison]::Ordinal) -or [regex]::IsMatch($s, '^[ \t]*\z')) { continue }
    if (vSsh $s) { $f.sshl++ } else { $f.sshbad = 1 }
  }
  if ($inpub) { $f.unterm = 1 }
  return [pscustomobject]@{ Flags = $f; Labels = $labels.ToArray() }
}
function vKeystore([byte[]]$b, [int]$n) {
  if ($n -lt 2) { return $false }
  $h = ''
  for ($k = 0; $k -lt [Math]::Min($n, 8); $k++) { $h += $b[$k].ToString('x2') }
  return ($h.StartsWith('feedfeed') -or $h.StartsWith('cececece') -or $h.StartsWith('0502') -or $h.StartsWith('0501') -or $h.StartsWith('53514c6974652066'))
}
function vHex([byte[]]$b, [int]$n) { $h = ''; for ($k = 0; $k -lt [Math]::Min($n, 8); $k++) { $h += $b[$k].ToString('x2') }; return $h }
`

// psStat describes one path: Get-Item, then psAcl.
var psStat = psPrelude + `try { $i = Get-Item -LiteralPath $a.Path -Force } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
$acl = psAcl $i.FullName
$link = psLink $i
$target = ''
if ($link) { $target = [string](@($i.Target)[0]) }
$size = 0
if (-not $i.PSIsContainer) { $size = [int64]$i.Length }
psOut ([pscustomobject]@{
  Path = $i.FullName; Size = $size; Modified = (psTime $i)
  IsDir = [bool]($i.PSIsContainer -and -not $link); IsLink = [bool]$link; Target = $target
  Owner = $acl.Owner; AclOk = $acl.Ok; Broad = $acl.Broad
})`

// psIdentify returns ONLY markers from one bounded read: size, the first
// eight bytes in hex, whether the window holds a NUL, up to 64 valid labels
// and the rule flags.
var psIdentify = psPrelude + `try { $r = vRead $a.Path ([int64]$a.Max) } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
if ($r.Error) { psOut ([pscustomobject]@{ Error = $r.Error }); exit 0 }
$nul = ([Array]::IndexOf($r.Buf, [byte]0, 0, $r.N) -ge 0)
$x = vInspect ($vL1.GetString($r.Buf, 0, $r.N))
psOut ([pscustomobject]@{ Size = $r.Size; Magic = (vHex $r.Buf $r.N); Nul = $nul; Labels = $x.Labels; Flags = $x.Flags })`

// psRead reads the buffer once, decides on it with the host-side rule (as the
// awk "decide" mode does) and only then prints base64 of THAT buffer.
var psRead = psPrelude + `try { $r = vRead $a.Path (([int64]$a.Max) + 1) } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
if ($r.Error) { psOut ([pscustomobject]@{ Error = $r.Error }); exit 0 }
if ($r.Size -gt [int64]$a.Max -or $r.N -gt [int64]$a.Max) { psOut ([pscustomobject]@{ Error = 'too_large' }); exit 0 }
$nul = ([Array]::IndexOf($r.Buf, [byte]0, 0, $r.N) -ge 0)
$f = (vInspect ($vL1.GetString($r.Buf, 0, $r.N))).Flags
$pubname = $a.Path.EndsWith('.pub', [StringComparison]::OrdinalIgnoreCase)
$ok = (-not $nul) -and (-not (vKeystore $r.Buf $r.N)) -and $f.bad -eq 0 -and $f.nonpub -eq 0 -and $f.unterm -eq 0 -and $f.priv -eq 0 -and (($f.nl -gt 0 -and $f.orun -eq 0) -or ($f.nl -eq 0 -and $pubname -and $f.sshl -gt 0 -and $f.sshbad -eq 0))
if (-not $ok) { psOut ([pscustomobject]@{ Error = 'not_public' }); exit 0 }
[Console]::Out.Write([Convert]::ToBase64String($r.Buf, 0, $r.N))`

// psReadText reads the buffer once, refuses it when it is not text, redacts
// it with the rules of RedactText and prints the result with the count.
var psReadText = psPrelude + `try { $r = vRead $a.Path (([int64]$a.Max) + 1) } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
if ($r.Error) { psOut ([pscustomobject]@{ Error = $r.Error }); exit 0 }
if ($r.Size -gt [int64]$a.Max -or $r.N -gt [int64]$a.Max) { psOut ([pscustomobject]@{ Error = 'too_large' }); exit 0 }
if (([Array]::IndexOf($r.Buf, [byte]0, 0, $r.N) -ge 0) -or (vKeystore $r.Buf $r.N)) { psOut ([pscustomobject]@{ Error = 'not_public' }); exit 0 }
$parts = ($vL1.GetString($r.Buf, 0, $r.N)).Split([char]10)
$sb = New-Object System.Text.StringBuilder
$n = 0; $drop = $false; $cnt = $parts.Length
for ($i = 0; $i -lt $cnt; $i++) {
  $line = $parts[$i]
  if ($i -eq $cnt - 1 -and $line.Length -eq 0) { break }
  $s = vStrip $line
  if ($drop) { if (vIsEnd $s) { $drop = $false }; continue }
  if (vIsBegin $s) {
    $l = vParse $s
    if ($null -eq $l -or -not ($vAllow -ccontains $l)) { $n++; if (-not (vIsEnd $s)) { $drop = $true }; continue }
  }
  $n += ([regex]::Matches($line, $vRun)).Count
  [void]$sb.Append([regex]::Replace($line, $vRun, '` + RedactedMarker + `'))
  if ($i -lt $cnt - 1) { [void]$sb.Append([char]10) }
}
psOut ([pscustomobject]@{ Redactions = $n; Data = [Convert]::ToBase64String($vL1.GetBytes($sb.ToString())) })`

// psList walks a tree itself rather than with Get-ChildItem -Recurse, so that
// a directory link or junction is reported and never entered on every
// PowerShell version, an unreadable directory is counted rather than
// silently skipped, files over the size bound are counted, and the walk stops
// at the bounds ON THE HOST. ACLs are not read here (a Get-Acl per file is too
// slow for a sweep); the sweep Stats the files it keeps.
var psList = psPrelude + `$root = [string]$a.Root
$maxDepth = [int]$a.Depth; $max = [int]$a.Max; $maxSize = [int64]$a.MaxSize; $cap = [int64]$a.ByteCap; $cross = [bool]$a.Cross
$excl = @(); if ($a.Exclude) { $excl = @($a.Exclude) }
$names = @(); if ($a.Names) { $names = @($a.Names) }
function isExcl([string]$p) {
  foreach ($e in $excl) { if ($p -ieq $e -or $p.StartsWith($e.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true } }
  return $false
}
function nameOk([string]$n) {
  if ($names.Count -eq 0) { return $true }
  foreach ($g in $names) { if ($n -like $g) { return $true } }
  return $false
}
function mkFile($c, [bool]$link) {
  $target = ''
  if ($link) { $target = [string](@($c.Target)[0]) }
  $size = 0
  if (-not $c.PSIsContainer) { $size = [int64]$c.Length }
  return [pscustomobject]@{ Path = $c.FullName; Size = $size; Modified = (psTime $c); IsLink = $link; Target = $target }
}
$files = New-Object System.Collections.Generic.List[object]
$denied = New-Object System.Collections.Generic.List[string]
$deniedCount = 0; $unreadable = 0; $oversize = 0; $trunc = $false; $bytes = 0
try { $ri = Get-Item -LiteralPath $root -Force } catch { psOut ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
$rootVol = [System.IO.Path]::GetPathRoot($ri.FullName)
if (-not $ri.PSIsContainer -or (psLink $ri)) {
  if (nameOk $ri.Name) {
    if ((psLink $ri) -or $ri.Length -le $maxSize) { $files.Add((mkFile $ri (psLink $ri))) } else { $oversize++ }
  }
} else {
  $stack = New-Object System.Collections.Generic.Stack[object]
  $stack.Push(@($ri.FullName, 0))
  while ($stack.Count -gt 0 -and -not $trunc) {
    $item = $stack.Pop(); $dir = [string]$item[0]; $depth = [int]$item[1]
    try { $children = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) } catch {
      if ((psErr $_.Exception) -eq 'denied') {
        $deniedCount++
        if ($denied.Count -lt 100) { $denied.Add($dir) }
      } else { $unreadable++ }
      continue
    }
    foreach ($c in $children) {
      try {
        if (isExcl $c.FullName) { continue }
        $link = psLink $c
        if ($c.PSIsContainer -and -not $link) {
          if ($depth -lt $maxDepth -and ($cross -or [System.IO.Path]::GetPathRoot($c.FullName) -ieq $rootVol)) { $stack.Push(@($c.FullName, ($depth + 1))) }
          continue
        }
        if (-not (nameOk $c.Name)) { continue }
        if (-not $link -and $c.Length -gt $maxSize) { $oversize++; continue }
        if ($files.Count -ge $max -or $bytes -ge $cap) { $trunc = $true; break }
        $o = mkFile $c $link
        $files.Add($o)
        $bytes += $o.Path.Length + $o.Target.Length + 120
      } catch { $unreadable++ }
    }
  }
}
psOut ([pscustomobject]@{ Files = $files.ToArray(); Denied = $denied.ToArray(); DeniedCount = $deniedCount; Unreadable = $unreadable; OverSize = $oversize; Truncated = $trunc })`

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

// psRun runs a script and returns its stdout with any byte-order mark and
// surrounding space removed. A non-zero exit is an error: every script here
// reports its own failures as JSON and exits 0.
func (t *RemoteWindowsTarget) psRun(ctx context.Context, script string, args any) ([]byte, error) {
	full, err := psScript(script, args)
	if err != nil {
		return nil, err
	}
	var out []byte
	var exit int
	if ir, ok := t.runner.(hostinventory.InputRunner); ok {
		out, _, exit, err = ir.RunInput(ctx, psStdinArgv, psStdin(full))
	} else {
		argv, aerr := psArgv(full)
		if aerr != nil {
			return nil, aerr
		}
		out, _, exit, err = t.runner.Run(ctx, argv)
	}
	if err != nil {
		return nil, err
	}
	if exit != 0 {
		return nil, fmt.Errorf("hostcrypto: powershell exited %d", exit)
	}
	return []byte(strings.TrimSpace(strings.TrimPrefix(string(out), "\ufeff"))), nil
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
	}
	return fmt.Errorf("hostcrypto: %s: could not be read", path)
}

type psPathArgs struct {
	Path string `json:"Path"`
	Max  int64  `json:"Max,omitempty"`
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
	out, err := t.psRun(ctx, psStat, psPathArgs{Path: path})
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
	Labels json.RawMessage `json:"Labels"`
	Flags  *psFlags        `json:"Flags"`
}

// identify runs psIdentify and returns the host's inspection. A field the
// host did not return is an error, never a default that could make a file
// public.
func (t *RemoteWindowsTarget) identify(ctx context.Context, path string) (inspection, error) {
	out, err := t.psRun(ctx, psIdentify, psPathArgs{Path: path, Max: t.maxBytes})
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
	if r.Size == nil || r.Nul == nil || f == nil || f.Bad == nil || f.NonPub == nil || f.Unterm == nil ||
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
	out, err := t.psRun(ctx, psRead, psPathArgs{Path: path, Max: readCap})
	if err != nil {
		return nil, err
	}
	if len(out) > 0 && out[0] == '{' {
		return nil, psJSONError(path, out)
	}
	b, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		return nil, fmt.Errorf("hostcrypto: read %s: unreadable answer", path)
	}
	return recheckPublic(path, b, readCap)
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

// ReadText returns a configuration file redacted on the host by psReadText,
// checked here as on Unix (see [RemoteUnixTarget.ReadText]).
func (t *RemoteWindowsTarget) ReadText(ctx context.Context, path string) ([]byte, int, error) {
	out, err := t.psRun(ctx, psReadText, psPathArgs{Path: path, Max: t.readCap()})
	if err != nil {
		return nil, 0, err
	}
	var r struct {
		Error      string `json:"Error"`
		Redactions *int   `json:"Redactions"`
		Data       string `json:"Data"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, 0, fmt.Errorf("hostcrypto: read text %s: unreadable answer", path)
	}
	if r.Error != "" {
		return nil, 0, psError(path, r.Error)
	}
	if r.Redactions == nil || *r.Redactions < 0 {
		return nil, 0, fmt.Errorf("hostcrypto: read text %s: the host did not report its redactions", path)
	}
	b, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		return nil, 0, fmt.Errorf("hostcrypto: read text %s: unreadable answer", path)
	}
	return checkRedacted(path, b, *r.Redactions)
}

type psListArgs struct {
	Root    string   `json:"Root"`
	Depth   int      `json:"Depth"`
	Max     int      `json:"Max"`
	MaxSize int64    `json:"MaxSize"`
	ByteCap int      `json:"ByteCap"`
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
		Exclude: nonNil(opts.Exclude), Names: nonNil(opts.Names),
	}
	out, err := t.psRun(ctx, psList, args)
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
