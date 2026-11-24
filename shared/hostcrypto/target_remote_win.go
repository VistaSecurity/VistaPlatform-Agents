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
	"strings"
	"time"
	"unicode/utf16"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// RemoteWindowsTarget is a Windows host reached through a
// [hostinventory.Runner], running PowerShell as host inventory does: every
// script goes as `powershell -NoProfile -NonInteractive -EncodedCommand
// <base64>`, the one form that survives both cmd.exe and a POSIX shell on the
// far side unquoted.
//
// Paths are never script text. Host inventory's scripts are constants with
// nothing to pass; these need a path, and -EncodedCommand carries no argument
// vector. So the arguments are put in a JSON object, the object is base64
// encoded, and the script decodes it into $a:
//
//	$a = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64>')) | ConvertFrom-Json
//
// Base64's alphabet holds no quote, so the literal cannot end early whatever
// the path is: a file called `'; Remove-Item C:\ -Recurse; '` is decoded as
// data and handed to -LiteralPath, which does not expand wildcards either.
type RemoteWindowsTarget struct {
	runner hostinventory.Runner
}

// NewRemoteWindowsTarget wraps r for a Windows host.
func NewRemoteWindowsTarget(r hostinventory.Runner) *RemoteWindowsTarget {
	return &RemoteWindowsTarget{runner: r}
}

// Run passes argv to the runner unchanged.
func (t *RemoteWindowsTarget) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return t.runner.Run(ctx, argv)
}

// Local is false: bytes read here cross a connection.
func (t *RemoteWindowsTarget) Local() bool { return false }

// psPrelude decodes the arguments and defines the helpers every script uses:
// psErr turns an exception into "not_found", "denied" or "other" (unwrapping
// the MethodInvocationException PowerShell puts round a .NET call), and
// psAcl projects Get-Acl onto the owner and ONE boolean worked out on the
// host: whether Everyone (S-1-1-0), BUILTIN\Users (S-1-5-32-545) or
// Authenticated Users (S-1-5-11) may read the file. No ACL entry crosses the
// connection.
const psPrelude = `$ErrorActionPreference='Stop'
$a = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%ARGS%')) | ConvertFrom-Json
function psErr($e) {
  while ($e -is [System.Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
  if ($e -is [System.Management.Automation.ItemNotFoundException] -or $e -is [System.IO.FileNotFoundException] -or $e -is [System.IO.DirectoryNotFoundException]) { return 'not_found' }
  if ($e -is [System.UnauthorizedAccessException] -or $e -is [System.Security.SecurityException]) { return 'denied' }
  return 'other'
}
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
`

// psStat describes one path: Get-Item, then psAcl.
const psStat = psPrelude + `try { $i = Get-Item -LiteralPath $a.Path -Force } catch { ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
$acl = psAcl $i.FullName
$link = psLink $i
$target = ''
if ($link) { $target = [string](@($i.Target)[0]) }
$size = 0
if (-not $i.PSIsContainer) { $size = [int64]$i.Length }
ConvertTo-Json -Compress -InputObject ([pscustomobject]@{
  Path = $i.FullName; Size = $size; Modified = (psTime $i)
  IsDir = [bool]($i.PSIsContainer -and -not $link); IsLink = [bool]$link; Target = $target
  Owner = $acl.Owner; AclOk = $acl.Ok; Broad = $acl.Broad
})`

// psIdentify returns ONLY markers: the first eight bytes in hex, whether a
// private header exists anywhere, and at most 64 label strings. The patterns
// are ScanPEMLabels's and hasPrivateMarker's.
const psIdentify = psPrelude + `try { $i = Get-Item -LiteralPath $a.Path -Force } catch { ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
if ($i.PSIsContainer) { ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Error = 'directory' }); exit 0 }
try {
  $fs = [System.IO.File]::Open($i.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try { $buf = New-Object byte[] 8; $n = $fs.Read($buf, 0, 8) } finally { $fs.Close() }
  $hex = ''
  for ($k = 0; $k -lt $n; $k++) { $hex += $buf[$k].ToString('x2') }
  $labels = @(Select-String -LiteralPath $i.FullName -Pattern '` + remotePEMPattern + `' -AllMatches -CaseSensitive |
    ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Select-Object -First 64)
  $priv = [bool](Select-String -LiteralPath $i.FullName -Pattern '` + remotePrivatePattern + `' -Quiet)
} catch { ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Magic = $hex; Private = $priv; Labels = $labels })`

// psList walks a tree itself rather than with Get-ChildItem -Recurse, so that
// a directory link or junction is reported and never entered on every
// PowerShell version, an unreadable directory is counted rather than
// silently skipped, and the walk stops at the bounds ON THE HOST. ACLs are not
// read here (a Get-Acl per file is too slow for a sweep); Stat the files you
// keep.
const psList = psPrelude + `$root = [string]$a.Root
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
$files = New-Object System.Collections.Generic.List[object]
$denied = New-Object System.Collections.Generic.List[string]
$deniedCount = 0; $trunc = $false; $bytes = 0
function mkFile($c, [bool]$link) {
  $target = ''
  if ($link) { $target = [string](@($c.Target)[0]) }
  $size = 0
  if (-not $c.PSIsContainer) { $size = [int64]$c.Length }
  return [pscustomobject]@{ Path = $c.FullName; Size = $size; Modified = (psTime $c); IsLink = $link; Target = $target }
}
try { $ri = Get-Item -LiteralPath $root -Force } catch { ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Error = (psErr $_.Exception) }); exit 0 }
$rootVol = [System.IO.Path]::GetPathRoot($ri.FullName)
if (-not $ri.PSIsContainer -or (psLink $ri)) {
  if ((nameOk $ri.Name) -and ((psLink $ri) -or $ri.Length -le $maxSize)) { $files.Add((mkFile $ri (psLink $ri))) }
} else {
  $stack = New-Object System.Collections.Generic.Stack[object]
  $stack.Push(@($ri.FullName, 0))
  while ($stack.Count -gt 0 -and -not $trunc) {
    $item = $stack.Pop(); $dir = [string]$item[0]; $depth = [int]$item[1]
    try { $children = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) } catch {
      $deniedCount++
      if ($denied.Count -lt 100) { $denied.Add($dir) }
      continue
    }
    foreach ($c in $children) {
      if (isExcl $c.FullName) { continue }
      $link = psLink $c
      if ($c.PSIsContainer -and -not $link) {
        if ($depth -lt $maxDepth -and ($cross -or [System.IO.Path]::GetPathRoot($c.FullName) -ieq $rootVol)) { $stack.Push(@($c.FullName, ($depth + 1))) }
        continue
      }
      if (-not (nameOk $c.Name)) { continue }
      if (-not $link -and $c.Length -gt $maxSize) { continue }
      if ($files.Count -ge $max -or $bytes -ge $cap) { $trunc = $true; break }
      $o = mkFile $c $link
      $files.Add($o)
      $bytes += $o.Path.Length + $o.Target.Length + 120
    }
  }
}
ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{ Files = $files.ToArray(); Denied = $denied.ToArray(); DeniedCount = $deniedCount; Truncated = $trunc })`

// psRead returns a file as base64, after the Go side has identified it as
// public. An error is a JSON object, which base64 can never start with.
const psRead = psPrelude + `try {
  $i = Get-Item -LiteralPath $a.Path -Force
  if ($i.PSIsContainer) { ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Error = 'directory' }); exit 0 }
  if ($i.Length -gt [int64]$a.Max) { ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Error = 'too_large' }); exit 0 }
  [Console]::Out.Write([Convert]::ToBase64String([System.IO.File]::ReadAllBytes($i.FullName)))
} catch { ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ Error = (psErr $_.Exception) }) }`

// remoteWindowsReadMax is the largest file the Windows target returns. Base64
// makes four characters of three bytes, and the runner refuses more than
// 8 MiB of output, so 6,000,000 bytes is the most that fits.
const remoteWindowsReadMax = 6000000

// base64Alphabet is what may be substituted into a script. It is checked,
// not assumed, so a future change to the encoding cannot open the literal.
var base64Alphabet = regexp.MustCompile(`^[A-Za-z0-9+/=]*$`)

// psArgv builds the PowerShell invocation of script with args as its $a.
func psArgv(script string, args any) ([]string, error) {
	j, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(j)
	if !base64Alphabet.MatchString(b64) {
		return nil, errors.New("hostcrypto: argument encoding produced unsafe characters")
	}
	if strings.Count(script, "%ARGS%") != 1 {
		return nil, errors.New("hostcrypto: script has no single argument slot")
	}
	full := strings.Replace(script, "%ARGS%", b64, 1)
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", psEncode(full)}, nil
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
	argv, err := psArgv(script, args)
	if err != nil {
		return nil, err
	}
	out, _, exit, err := t.runner.Run(ctx, argv)
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

type psIdentifyResult struct {
	Error   string          `json:"Error"`
	Magic   string          `json:"Magic"`
	Private *bool           `json:"Private"`
	Labels  json.RawMessage `json:"Labels"`
}

// Identify runs psIdentify and classifies what it returns. An answer without
// the private flag is treated as "private present".
func (t *RemoteWindowsTarget) Identify(ctx context.Context, path string) (Identity, error) {
	out, err := t.psRun(ctx, psIdentify, psPathArgs{Path: path})
	if err != nil {
		return Identity{}, err
	}
	var r psIdentifyResult
	if err := json.Unmarshal(out, &r); err != nil {
		return Identity{}, fmt.Errorf("hostcrypto: identify %s: unreadable answer", path)
	}
	if r.Error != "" {
		return Identity{}, psError(path, r.Error)
	}
	magic, err := hex.DecodeString(r.Magic)
	if err != nil || len(magic) > MagicBytes {
		return Identity{}, fmt.Errorf("hostcrypto: identify %s: unreadable magic", path)
	}
	var raw []string
	if len(r.Labels) > 0 && string(r.Labels) != "null" {
		if err := json.Unmarshal(r.Labels, &raw); err != nil {
			// PowerShell 5.1 renders a one-element array as a bare string.
			var one string
			if err2 := json.Unmarshal(r.Labels, &one); err2 != nil {
				return Identity{}, fmt.Errorf("hostcrypto: identify %s: unreadable labels", path)
			}
			raw = []string{one}
		}
	}
	var labels []string
	for _, l := range raw {
		if len(labels) >= maxPEMLabels {
			break
		}
		if found := ScanPEMLabels([]byte(l), 1); len(found) == 1 {
			labels = append(labels, found[0])
		}
	}
	private := r.Private == nil || *r.Private
	return identityFrom(path, magic, labels, private), nil
}

// ReadFile identifies path first and refuses, with [ErrNotPublic], anything
// not identified as public; on refusal no script that returns content is run.
// The bytes that arrive are identified again, as on Unix (see
// [RemoteUnixTarget.ReadFile]).
//
// The host's OpenSSH shell is cmd.exe, so the runner's own ReadFile (`cat`)
// does not apply; the file comes back base64 encoded, at most 6,000,000 bytes.
func (t *RemoteWindowsTarget) ReadFile(ctx context.Context, path string) ([]byte, error) {
	id, err := t.Identify(ctx, path)
	if err != nil {
		return nil, err
	}
	if !id.Public() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotPublic)
	}
	out, err := t.psRun(ctx, psRead, psPathArgs{Path: path, Max: remoteWindowsReadMax})
	if err != nil {
		return nil, err
	}
	if len(out) > 0 && out[0] == '{' {
		var r struct {
			Error string `json:"Error"`
		}
		if json.Unmarshal(out, &r) == nil && r.Error != "" {
			return nil, psError(path, r.Error)
		}
		return nil, fmt.Errorf("hostcrypto: read %s: unreadable answer", path)
	}
	b, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		return nil, fmt.Errorf("hostcrypto: read %s: unreadable answer", path)
	}
	return recheckPublic(path, b)
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
	Truncated   bool            `json:"Truncated"`
}

// List runs psList. The walk and every bound run on the host; the answer is
// sorted by path here so it does not depend on the host's traversal order.
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
	sort.Slice(infos, func(i, j int) bool { return infos[i].Path < infos[j].Path })
	lerr := &ListError{Truncated: r.Truncated, DeniedCount: r.DeniedCount}
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
// object (one element), null or nothing.
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
