package hostcrypto

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// Pass 3, the running system: listening sockets, the processes that own
// them, the crypto libraries those processes have loaded, and the key,
// certificate and keystore files they hold open or name on their command
// line. What it adds:
//
//   - UsedBy on the items passes 1 and 2 already found: a "process" usage
//     (the executable's name) and one "listener" usage per socket the
//     process listens on. Process ids are not kept: they mean nothing once
//     the process is gone.
//   - LoadedBy on the libraries, and a "process"-sourced library for one no
//     other step found.
//   - Paths no other pass found, identified and recorded with FoundBy
//     "process".
//
// # Command lines and environments are not collected
//
// A command line carries secrets (--password=..., a token in a URL) and an
// environment more so. The environment is never read. A command line is
// read ON THE HOST by a filter (platArgsAwk, or its PowerShell twin) that
// prints only the absolute paths in it that end in a crypto file extension,
// and skips every argument whose option name says it is a secret; Go checks
// each path again (platArgPath) before it is used. So a command line never
// crosses the connection, and nothing of one reaches the Report but a path.
//
// # Rights
//
// Another user's process can be attributed only by root or SYSTEM. Without
// them the section says partial and how many processes it could not look
// at.

// platMaxProcesses bounds the processes pass 3 describes.
const platMaxProcesses = 512

// platCryptoExts are the extensions of the files pass 3 follows.
var platCryptoExts = []string{"pem", "crt", "cer", "der", "key", "p12", "pfx", "jks", "jceks", "bcfks", "bks", "keystore", "truststore", "kdb", "p8", "pk8", "keytab", "kt", "ppk"}

// platSecretOption matches an option name that introduces a secret. An
// argument "<name>=<value>" with such a name is skipped whole.
var platSecretOption = regexp.MustCompile(`(?i)(pass|secret|pin|token|cred|pwd)`)

// platArgsAwk filters lines "M <path>", "F <path>" and "A <argument>" on the
// host: M is kept when the path's base name is a crypto library's, F when
// the path ends in a crypto extension, and A is split on '=', ',' and ';'
// and each absolute part ending in a crypto extension is printed as "A
// <path>"; an A whose option name (before '=') names a secret prints
// nothing. Nothing else is printed.
var platArgsAwk = `function extok(p,  l) { l = tolower(p); return l ~ /\.(` + strings.Join(platCryptoExts, "|") + `)$/ }
function libok(p,  b) { b = p; sub(/.*\//, "", b); b = tolower(b)
  return b ~ /^(libssl|libcrypto|libgnutls|libnss3|libsoftokn3|libfreebl3|libfreeblpriv3|libgcrypt|libwolfssl|libmbedtls|libmbedcrypto|libmbedx509|libboringssl|libtls)[.-]/ || b ~ /^fips\.(so|dylib)$/ || b ~ /^(bcprov|bc-fips).*\.jar$/ }
function clean(p) { return p !~ /[ \t"<>|]/ && index(p, "\047") == 0 }
{
  t = substr($0, 1, 2); v = substr($0, 3)
  if (t == "M ") { if (substr(v, 1, 1) == "/" && libok(v)) print "M " v; next }
  if (t == "F ") { if (substr(v, 1, 1) == "/" && extok(v)) print "F " v; next }
  if (t == "A ") {
    e = index(v, "=")
    if (e > 0 && tolower(substr(v, 1, e - 1)) ~ /(pass|secret|pin|token|cred|pwd)/) next
    n = split(v, part, /[=,;]/)
    for (i = 1; i <= n; i++) if (substr(part[i], 1, 1) == "/" && extok(part[i]) && clean(part[i])) print "A " part[i]
  }
}`

// platLinuxRunningScript is pass 3 on Linux, through /proc:
//
//	U <uid>                          the collecting account
//	L <tcp|udp> <inode> <hexaddr:hexport>   a listening socket (/proc/net)
//	P <pid> <name>                   a process holding a listening socket
//	S <inode>                        a listening socket it holds
//	M <path>                         a crypto library it has mapped
//	F <path>                         a crypto file it holds open
//	A <path>                         a crypto path on its command line
//	D <pid>                          a process whose descriptors are refused
//	T                                the process bound stopped the walk
//
// /proc/net lists only LISTEN TCP and unconnected UDP sockets: established
// connections (other hosts' addresses) are filtered out on the host. Only a
// process that holds a listening socket is described.
var platLinuxRunningScript = platWithAwk(`me=$$
printf 'U %s\n' "$(id -u)"
li=$( { for f in /proc/net/tcp /proc/net/tcp6; do [ -r "$f" ] && awk -v t=tcp 'NR > 1 && $4 == "0A" { print t, $10, $2 }' "$f"; done
        for f in /proc/net/udp /proc/net/udp6; do [ -r "$f" ] && awk -v t=udp 'NR > 1 && $4 == "07" && $3 ~ /:0000$/ { print t, $10, $2 }' "$f"; done; } )
printf '%s\n' "$li" | awk 'NF == 3 { print "L", $1, $2, $3 }'
inodes=" $(printf '%s\n' "$li" | awk 'NF == 3 && $2 != "0" { printf "%s ", $2 }')"
n=0
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  [ "$p" = "$me" ] && continue
  o=$(ls -l "$d/fd" 2>/dev/null) || { [ -d "$d" ] && echo "D $p"; continue; }
  s=$(printf '%s\n' "$o" | awk -v li="$inodes" '{ i = index($0, " -> socket:["); if (i) { x = substr($0, i + 12); sub(/\].*/, "", x); if (index(li, " " x " ")) print x } }')
  [ -n "$s" ] || continue
  n=$((n + 1))
  if [ "$n" -gt ` + strconv.Itoa(platMaxProcesses) + ` ]; then echo T; break; fi
  e=$(readlink "$d/exe" 2>/dev/null); e=${e%% (deleted)}; e=${e##*/}
  [ -n "$e" ] || e=$(cat "$d/comm" 2>/dev/null)
  printf 'P %s %s\n' "$p" "$e"
  printf '%s\n' "$s" | sed 's/^/S /'
  { printf '%s\n' "$o" | awk '{ i = index($0, " -> /"); if (i) print "F " substr($0, i + 4) }'
    [ -r "$d/maps" ] && awk 'NF >= 6 { x = $6; for (j = 7; j <= NF; j++) x = x " " $j; print "M " x }' "$d/maps" 2>/dev/null | sort -u
    [ -r "$d/cmdline" ] && tr '\000' '\n' < "$d/cmdline" | sed 's/^/A /'
  } | awk 'PLAT_ARGS_AWK'
done
exit 0`)

// platDarwinRunningScript is pass 3 on macOS, through lsof and ps, with the
// lines of platLinuxRunningScript plus
//
//	N <tcp|udp> <address:port>       a socket the current P listens on
//
// lsof's names are filtered on the host as Linux's are; ps prints the
// command line into the same host-side filter.
var platDarwinRunningScript = platWithAwk(`printf 'U %s\n' "$(id -u)"
command -v lsof >/dev/null 2>&1 || exit 127
pids=$( { lsof -nP -iTCP -sTCP:LISTEN -FpcPn 2>/dev/null; lsof -nP -iUDP -FpcPn 2>/dev/null; } | awk '
  /^p/ { pid = substr($0, 2); next }
  /^c/ { cmd[pid] = substr($0, 2); next }
  /^P/ { proto = tolower(substr($0, 2)); next }
  /^n/ { x = substr($0, 2); if (index(x, "->")) next; if (!(pid in seen)) { seen[pid] = 1; order[++m] = pid }; lines[pid] = lines[pid] "N " proto " " x "\n"; next }
  END { for (i = 1; i <= m && i <= ` + strconv.Itoa(platMaxProcesses) + `; i++) { k = order[i]; printf "P %s %s\n%s", k, cmd[k], lines[k] } ; if (m > ` + strconv.Itoa(platMaxProcesses) + `) print "T" }')
printf '%s\n' "$pids"
for p in $(printf '%s\n' "$pids" | awk '$1 == "P" { print $2 }'); do
  printf 'P %s\n' "$p"
  { lsof -nP -p "$p" -Ffn 2>/dev/null | awk '/^f/ { fd = substr($0, 2); next } /^n\// { x = substr($0, 2); if (fd == "txt") print "M " x; else print "F " x }'
    ps -ww -o args= -p "$p" 2>/dev/null | tr ' ' '\n' | sed 's/^/A /'
  } | awk 'PLAT_ARGS_AWK'
done
exit 0`)

// platWithAwk splices platArgsAwk into a script's one PLAT_ARGS_AWK, in
// single quotes (platArgsAwk holds none).
func platWithAwk(script string) string {
	if strings.Count(script, "PLAT_ARGS_AWK") != 1 || strings.Contains(platArgsAwk, "'") {
		panic("hostcrypto: platWithAwk: bad template")
	}
	return strings.Replace(script, "PLAT_ARGS_AWK", platArgsAwk, 1)
}

// platProc is one process holding a listening socket.
type platProc struct {
	pid       string
	name      string
	listeners []Usage
	libs      []string
	files     []string
	args      []string
}

// platRunning is what one pass-3 listing amounts to.
type platRunning struct {
	uid       string
	elevated  *bool
	procs     []*platProc
	denied    int
	truncated bool
	// unowned is how many listening sockets no visible process holds.
	unowned int
}

// platParseUnixRunning parses the Linux or macOS listing.
func platParseUnixRunning(b []byte) platRunning {
	var r platRunning
	listen := map[string]Usage{}
	byPID := map[string]*platProc{}
	var cur *platProc
	owned := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if len(line) < 1 {
			continue
		}
		kind, rest, _ := strings.Cut(line, " ")
		switch kind {
		case "U":
			r.uid = strings.TrimSpace(rest)
			e := r.uid == "0"
			r.elevated = &e
		case "L":
			f := strings.Fields(rest)
			if len(f) != 3 {
				continue
			}
			if addr, port, ok := platProcNetAddr(f[2]); ok {
				listen[f[1]] = platListener("", addr, port, f[0])
			}
		case "P":
			pid, name, _ := strings.Cut(rest, " ")
			if _, err := strconv.Atoi(pid); err != nil {
				cur = nil
				continue
			}
			if p, ok := byPID[pid]; ok {
				cur = p
				continue
			}
			if len(r.procs) >= platMaxProcesses {
				r.truncated = true
				cur = nil
				continue
			}
			cur = &platProc{pid: pid, name: platProcName(name)}
			byPID[pid] = cur
			r.procs = append(r.procs, cur)
		case "S":
			if cur == nil {
				continue
			}
			ino := strings.TrimSpace(rest)
			if u, ok := listen[ino]; ok {
				u.Process, u.Product = cur.name, cur.name
				cur.listeners = append(cur.listeners, u)
				owned[ino] = true
			}
		case "N":
			if cur == nil {
				continue
			}
			f := strings.Fields(rest)
			if len(f) != 2 || (f[0] != "tcp" && f[0] != "udp") {
				continue
			}
			if addr, port, ok := platLsofAddr(f[1]); ok {
				cur.listeners = append(cur.listeners, platListener(cur.name, addr, port, f[0]))
			}
		case "M":
			if cur != nil && platAbsPath(rest, false) {
				if n, _, _ := platLibraryFile(rest); n != "" && len(cur.libs) < 256 {
					cur.libs = append(cur.libs, rest)
				}
			}
		case "F":
			if cur != nil && platCryptoPath(rest, false) && len(cur.files) < 256 {
				cur.files = append(cur.files, rest)
			}
		case "A":
			if cur != nil {
				if p, ok := platArgPath(rest, false); ok && len(cur.args) < 256 {
					cur.args = append(cur.args, p)
				}
			}
		case "D":
			r.denied++
		case "T":
			r.truncated = true
		}
	}
	for ino := range listen {
		if !owned[ino] {
			r.unowned++
		}
	}
	// On macOS the listeners are named directly (N), so none is unowned.
	return r
}

// platListener is a "listener" usage: the process, and its socket. Product
// is the process (what uses the item) and Context the port it listens on,
// as a configuration usage names its product and server block.
func platListener(process, addr string, port int, transport string) Usage {
	return Usage{Kind: "listener", Process: process, Product: process, Address: addr, Port: port, Transport: transport, Context: strconv.Itoa(port)}
}

// platProcName keeps a process name: printable, one line, short.
func platProcName(s string) string {
	s = strings.TrimSpace(s)
	if !platPrintableUTF8(s) {
		return ""
	}
	return platCap(s, 64)
}

// platCryptoPath reports whether p is an absolute path ending in a crypto
// file extension.
func platCryptoPath(p string, windows bool) bool {
	if !platAbsPath(p, windows) {
		return false
	}
	l := strings.ToLower(p)
	for _, e := range platCryptoExts {
		if strings.HasSuffix(l, "."+e) {
			return true
		}
	}
	return false
}

// platArgPath is Go's own check of a path the host filter printed from a
// command line: one absolute crypto path, no '=' (so no "option=value"
// passed through whole), no quote or blank, and no secret option name
// anywhere in it.
func platArgPath(p string, windows bool) (string, bool) {
	if !platCryptoPath(p, windows) || strings.ContainsAny(p, "=,;\"'<>| \t") || platSecretOption.MatchString(p) {
		return "", false
	}
	return p, true
}

// platProcNetAddr decodes /proc/net's "0100007F:1F90" (IPv4, each 32-bit
// word in host order, little-endian on every architecture Linux runs this
// on) or its 32-digit IPv6 form, and the big-endian port.
func platProcNetAddr(s string) (string, int, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return ip.String(), int(port), true
}

// platLsofAddr parses lsof's "*:7000", "127.0.0.1:631" or "[::1]:631".
func platLsofAddr(s string) (string, int, bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	addr := strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]")
	if addr == "*" {
		return "*", port, true
	}
	if net.ParseIP(addr) == nil {
		return "", 0, false
	}
	return addr, port, true
}

// platPSRunning is pass 3 on Windows: the listening TCP connections and UDP
// endpoints with their owning process, each process's name and the crypto
// libraries among its modules, and the crypto paths of its command line,
// filtered by the same rules as platArgsAwk before anything is printed (the
// command line itself is never printed). Windows has no built-in list of a
// process's open files, so there are no F entries.
var platPSRunning = `$rnL = New-Object 'System.Collections.Generic.List[object]'
$rnErr = ''
try { foreach ($rnC in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) { [void]$rnL.Add([pscustomobject]@{ Proto = 'tcp'; Addr = [string]$rnC.LocalAddress; Port = [int]$rnC.LocalPort; Id = [int]$rnC.OwningProcess }) } } catch { $rnErr = (plErr $_.Exception) }
try { foreach ($rnC in @(Get-NetUDPEndpoint -ErrorAction Stop)) { [void]$rnL.Add([pscustomobject]@{ Proto = 'udp'; Addr = [string]$rnC.LocalAddress; Port = [int]$rnC.LocalPort; Id = [int]$rnC.OwningProcess }) } } catch { $rnUdpErr = (plErr $_.Exception) }
$rnLibRx = [regex]::new('^(?:(?:libcrypto|libssl)(?:-[0-9_]+)?(?:-x64|-arm64)?\.dll|libeay32\.dll|ssleay32\.dll|libgnutls(?:-[0-9]+)?\.dll|nss3\.dll|softokn3\.dll|libgcrypt(?:-[0-9]+)?\.dll|wolfssl\.dll|mbedcrypto\.dll|mbedtls\.dll|fips\.dll|schannel\.dll)\z', 'IgnoreCase, CultureInvariant')
$rnTokRx = [regex]::new('(?:[^\s"]+|"[^"]*")+')
$rnSecRx = [regex]::new('(pass|secret|pin|token|cred|pwd)', 'IgnoreCase, CultureInvariant')
$rnPathRx = [regex]::new('^(?:[A-Za-z]:\\|\\\\)[^"<>|*?\r\n\t ]*\.(?:` + strings.Join(platCryptoExts, "|") + `)\z', 'IgnoreCase, CultureInvariant')
$rnCmd = New-Object 'System.Collections.Generic.Dictionary[int,string]'
try { foreach ($rnW in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) { if ($null -ne $rnW.CommandLine) { $rnCmd[[int]$rnW.ProcessId] = [string]$rnW.CommandLine } } } catch { $rnCmdErr = (plErr $_.Exception) }
$rnIds = New-Object 'System.Collections.Generic.List[int]'
$rnSeen = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($rnE in $rnL) { if ($rnE.Id -gt 4 -and $rnSeen.Add($rnE.Id)) { [void]$rnIds.Add($rnE.Id) } }
$rnProcs = New-Object 'System.Collections.Generic.List[object]'
$rnTrunc = $false
foreach ($rnId in $rnIds) {
  if ($rnProcs.Count -ge [int]$a.Max) { $rnTrunc = $true; break }
  $rnName = ''
  $rnDenied = $false
  $rnMods = New-Object 'System.Collections.Generic.List[string]'
  try {
    $rnP = Get-Process -Id $rnId -ErrorAction Stop
    $rnName = [string]$rnP.ProcessName
    try { foreach ($rnM in @($rnP.Modules)) { $rnF = [string]$rnM.FileName; if ($rnF -and $rnLibRx.IsMatch([System.IO.Path]::GetFileName($rnF))) { [void]$rnMods.Add($rnF) } } } catch { $rnDenied = $true }
  } catch { $rnDenied = $true }
  $rnArgs = New-Object 'System.Collections.Generic.List[string]'
  if ($rnCmd.ContainsKey($rnId)) {
    foreach ($rnT in $rnTokRx.Matches($rnCmd[$rnId])) {
      $rnTok = $rnT.Value.Replace([string][char]34, '')
      $rnEq = $rnTok.IndexOf([char]61)
      if ($rnEq -gt 0 -and $rnSecRx.IsMatch($rnTok.Substring(0, $rnEq))) { continue }
      foreach ($rnPart in $rnTok.Split([char[]]@([char]61, [char]44, [char]59))) { if ($rnPathRx.IsMatch($rnPart) -and $rnArgs.Count -lt 256) { [void]$rnArgs.Add($rnPart) } }
    }
  }
  [void]$rnProcs.Add([pscustomobject]@{ Id = $rnId; Name = $rnName; Denied = $rnDenied; Libs = $rnMods.ToArray(); Args = $rnArgs.ToArray() })
}
plOut ([pscustomobject]@{ Elevated = (plElevated); Error = $rnErr; Listeners = $rnL.ToArray(); Procs = $rnProcs.ToArray(); Truncated = $rnTrunc })
`

type platWinListener struct {
	Proto string `json:"Proto"`
	Addr  string `json:"Addr"`
	Port  int    `json:"Port"`
	ID    int    `json:"Id"`
}

type platWinProc struct {
	ID     int             `json:"Id"`
	Name   string          `json:"Name"`
	Denied bool            `json:"Denied"`
	Libs   json.RawMessage `json:"Libs"`
	Args   json.RawMessage `json:"Args"`
}

type platWinRunningAnswer struct {
	Elevated  *bool           `json:"Elevated"`
	Error     string          `json:"Error"`
	Listeners json.RawMessage `json:"Listeners"`
	Procs     json.RawMessage `json:"Procs"`
	Truncated bool            `json:"Truncated"`
}

// platParseWindowsRunning parses platPSRunning's answer.
func platParseWindowsRunning(b []byte) (platRunning, error) {
	var r platRunning
	var ans platWinRunningAnswer
	if err := json.Unmarshal(b, &ans); err != nil {
		return r, errors.New("hostcrypto: unreadable process answer")
	}
	if err := platPSError("listening sockets", ans.Error); err != nil {
		return r, err
	}
	r.elevated = ans.Elevated
	r.truncated = ans.Truncated
	listeners, err := psArray[platWinListener](ans.Listeners)
	if err != nil {
		return r, errors.New("hostcrypto: unreadable process answer")
	}
	procs, err := psArray[platWinProc](ans.Procs)
	if err != nil {
		return r, errors.New("hostcrypto: unreadable process answer")
	}
	byID := map[int]*platProc{}
	for _, wp := range procs {
		if len(r.procs) >= platMaxProcesses {
			r.truncated = true
			break
		}
		p := &platProc{pid: strconv.Itoa(wp.ID), name: platProcName(wp.Name)}
		if wp.Denied {
			r.denied++
		}
		libs, _ := psArray[string](wp.Libs)
		for _, l := range libs {
			if n, _, _ := platLibraryFile(l); n != "" && platAbsPath(l, true) && len(p.libs) < 256 {
				p.libs = append(p.libs, l)
			}
		}
		args, _ := psArray[string](wp.Args)
		for _, a := range args {
			if v, ok := platArgPath(a, true); ok && len(p.args) < 256 {
				p.args = append(p.args, v)
			}
		}
		byID[wp.ID] = p
		r.procs = append(r.procs, p)
	}
	for _, l := range listeners {
		if l.Proto != "tcp" && l.Proto != "udp" || l.Port <= 0 || l.Port > 65535 {
			continue
		}
		addr := l.Addr
		if net.ParseIP(addr) == nil {
			continue
		}
		p, ok := byID[l.ID]
		if !ok {
			if l.ID > 4 {
				r.unowned++
			}
			continue
		}
		p.listeners = append(p.listeners, platListener(p.name, addr, l.Port, l.Proto))
	}
	return r, nil
}

// platRunningPass is pass 3.
func platRunningPass(ctx context.Context, c *collection) {
	var r platRunning
	var err error
	windows := false
	switch c.opts.Platform {
	case hostinventory.PlatformLinux, hostinventory.PlatformDarwin:
		script := platLinuxRunningScript
		if c.opts.Platform == hostinventory.PlatformDarwin {
			script = platDarwinRunningScript
		}
		out, stderr, exit, rerr := platRun(ctx, c.target, platSh(script))
		switch {
		case rerr != nil:
			err = rerr
		case exit != 0:
			err = platStderr("processes", stderr, exit)
		default:
			r = platParseUnixRunning(out)
		}
	case hostinventory.PlatformWindows:
		windows = true
		var b []byte
		b, err = platPS(ctx, c.target, platPSRunning, struct {
			Max int `json:"Max"`
		}{platMaxProcesses})
		if err == nil {
			r, err = platParseWindowsRunning(b)
		}
	default:
		return
	}
	if err != nil {
		platOutcome(c, SectionProcesses, err)
		return
	}
	platSetElevated(c, r.elevated)
	platApplyRunning(ctx, c, r, windows)

	elevated := platIsElevated(c)
	switch {
	case r.denied > 0 && !elevated:
		c.partial(SectionProcesses, fmt.Errorf("%d processes could not be inspected without root or an elevated administrator", r.denied))
	case r.denied > 0:
		c.partial(SectionProcesses, fmt.Errorf("%d processes could not be inspected", r.denied))
	case r.unowned > 0 && !elevated:
		c.partial(SectionProcesses, fmt.Errorf("%d listening sockets belong to processes this account cannot see", r.unowned))
	case c.opts.Platform == hostinventory.PlatformDarwin && !elevated:
		// lsof shows another user's sockets only to root, and says nothing
		// of what it left out.
		c.partial(SectionProcesses, errors.New("other users' processes are not visible without root"))
	}
	if r.truncated {
		c.limit(SectionProcesses, "max_records", fmt.Sprintf("described the first %d processes", platMaxProcesses))
	}
	c.mark(SectionProcesses, SectionOK)
}

// platApplyRunning turns the processes into usages, libraries and visits.
func platApplyRunning(ctx context.Context, c *collection, r platRunning, windows bool) {
	type use struct {
		usages []Usage
	}
	paths := map[string]*use{}
	var order []string
	libs := map[string][]string{} // path -> process names
	var libOrder []string
	for _, p := range r.procs {
		if p.name == "" {
			continue
		}
		usages := append([]Usage{{Kind: "process", Process: p.name, Product: p.name}}, p.listeners...)
		for _, f := range append(append([]string(nil), p.files...), p.args...) {
			u, ok := paths[f]
			if !ok {
				u = &use{}
				paths[f] = u
				order = append(order, f)
			}
			u.usages = append(u.usages, usages...)
		}
		for _, l := range p.libs {
			if _, ok := libs[l]; !ok {
				libOrder = append(libOrder, l)
			}
			libs[l] = append(libs[l], p.name)
		}
	}
	for _, l := range libOrder {
		name, fips, _ := platLibraryFile(l)
		if name == "" {
			continue
		}
		c.registry.platLoadedBy(name, l, libs[l], fips, windows)
	}
	sort.Strings(order)
	for _, f := range order {
		if c.timeUp(ctx, SectionProcesses) {
			return
		}
		platVisitPath(ctx, c, f, platDedupeUsage(paths[f].usages), windows)
	}
	c.locFlushRecords()
}

func platDedupeUsage(in []Usage) []Usage {
	var out []Usage
	for _, u := range in {
		dup := false
		for _, have := range out {
			if have == u {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, u)
		}
	}
	return out
}

// platLoadedBy adds process names to every library at path (by real path),
// or records a process-sourced library when none is held.
//
// Windows paths compare without regard to case: a module list names
// "schannel.DLL" where the file is "schannel.dll".
func (r *registry) platLoadedBy(name, p string, procs []string, fips, windows bool) {
	r.mu.Lock()
	rp := r.realPath(p)
	hit := false
	for i := range r.libraries.items {
		l := &r.libraries.items[i]
		if l.Path == "" || l.Name != name {
			continue
		}
		lp := r.realPath(l.Path)
		if lp == rp || windows && strings.EqualFold(lp, rp) {
			l.LoadedBy = unionStrings(l.LoadedBy, procs)
			hit = true
		}
	}
	r.mu.Unlock()
	if hit {
		return
	}
	l := CryptoLibrary{Name: name, Path: p, Source: "process", LoadedBy: procs}
	if fips {
		l.FIPSProvider = platBoolPtr(true)
	}
	r.addLibrary(l)
}

// platAttach adds a process sighting to every item the registry holds at
// path p (by real path, as a file or as an entry's container), and reports
// whether there was one.
func (r *registry) platAttach(p string, usages []Usage, windows bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rp := r.realPath(p)
	src := Location{FoundBy: FoundByProcess, UsedBy: usages}
	hit := false
	same := func(q string) bool {
		if q == "" {
			return false
		}
		rq := r.realPath(q)
		return rq == rp || windows && strings.EqualFold(rq, rp)
	}
	at := func(l *Location) {
		if same(l.Path) || same(l.Container) {
			mergeLocation(l, src)
			hit = true
		}
	}
	for i := range r.certs.items {
		at(&r.certs.items[i].Location)
	}
	for i := range r.keys.items {
		at(&r.keys.items[i].Location)
	}
	for i := range r.keystores.items {
		at(&r.keystores.items[i].Location)
	}
	for i := range r.configs.items {
		at(&r.configs.items[i].Location)
	}
	for i := range r.authKeys.items {
		at(&r.authKeys.items[i].Location)
	}
	for i := range r.known.items {
		at(&r.known.items[i].Location)
	}
	return hit
}

// platVisitPath records what a running process holds or names. An item an
// earlier pass already registered gets the usages; a new path is visited
// through pass 1's dispatcher (locVisit) with FoundBy process, so it gets the
// same record, and meets the same remote rules (a private key file is never
// read remotely), as a file found in a known location.
func platVisitPath(ctx context.Context, c *collection, p string, usages []Usage, windows bool) {
	if c.registry.platAttach(p, usages, windows) {
		return
	}
	c.locVisit(ctx, locVisit{Path: p, Kind: locMaterial, FoundBy: FoundByProcess, UsedBy: usages, Section: SectionProcesses})
}
