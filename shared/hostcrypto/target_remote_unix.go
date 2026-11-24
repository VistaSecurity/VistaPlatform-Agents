package hostcrypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// RemoteUnixTarget is a Linux or macOS host reached through a
// [hostinventory.Runner], in production the SSH runner.
//
// Every command is an argv slice. Where a pipeline is needed, a FIXED script
// is passed to `sh -c` and the paths follow it as positional arguments ("$1",
// "$@"), so a path is always data to the far side and never script text: a
// file called `$(reboot)` is a file called `$(reboot)`. The SSH runner
// single-quotes every element, which keeps that true over the wire.
//
// Every command runs under `env LC_ALL=C`, so the error text the sentinel
// mapping reads ("No such file or directory") is not translated, and awk,
// tr and head work on bytes.
//
// No command writes anything on the host: no temporary file, ever.
type RemoteUnixTarget struct {
	runner   hostinventory.Runner
	platform string
	maxBytes int64
}

// remoteUnixReadMax is the most a remote Unix read returns: the runner
// refuses more than 8 MiB of output, so a larger file is ErrFileTooLarge
// rather than a truncated read. Identify still scans the full read bound.
const remoteUnixReadMax = 8000000

// NewRemoteUnixTarget wraps r for a host whose platform is "linux" or
// "darwin". The two differ in stat's flags (GNU `-c`/`--printf`, BSD `-f`)
// and in how a read is pinned to one file (see readPrelude); anything other
// than "darwin" is treated as Linux.
func NewRemoteUnixTarget(r hostinventory.Runner, platform string) *RemoteUnixTarget {
	return &RemoteUnixTarget{runner: r, platform: platform, maxBytes: defaultMaxFileBytes}
}

// SetMaxFileBytes sets the read bound; n <= 0 restores 10 MiB. Reads are
// further capped at 8,000,000 bytes by the transport.
func (t *RemoteUnixTarget) SetMaxFileBytes(n int64) {
	if n <= 0 {
		n = defaultMaxFileBytes
	}
	t.maxBytes = n
}

func (t *RemoteUnixTarget) readCap() int64 { return min(t.maxBytes, remoteUnixReadMax) }

func (t *RemoteUnixTarget) darwin() bool { return t.platform == hostinventory.PlatformDarwin }

func (t *RemoteUnixTarget) platformArg() string {
	if t.darwin() {
		return hostinventory.PlatformDarwin
	}
	return hostinventory.PlatformLinux
}

// Run passes argv to the runner unchanged.
func (t *RemoteUnixTarget) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return t.runner.Run(ctx, argv)
}

// Local is false: bytes read here cross a connection.
func (t *RemoteUnixTarget) Local() bool { return false }

// awkRules is the text rule set of redact.go as a POSIX awk program: no
// interval expressions (mawk 1.3.3 and old BWK awk lack them), no gawk
// extensions, no single quote (it sits inside one in the shell script). Three
// modes, chosen with -v mode=:
//
//	identify  print up to 64 "label:" lines and one "flags:" line
//	decide    print "public" or "refuse" (needs -v nul, ks, pubname)
//	redact    print the redacted text (needs -v nonl) and the count on stderr
//
// It mirrors inspect, identityFrom's host-side core, and RedactText; the
// parity tests run it for real and compare.
var awkRules = `function cls(n,   r, i) { r = ""; for (i = 0; i < n; i++) r = r "[A-Za-z0-9+/=]"; return r }
function isbegin(s) { return index(s, "----BEGIN") || index(s, "---- BEGIN") }
function isend(s) { return index(s, "----END") || index(s, "---- END") }
function parsebegin(s,   n, l) {
  n = length(s); LAB = ""
  if (n < 17) return 0
  if (!((substr(s, 1, 11) == "-----BEGIN " && substr(s, n - 4) == "-----") || (substr(s, 1, 11) == "---- BEGIN " && substr(s, n - 4) == " ----"))) return 0
  l = substr(s, 12, n - 16)
  if (length(l) > 64 || l !~ /^[A-Z0-9 -]+$/) return 0
  LAB = l
  return 1
}
function namespriv(s,   u) { u = toupper(s); return index(u, "PRIVATE") || index(u, "SECRET") || index(u, "KEY") }
function sshline(s,   i, t, r, j, b, c) {
  i = index(s, " ")
  if (i < 2) return 0
  t = substr(s, 1, i - 1)
  if (substr(t, 1, 4) != "ssh-" && substr(t, 1, 11) != "ecdsa-sha2-" && substr(t, 1, 3) != "sk-") return 0
  if (t !~ /^[a-z0-9@.-]+$/) return 0
  r = substr(s, i + 1)
  j = index(r, " ")
  if (j == 0) { b = r; c = "" } else { b = substr(r, 1, j - 1); c = substr(r, j + 1) }
  if (b !~ /^[A-Za-z0-9+\/]+=*$/) return 0
  if (match(c, RUN)) return 0
  return 1
}
function redact(s,   o) {
  o = ""
  while (match(s, RUN)) { o = o substr(s, 1, RSTART - 1) "` + RedactedMarker + `"; s = substr(s, RSTART + RLENGTH); NRED++ }
  return o s
}
BEGIN {
  RUN = cls(` + strconv.Itoa(RedactRunLength) + `) "[A-Za-z0-9+/=]*"
  na = split("` + strings.Join(publicPEMLabels, "|") + `", AL, "|")
  for (k = 1; k <= na; k++) ALLOW[AL[k]] = 1
  inpub = 0; drop = 0; NRED = 0; pend = 0
}
mode == "redact" {
  if (pend) { printf "%s\n", P; pend = 0 }
  line = $0; s = line; sub(/\r$/, "", s)
  if (drop) { if (isend(s)) drop = 0; next }
  if (isbegin(s)) { if (!parsebegin(s) || !(LAB in ALLOW)) { NRED++; if (!isend(s)) drop = 1; next } }
  P = redact(line); pend = 1
  next
}
{
  s = $0; sub(/\r$/, "", s)
  if (isbegin(s)) {
    if (inpub) unterm = 1
    inpub = 0
    ok = parsebegin(s); pub = ok && (LAB in ALLOW)
    if (!pub && namespriv(s)) priv = 1
    if (!ok) { bad = 1; next }
    nl++
    if (mode == "identify" && nl <= 64) print "label:" LAB
    if (pub) inpub = 1; else nonpub = 1
    next
  }
  if (inpub) { if (isend(s)) inpub = 0; next }
  if (match(s, RUN)) orun = 1
  if (substr(s, 1, 1) == "#" || s ~ /^[ \t]*$/) next
  if (sshline(s)) sshl++; else sshbad = 1
}
END {
  if (mode == "redact") {
    if (pend) printf "%s%s", P, (nonl ? "" : "\n")
    print "vista-redactions:" NRED > "/dev/stderr"
    exit 0
  }
  if (inpub) unterm = 1
  if (mode == "identify") { print "flags:" (bad + 0) " " (nonpub + 0) " " (unterm + 0) " " (priv + 0) " " (orun + 0) " " (sshbad + 0) " " (sshl + 0) " " (nl + 0); exit 0 }
  ok = !nul && !ks && !bad && !nonpub && !unterm && !priv && ((nl > 0 && !orun) || (nl == 0 && pubname && sshl > 0 && !sshbad))
  print (ok ? "public" : "refuse")
}`

// readPrelude starts every script that reads a file. $1 is the path, $2 the
// platform, $3 the byte bound. It refuses with an exit code rather than a
// message (3 missing, 4 permission, 5 directory, 6 not a regular file, 9
// changed, 10 cannot pin), then pins the file:
//
// The file is opened ONCE, on fd 3, and every later check and the output read
// that one file rather than whatever the path names by then:
//
//   - Linux: everything reads /proc/self/fd/3, which opens the inode fd 3
//     holds even if the path has been renamed, replaced or re-linked since.
//     A host without /proc refuses (exit 10) rather than read unpinned.
//   - macOS (no /proc): the checks read the path; before them and again just
//     before the output, the path's device, inode, size and mtime must equal
//     those of fd 3 (stat of /dev/fd/3), and the output is read from fd 3.
//
// RESIDUAL WINDOW, stated honestly: the file's CONTENT can still change in
// place between the checks and the output (same inode; on macOS also a
// rename away and back between the two comparisons). The identity is checked
// again just before the output, which catches a change of size or mtime; a
// same-size rewrite within one second is not caught on the host. The Go side
// re-checks every byte that arrives and drops it if it fails, so such a
// swap is never parsed or reported — but its bytes have crossed.
//
// `[ -f ]` runs before the open, so a FIFO is never opened (a FIFO swapped in
// between the test and the open would block until the command timeout).
const readPrelude = `p=$1; plat=$2; max=$3
if [ ! -e "$p" ]; then
  if [ -L "$p" ]; then exit 3; fi
  e=$(stat -- "$p" 2>&1 >/dev/null)
  case $e in *"ermission denied"*) exit 4;; esac
  exit 3
fi
if [ -d "$p" ]; then exit 5; fi
if [ ! -f "$p" ]; then exit 6; fi
if [ ! -r "$p" ]; then exit 4; fi
exec 3< "$p" || exit 4
fid() { if [ "$plat" = darwin ]; then stat -L -f '%d:%i:%z:%m' -- "$1"; else stat -L -c '%d:%i:%s:%Y' -- "$1"; fi 2>/dev/null; }
if [ "$plat" = darwin ]; then
  F=$p; pin=$(fid /dev/fd/3)
  if [ -z "$pin" ] || [ "$pin" != "$(fid "$p")" ]; then exit 9; fi
else
  F=/proc/self/fd/3
  if [ ! -r "$F" ]; then exit 10; fi
  pin=$(fid "$F")
fi
if [ ! -f "$F" ]; then exit 6; fi
size=${pin#*:}; size=${size#*:}; size=${size%%:*}
case $size in ''|*[!0-9]*) exit 10;; esac
win() { if [ "$w" -gt 0 ]; then head -c "$w" -- "$F"; fi; }
repin() {
  if [ "$pin" != "$(fid "$F")" ]; then exit 9; fi
  if [ "$plat" = darwin ] && [ "$pin" != "$(fid "$p")" ]; then exit 9; fi
}
magic=$(head -c 8 -- "$F" | od -An -v -tx1 | tr -d ' \n')
ks=0
case $magic in feedfeed*|cececece*|0502*|0501*|53514c6974652066*) ks=1;; esac
`

// identifyScript prints ONLY markers: the size, the first eight bytes in hex,
// whether the scanned window holds a NUL, up to 64 valid labels and the rule
// flags. It reads at most the byte bound.
var identifyScript = readPrelude + `w=$size
if [ "$w" -gt "$max" ]; then w=$max; fi
printf 'size:%s\nmagic:%s\n' "$size" "$magic"
n=$(win | tr -d '\000' | wc -c)
if [ "$((n + 0))" -eq "$w" ]; then echo nul:0; else echo nul:1; fi
win | awk -v mode=identify '` + awkRules + `'
exit 0`

// readScript decides on the host, from the pinned file, with the
// conservative rule (no NUL, no keystore magic, every label on the allowlist,
// nothing private-looking, no long run outside public blocks, or an OpenSSH
// .pub file of public key lines only), and only then prints the file. Exit 7
// is over the bound, 8 is not public; nothing is printed for either.
var readScript = readPrelude + `if [ "$size" -gt "$max" ]; then exit 7; fi
w=$size
n=$(win | tr -d '\000' | wc -c)
nul=0; if [ "$((n + 0))" -ne "$w" ]; then nul=1; fi
pn=0; case $p in *.pub) pn=1;; esac
d=$(win | awk -v mode=decide -v nul=$nul -v ks=$ks -v pubname=$pn '` + awkRules + `')
if [ "$d" != public ]; then exit 8; fi
repin
if [ "$plat" = darwin ]; then cat <&3; else cat -- "$F"; fi`

// readTextScript refuses a file that is not text (NUL anywhere, keystore
// magic: exit 8) or over the bound (exit 7), then prints it redacted by the
// awk rules, with the redaction count on stderr.
var readTextScript = readPrelude + `if [ "$size" -gt "$max" ]; then exit 7; fi
if [ "$ks" = 1 ]; then exit 8; fi
w=$size
n=$(win | tr -d '\000' | wc -c)
if [ "$((n + 0))" -ne "$w" ]; then exit 8; fi
nonl=0
if [ "$w" -gt 0 ]; then
  l=$(tail -c 1 -- "$F" | od -An -tx1 | tr -d ' \n')
  if [ "$l" != 0a ]; then nonl=1; fi
fi
repin
if [ "$plat" = darwin ]; then awk -v mode=redact -v nonl=$nonl '` + awkRules + `' <&3
else awk -v mode=redact -v nonl=$nonl '` + awkRules + `' < "$F"; fi`

// errChanged is a read the host refused because the file changed between
// being opened and being read.
var errChanged = errors.New("hostcrypto: the file changed while it was read")

// scriptArgv runs one of the fixed scripts on path.
func (t *RemoteUnixTarget) scriptArgv(script, path string, bound int64) []string {
	return []string{"env", "LC_ALL=C", "sh", "-c", script, "sh", path, t.platformArg(), strconv.FormatInt(bound, 10)}
}

func (t *RemoteUnixTarget) identifyArgv(path string) []string {
	return t.scriptArgv(identifyScript, path, t.maxBytes)
}

// scriptError maps a read script's exit code.
func scriptError(path string, exit int) error {
	switch exit {
	case 3:
		return fmt.Errorf("%s: %w", path, ErrNotExist)
	case 4:
		return fmt.Errorf("%s: %w", path, ErrPermission)
	case 5:
		return fmt.Errorf("hostcrypto: %s is a directory", path)
	case 6:
		return fmt.Errorf("%s: %w", path, errNotRegular)
	case 7:
		return fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	case 8:
		return fmt.Errorf("%s: %w", path, ErrNotPublic)
	case 9:
		return fmt.Errorf("%s: %w", path, errChanged)
	case 10:
		return fmt.Errorf("hostcrypto: %s: the host cannot pin the file for reading (no /proc/self/fd)", path)
	}
	return fmt.Errorf("hostcrypto: %s: exit %d", path, exit)
}

// identify runs identifyScript and returns the host's inspection.
func (t *RemoteUnixTarget) identify(ctx context.Context, path string) (inspection, error) {
	out, _, exit, err := t.runner.Run(ctx, t.identifyArgv(path))
	if err != nil {
		return inspection{}, err
	}
	if exit != 0 {
		return inspection{}, scriptError(path, exit)
	}
	in, err := parseIdentifyOutput(out, t.maxBytes)
	if err != nil {
		return inspection{}, fmt.Errorf("hostcrypto: identify %s: %w", path, err)
	}
	return in, nil
}

// Identify runs identifyScript on the host and classifies what it returns.
func (t *RemoteUnixTarget) Identify(ctx context.Context, path string) (Identity, error) {
	in, err := t.identify(ctx, path)
	if err != nil {
		return Identity{}, err
	}
	return identityFrom(path, in), nil
}

// parseIdentifyOutput reads identifyScript's output. An answer missing a
// line, or with a malformed one, is an error: an answer the host did not give
// must not make a file public.
func parseIdentifyOutput(out []byte, window int64) (inspection, error) {
	var in inspection
	var sawSize, sawMagic, sawNul, sawFlags bool
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "size:"):
			n, err := strconv.ParseInt(strings.TrimPrefix(line, "size:"), 10, 64)
			if err != nil || n < 0 {
				return in, errors.New("unreadable size")
			}
			in.size, in.truncated, sawSize = n, n > window, true
		case strings.HasPrefix(line, "magic:"):
			b, err := hex.DecodeString(strings.TrimPrefix(line, "magic:"))
			if err != nil || len(b) > MagicBytes {
				return in, errors.New("unreadable magic")
			}
			if len(b) > 0 {
				in.magic = b
			}
			sawMagic = true
		case line == "nul:0", line == "nul:1":
			in.nul, sawNul = line == "nul:1", true
		case strings.HasPrefix(line, "label:"):
			l := strings.TrimPrefix(line, "label:")
			if _, ok := parseBeginLine("-----BEGIN " + l + "-----"); !ok {
				in.bad = true
				continue
			}
			if len(in.labels) < maxPEMLabels {
				in.labels = append(in.labels, l)
			}
		case strings.HasPrefix(line, "flags:"):
			f := strings.Fields(strings.TrimPrefix(line, "flags:"))
			if len(f) != 8 {
				return in, errors.New("unreadable flags")
			}
			v := make([]int, 8)
			for i, s := range f {
				n, err := strconv.Atoi(s)
				if err != nil || n < 0 {
					return in, errors.New("unreadable flags")
				}
				v[i] = n
			}
			in.bad = in.bad || v[0] != 0
			in.nonPublic, in.unterminated, in.private = v[1] != 0, v[2] != 0, v[3] != 0
			in.outsideRun, in.sshBad, in.sshLines, in.nLabel = v[4] != 0, v[5] != 0, v[6], v[7]
			sawFlags = true
		}
	}
	if !sawSize || !sawMagic || !sawNul || !sawFlags {
		return in, errors.New("incomplete answer")
	}
	if len(in.labels) > in.nLabel {
		return in, errors.New("inconsistent answer")
	}
	return in, nil
}

// ReadFile returns a file only when it is public, decided twice before any
// byte crosses and once after:
//
//  1. Identify, decided in Go with the full rule (name included). Not public:
//     ErrNotPublic, and no command that prints content is sent. Over the read
//     cap: ErrFileTooLarge, and nothing is sent.
//  2. readScript, which pins the file and decides again ON THE HOST from the
//     bytes it is about to print, and prints nothing unless they pass.
//  3. The bytes that arrive are inspected again here and dropped (cleared)
//     unless public: the backstop for the residual window in readPrelude.
func (t *RemoteUnixTarget) ReadFile(ctx context.Context, path string) ([]byte, error) {
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
	out, _, exit, err := t.runner.Run(ctx, t.scriptArgv(readScript, path, readCap))
	if err != nil {
		return nil, err
	}
	if exit != 0 {
		clear(out)
		return nil, scriptError(path, exit)
	}
	return recheckPublic(path, out, readCap)
}

// recheckPublic inspects bytes a remote read returned and refuses them when
// they are not public after all. The buffer is cleared before it is dropped.
func recheckPublic(path string, b []byte, readCap int64) ([]byte, error) {
	if int64(len(b)) > readCap {
		clear(b)
		return nil, fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	}
	if !identityFrom(path, inspect(b, int64(len(b)))).Public() {
		clear(b)
		return nil, fmt.Errorf("%s: %w (content changed after identification)", path, ErrNotPublic)
	}
	return b, nil
}

// ReadText returns a configuration file redacted ON THE HOST by
// readTextScript. What arrives is checked: no NUL, and RedactText must find
// nothing left to redact (the rule is idempotent); otherwise it is dropped
// with ErrNotPublic.
func (t *RemoteUnixTarget) ReadText(ctx context.Context, path string) ([]byte, int, error) {
	readCap := t.readCap()
	out, stderr, exit, err := t.runner.Run(ctx, t.scriptArgv(readTextScript, path, readCap))
	if err != nil {
		return nil, 0, err
	}
	if exit != 0 {
		clear(out)
		return nil, 0, scriptError(path, exit)
	}
	n, ok := parseRedactionCount(stderr)
	if !ok {
		clear(out)
		return nil, 0, fmt.Errorf("hostcrypto: read text %s: the host did not report its redactions", path)
	}
	return checkRedacted(path, out, n)
}

// checkRedacted is the backstop for a host's redaction.
func checkRedacted(path string, out []byte, n int) ([]byte, int, error) {
	if bytes.IndexByte(out, 0) >= 0 {
		clear(out)
		return nil, 0, fmt.Errorf("%s: %w (not text)", path, ErrNotPublic)
	}
	if again, k := RedactText(out); k != 0 || !bytes.Equal(again, out) {
		clear(out)
		return nil, 0, fmt.Errorf("%s: %w (the host's redaction left material)", path, ErrNotPublic)
	}
	return out, n, nil
}

// parseRedactionCount finds awk's "vista-redactions:N" line.
func parseRedactionCount(stderr []byte) (int, bool) {
	for _, line := range strings.Split(string(stderr), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "vista-redactions:"); ok {
			n, err := strconv.Atoi(v)
			return n, err == nil && n >= 0
		}
	}
	return 0, false
}

// statArgv is the per-platform batched stat: size, raw mode, owner and group
// names, numeric ids, mtime, the name, and the link target, for every path in
// one command.
//
// GNU: --printf with NUL terminators, "fields|name\0%N\0", where %N under
// QUOTING_STYLE=literal is "name -> target" for a link: every field and the
// target are exact, whatever the name holds. BSD: "fields|name|target\n"
// (%Y is the link target, empty otherwise); a link TARGET holding a newline is
// misread on macOS, which is accepted and stated.
func (t *RemoteUnixTarget) statArgv(paths []string) []string {
	var argv []string
	if t.darwin() {
		argv = []string{"env", "LC_ALL=C", "stat", "-f", "%z|%p|%Su|%Sg|%u|%g|%m|%N|%Y"}
	} else {
		argv = []string{"env", "LC_ALL=C", "QUOTING_STYLE=literal", "stat", "--printf", `%s|%f|%U|%G|%u|%g|%Y|%n\0%N\0`}
	}
	argv = append(argv, "--")
	return append(argv, paths...)
}

// Stat runs stat on one path, not following a link.
func (t *RemoteUnixTarget) Stat(ctx context.Context, path string) (FileInfo, error) {
	out, stderr, exit, err := t.runner.Run(ctx, t.statArgv([]string{path}))
	if err != nil {
		return FileInfo{}, err
	}
	infos := t.parseStat(out, []string{path})
	if len(infos) != 1 {
		if exit != 0 {
			return FileInfo{}, unixStderrError(path, stderr, exit)
		}
		return FileInfo{}, fmt.Errorf("hostcrypto: stat %s: unreadable answer", path)
	}
	return infos[0], nil
}

// parseStat reads a batched stat's output for the paths asked for. A path
// stat could not read prints nothing, so fewer records than paths come back;
// the caller counts the difference.
func (t *RemoteUnixTarget) parseStat(out []byte, paths []string) []FileInfo {
	if t.darwin() {
		return t.parseBSDStat(string(out), paths)
	}
	want := make(map[string]bool, len(paths))
	for _, p := range paths {
		want[p] = true
	}
	var infos []FileInfo
	tokens := strings.Split(string(out), "\x00")
	for i := 0; i+1 < len(tokens); i += 2 {
		rec, n := tokens[i], tokens[i+1]
		f := strings.SplitN(rec, "|", 8)
		if len(f) != 8 || !want[f[7]] {
			continue
		}
		fi, ok := t.statFields(f[:7], f[7])
		if !ok {
			continue
		}
		if fi.IsSymlink {
			fi.LinkTarget = strings.TrimPrefix(n, f[7]+" -> ")
		}
		infos = append(infos, fi)
	}
	return infos
}

// parseBSDStat matches "fields|name|target\n" records against the paths
// asked for, in order; a record that does not carry the next expected name
// means that path failed.
func (t *RemoteUnixTarget) parseBSDStat(rest string, paths []string) []FileInfo {
	var infos []FileInfo
	for _, p := range paths {
		f, after, ok := cutFields(rest, 7)
		if !ok || !strings.HasPrefix(after, p+"|") {
			continue
		}
		after = after[len(p)+1:]
		nl := strings.IndexByte(after, '\n')
		if nl < 0 {
			continue
		}
		target := after[:nl]
		rest = after[nl+1:]
		fi, ok := t.statFields(f, p)
		if !ok {
			continue
		}
		if fi.IsSymlink {
			fi.LinkTarget = target
		}
		infos = append(infos, fi)
	}
	return infos
}

// cutFields takes n '|'-terminated fields from the front of s; none may hold
// a newline.
func cutFields(s string, n int) ([]string, string, bool) {
	f := make([]string, 0, n)
	for i := 0; i < n; i++ {
		j := strings.IndexByte(s, '|')
		if j < 0 || strings.ContainsRune(s[:j], '\n') {
			return nil, s, false
		}
		f = append(f, s[:j])
		s = s[j+1:]
	}
	return f, s, true
}

// statFields reads the seven stat fields.
func (t *RemoteUnixTarget) statFields(f []string, path string) (FileInfo, bool) {
	size, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return FileInfo{}, false
	}
	base := 16
	if t.darwin() {
		base = 8
	}
	raw, err := strconv.ParseUint(f[1], base, 32)
	if err != nil {
		return FileInfo{}, false
	}
	mtime, err := strconv.ParseInt(f[6], 10, 64)
	if err != nil {
		return FileInfo{}, false
	}
	owner, group := f[2], f[3]
	if owner == "" || owner == "UNKNOWN" {
		owner = f[4]
	}
	if group == "" || group == "UNKNOWN" {
		group = f[5]
	}
	mode := uint32(raw) & 0o7777
	world, grp := mode&0o004 != 0, mode&0o040 != 0
	typ := uint32(raw) & 0o170000
	return FileInfo{
		Path:          path,
		Size:          size,
		Mode:          mode,
		Owner:         owner,
		Group:         group,
		WorldReadable: &world,
		GroupReadable: &grp,
		ModifiedAt:    time.Unix(mtime, 0).UTC().Format(time.RFC3339),
		IsDir:         typ == 0o040000,
		IsSymlink:     typ == 0o120000,
	}, true
}

// unixStderrError maps a failed command's stderr to the sentinels. LC_ALL=C
// keeps the text in English.
func unixStderrError(path string, stderr []byte, exit int) error {
	s := string(stderr)
	switch {
	case strings.Contains(s, "No such file or directory"):
		return fmt.Errorf("%s: %w", path, ErrNotExist)
	case strings.Contains(s, "Permission denied"), strings.Contains(s, "Operation not permitted"):
		return fmt.Errorf("%s: %w", path, ErrPermission)
	}
	return fmt.Errorf("hostcrypto: %s: exit %d", path, exit)
}

// listScript runs find with the expression the target built and keeps at
// most "$1" bytes of its NUL-separated output, so a tree of a million files
// is cut on the host rather than over the wire. The expression arrives as
// positional arguments; nothing in it is script text.
const listScript = `n=$1
shift
find "$@" | head -c "$n"`

// remoteListByteCap bounds one listing's output below the runner's 8 MiB
// read bound, so a long listing is reported as truncated rather than failing.
const remoteListByteCap = 7 << 20

// statBatchBytes bounds one batched stat command line. Linux caps a single
// argument at 128 KiB, and the SSH runner sends the whole command as one
// argument to the far shell.
const statBatchBytes = 64 << 10

// findArgv builds the find expression for one walk:
//
//	find ROOT [-xdev] -maxdepth N [( -path EX -o -path EX/* ... ) -prune -o]
//	     ( -type f -o -type l ) [( -name G -o ... )] -print0
//
// -maxdepth is MaxDepth+1 because find counts root's own entries as depth 1.
// Exclusions are escaped so a path holding * or [ is matched literally.
func findArgv(root string, opts ListOptions) []string {
	argv := []string{"find", root}
	if !opts.CrossFilesystems {
		argv = append(argv, "-xdev")
	}
	argv = append(argv, "-maxdepth", strconv.Itoa(opts.MaxDepth+1))
	var ex []string
	for _, e := range opts.Exclude {
		e = strings.TrimRight(e, "/")
		if e == "" {
			continue
		}
		ex = append(ex, e)
	}
	if len(ex) > 0 {
		argv = append(argv, "(")
		for i, e := range ex {
			if i > 0 {
				argv = append(argv, "-o")
			}
			esc := escapeFindGlob(e)
			argv = append(argv, "-path", esc, "-o", "-path", esc+"/*")
		}
		argv = append(argv, ")", "-prune", "-o")
	}
	argv = append(argv, "(", "-type", "f", "-o", "-type", "l", ")")
	if len(opts.Names) > 0 {
		argv = append(argv, "(")
		for i, n := range opts.Names {
			if i > 0 {
				argv = append(argv, "-o")
			}
			argv = append(argv, "-name", n)
		}
		argv = append(argv, ")")
	}
	return append(argv, "-print0")
}

// escapeFindGlob escapes the characters fnmatch treats specially.
func escapeFindGlob(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '*', '?', '[', ']':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// listByteCap is how much find output one walk may return: enough for
// MaxFiles entries of typical length, never more than the runner can carry.
func listByteCap(maxFiles int) int {
	c := maxFiles * 512
	if c < 64<<10 {
		c = 64 << 10
	}
	if c > remoteListByteCap {
		c = remoteListByteCap
	}
	return c
}

func (t *RemoteUnixTarget) listArgv(root string, opts ListOptions, byteCap int) []string {
	argv := []string{"env", "LC_ALL=C", "sh", "-c", listScript, "sh", strconv.Itoa(byteCap)}
	return append(argv, findArgv(root, opts)...)
}

// List runs find on the host, sorts the paths (so a MaxFiles cut is the same
// every run), then stats them in batches, link targets included. root must be
// absolute: a root starting with "-" would be read by find as an expression.
//
// Nothing is dropped silently: a path stat could not read (a name too long,
// gone mid-walk) is counted in ListError.Unreadable, a file over
// MaxSizeBytes in OverSize, an unreadable directory in Denied.
func (t *RemoteUnixTarget) List(ctx context.Context, root string, opts ListOptions) ([]FileInfo, error) {
	if !strings.HasPrefix(root, "/") {
		return nil, fmt.Errorf("hostcrypto: list %q: root must be an absolute path", root)
	}
	// BSD find prints "/etc//x" for a root of "/etc/", which no exclusion or
	// expected path would match.
	if trimmed := strings.TrimRight(root, "/"); trimmed != "" {
		root = trimmed
	}
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}
	maxSize := opts.MaxSizeBytes
	if maxSize <= 0 {
		maxSize = defaultMaxFileBytes
	}
	byteCap := listByteCap(maxFiles)
	out, stderr, exit, err := t.runner.Run(ctx, t.listArgv(root, opts, byteCap))
	if err != nil {
		return nil, err
	}
	lerr := &ListError{}
	rootErr := parseFindStderr(stderr, root, lerr)
	if len(out) == 0 && rootErr != nil {
		return nil, rootErr
	}
	if exit != 0 && len(out) == 0 && lerr.DeniedCount == 0 && lerr.Unreadable == 0 {
		return nil, unixStderrError(root, stderr, exit)
	}
	if len(out) >= byteCap {
		lerr.Truncated = true
	}
	paths := splitNUL(out)
	sort.Strings(paths)
	excl := cleanExcludesSlash(opts.Exclude)

	var infos []FileInfo
	for len(paths) > 0 && len(infos) < maxFiles {
		if cerr := ctx.Err(); cerr != nil {
			return infos, cerr
		}
		batch, remain := nextStatBatch(paths)
		paths = remain
		bout, _, _, berr := t.runner.Run(ctx, t.statArgv(batch))
		if berr != nil {
			return infos, berr
		}
		got := t.parseStat(bout, batch)
		lerr.Unreadable += len(batch) - len(got)
		for _, fi := range got {
			if isExcludedSlash(fi.Path, excl) || fi.IsDir {
				continue
			}
			if !fi.IsSymlink && fi.Size > maxSize {
				lerr.OverSize++
				continue
			}
			if len(infos) >= maxFiles {
				lerr.Truncated = true
				break
			}
			infos = append(infos, fi)
		}
	}
	if len(paths) > 0 {
		lerr.Truncated = true
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Path < infos[j].Path })
	return infos, lerr.orNil()
}

// nextStatBatch takes paths from the front up to statBatchBytes of argv.
func nextStatBatch(paths []string) (batch, rest []string) {
	total := 0
	i := 0
	for i < len(paths) {
		n := len(paths[i]) + 3
		if i > 0 && total+n > statBatchBytes {
			break
		}
		total += n
		i++
	}
	return paths[:i], paths[i:]
}

// splitNUL splits find's -print0 output. A complete listing ends in NUL,
// leaving an empty last element; one cut at the byte bound leaves a partial
// path there. Either way the last element is dropped.
func splitNUL(out []byte) []string {
	parts := bytes.Split(out, []byte{0})
	if len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	paths := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			paths = append(paths, string(p))
		}
	}
	return paths
}

// parseFindStderr collects the directories find could not read, counts other
// failures as unreadable, and returns the sentinel error for the root itself
// if the root was the problem. GNU quotes the path ("find: '/x': Permission
// denied"), BSD does not.
func parseFindStderr(stderr []byte, root string, lerr *ListError) error {
	var rootErr error
	for _, line := range strings.Split(string(stderr), "\n") {
		if !strings.HasPrefix(line, "find: ") {
			continue
		}
		body := strings.TrimPrefix(line, "find: ")
		i := strings.LastIndex(body, ": ")
		if i < 0 {
			continue
		}
		p, reason := body[:i], body[i+2:]
		p = strings.TrimSuffix(strings.TrimPrefix(p, "'"), "'")
		p = strings.TrimSuffix(strings.TrimPrefix(p, "‘"), "’")
		switch reason {
		case "Permission denied", "Operation not permitted":
			if p == root {
				rootErr = fmt.Errorf("%s: %w", root, ErrPermission)
				continue
			}
			lerr.addDenied(p)
		case "No such file or directory":
			if p == root {
				rootErr = fmt.Errorf("%s: %w", root, ErrNotExist)
			}
		default:
			lerr.Unreadable++
		}
	}
	return rootErr
}

// cleanExcludesSlash and isExcludedSlash are the remote, always-slash forms
// of the local exclusion check: the far side's separator, not ours.
func cleanExcludesSlash(ex []string) []string {
	out := make([]string, 0, len(ex))
	for _, e := range ex {
		e = strings.TrimRight(e, "/")
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

func isExcludedSlash(p string, excludes []string) bool {
	for _, e := range excludes {
		if p == e || strings.HasPrefix(p, e+"/") {
			return true
		}
	}
	return false
}
