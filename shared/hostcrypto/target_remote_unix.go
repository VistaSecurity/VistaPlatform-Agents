package hostcrypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
	"golang.org/x/crypto/ssh"
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
	// coarse makes the read scripts pin the file with whole-second times,
	// as a host whose stat has no finer ones does. Tests only: it is how
	// the quiescence rule is shown to hold without fine times.
	coarse bool
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
	p := hostinventory.PlatformLinux
	if t.darwin() {
		p = hostinventory.PlatformDarwin
	}
	if t.coarse {
		p += "-coarse"
	}
	return p
}

// Run passes argv to the runner unchanged.
func (t *RemoteUnixTarget) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return t.runner.Run(ctx, argv)
}

// Local is false: bytes read here cross a connection.
func (t *RemoteUnixTarget) Local() bool { return false }

// sshKeyTable renders sshKeyTypes for the awk program: one
// "name|min|max|prefix" per entry, ";"-separated.
func sshKeyTable() string {
	parts := make([]string, len(sshKeyTypes))
	for i, k := range sshKeyTypes {
		parts[i] = k.name + "|" + strconv.Itoa(k.minLen) + "|" + strconv.Itoa(k.maxLen) + "|" + k.prefix
	}
	return strings.Join(parts, ";")
}

// awkRules is the rule set of redact.go as one POSIX awk program: no interval
// expressions (mawk 1.3.3 and old BWK awk lack them), no gawk extensions, no
// single quote (it sits inside one in the shell scripts). Its input comes
// through tr, so every awk sees a NUL the same way, as 0x01: text and
// identify modes map NUL to 0x01 (and refuse 0x01 itself, as Go does);
// public mode maps NUL to 0x01 and 0x01 to 0x02, so 0x01 means NUL alone —
// lossless for everything public mode can print, which is base64, PEM
// frames and key types. Modes, by -v mode=:
//
//	identify  print up to 64 "label:" lines and one "flags:" line (inspect)
//	public    buffer, then print ONLY the public blocks and genuine SSH key
//	          lines, or nothing and exit 8 (publicContent)
//	text      buffer, then print the kept, redacted lines and the count on
//	          stderr, or nothing and exit 8 (not text) or 7 (too many lines)
//	          (filterConfig; the keep words come from ENVIRON["HC_KEEP"], so
//	          awk -v never processes an escape in them). The shell appends
//	          one "\n" to the file, so the last record is always the file's
//	          last segment, and it is a line only when it is not empty: that
//	          is how awk tells "x" from "x\n" and a file that is only a
//	          byte-order mark from one that is a mark and a line end.
//	          @statements splits each record at the bytes that matter to the
//	          tokeniser (gsub then split, linear in the record) rather than
//	          walking it byte by byte.
//
// In public and text modes NOTHING is printed before END: what is printed is
// what was decided on, from the one read the shell gave it.
var awkRules = `function isbegin(s) { return index(s, "----BEGIN") || index(s, "---- BEGIN") }
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
function field1(s,   t) { t = s; sub(/[ \t].*$/, "", t); return t }
function sshkey(s,   r, t, b, n, i, c, q) {
  if (!index(s, "ssh-") && !index(s, "ecdsa-")) return ""
  r = s; sub(/^[ \t]+/, "", r)
  t = field1(r)
  if (!(t in KMIN)) {
    n = length(r); q = 0
    for (i = 1; i <= n; i++) {
      c = substr(r, i, 1)
      if (q) { if (c == "\\" && i < n) { i++; continue }; if (c == "\"") q = 0 }
      else { if (c == " " || c == "\t") break; if (c == "\"") q = 1 }
    }
    if (q) return ""
    r = substr(r, i); sub(/^[ \t]+/, "", r)
    t = field1(r)
    if (!(t in KMIN)) return ""
  }
  r = substr(r, length(t) + 1); sub(/^[ \t]+/, "", r)
  b = field1(r)
  if (b ~ /^[A-Za-z0-9+\/]+=*$/ && length(b) >= KMIN[t] && length(b) <= KMAX[t] && substr(b, 1, length(KP[t])) == KP[t]) return t " " b
  return ""
}
function redact(s,   o) {
  o = ""
  while (match(s, RUN)) { o = o substr(s, 1, RSTART - 1) "` + RedactedMarker + `"; s = substr(s, RSTART + RLENGTH); NRED++ }
  return o s
}
function bodyline(s) { return length(s) >= 1 && length(s) <= ` + strconv.Itoa(maxPEMBodyLine) + ` && s ~ /^[A-Za-z0-9+\/=]+$/ }
function emit(s) {
  if (DROP) { if (isend(s)) DROP = 0; return }
  if (isbegin(s)) { NRED++; if (!isend(s)) DROP = 1; return }
  OUT[++NO] = redact(s)
  OUTB += length(OUT[NO]) + 1
}
function fw(t,   i, c) {
  sub(/^[ \t]+/, "", t)
  if (substr(t, 1, 1) == "<") t = substr(t, 2)
  if (substr(t, 1, 2) == "-D") t = substr(t, 3)
  if (substr(t, 1, 1) == "@") t = substr(t, 2)
  for (i = 1; i <= length(t); i++) { c = substr(t, i, 1); if (c == " " || c == "\t" || c == "=" || c == ":" || c == ";" || c == "{" || c == "}") break }
  t = substr(t, 1, i - 1)
  if (substr(t, length(t)) == ">") t = substr(t, 1, length(t) - 1)
  return tolower(t)
}
function oddbs(s) { return match(s, /\\+$/) && RLENGTH % 2 == 1 }
function iscomment(t,   c) { c = substr(t, 1, 1); return c == "#" || c == "!" || c == ";" || substr(t, 1, 2) == "//" }
function hdrlike(t) { return length(t) >= 2 && substr(t, 1, 1) == "[" && substr(t, length(t)) == "]" }
function secname(t,   n) {
  if (!hdrlike(t) || length(t) < 3) return ""
  n = substr(t, 2, length(t) - 2); sub(/^[ \t]+/, "", n); sub(/[ \t]+$/, "", n)
  if (n == "" || length(n) > 64 || n !~ /^[A-Za-z0-9_.-]+$/) return ""
  return tolower(n)
}
function closetag(t) { if (length(t) >= 4 && length(t) <= 67 && t ~ /^<\/[A-Za-z0-9_.:-]+>$/) return tolower(substr(t, 3, length(t) - 3)); return "" }
function opentag(t,   c) {
  if (length(t) < 3 || t !~ /^<[A-Za-z]/ || substr(t, length(t)) != ">") return ""
  match(t, /^<[A-Za-z0-9_.:-]+/)
  if (RLENGTH - 1 > 64) return ""
  c = substr(t, RLENGTH + 1, 1)
  if (c != ">" && c != " " && c != "\t") return ""
  return tolower(substr(t, 2, RLENGTH - 1))
}
function lline(s,   t, tr, w, nm, hdr) {
  t = s; sub(/^[ \t]+/, "", t)
  if (DROPB || DROPT != "") {
    if (t == "" || iscomment(t)) return
    tr = t; sub(/[ \t]+$/, "", tr)
    if (DROPB) { if (substr(tr, 1, 1) == "}") DDEPTH--; if (substr(tr, length(tr)) == "{") DDEPTH++ }
    else if ((nm = opentag(tr)) != "" && nm == DROPT) DDEPTH++
    else if ((nm = closetag(tr)) != "" && nm == DROPT) DDEPTH--
    if (DDEPTH <= 0) { DROPB = 0; DROPT = "" }
    return
  }
  tr = t; sub(/[ \t]+$/, "", tr)
  hdr = (OPTSEC || OPTANYSEC) && hdrlike(tr) && !index(s, "\r")
  if (DROPSEC && !hdr) return
  if (index(s, "\r")) {
    BSC = 0; DROPC = 0; PREVK = 0; HAVEL = 1; LKEPT = 0; CONTN = 0
    if (tr != "" && substr(tr, length(tr)) == "{") { DROPB = 1; DDEPTH = 1 }
    else if ((nm = opentag(tr)) != "" && OPTTAGS) { DROPT = nm; DDEPTH = 1 }
    return
  }
  if (BSC) { CONTN++; BSC = oddbs(s); if (CONTN <= ` + strconv.Itoa(maxContinuation) + ` && substr(t, 1, 1) != "#") emit(s); return }
  if (DROPC) { DROPC = (substr(s, length(s)) == "\\"); return }
  if (OPTIND && HAVEL && t != "" && (substr(s, 1, 1) == " " || substr(s, 1, 1) == "\t")) {
    if (substr(t, 1, 1) == "#") return
    CONTN++
    if (LKEPT && CONTN <= ` + strconv.Itoa(maxContinuation) + `) emit(s)
    return
  }
  if (t == "") { emit(s); return }
  if (iscomment(t)) return
  HAVEL = 1; LKEPT = 0; CONTN = 0
  if (hdr) {
    nm = secname(tr)
    DROPSEC = (nm == "" || (!OPTANYSEC && !(nm in K)))
    if (!DROPSEC) emit(s)
    PREVK = 0
    return
  }
  if ((nm = closetag(tr)) != "" && OPTTAGS && (nm in K)) { emit(s); PREVK = 0; return }
  if (tr == "}" || tr == "};" || (tr == "{" && PREVK)) { emit(s); PREVK = 0; return }
  w = fw(t)
  if (w != "" && (w in K)) { emit(s); PREVK = 1; LKEPT = 1; BSC = OPTBS && oddbs(s); return }
  PREVK = 0
  if (OPTBS && substr(s, length(s)) == "\\") DROPC = 1
  else if (substr(tr, length(tr)) == "{") { DROPB = 1; DDEPTH = 1 }
  else if ((nm = opentag(tr)) != "" && OPTTAGS) { DROPT = nm; DDEPTH = 1 }
}
function stadd(tok, ends, over) {
  if (OVER) return
  if (over) { OVER = 1; STARTED = 1; BUF = ""; return }
  if (STARTED && SEP) BUF = BUF " "
  BUF = BUF tok; STARTED = 1; SEP = 0; STNL += ends
  if (length(BUF) > ` + strconv.Itoa(maxStatementBytes) + ` || STNL >= ` + strconv.Itoa(maxStatementLines) + `) { OVER = 1; BUF = "" }
}
function stkept(   w) { if (OVER || !STARTED || DROPAT) return 0; w = fw(BUF); return w != "" && (w in K) }
function streset() { BUF = ""; STARTED = 0; SEP = 0; OVER = 0; STNL = 0 }
function wadd(e) { INW = 1; WLAST = substr(e, length(e)); if (!WOVER) { W = W e; if (length(W) > ` + strconv.Itoa(maxStatementBytes) + `) WOVER = 1 } }
function wflush() { if (INW) { stadd(W, 0, WOVER); W = ""; INW = 0; WOVER = 0 } }
function qadd(e) { if (!QOVER) { QTOK = QTOK e; if (length(QTOK) > ` + strconv.Itoa(maxStatementBytes) + `) QOVER = 1 } }
function sttok(e) {
  if (INCOM) { if (e != "\n") return; INCOM = 0 }
  if (INQ != "") {
    if (QESC) { QESC = 0; if (e == INQ || e == "\\") { qadd(e); return } }
    if (e == "\\") { qadd(e); QESC = 1; return }
    if (e == INQ) { qadd(e); INQ = ""; stadd(QTOK, QNL, QOVER); return }
    if (e == "\n") { qadd(" "); QNL++; return }
    if (e == "\r") { qadd(" "); return }
    qadd(e); return
  }
  if (DOLLAR) { if (e == "}") { wadd(e); DOLLAR = 0; return }; if (e != "\n") { wadd(e); return }; DOLLAR = 0 }
  if (WESC) { WESC = 0; if (e != "\n") { wadd(e); return } }
  if (e == "\n") { wflush(); SEP = 1; if (STARTED && !OVER) { STNL++; if (STNL >= ` + strconv.Itoa(maxStatementLines) + `) { OVER = 1; BUF = "" } }; return }
  if (e == " " || e == "\t" || e == "\014" || e == "\013" || e == "\r") { wflush(); SEP = 1; return }
  if (e == ";") { wflush(); if (stkept()) emit(BUF ";"); streset(); return }
  if (e == "{") {
    if (INW && WLAST == "$") { wadd(e); DOLLAR = 1; return }
    wflush(); DEPTH++
    if (stkept() && DEPTH <= ` + strconv.Itoa(maxBlockDepth) + `) emit(BUF " {"); else if (!DROPAT) DROPAT = DEPTH
    streset(); return
  }
  if (e == "}") { wflush(); streset(); if (DEPTH == 0) emit("}"); else { if (!DROPAT) emit("}"); if (DROPAT == DEPTH) DROPAT = 0; DEPTH-- }; return }
  if (!INW && e == "#") { INCOM = 1; SEP = 1; return }
  if (!INW && (e == "\"" || e == Q1)) { INQ = e; QTOK = e; QNL = 0; QESC = 0; QOVER = 0; return }
  if (e == "\\") WESC = 1
  wadd(e)
}
function stline(s,   n, A, k) {
  gsub(SPECIAL, "\n&\n", s)
  n = split(s, A, "\n")
  for (k = 1; k <= n; k++) if (A[k] != "") sttok(A[k])
  sttok("\n")
}
function tline(s) {
  if (++NLINES > ` + strconv.Itoa(maxConfigLines) + `) { TOOMANY = 1; return }
  if (OPTST) stline(s); else lline(s)
}
function tproc(r,   n, P, i) {
  if (BAD || TOOMANY) return
  if (substr(r, length(r)) == "\r") r = substr(r, 1, length(r) - 1)
  if (OPTST || !OPTCR || !index(r, "\r")) { tline(r); return }
  n = split(r, P, "\r")
  for (i = 1; i <= n; i++) tline(P[i])
}
function magic(r) { return substr(r, 1, 4) == "\376\355\376\355" || substr(r, 1, 4) == "\316\316\316\316" || substr(r, 1, 2) == "\005\002" || substr(r, 1, 2) == "\005\001" || substr(r, 1, 8) == "SQLite f" }
BEGIN {
  Q1 = sprintf("%c", 39)
  SPECIAL = "[ \t\014\013\r;{}#\"" Q1 "\\\\]"
  RUN = ""
  for (i = 0; i < ` + strconv.Itoa(RedactRunLength) + `; i++) RUN = RUN "[A-Za-z0-9+/=]"
  RUN = RUN "[A-Za-z0-9+/=]*"
  OSSL = "openssl x509 -outform PEM 2>/dev/null"
  na = split("` + strings.Join(certificateLabels, "|") + `", CL, "|")
  for (k = 1; k <= na; k++) CERTL[CL[k]] = 1
  na = split("` + strings.Join(publicPEMLabels, "|") + `", AL, "|")
  for (k = 1; k <= na; k++) ALLOW[AL[k]] = 1
  nt = split("` + sshKeyTable() + `", TT, ";")
  for (k = 1; k <= nt; k++) { split(TT[k], F, "|"); KMIN[F[1]] = F[2] + 0; KMAX[F[1]] = F[3] + 0; KP[F[1]] = F[4] }
  nk = split(ENVIRON["HC_KEEP"], KW, " ")
  for (k = 1; k <= nk; k++) {
    w = tolower(KW[k])
    if (w == "` + KeepOptStatements + `") OPTST = 1
    else if (w == "` + KeepOptBackslash + `") OPTBS = 1
    else if (w == "` + KeepOptIndent + `") OPTIND = 1
    else if (w == "` + KeepOptCR + `") OPTCR = 1
    else if (w == "` + KeepOptSections + `") OPTSEC = 1
    else if (w == "` + KeepOptAnySections + `") OPTANYSEC = 1
    else if (w == "` + KeepOptTags + `") OPTTAGS = 1
    else if (substr(w, 1, 1) == "@") BADOPT = 1
    else if (w != "") { K[w] = 1; NK++ }
  }
}
mode == "text" {
  r = $0
  if (NR == 1) {
    if (magic(r) || substr(r, 1, 2) == "\377\376" || substr(r, 1, 2) == "\376\377") BAD = 1
    if (substr(r, 1, 3) == "\357\273\277") { r = substr(r, 4); if (magic(r)) BAD = 1 }
  }
  if (index(r, "\001")) BAD = 1
  if (HAVE) tproc(PREV)
  PREV = r; HAVE = 1
  next
}
{
  s = $0
  if (NR == 1 && substr(s, 1, 3) == "\357\273\277") s = substr(s, 4)
  if (index(s, "\001")) POISON = 1
  if (substr(s, length(s)) == "\r") s = substr(s, 1, length(s) - 1)
}
mode == "public" {
  if (isbegin(s)) {
    INB = 0
    if (!parsebegin(s) || !(LAB in ALLOW)) { POISON = 1; next }
    INB = 1; BOK = 1; BN = 0; BB[++BN] = s
    if (substr(s, 1, 5) == "-----") BE = "-----END " LAB "-----"; else BE = "---- END " LAB " ----"
    next
  }
  if (INB) {
    if (s == BE) {
      INB = 0
      if (!BOK || !(LAB in CERTL) || substr(s, 1, 5) != "-----") next
      BB[++BN] = s; c = ""
      for (i = 1; i <= BN; i++) c = c BB[i] "\n"
      PUB[++NP] = c; PKIND[NP] = "C"; NCERT++
      next
    }
    if (isend(s)) { INB = 0; next }
    if (!bodyline(s)) BOK = 0
    BB[++BN] = s
    next
  }
  k = sshkey(s)
  if (k != "") { PUB[++NP] = k; PKIND[NP] = "S" }
  next
}
mode == "identify" {
  if (isbegin(s)) {
    if (inpub) unterm = 1
    inpub = 0
    ok = parsebegin(s); pub = ok && (LAB in ALLOW)
    if (!pub && namespriv(s)) priv = 1
    if (!ok) { bad = 1; next }
    nl++
    if (nl <= 64) print "label:" LAB
    if (pub) inpub = 1; else nonpub = 1
    next
  }
  if (inpub) { if (isend(s)) inpub = 0; next }
  if (match(s, RUN)) orun = 1
  if (substr(s, 1, 1) == "#" || s ~ /^[ \t]*$/) next
  if (sshkey(s) != "") sshl++; else sshbad = 1
}
END {
  if (mode == "text") {
    if (HAVE && PREV != "") tproc(PREV)
    if (BAD || BADOPT || !NK) exit 8
    if (TOOMANY || OUTB > ` + strconv.Itoa(maxConfigOutput) + `) exit 7
    for (i = 1; i <= NO; i++) print OUT[i]
    print "vista-redactions:" (NRED + 0) > "/dev/stderr"
    exit 0
  }
  if (mode == "public") {
    if (POISON || NP == 0) exit 8
    if (NCERT && ENVIRON["HC_OPENSSL"] != "1") exit 12
    for (i = 1; i <= NP; i++) {
      if (PKIND[i] == "S") { print PUB[i]; continue }
      fflush()
      printf "%s", PUB[i] | OSSL
      if (close(OSSL) != 0) NDROP++
    }
    print "vista-refused:" (NDROP + 0) > "/dev/stderr"
    exit 0
  }
  if (inpub) unterm = 1
  print "flags:" (bad + 0) " " (nonpub + 0) " " (unterm + 0) " " (priv + 0) " " (orun + 0) " " (sshbad + 0) " " (sshl + 0) " " (nl + 0)
}`

// readPrelude starts every script that reads a file. $1 is the path, $2 the
// platform, $3 the byte bound. It refuses with an exit code rather than a
// message (3 missing, 4 permission denied, 5 directory, 6 not a regular file,
// 10 cannot pin, 11 could not open for another reason), then opens the file
// ONCE, on fd 3, and takes its identity (the PIN) from that descriptor:
//
//   - Linux: stat of /proc/self/fd/3, the open file itself: device, inode,
//     size, modification and change times with nanoseconds (%y, %z), type.
//   - macOS: `stat -f ... <&3`, which BSD stat answers with fstat of its
//     standard input: device, inode, size, modification and change times as
//     seconds with nanoseconds (%Fm, %Fc; whole seconds if that stat lacks
//     the F format), mode. (stat of /dev/fd/3 answers for the devfs node,
//     not the file, and a second open of /dev/fd/3 shares fd 3's offset.)
//
// The size and type come from the pin, so they describe the file that will
// be read. ReadFile and ReadText then read fd 3 exactly ONCE, from offset 0
// (`head -c "$size" <&3`), into an awk program that decides from that one
// buffer; the shell holds what awk decided, takes the pin AGAIN
// (readRepin), and prints only if nothing changed, else exits 9 having
// printed nothing. A file rewritten in place while it is read (same inode,
// same size: `dd conv=notrunc`) gives awk a mixture of two versions, and a
// mixture can join a kept word of one version to a secret of the other; the
// second pin catches the rewrite by its times. What it cannot catch is a
// rewrite whose times the file system does not move (a write in the same
// clock tick as the one before the pin, on a kernel with coarse timestamps).
//
// "Permission denied" is reported only when the host's own error says so: a
// path that vanishes during a swap is not a permission problem.
//
// `[ -f ]` runs before the open, so a FIFO is never opened (a FIFO swapped in
// between the test and the open would block until the command timeout).
const readPrelude = `p=$1; plat=$2; max=$3; keep=$4
coarse=0
case $plat in *-coarse) coarse=1; plat=${plat%-coarse};; esac
if [ ! -e "$p" ]; then
  if [ -L "$p" ]; then exit 3; fi
  e=$(stat -- "$p" 2>&1 >/dev/null)
  case $e in *"Permission denied"*) exit 4;; esac
  exit 3
fi
if [ -d "$p" ]; then exit 5; fi
if [ ! -f "$p" ]; then exit 6; fi
if [ ! -r "$p" ]; then
  e=$(head -c 1 -- "$p" 2>&1 >/dev/null)
  case $e in *"Permission denied"*) exit 4;; *"No such file"*) exit 3;; esac
  exit 11
fi
exec 3< "$p" || exit 11
if [ "$plat" = darwin ]; then
  fmt='%d:%i:%z:%m:%c:%Fm:%Fc:%p'
  if [ "$coarse" = 1 ]; then fmt='%d:%i:%z:%m:%c:%p'; fi
  pin=$(stat -f "$fmt" <&3 2>/dev/null) || { fmt='%d:%i:%z:%m:%c:%p'; pin=$(stat -f "$fmt" <&3 2>/dev/null); }
  F=$p
else
  fmt='%d:%i:%s:%Y:%Z:%y:%z:%f'
  if [ "$coarse" = 1 ]; then fmt='%d:%i:%s:%Y:%Z:%f'; fi
  pin=$(stat -L -c "$fmt" /proc/self/fd/3 2>/dev/null)
  F=/proc/self/fd/3
fi
if [ -z "$pin" ]; then exit 10; fi
case $plat:${pin##*:} in darwin:100*|linux:8???) ;; *) exit 6;; esac
size=${pin#*:}; size=${size#*:}; mt=${size#*:}; size=${size%%:*}
ct=${mt#*:}; mt=${mt%%:*}; ct=${ct%%:*}
case $size:$mt:$ct in *[!0-9:]*|:*|*::*|*:) exit 10;; esac
`

// readQuiet refuses (exit 9) a file whose modification or change time is
// within 3 seconds of the host's clock, or ahead of it: a file still being
// written. With it, a file system whose times have whole seconds (macOS
// without stat's F format, coarse file systems) cannot hide a rewrite from
// the second pin: a rewrite during the read moves a time that was at least
// three seconds old to "now".
const readQuiet = `now=$(date +%s)
case $now in ''|*[!0-9]*) exit 10;; esac
if [ "$((now - mt))" -lt 3 ] || [ "$((now - ct))" -lt 3 ]; then exit 9; fi
`

// readRepin ends ReadFile's and ReadText's scripts: $out holds what awk
// printed followed by "." and awk's exit code. The file is pinned again from
// fd 3; a different pin exits 9 and prints nothing, else the output is
// printed and the script exits with awk's code.
const readRepin = `
rc=${out##*.}; out=${out%.*}
if [ "$plat" = darwin ]; then pin2=$(stat -f "$fmt" <&3 2>/dev/null); else pin2=$(stat -L -c "$fmt" /proc/self/fd/3 2>/dev/null); fi
if [ "$pin2" != "$pin" ]; then exit 9; fi
printf '%s' "$out"
exit "$rc"`

// identifyScript prints ONLY markers: the size, the first eight bytes in hex,
// whether the scanned window holds a NUL, whether a UTF-16 file names a
// private key, up to 64 valid labels and the rule flags. It reads at most the
// byte bound. (Identification is advisory: ReadFile decides again from its
// own single read.)
var identifyScript = readPrelude + `w=$size
if [ "$w" -gt "$max" ]; then w=$max; fi
win() { if [ "$w" -gt 0 ]; then head -c "$w" -- "$F"; fi; }
magic=$(head -c 8 -- "$F" | od -An -v -tx1 | tr -d ' \n')
printf 'size:%s\nmagic:%s\n' "$size" "$magic"
n=$(win | tr -d '\000' | wc -c)
if [ "$((n + 0))" -eq "$w" ]; then echo nul:0; else echo nul:1; fi
u=0
case $magic in fffe*|feff*) u=$(win | tr -d '\000\376\377' | awk '{ x = toupper($0) } index(x, "BEGIN") && index(x, "PRIVATE") { f = 1 } END { print f + 0 }');; esac
echo "utf16:$u"
win | tr '\000' '\001' | awk -v mode=identify '` + awkRules + `'
exit 0`

// readScript reads the pinned file ONCE and prints only what publicContent
// would, after the re-pin: exit 7 over the bound, 8 not public (and so when
// every certificate block was refused and nothing is left: the shell decides
// that from the empty output, because macOS awk's close() does not report
// openssl's exit status), 9 changed while read, 12 no openssl; nothing
// printed for any of them. The "vista-refused:N" count on stderr is
// informational and is 0 where close() does not report a failure.
var readScript = readPrelude + readQuiet + `if [ "$size" -gt "$max" ]; then exit 7; fi
if [ "$size" -eq 0 ]; then exit 8; fi
if command -v openssl >/dev/null 2>&1; then o=1; else o=0; fi
out=$(head -c "$size" <&3 | tr '\000\001' '\001\002' | HC_OPENSSL=$o awk -v mode=public '` + awkRules + `'; printf '.%s' "$?")
case $out in .0) out=.8;; esac` + readRepin

// readTextScript reads the pinned file ONCE and prints only what
// filterConfig would, after the re-pin; $4 is the space-separated keep list.
// Exit 7 over the bound or the line bound, 8 not text, 9 changed while read.
var readTextScript = readPrelude + readQuiet + `if [ "$size" -gt "$max" ]; then exit 7; fi
out=$({ if [ "$size" -gt 0 ]; then head -c "$size" <&3; fi; printf '\n'; } | tr '\000' '\001' | HC_KEEP=$keep awk -v mode=text '` + awkRules + `'; printf '.%s' "$?")` + readRepin

// errChanged is a read the host refused because the file changed between
// being opened and being read.
var errChanged = errors.New("hostcrypto: the file changed while it was read")

// ErrNoHostParser is a remote read of a file holding certificates from a
// host with no certificate parser (no openssl on a Unix host). A
// certificate crosses only as a parser's re-encoding, so nothing crosses;
// the caller reports the section partial, with this as the reason.
var ErrNoHostParser = errors.New("hostcrypto: the host has no certificate parser (openssl), so no certificate can be read from it")

// scriptArgv runs one of the fixed scripts on path.
func (t *RemoteUnixTarget) scriptArgv(script, path string, bound int64, extra ...string) []string {
	argv := []string{"env", "LC_ALL=C", "sh", "-c", script, "sh", path, t.platformArg(), strconv.FormatInt(bound, 10)}
	return append(argv, extra...)
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
		return fmt.Errorf("hostcrypto: %s: the host could not describe the open file", path)
	case 12:
		return fmt.Errorf("%s: %w", path, ErrNoHostParser)
	case 2, 11:
		return fmt.Errorf("hostcrypto: %s: could not be opened", path)
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
	var sawSize, sawMagic, sawNul, sawUTF16, sawFlags bool
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
		case line == "utf16:0", line == "utf16:1":
			in.utf16Private, sawUTF16 = line == "utf16:1", true
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
	if !sawSize || !sawMagic || !sawNul || !sawUTF16 || !sawFlags {
		return in, errors.New("incomplete answer")
	}
	if len(in.labels) > in.nLabel {
		return in, errors.New("inconsistent answer")
	}
	in.utf16 = bytes.HasPrefix(in.magic, []byte{0xFF, 0xFE}) || bytes.HasPrefix(in.magic, []byte{0xFE, 0xFF})
	if !in.utf16 && in.utf16Private {
		return in, errors.New("inconsistent answer")
	}
	return in, nil
}

// ReadFile returns the PUBLIC CONTENT of a file (publicContent: its
// certificates, each as the host's openssl re-encodes it, and its genuine
// SSH public key lines, nothing else), decided twice before any byte crosses
// and once after:
//
//  1. Identify, decided in Go with the full rule (name included). Not public
//     (Identity.Public: a certificate or SSH key file): ErrNotPublic, and no
//     command that prints content is sent. Over the read cap:
//     ErrFileTooLarge, and nothing is sent.
//  2. readScript, which refuses a file written in the last 3 seconds, reads
//     the pinned file once, decides from that one buffer which blocks are
//     certificate blocks and which lines are key lines, feeds each
//     certificate block ALONE to `openssl x509 -outform PEM` (a block it
//     cannot parse is dropped and counted on stderr; one invocation per
//     block because one over a bundle reads only the first certificate),
//     holds what openssl and awk printed, pins the file again and prints
//     only if nothing changed. A host without openssl answers
//     ErrNoHostParser for a file with a certificate block, and prints
//     nothing.
//  3. What arrives must be exactly its own public content, or it is dropped
//     (cleared): a backstop, and a check that the host ran the rule.
//
// OpenSSL 3 takes the first certificate of a CERTIFICATE block that has
// bytes after it (LibreSSL and Go refuse such a block); what crosses is
// still that certificate's encoding, never the bytes after it.
//
// A DER certificate is not readable remotely (see publicContent).
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

// recheckPublic requires bytes a remote read returned to be exactly their
// own public content, and every SSH key line to parse as the key it claims
// to be. Anything else is cleared and refused.
func recheckPublic(path string, b []byte, readCap int64) ([]byte, error) {
	if int64(len(b)) > readCap {
		clear(b)
		return nil, fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	}
	again, ok := publicContent(b)
	if !ok || !bytes.Equal(again, b) || !sshLinesParse(b) {
		clear(b)
		return nil, fmt.Errorf("%s: %w (the host returned more than public content)", path, ErrNotPublic)
	}
	return b, nil
}

// ReadText returns the lines of a configuration file a parser asked for,
// narrowed and redacted ON THE HOST by readTextScript (filterConfig's rule).
// An empty keep is refused before any command is sent. What arrives is
// checked: it must hold no NUL and be unchanged by the rule applied again.
func (t *RemoteUnixTarget) ReadText(ctx context.Context, path string, keep []string) ([]byte, int, error) {
	words, err := keepArg(keep)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	readCap := t.readCap()
	out, stderr, exit, err := t.runner.Run(ctx, t.scriptArgv(readTextScript, path, readCap, words))
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
	return checkFiltered(path, out, n)
}

// keepArg validates keep and joins it for the host: directive names of
// [A-Za-z0-9._*+/-] and the options ([KeepOptStatements] and the rest). Anything else, a ";" or an unknown "@" entry included, is refused
// rather than escaped. A keep with no directive name is ErrNotPublic.
func keepArg(keep []string) (string, error) {
	var words []string
	names := 0
	for _, w := range keep {
		if w == "" {
			continue
		}
		if w[0] == '@' {
			switch asciiLower(w) {
			case KeepOptStatements, KeepOptBackslash, KeepOptIndent, KeepOptCR, KeepOptSections, KeepOptAnySections, KeepOptTags:
				words = append(words, asciiLower(w))
				continue
			}
			return "", fmt.Errorf("hostcrypto: keep option %q is not one of the options", w)
		}
		if !isKeepWord(w) {
			return "", fmt.Errorf("hostcrypto: keep word %q is not a directive name", w)
		}
		words = append(words, asciiLower(w))
		names++
	}
	if names == 0 {
		return "", ErrNotPublic
	}
	return strings.Join(words, " "), nil
}

// checkFiltered is the backstop for a host's filtering. It cannot re-derive
// which lines the host kept (a continuation line is kept for its
// predecessor's sake), so it checks the properties that matter: no NUL or
// 0x01, no PEM BEGIN line, no run of RedactRunLength base64 characters, no
// more lines than the bound. Anything else is cleared and refused.
func checkFiltered(path string, out []byte, n int) ([]byte, int, error) {
	bad := bytes.IndexByte(out, 0) >= 0 || bytes.IndexByte(out, 1) >= 0
	lines := 0
	for _, s := range configLines(out) {
		lines++
		if isBeginLine(s) || hasLongRun(s) {
			bad = true
		}
	}
	if bad || lines > maxConfigLines {
		clear(out)
		return nil, 0, fmt.Errorf("%s: %w (the host's filtering left material)", path, ErrNotPublic)
	}
	return out, n, nil
}

// sshLinesParse requires every SSH key line of a public read to decode and
// parse as a key of the type it declares: stronger than the host's prefix
// and length rule, which needs no decoder.
func sshLinesParse(b []byte) bool {
	for _, s := range pemLines(b) {
		typ, blob, ok := strings.Cut(s, " ")
		if !ok {
			continue
		}
		if _, known := findSSHKeyType(typ); !known {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil {
			return false
		}
		pub, err := ssh.ParsePublicKey(raw)
		if err != nil || pub.Type() != typ {
			return false
		}
	}
	return true
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
