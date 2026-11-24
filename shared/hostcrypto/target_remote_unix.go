package hostcrypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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
// mapping reads ("No such file or directory") is not translated.
type RemoteUnixTarget struct {
	runner   hostinventory.Runner
	platform string
}

// NewRemoteUnixTarget wraps r for a host whose platform is "linux" or
// "darwin". The two differ in stat's flags (GNU `-c`, BSD `-f`); anything else
// is treated as Linux, whose flags are also those of busybox.
func NewRemoteUnixTarget(r hostinventory.Runner, platform string) *RemoteUnixTarget {
	return &RemoteUnixTarget{runner: r, platform: platform}
}

// Run passes argv to the runner unchanged.
func (t *RemoteUnixTarget) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return t.runner.Run(ctx, argv)
}

// Local is false: bytes read here cross a connection.
func (t *RemoteUnixTarget) Local() bool { return false }

// ReadFile identifies path on the host first and refuses, with
// [ErrNotPublic], anything not identified as public. That refusal is the one
// place the "no private key byte crosses the connection" rule is enforced: on
// refusal no command that prints file content is run.
//
// The bytes that do arrive are identified again here, and dropped with
// ErrNotPublic if they are not public after all. That closes the window in
// which the file could be replaced between the two commands only after the
// fact (the bytes crossed); it exists so such a swap is never PARSED or
// reported, and is noted, not relied on.
func (t *RemoteUnixTarget) ReadFile(ctx context.Context, path string) ([]byte, error) {
	id, err := t.Identify(ctx, path)
	if err != nil {
		return nil, err
	}
	if !id.Public() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotPublic)
	}
	b, err := t.runner.ReadFile(ctx, path)
	if err != nil {
		return nil, err
	}
	return recheckPublic(path, b)
}

// recheckPublic classifies bytes a remote read returned and refuses them when
// they are not what Identify said. The buffer is cleared before it is
// dropped.
func recheckPublic(path string, b []byte) ([]byte, error) {
	if len(b) > defaultMaxFileBytes {
		clear(b)
		return nil, fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	}
	magic := b
	if len(magic) > MagicBytes {
		magic = magic[:MagicBytes]
	}
	id := identityFrom(path, magic, ScanPEMLabels(b, maxPEMLabels), hasPrivateMarker(b))
	if !id.Public() {
		clear(b)
		return nil, fmt.Errorf("%s: %w (content changed after identification)", path, ErrNotPublic)
	}
	return b, nil
}

// remotePEMPattern is the extended regular expression the host's grep runs
// for PEM labels. It is ScanPEMLabels's rule: one to 80 characters that are
// not a dash, in either the RFC 7468 or the RFC 4716 frame. Both GNU and BSD
// grep take -a, -o, -m, -E and -e.
const remotePEMPattern = `-----BEGIN [^-]{1,80}-----|---- BEGIN [^-]{1,80} ----`

// remotePrivatePattern is hasPrivateMarker's rule: a BEGIN header naming
// private material anywhere in the file, past the label bound.
const remotePrivatePattern = `BEGIN [^-]*PRIVATE`

// identifyScript prints ONLY markers: the first eight bytes as hex, whether a
// private header exists, and up to 64 label lines. The exit codes 3 to 5 say
// why it could not, so stderr is never parsed. It reads "$1" and nothing else.
const identifyScript = `p=$1
if [ ! -e "$p" ]; then exit 3; fi
if [ -d "$p" ]; then exit 5; fi
if [ ! -r "$p" ]; then exit 4; fi
printf 'magic:'
head -c 8 -- "$p" | od -An -v -tx1 | tr -d ' \n'
printf '\n'
if grep -a -q -i -E -e '` + remotePrivatePattern + `' -- "$p"; then echo 'private:1'; else echo 'private:0'; fi
grep -a -o -m 64 -E -e '` + remotePEMPattern + `' -- "$p" | head -n 64 | sed 's/^/label:/'
exit 0`

// Exit codes of identifyScript.
const (
	identifyExitNotExist   = 3
	identifyExitPermission = 4
	identifyExitDirectory  = 5
)

func (t *RemoteUnixTarget) identifyArgv(path string) []string {
	return []string{"env", "LC_ALL=C", "sh", "-c", identifyScript, "sh", path}
}

// Identify runs identifyScript on the host and classifies what it returns.
func (t *RemoteUnixTarget) Identify(ctx context.Context, path string) (Identity, error) {
	out, _, exit, err := t.runner.Run(ctx, t.identifyArgv(path))
	if err != nil {
		return Identity{}, err
	}
	switch exit {
	case 0:
	case identifyExitNotExist:
		return Identity{}, fmt.Errorf("%s: %w", path, ErrNotExist)
	case identifyExitPermission:
		return Identity{}, fmt.Errorf("%s: %w", path, ErrPermission)
	case identifyExitDirectory:
		return Identity{}, fmt.Errorf("hostcrypto: %s is a directory", path)
	default:
		return Identity{}, fmt.Errorf("hostcrypto: identify %s: exit %d", path, exit)
	}
	magic, labels, private, err := parseIdentifyOutput(out)
	if err != nil {
		return Identity{}, fmt.Errorf("hostcrypto: identify %s: %w", path, err)
	}
	return identityFrom(path, magic, labels, private), nil
}

// parseIdentifyOutput reads identifyScript's output. A missing private line
// is treated as "private present": an answer the script did not give must not
// make a file public.
func parseIdentifyOutput(out []byte) (magic []byte, labels []string, private bool, err error) {
	private = true
	sawMagic, sawPrivate := false, false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "magic:"):
			h := strings.TrimSpace(strings.TrimPrefix(line, "magic:"))
			b, derr := hex.DecodeString(h)
			if derr != nil || len(b) > MagicBytes {
				return nil, nil, true, errors.New("unreadable magic")
			}
			magic, sawMagic = b, true
		case line == "private:0":
			private, sawPrivate = false, true
		case line == "private:1":
			private, sawPrivate = true, true
		case strings.HasPrefix(line, "label:"):
			if len(labels) >= maxPEMLabels {
				continue
			}
			l := strings.TrimPrefix(line, "label:")
			if found := ScanPEMLabels([]byte(l), 1); len(found) == 1 {
				labels = append(labels, found[0])
			}
		}
	}
	if !sawMagic || !sawPrivate {
		return nil, nil, true, errors.New("incomplete answer")
	}
	return magic, labels, private, nil
}

// statFormat is the per-platform stat format: size, raw mode, owner and group
// names, numeric uid and gid, modification time (epoch seconds), then the
// name LAST so the output can be matched against the paths asked for even
// when a name holds a newline or the separator. GNU prints the mode in hex
// (%f), BSD in octal (%p).
func (t *RemoteUnixTarget) statArgv(paths []string) []string {
	argv := []string{"env", "LC_ALL=C", "stat"}
	if t.platform == hostinventory.PlatformDarwin {
		argv = append(argv, "-f", "%z|%p|%Su|%Sg|%u|%g|%m|%N")
	} else {
		argv = append(argv, "-c", "%s|%f|%U|%G|%u|%g|%Y|%n")
	}
	argv = append(argv, "--")
	return append(argv, paths...)
}

// Stat runs stat on one path (not following a link) and, for a link,
// readlink.
func (t *RemoteUnixTarget) Stat(ctx context.Context, path string) (FileInfo, error) {
	out, stderr, exit, err := t.runner.Run(ctx, t.statArgv([]string{path}))
	if err != nil {
		return FileInfo{}, err
	}
	if exit != 0 {
		return FileInfo{}, unixStderrError(path, stderr, exit)
	}
	infos := t.parseStat(out, []string{path})
	if len(infos) != 1 {
		return FileInfo{}, fmt.Errorf("hostcrypto: stat %s: unreadable answer", path)
	}
	fi := infos[0]
	if fi.IsSymlink {
		fi.LinkTarget = t.readlink(ctx, path)
	}
	return fi, nil
}

// readlink returns a link's target, or "" when it cannot be read.
func (t *RemoteUnixTarget) readlink(ctx context.Context, path string) string {
	out, _, exit, err := t.runner.Run(ctx, []string{"env", "LC_ALL=C", "readlink", "--", path})
	if err != nil || exit != 0 {
		return ""
	}
	return strings.TrimSuffix(string(out), "\n")
}

// parseStat matches stat's output against the paths asked for, in order. A
// path stat could not read prints nothing on stdout, so a record that does not
// end in the next expected name means that path failed and the next is tried.
func (t *RemoteUnixTarget) parseStat(out []byte, paths []string) []FileInfo {
	var infos []FileInfo
	rest := string(out)
	for _, p := range paths {
		rec, remain, ok := matchStatRecord(rest, p)
		if !ok {
			continue
		}
		rest = remain
		if fi, ok := t.parseStatFields(rec, p); ok {
			infos = append(infos, fi)
		}
	}
	return infos
}

// matchStatRecord finds "<7 fields>|<path>\n" at the start of s.
//
// One ambiguity remains and is accepted: if a path failed AND the next path
// is that path plus a newline and more, the failed path takes the next one's
// record and the next one is dropped. It mis-attributes metadata only; what a
// file IS is always asked of the host per path.
func matchStatRecord(s, path string) (fields string, rest string, ok bool) {
	suffix := "|" + path + "\n"
	// Seven fields hold no newline, so the record's end is the first
	// occurrence of the suffix after the first six separators.
	idx := 0
	for i := 0; i < 6; i++ {
		j := strings.IndexByte(s[idx:], '|')
		if j < 0 {
			return "", s, false
		}
		idx += j + 1
	}
	nl := strings.IndexByte(s[idx:], '|')
	if nl < 0 {
		return "", s, false
	}
	end := idx + nl
	if strings.ContainsRune(s[:end], '\n') || !strings.HasPrefix(s[end:], suffix) {
		return "", s, false
	}
	return s[:end], s[end+len(suffix):], true
}

// parseStatFields reads the seven fields of one stat record.
func (t *RemoteUnixTarget) parseStatFields(rec, path string) (FileInfo, bool) {
	f := strings.Split(rec, "|")
	if len(f) != 7 {
		return FileInfo{}, false
	}
	size, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return FileInfo{}, false
	}
	base := 16
	if t.platform == hostinventory.PlatformDarwin {
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

// List runs find on the host, then stat in batches. root must be absolute: a
// root starting with "-" would be read by find as an expression.
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
	if exit != 0 && len(out) == 0 && lerr.DeniedCount == 0 {
		return nil, unixStderrError(root, stderr, exit)
	}
	if len(out) >= byteCap {
		lerr.Truncated = true
	}
	paths := splitNUL(out)
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
		for _, fi := range t.parseStat(bout, batch) {
			if isExcludedSlash(fi.Path, excl) || fi.IsDir {
				continue
			}
			if !fi.IsSymlink && fi.Size > maxSize {
				continue
			}
			if len(infos) >= maxFiles {
				lerr.Truncated = true
				break
			}
			if fi.IsSymlink {
				fi.LinkTarget = t.readlink(ctx, fi.Path)
			}
			infos = append(infos, fi)
		}
	}
	if len(paths) > 0 {
		lerr.Truncated = true
	}
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

// parseFindStderr collects the directories find could not read and returns
// the sentinel error for the root itself, if the root was the problem. GNU
// quotes the path ("find: '/x': Permission denied"), BSD does not.
func parseFindStderr(stderr []byte, root string, lerr *ListError) error {
	var rootErr error
	for _, line := range strings.Split(string(stderr), "\n") {
		if !strings.HasPrefix(line, "find: ") {
			continue
		}
		body := strings.TrimPrefix(line, "find: ")
		var p, reason string
		if i := strings.LastIndex(body, ": "); i >= 0 {
			p, reason = body[:i], body[i+2:]
		} else {
			continue
		}
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
