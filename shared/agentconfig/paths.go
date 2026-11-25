package agentconfig

import (
	"fmt"
	"sort"
	"strings"
)

// Path lists: the one rule for the agent's "host crypto excluded paths"
// setting, shared by the platform's validation and the agent that applies the
// value, and the same rule a host_crypto job's options are held to
// (schemas/managed/v1/defs/host-crypto-job.json, $defs/path).
//
// A path list travels as a STRING in canonical form, one path per line,
// for the reason a port list does (ports.go): an agent older than the setting
// decodes the whole heartbeat answer through Value, and an array would cost
// it every setting. Lines rather than commas because a path may hold a comma
// or a space; it may not hold a line break, which no tool an operator uses
// can type into a path anyway.

// MaxPathListEntries bounds a path list. Each entry is checked against every
// directory a collection walks, so an unbounded list is an unbounded cost.
const MaxPathListEntries = 64

// MaxPathLength bounds one path, in bytes. Longer than any path the
// collectors accept on any platform they run on.
const MaxPathLength = 1024

// ParsePathList reads a path list typed by a person or sent by a client.
//
// Entries are separated by line breaks; surrounding blanks are trimmed and
// empty lines skipped, so "" is the empty list. The result is sorted with
// duplicates removed. Every unusable entry produces its own problem naming
// it, and any problem means the list as a whole is refused, as for ports.
func ParsePathList(s string) ([]string, []string) {
	return ParsePathListWith(s, MaxPathListEntries, CheckPath)
}

// ParsePathListWith is ParsePathList with a field's own bound and path rule
// (the sweep roots: at most MaxSweepRoots, CheckSweepRoot).
func ParsePathListWith(s string, max int, check func(string) string) ([]string, []string) {
	seen := map[string]struct{}{}
	var paths, problems []string
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }) {
		p := strings.TrimSpace(line)
		if p == "" {
			continue
		}
		if problem := check(p); problem != "" {
			problems = append(problems, problem)
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) > max {
		problems = append(problems, fmt.Sprintf("%d paths listed; at most %d are allowed", len(paths), max))
	}
	return paths, problems
}

// CheckPath says what is wrong with one path, or "" when nothing is. A path
// must be absolute for the platform it names: "/..." on Linux and macOS,
// "C:\..." (or "C:/...") or "\\server\share" on Windows. The agent cannot
// tell which platform a remote host runs before it connects, so both forms
// are accepted everywhere, and a path of the other form simply matches
// nothing.
func CheckPath(p string) string {
	if len(p) > MaxPathLength {
		return fmt.Sprintf("a path of %d bytes is longer than the %d allowed", len(p), MaxPathLength)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Sprintf("%q holds a control character", p)
		}
	}
	switch {
	case strings.HasPrefix(p, "/"):
	case len(p) >= 3 && isASCIILetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'):
	case strings.HasPrefix(p, `\\`):
	default:
		return fmt.Sprintf("%q is not an absolute path", p)
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			// Excluding /a/../b is excluding /b written so that a reader
			// cannot see it; say the path that is meant.
			return fmt.Sprintf("%q climbs with \"..\"; write the path it means", p)
		}
	}
	return ""
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// FormatPathList writes paths in canonical form: trimmed, sorted, without
// duplicates or unusable entries, one per line. The empty list is "".
func FormatPathList(paths []string) string {
	seen := map[string]struct{}{}
	keep := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || CheckPath(p) != "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		keep = append(keep, p)
	}
	sort.Strings(keep)
	return strings.Join(keep, "\n")
}

// MaxSweepRoots bounds the sweep-roots setting and a job's sweep_roots.
const MaxSweepRoots = 16

// IsFilesystemRoot reports whether p names a whole filesystem: "/", a drive
// root ("C:\", "C:/") or a share root ("\\server\share").
func IsFilesystemRoot(p string) bool {
	t := strings.TrimRight(p, `/\`)
	switch {
	case t == "":
		return true
	case len(t) == 2 && isASCIILetter(t[0]) && t[1] == ':':
		return true
	case strings.HasPrefix(p, `\\`):
		parts := strings.FieldsFunc(t, func(r rune) bool { return r == '\\' || r == '/' })
		return len(parts) <= 2
	}
	return false
}

// IsUnderHome reports whether p is in (or is) a home directory on any of the
// platforms the agent collects: /home, /Users, /root, /var/root, and a
// drive's \Users.
func IsUnderHome(p string) bool {
	q := strings.ReplaceAll(p, `\`, "/")
	if len(q) >= 2 && isASCIILetter(q[0]) && q[1] == ':' {
		q = q[2:]
	}
	q = strings.ToLower(q)
	for _, h := range []string{"/home", "/users", "/root", "/var/root"} {
		if q == h || strings.HasPrefix(q, h+"/") {
			return true
		}
	}
	return false
}

// CheckSweepRoot is CheckPath plus the rule a sweep root keeps: not a whole
// filesystem.
func CheckSweepRoot(p string) string {
	if problem := CheckPath(p); problem != "" {
		return problem
	}
	if IsFilesystemRoot(p) {
		return fmt.Sprintf("%q is a whole filesystem: a sweep of it would spend the file budget on the first directories it meets; name the directory the application keeps its keys in", p)
	}
	return ""
}

// ParsePathFor reads a path-list setting under its field's rules: the sweep
// roots at most MaxSweepRoots and never a whole filesystem, every other
// path list as ParsePathList.
func ParsePathFor(f Field, s string) ([]string, []string) {
	if f.Key == KeyHostCryptoSweepRoots {
		return ParsePathListWith(s, MaxSweepRoots, CheckSweepRoot)
	}
	return ParsePathList(s)
}
