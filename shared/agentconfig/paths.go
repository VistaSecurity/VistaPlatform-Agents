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
	seen := map[string]struct{}{}
	var paths, problems []string
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }) {
		p := strings.TrimSpace(line)
		if p == "" {
			continue
		}
		if problem := CheckPath(p); problem != "" {
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
	if len(paths) > MaxPathListEntries {
		problems = append(problems, fmt.Sprintf("%d paths listed; at most %d are allowed", len(paths), MaxPathListEntries))
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
