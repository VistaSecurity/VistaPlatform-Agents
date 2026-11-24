package hostcrypto

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
)

// tgtFakeTarget is an in-memory host implementing [Target], for the tests of
// everything that sits on a target: the collector, the registry, the passes.
// Later slices reuse it, so it behaves like the real targets where it
// matters:
//
//   - Paths are slash-separated and absolute. Parents are created on demand.
//   - Identify classifies the stored bytes exactly as the real targets do
//     (identityFrom over inspect of the read-bound window).
//   - A REMOTE fake (local=false) refuses ReadFile of anything not public with
//     ErrNotPublic, as RemoteUnixTarget and RemoteWindowsTarget do, so a pass
//     tested on it meets the same guard it meets in production. Both kinds
//     refuse a file over the read bound with ErrFileTooLarge.
//   - ReadText refuses a file that is not text and redacts with RedactText,
//     the rule every real target applies.
//   - A FIFO (fifo) is not a regular file: Identify and the reads return
//     errNotRegular, as the real targets do, and List skips it.
//   - List honours MaxDepth, MaxFiles, MaxSizeBytes, Exclude and Names, never
//     descends a symlink, and reports denied directories, unreadable entries
//     (unreadable), files over the size bound and truncation through a
//     *ListError.
//   - Run answers from a table keyed by the argv joined with spaces; an
//     unscripted command is "not installed" (exit 127).
//
// Every call is recorded as "<op> <path>" (ops: run, read, read-refused,
// readtext, stat, list, identify) so a test can assert what a pass asked for.
type tgtFakeTarget struct {
	local    bool
	maxBytes int64

	mu    sync.Mutex
	nodes map[string]*tgtNode
	runs  map[string]tgtResult
	calls []string
}

// tgtNode is one path in the fake tree.
type tgtNode struct {
	dir     bool
	content []byte
	link    string // symlink target when non-empty
	denied  bool   // every operation on it is ErrPermission
	fifo    bool   // not a regular file
	unread  bool   // stat works, but List counts it unreadable
	mode    uint32
	owner   string
}

func newTgtFakeTarget(local bool) *tgtFakeTarget {
	t := &tgtFakeTarget{local: local, maxBytes: defaultMaxFileBytes, nodes: map[string]*tgtNode{}, runs: map[string]tgtResult{}}
	t.nodes["/"] = &tgtNode{dir: true, mode: 0o755, owner: "root"}
	return t
}

func (t *tgtFakeTarget) ensureParents(p string) {
	for dir := path.Dir(p); ; dir = path.Dir(dir) {
		if _, ok := t.nodes[dir]; !ok {
			t.nodes[dir] = &tgtNode{dir: true, mode: 0o755, owner: "root"}
		}
		if dir == "/" {
			return
		}
	}
}

// file adds a regular file with mode 0644.
func (t *tgtFakeTarget) file(p string, content []byte) *tgtFakeTarget {
	return t.fileMode(p, content, 0o644)
}

// fileMode adds a regular file with the given permission bits.
func (t *tgtFakeTarget) fileMode(p string, content []byte, mode uint32) *tgtFakeTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureParents(p)
	t.nodes[p] = &tgtNode{content: append([]byte(nil), content...), mode: mode, owner: "root"}
	return t
}

// dir adds an empty directory.
func (t *tgtFakeTarget) dir(p string) *tgtFakeTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureParents(p)
	t.nodes[p] = &tgtNode{dir: true, mode: 0o755, owner: "root"}
	return t
}

// symlink adds a symbolic link.
func (t *tgtFakeTarget) symlink(p, target string) *tgtFakeTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureParents(p)
	t.nodes[p] = &tgtNode{link: target, mode: 0o777, owner: "root"}
	return t
}

// fifo adds a named pipe.
func (t *tgtFakeTarget) fifo(p string) *tgtFakeTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureParents(p)
	t.nodes[p] = &tgtNode{fifo: true, mode: 0o644, owner: "root"}
	return t
}

// unreadable marks an existing path as one List counts but cannot return.
func (t *tgtFakeTarget) unreadable(p string) *tgtFakeTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n, ok := t.nodes[p]; ok {
		n.unread = true
	}
	return t
}

// SetMaxFileBytes is the real targets' setter, so Collect threads the bound.
func (t *tgtFakeTarget) SetMaxFileBytes(n int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n <= 0 {
		n = defaultMaxFileBytes
	}
	t.maxBytes = n
}

// deny makes an existing path unreadable.
func (t *tgtFakeTarget) deny(p string) *tgtFakeTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n, ok := t.nodes[p]; ok {
		n.denied = true
	}
	return t
}

// script answers one command.
func (t *tgtFakeTarget) script(argv []string, r tgtResult) *tgtFakeTarget {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.runs[strings.Join(argv, " ")] = r
	return t
}

func (t *tgtFakeTarget) record(op, p string) {
	t.calls = append(t.calls, op+" "+p)
}

// recorded returns the calls so far.
func (t *tgtFakeTarget) recorded() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.calls...)
}

// called reports whether one exact call was made.
func (t *tgtFakeTarget) called(op, p string) bool {
	for _, c := range t.recorded() {
		if c == op+" "+p {
			return true
		}
	}
	return false
}

func (t *tgtFakeTarget) Local() bool { return t.local }

func (t *tgtFakeTarget) Run(_ context.Context, argv []string) ([]byte, []byte, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := strings.Join(argv, " ")
	t.record("run", key)
	r, ok := t.runs[key]
	if !ok {
		return nil, []byte("command not found"), 127, nil
	}
	return []byte(r.stdout), []byte(r.stderr), r.exit, r.err
}

// lookup finds a node, or the sentinel error a real target would return.
func (t *tgtFakeTarget) lookup(p string) (*tgtNode, error) {
	n, ok := t.nodes[p]
	if !ok {
		return nil, fmt.Errorf("%s: %w", p, ErrNotExist)
	}
	if n.denied {
		return nil, fmt.Errorf("%s: %w", p, ErrPermission)
	}
	return n, nil
}

// regularLocked follows links to a regular file's node.
func (t *tgtFakeTarget) regularLocked(p string) (*tgtNode, error) {
	n, err := t.lookup(p)
	for hops := 0; err == nil && n.link != ""; hops++ {
		if hops > 8 {
			return nil, fmt.Errorf("%s: %w", p, ErrNotExist)
		}
		n, err = t.lookup(n.link)
	}
	if err != nil {
		return nil, err
	}
	if n.dir {
		return nil, fmt.Errorf("hostcrypto: %s is a directory", p)
	}
	if n.fifo {
		return nil, fmt.Errorf("%s: %w", p, errNotRegular)
	}
	return n, nil
}

func (t *tgtFakeTarget) identifyLocked(p string) (Identity, error) {
	n, err := t.regularLocked(p)
	if err != nil {
		return Identity{}, err
	}
	w := n.content[:min(int64(len(n.content)), t.maxBytes)]
	return identityFrom(p, inspect(w, int64(len(n.content)))), nil
}

func (t *tgtFakeTarget) Identify(_ context.Context, p string) (Identity, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record("identify", p)
	return t.identifyLocked(p)
}

func (t *tgtFakeTarget) ReadFile(_ context.Context, p string) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, err := t.regularLocked(p)
	if err != nil {
		return nil, err
	}
	if !t.local {
		id, err := t.identifyLocked(p)
		if err != nil {
			return nil, err
		}
		if !id.Public() {
			t.record("read-refused", p)
			return nil, fmt.Errorf("%s: %w", p, ErrNotPublic)
		}
	}
	if int64(len(n.content)) > t.maxBytes {
		return nil, fmt.Errorf("%s: %w", p, ErrFileTooLarge)
	}
	t.record("read", p)
	return append([]byte(nil), n.content...), nil
}

func (t *tgtFakeTarget) ReadText(_ context.Context, p string) ([]byte, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record("readtext", p)
	n, err := t.regularLocked(p)
	if err != nil {
		return nil, 0, err
	}
	if int64(len(n.content)) > t.maxBytes {
		return nil, 0, fmt.Errorf("%s: %w", p, ErrFileTooLarge)
	}
	if textRefused(n.content) {
		return nil, 0, fmt.Errorf("%s: %w (not text)", p, ErrNotPublic)
	}
	out, k := RedactText(n.content)
	return out, k, nil
}

func (t *tgtFakeTarget) infoLocked(p string, n *tgtNode) FileInfo {
	world, group := n.mode&0o004 != 0, n.mode&0o040 != 0
	return FileInfo{
		Path: p, Size: int64(len(n.content)), Mode: n.mode, Owner: n.owner, Group: n.owner,
		WorldReadable: &world, GroupReadable: &group,
		ModifiedAt: "2026-11-24T00:00:00Z",
		IsDir:      n.dir, IsSymlink: n.link != "", LinkTarget: n.link,
	}
}

func (t *tgtFakeTarget) Stat(_ context.Context, p string) (FileInfo, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record("stat", p)
	n, err := t.lookup(p)
	if err != nil {
		return FileInfo{}, err
	}
	return t.infoLocked(p, n), nil
}

func (t *tgtFakeTarget) List(ctx context.Context, root string, opts ListOptions) ([]FileInfo, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record("list", root)
	rn, err := t.lookup(root)
	if err != nil {
		return nil, err
	}
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}
	maxSize := opts.MaxSizeBytes
	if maxSize <= 0 {
		maxSize = defaultMaxFileBytes
	}
	if !rn.dir {
		return []FileInfo{t.infoLocked(root, rn)}, nil
	}
	paths := make([]string, 0, len(t.nodes))
	for p := range t.nodes {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	prefix := strings.TrimSuffix(root, "/") + "/"
	lerr := &ListError{}
	var out []FileInfo
	var skip []string // directories not entered
	for _, p := range paths {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		under := false
		for _, s := range skip {
			if strings.HasPrefix(p, s+"/") {
				under = true
				break
			}
		}
		if under || isExcludedSlash(p, cleanExcludesSlash(opts.Exclude)) {
			continue
		}
		n := t.nodes[p]
		depth := strings.Count(strings.TrimPrefix(p, prefix), "/")
		if depth > opts.MaxDepth {
			continue
		}
		if n.dir {
			if n.denied {
				lerr.addDenied(p)
				skip = append(skip, p)
			}
			continue
		}
		if n.fifo {
			continue
		}
		if n.unread {
			lerr.Unreadable++
			continue
		}
		if len(opts.Names) > 0 && !matchAnyName(path.Base(p), opts.Names) {
			continue
		}
		if n.link == "" && int64(len(n.content)) > maxSize {
			lerr.OverSize++
			continue
		}
		if len(out) >= maxFiles {
			lerr.Truncated = true
			break
		}
		out = append(out, t.infoLocked(p, n))
	}
	return out, lerr.orNil()
}

var _ Target = (*tgtFakeTarget)(nil)
