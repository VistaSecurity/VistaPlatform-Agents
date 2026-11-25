package hostcrypto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// Package-wide default bounds, shared by every target and by [Options].
const (
	defaultMaxFiles     = 200000
	defaultMaxFileBytes = 10 << 20 // 10 MiB
	// maxDeniedListed bounds how many unreadable directory paths a
	// [ListError] carries; DeniedCount has the total.
	maxDeniedListed = 100
)

// errNotRegular is returned by Identify, ReadFile and ReadText for a path
// that exists but is not a regular file: a FIFO, a device, a socket. Opening
// a FIFO to look at it blocks forever, so every target checks first. It is
// deliberately not ErrNotPublic (nothing was refused for being private) and
// not ErrNotExist.
var errNotRegular = errors.New("hostcrypto: not a regular file")

// ListError is what [Target.List] returns when the walk finished but did not
// see everything. The files it did see are returned beside it and are real.
//
// It matches [ErrPermission] with errors.Is when any directory was denied and
// [ErrListTruncated] when a bound stopped the walk. Unreadable and OverSize
// are counts of files that were seen and could not be returned; they do not
// match either sentinel, but they make the error non-nil, so nothing a walk
// passes over is silent.
type ListError struct {
	// Denied are directories the account could not read, at most 100 of
	// them. DeniedCount is how many there were in all.
	Denied      []string
	DeniedCount int
	// Truncated is true when MaxFiles (or a remote output bound) stopped the
	// walk.
	Truncated bool
	// Unreadable counts entries that could not be stat'ed or read for a
	// reason other than a permission denial (a name too long, an I/O error,
	// an entry gone mid-walk).
	Unreadable int
	// OverSize counts regular files skipped for MaxSizeBytes.
	OverSize int
}

// Error says what happened in a few words. It names counts, not paths.
func (e *ListError) Error() string {
	var parts []string
	if e.DeniedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d directories could not be read", e.DeniedCount))
	}
	if e.Unreadable > 0 {
		parts = append(parts, fmt.Sprintf("%d entries could not be read", e.Unreadable))
	}
	if e.OverSize > 0 {
		parts = append(parts, fmt.Sprintf("%d files over the size bound were skipped", e.OverSize))
	}
	if e.Truncated {
		parts = append(parts, "the listing stopped at a bound")
	}
	if len(parts) == 0 {
		return "hostcrypto: listing incomplete"
	}
	return "hostcrypto: listing incomplete: " + strings.Join(parts, "; ")
}

// Is lets errors.Is match the sentinels this error stands for.
func (e *ListError) Is(target error) bool {
	switch target {
	case ErrPermission:
		return e.DeniedCount > 0
	case ErrListTruncated:
		return e.Truncated
	}
	return false
}

// addDenied records one unreadable directory.
func (e *ListError) addDenied(p string) {
	e.DeniedCount++
	if len(e.Denied) < maxDeniedListed {
		e.Denied = append(e.Denied, p)
	}
}

// orNil returns e when it records anything, else nil.
func (e *ListError) orNil() error {
	if e.DeniedCount == 0 && !e.Truncated && e.Unreadable == 0 && e.OverSize == 0 {
		return nil
	}
	return e
}

// LocalTarget is the host the agent runs on. Commands run through host
// inventory's [hostinventory.LocalRunner]; files are read with the standard
// library, so a private key file is parsed in the agent's memory and never
// leaves it.
type LocalTarget struct {
	runner   *hostinventory.LocalRunner
	ids      *idCache
	maxBytes int64
}

// NewLocalTarget returns the target for the host the agent runs on.
func NewLocalTarget() *LocalTarget {
	return &LocalTarget{runner: hostinventory.NewLocalRunner(), ids: newIDCache(), maxBytes: defaultMaxFileBytes}
}

// SetMaxFileBytes sets the read bound (ReadFile, ReadText, and the window
// Identify scans). n <= 0 restores the default of 10 MiB. [Collect] sets it
// from Options.MaxFileBytes.
func (t *LocalTarget) SetMaxFileBytes(n int64) {
	if n <= 0 {
		n = defaultMaxFileBytes
	}
	t.maxBytes = n
}

// Run executes argv locally, without a shell.
func (t *LocalTarget) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return t.runner.Run(ctx, argv)
}

// Local is true: bytes read here stay on this host.
func (t *LocalTarget) Local() bool { return true }

// readWindow opens path as a regular file (never blocking on a FIFO swapped
// in after the check) and reads at most limit bytes. It returns the bytes and
// the file's size.
func readWindow(path string, limit int64) ([]byte, int64, error) {
	f, size, err := openRegular(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, 0, mapOSError(path, err)
	}
	return b, size, nil
}

// ReadFile reads a local file within the read bound. A larger file is
// [ErrFileTooLarge], not a truncated read: a cut-off PEM bundle parses and is
// silently short.
func (t *LocalTarget) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, size, err := readWindow(path, t.maxBytes+1)
	if err != nil {
		return nil, err
	}
	if size > t.maxBytes || int64(len(b)) > t.maxBytes {
		clear(b)
		return nil, fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	}
	return b, nil
}

// ReadText returns the lines of a configuration file a parser asked for,
// by [FilterConfigText], the rule every remote host applies, so a parser
// sees the same bytes in both modes. An empty keep is refused before the file
// is opened.
func (t *LocalTarget) ReadText(ctx context.Context, path string, keep []string) ([]byte, int, error) {
	if !newKeepSet(keep).usable() {
		return nil, 0, fmt.Errorf("%s: %w (no keep words)", path, ErrNotPublic)
	}
	b, err := t.ReadFile(ctx, path)
	if err != nil {
		return nil, 0, err
	}
	defer clear(b)
	return configResult(path, b, keep)
}

// configResult runs filterConfig and maps its refusals to the sentinels.
func configResult(path string, b []byte, keep []string) ([]byte, int, error) {
	out, n, st := filterConfig(b, keep)
	switch st {
	case configOK:
		return out, n, nil
	case configTooManyLines:
		return nil, 0, fmt.Errorf("%s: %w (more than %d lines)", path, ErrFileTooLarge, maxConfigLines)
	case configNoKeep:
		return nil, 0, fmt.Errorf("%s: %w (no keep words)", path, ErrNotPublic)
	}
	return nil, 0, fmt.Errorf("%s: %w (not text)", path, ErrNotPublic)
}

// Stat describes path itself, not what a link points at.
func (t *LocalTarget) Stat(ctx context.Context, path string) (FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return FileInfo{}, err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return FileInfo{}, mapOSError(path, err)
	}
	return t.fileInfo(path, fi), nil
}

// fileInfo turns an os.FileInfo into this package's, with the platform's
// ownership and permission reading (target_local_unix.go,
// target_local_windows.go). A Windows junction, which Go reports as an
// irregular file rather than a link, is reported as a link when it can be
// read as one.
func (t *LocalTarget) fileInfo(path string, fi os.FileInfo) FileInfo {
	out := FileInfo{
		Path:       path,
		Size:       fi.Size(),
		ModifiedAt: fi.ModTime().UTC().Format(time.RFC3339),
		IsDir:      fi.IsDir(),
	}
	if isLinkLike(fi) {
		if target, err := os.Readlink(path); err == nil {
			out.IsSymlink, out.LinkTarget, out.IsDir = true, target, false
		} else if fi.Mode()&fs.ModeSymlink != 0 {
			out.IsSymlink = true
		}
	}
	localOwnership(path, fi, &out, t.ids)
	return out
}

// isLinkLike is a symbolic link, or an irregular entry that may be a
// junction or mount point.
func isLinkLike(fi fs.FileInfo) bool {
	return fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0
}

// Identify inspects the first read-bound bytes of path: the same window a
// remote target scans, so both modes see the same labels and flags. It
// follows a symbolic link, as a read would, and refuses anything that is not
// a regular file without opening it.
func (t *LocalTarget) Identify(ctx context.Context, path string) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	buf, size, err := readWindow(path, t.maxBytes)
	if err != nil {
		return Identity{}, err
	}
	defer clear(buf)
	return identityFrom(path, inspect(buf, size)), nil
}

// List walks root with filepath.WalkDir, which never follows a symbolic link:
// a link (or junction) is reported as itself and never descended.
//
// Unreadable directories and entries do not stop the walk; they are counted
// into a [ListError] returned with the files that were seen, as are files
// skipped for size. A cancelled context returns what was seen and the
// context's error.
func (t *LocalTarget) List(ctx context.Context, root string, opts ListOptions) ([]FileInfo, error) {
	root = filepath.Clean(root)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, mapOSError(root, err)
	}
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}
	maxSize := opts.MaxSizeBytes
	if maxSize <= 0 {
		maxSize = defaultMaxFileBytes
	}
	excludes := cleanExcludes(opts.Exclude)
	rootDev, rootDevOK := localDevice(root, rootInfo)

	var out []FileInfo
	lerr := &ListError{}

	// keep applies the Names and size filters, counting size skips.
	keep := func(path string, info fs.FileInfo) bool {
		if len(opts.Names) > 0 && !matchAnyName(filepath.Base(path), opts.Names) {
			return false
		}
		if info.Mode().IsRegular() && info.Size() > maxSize {
			lerr.OverSize++
			return false
		}
		return true
	}

	// A root that is itself a file or a link is its own listing.
	if !rootInfo.IsDir() {
		if (rootInfo.Mode().IsRegular() || isLinkLike(rootInfo)) && keep(root, rootInfo) {
			out = append(out, t.fileInfo(root, rootInfo))
		}
		return out, lerr.orNil()
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			if path == root {
				return mapOSError(root, err)
			}
			switch {
			case errors.Is(err, fs.ErrPermission):
				lerr.addDenied(path)
			case errors.Is(err, fs.ErrNotExist):
				// Removed mid-walk: the host changed under us, not a gap.
			default:
				lerr.Unreadable++
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path == root {
			return nil
		}
		if isExcluded(path, excludes) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		depth := strings.Count(rel, string(filepath.Separator))

		typ := d.Type()
		switch {
		case d.IsDir():
			if depth >= opts.MaxDepth {
				return fs.SkipDir
			}
			if !opts.CrossFilesystems && rootDevOK {
				if info, ierr := d.Info(); ierr == nil {
					if dev, ok := localDevice(path, info); ok && dev != rootDev {
						return fs.SkipDir
					}
				}
			}
			return nil
		case typ&fs.ModeSymlink != 0, typ.IsRegular(), typ&fs.ModeIrregular != 0:
			info, ierr := d.Info()
			if ierr != nil {
				if !errors.Is(ierr, fs.ErrNotExist) {
					lerr.Unreadable++
				}
				return nil
			}
			if typ&fs.ModeIrregular != 0 {
				// A junction is reported as a link; any other irregular
				// entry is not a file.
				if _, lerr2 := os.Readlink(path); lerr2 != nil {
					return nil
				}
			}
			if !keep(path, info) {
				return nil
			}
			if len(out) >= maxFiles {
				lerr.Truncated = true
				return fs.SkipAll
			}
			out = append(out, t.fileInfo(path, info))
			return nil
		default:
			// Devices, sockets, FIFOs: not files, and a FIFO opened to
			// identify it would block.
			return nil
		}
	})
	if walkErr != nil {
		// A cancelled context, or a root that became unreadable: what was
		// seen is still returned.
		return out, walkErr
	}
	return out, lerr.orNil()
}

// idCache remembers owner and group names by id, so a walk of 200,000 files
// does not look the same uid up 200,000 times.
type idCache struct {
	mu    sync.Mutex
	names map[string]string
}

func newIDCache() *idCache { return &idCache{names: map[string]string{}} }

// lookup returns the cached name for key, computing it once with fn.
func (c *idCache) lookup(key string, fn func() string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.names[key]; ok {
		return v
	}
	v := fn()
	c.names[key] = v
	return v
}

// matchAnyName reports whether base matches one of the glob patterns. A
// malformed pattern matches nothing.
func matchAnyName(base string, patterns []string) bool {
	for _, p := range patterns {
		if ok, err := filepath.Match(p, base); err == nil && ok {
			return true
		}
	}
	return false
}

// cleanExcludes normalises exclusion prefixes once per walk.
func cleanExcludes(ex []string) []string {
	out := make([]string, 0, len(ex))
	for _, e := range ex {
		if e == "" {
			continue
		}
		out = append(out, filepath.Clean(e))
	}
	return out
}

// isExcluded reports whether path is an excluded prefix or below one. "/proc"
// excludes "/proc/1" but not "/procfs".
func isExcluded(path string, excludes []string) bool {
	for _, e := range excludes {
		if path == e || strings.HasPrefix(path, strings.TrimSuffix(e, string(filepath.Separator))+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// mapOSError wraps an os error in this package's sentinel, keeping the path
// (never content) for the message.
func mapOSError(path string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: %w", path, ErrNotExist)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s: %w", path, ErrPermission)
	}
	return err
}

// StatIdentifyMany is the single calls in a loop: nothing is saved locally
// by batching.
func (t *LocalTarget) StatIdentifyMany(ctx context.Context, paths []string) ([]PathInfo, error) {
	out := make([]PathInfo, 0, len(paths))
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		out = append(out, statIdentifySingle(ctx, t, p))
	}
	return out, ctx.Err()
}

var _ BatchTarget = (*LocalTarget)(nil)
