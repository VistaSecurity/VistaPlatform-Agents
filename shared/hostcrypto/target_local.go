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
	// identifyScanBytes is how much of a file the LOCAL target reads to find
	// PEM labels. A remote target's grep reads the whole file on the host,
	// but returns only the labels.
	identifyScanBytes = 1 << 20
	// maxDeniedListed bounds how many unreadable directory paths a
	// [ListError] carries; DeniedCount has the total.
	maxDeniedListed = 100
)

// ErrFileTooLarge is returned by a target's ReadFile for a file over the read
// bound (10 MiB). The collector records it as the "max_file_bytes" limit.
var ErrFileTooLarge = errors.New("hostcrypto: file exceeds the read bound")

// ListError is what [Target.List] returns when the walk finished but did not
// see everything: some directories could not be read, a bound stopped it, or
// both. The files it did see are returned beside it and are real.
//
// It matches [ErrPermission] with errors.Is when any directory was denied and
// [ErrListTruncated] when a bound stopped the walk, so a caller can test for
// either without a type assertion, and both when both happened.
type ListError struct {
	// Denied are directories the account could not read, at most 100 of
	// them. DeniedCount is how many there were in all.
	Denied      []string
	DeniedCount int
	// Truncated is true when MaxFiles (or a remote output bound) stopped the
	// walk.
	Truncated bool
}

// Error says what happened in a few words. It names a count, not the paths.
func (e *ListError) Error() string {
	var parts []string
	if e.DeniedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d directories could not be read", e.DeniedCount))
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
	if e.DeniedCount == 0 && !e.Truncated {
		return nil
	}
	return e
}

// LocalTarget is the host the agent runs on. Commands run through host
// inventory's [hostinventory.LocalRunner]; files are read with the standard
// library, so a private key file is parsed in the agent's memory and never
// leaves it.
type LocalTarget struct {
	runner *hostinventory.LocalRunner
	ids    *idCache
}

// NewLocalTarget returns the target for the host the agent runs on.
func NewLocalTarget() *LocalTarget {
	return &LocalTarget{runner: hostinventory.NewLocalRunner(), ids: newIDCache()}
}

// Run executes argv locally, without a shell.
func (t *LocalTarget) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	return t.runner.Run(ctx, argv)
}

// Local is true: bytes read here stay on this host.
func (t *LocalTarget) Local() bool { return true }

// ReadFile reads a local file of at most 10 MiB. A larger file is
// [ErrFileTooLarge], not a truncated read: a cut-off PEM bundle parses and is
// silently short.
func (t *LocalTarget) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // reading the host's files is this package's purpose
	if err != nil {
		return nil, mapOSError(path, err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err == nil {
		if fi.IsDir() {
			return nil, fmt.Errorf("hostcrypto: %s is a directory", path)
		}
		if fi.Size() > defaultMaxFileBytes {
			return nil, fmt.Errorf("%s: %w", path, ErrFileTooLarge)
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, defaultMaxFileBytes+1))
	if err != nil {
		return nil, mapOSError(path, err)
	}
	if len(b) > defaultMaxFileBytes {
		return nil, fmt.Errorf("%s: %w", path, ErrFileTooLarge)
	}
	return b, nil
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
// target_local_windows.go).
func (t *LocalTarget) fileInfo(path string, fi os.FileInfo) FileInfo {
	out := FileInfo{
		Path:       path,
		Size:       fi.Size(),
		ModifiedAt: fi.ModTime().UTC().Format(time.RFC3339),
		IsDir:      fi.IsDir(),
		IsSymlink:  fi.Mode()&fs.ModeSymlink != 0,
	}
	if out.IsSymlink {
		if target, err := os.Readlink(path); err == nil {
			out.LinkTarget = target
		}
	}
	localOwnership(path, fi, &out, t.ids)
	return out
}

// Identify reads the first [MagicBytes] of path and looks for PEM labels in
// its first 1 MiB. It follows a symbolic link, as a read would.
func (t *LocalTarget) Identify(ctx context.Context, path string) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	f, err := os.Open(path) //nolint:gosec // identifying the host's files is this package's purpose
	if err != nil {
		return Identity{}, mapOSError(path, err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err == nil && fi.IsDir() {
		return Identity{}, fmt.Errorf("hostcrypto: %s is a directory", path)
	}
	buf, err := io.ReadAll(io.LimitReader(f, identifyScanBytes))
	if err != nil {
		return Identity{}, mapOSError(path, err)
	}
	magic := buf
	if len(magic) > MagicBytes {
		magic = magic[:MagicBytes]
	}
	return identityFrom(path, magic, ScanPEMLabels(buf, maxPEMLabels), hasPrivateMarker(buf)), nil
}

// List walks root with filepath.WalkDir, which never follows a symbolic link:
// a link is reported as itself (IsSymlink, LinkTarget) and never descended.
//
// Unreadable directories do not stop the walk; they are collected into a
// [ListError] returned with the files that were seen. A cancelled context
// returns what was seen and the context's error.
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

	// A root that is itself a file or a link is its own listing.
	if !rootInfo.IsDir() {
		if keep := listKeep(root, rootInfo, opts.Names, maxSize); keep {
			out = append(out, t.fileInfo(root, rootInfo))
		}
		return out, nil
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			if path == root {
				return mapOSError(root, err)
			}
			if errors.Is(err, fs.ErrPermission) {
				lerr.addDenied(path)
			}
			// Anything else (a file removed mid-walk) is the host changing
			// under us, not a gap in what we were allowed to see.
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
		case d.Type()&fs.ModeSymlink != 0, d.Type().IsRegular():
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			if !listKeep(path, info, opts.Names, maxSize) {
				return nil
			}
			if len(out) >= maxFiles {
				lerr.Truncated = true
				return fs.SkipAll
			}
			out = append(out, t.fileInfo(path, info))
			return nil
		default:
			// Devices, sockets, FIFOs, Windows junctions: not files, and a
			// FIFO opened to identify it would block.
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

// listKeep applies the Names and size filters to one entry. Symbolic links
// are kept regardless of size: their size is the link's, not the file's.
func listKeep(path string, info fs.FileInfo, names []string, maxSize int64) bool {
	if len(names) > 0 && !matchAnyName(filepath.Base(path), names) {
		return false
	}
	if info.Mode().IsRegular() && info.Size() > maxSize {
		return false
	}
	return true
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
