package agentlogs

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The agent's log on disk. A Windows service has no stderr, so without a file
// it has no log an operator can read on the host.

// RotatingFile is an append-only log file that moves itself to <path>.1
// once it would exceed maxBytes, replacing the previous backup.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

// OpenRotatingFile opens (creating it and its directory) the log at path for
// appending; it rotates at maxBytes.
func OpenRotatingFile(path string, maxBytes int64) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, maxBytes: maxBytes}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.file, r.size = f, info.Size()
	return nil
}

// Write appends p, rotating first if p would take the file past maxBytes. A
// write is never split across the two files.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		r.rotate()
	}
	if r.file == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate moves the current file to <path>.1. If the move fails (on Windows,
// a reader without delete sharing holds the file open) the agent keeps
// appending to the current file and tries again on a later write — losing log
// lines over a rotation would be worse than an oversized file.
func (r *RotatingFile) rotate() {
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	backup := r.path + ".1"
	// Windows will not rename over an existing file.
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
	_ = os.Rename(r.path, backup)
	// open() runs in Write, and re-reads the size: 0 after a rotation, the
	// current size if the rename failed.
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

// TeeStandardLog points the standard logger at ring, then a RotatingFile at
// path, then each of extra (stderr, where there is one). backfill, what was
// logged before the path was known (the ring's lines), is written to the file
// first. The ring comes first so a failing file (a full disk) never empties
// what the console can fetch.
func TeeStandardLog(path string, maxBytes int64, backfill []string, ring io.Writer, extra ...io.Writer) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("no log path")
	}
	f, err := OpenRotatingFile(path, maxBytes)
	if err != nil {
		return err
	}
	if len(backfill) > 0 {
		if _, err := f.Write([]byte(strings.Join(backfill, "\n") + "\n")); err != nil {
			_ = f.Close()
			return err
		}
	}
	log.SetOutput(NewTolerantWriter(append([]io.Writer{ring, f}, extra...)...))
	return nil
}

// NewTolerantWriter returns a writer that writes to every sink in order even
// when an earlier one fails, and reports the first error.
func NewTolerantWriter(writers ...io.Writer) io.Writer {
	return &tolerantWriter{writers: writers}
}

// tolerantWriter writes to every sink even when an earlier one fails, and
// reports the first error. io.MultiWriter stops at the first failing writer, so
// a full disk (file write fails) used to leave stderr, and so journald or the
// service log, with nothing at exactly the moment an operator needs it.
type tolerantWriter struct {
	writers []io.Writer
}

func (m *tolerantWriter) Write(p []byte) (int, error) {
	var firstErr error
	for _, w := range m.writers {
		if n, err := w.Write(p); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else if n != len(p) && firstErr == nil {
			firstErr = io.ErrShortWrite
		}
	}
	if firstErr != nil {
		return 0, firstErr
	}
	return len(p), nil
}
