// Package repo finds the root of this module for tests that read a file
// outside their own package (standards/, fixtures/, scripts/).
//
// The root is the nearest directory above the working directory whose go.mod
// declares this module. A test that cannot find it FAILS: a check that skips
// when its input is missing is a check that cannot fail.
package repo

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Module is the module path the root's go.mod must declare.
const Module = "github.com/vistasecurity/vistaplatform-agents"

// Root returns the module root, or an error when no go.mod above the working
// directory declares Module.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if declaresModule(filepath.Join(dir, "go.mod")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod declaring " + Module + " above the working directory")
		}
		dir = parent
	}
}

// MustRoot is Root for a test: it fails the test instead of returning an error.
func MustRoot(t testing.TB) string {
	t.Helper()
	root, err := Root()
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	return root
}

// Path joins elements onto the module root.
func Path(t testing.TB, elem ...string) string {
	t.Helper()
	return filepath.Join(append([]string{MustRoot(t)}, elem...)...)
}

func declaresModule(gomod string) bool {
	f, err := os.Open(gomod) //nolint:gosec // walking up from the working directory is the point
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module ")) == Module
		}
	}
	return false
}
