package hostcrypto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// tgtWrite writes a file under dir, creating parents.
func tgtWrite(t *testing.T, dir, rel string, content []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// tgtRels returns the listed paths relative to dir, slash-separated, sorted.
func tgtRels(t *testing.T, dir string, files []FileInfo) []string {
	t.Helper()
	var out []string
	for _, f := range files {
		r, err := filepath.Rel(dir, f.Path)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, filepath.ToSlash(r))
	}
	sort.Strings(out)
	return out
}

// tgtTree builds the walk fixture:
//
//	a.pem  b.txt  big.bin(2 KiB)  d1/c.key  d1/d2/e.crt  d1/d2/d3/f.pem  skip/g.pem
func tgtTree(t *testing.T) string {
	t.Helper()
	certPEM, _, _, _ := tgtMaterial(t)
	dir := t.TempDir()
	tgtWrite(t, dir, "a.pem", certPEM, 0o644)
	tgtWrite(t, dir, "b.txt", []byte("hello\n"), 0o644)
	tgtWrite(t, dir, "big.bin", make([]byte, 2048), 0o644)
	tgtWrite(t, dir, "d1/c.key", []byte("x"), 0o600)
	tgtWrite(t, dir, "d1/d2/e.crt", certPEM, 0o644)
	tgtWrite(t, dir, "d1/d2/d3/f.pem", certPEM, 0o644)
	tgtWrite(t, dir, "skip/g.pem", certPEM, 0o644)
	return dir
}

func TestLocalTargetListBounds(t *testing.T) {
	dir := tgtTree(t)
	lt := NewLocalTarget()
	ctx := context.Background()
	all := []string{"a.pem", "b.txt", "big.bin", "d1/c.key", "d1/d2/d3/f.pem", "d1/d2/e.crt", "skip/g.pem"}

	cases := []struct {
		name      string
		opts      ListOptions
		want      []string
		truncated bool
	}{
		{"depth 0 is root's entries", ListOptions{MaxDepth: 0}, []string{"a.pem", "b.txt", "big.bin"}, false},
		{"depth 1", ListOptions{MaxDepth: 1}, []string{"a.pem", "b.txt", "big.bin", "d1/c.key", "skip/g.pem"}, false},
		{"depth 10", ListOptions{MaxDepth: 10}, all, false},
		{"exclude", ListOptions{MaxDepth: 10, Exclude: []string{filepath.Join(dir, "skip"), filepath.Join(dir, "d1", "d2")}},
			[]string{"a.pem", "b.txt", "big.bin", "d1/c.key"}, false},
		{"exclude is a prefix of whole elements", ListOptions{MaxDepth: 10, Exclude: []string{filepath.Join(dir, "d")}}, all, false},
		{"names", ListOptions{MaxDepth: 10, Names: []string{"*.pem", "*.key"}},
			[]string{"a.pem", "d1/c.key", "d1/d2/d3/f.pem", "skip/g.pem"}, false},
		{"bad glob matches nothing", ListOptions{MaxDepth: 10, Names: []string{"[", "*.txt"}}, []string{"b.txt"}, false},
		{"size", ListOptions{MaxDepth: 10, MaxSizeBytes: 1024}, []string{"a.pem", "b.txt", "d1/c.key", "d1/d2/d3/f.pem", "d1/d2/e.crt", "skip/g.pem"}, false},
		{"max files", ListOptions{MaxDepth: 10, MaxFiles: 2}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files, err := lt.List(ctx, dir, tc.opts)
			if tc.truncated {
				if !errors.Is(err, ErrListTruncated) {
					t.Fatalf("err = %v, want ErrListTruncated", err)
				}
				if errors.Is(err, ErrPermission) {
					t.Fatal("truncation also matched ErrPermission")
				}
				if len(files) != 2 {
					t.Fatalf("got %d files, want the 2 seen before the bound", len(files))
				}
				return
			}
			var lerr *ListError
			switch {
			case tc.name == "size":
				// The file over the bound is counted, not dropped silently.
				if !errors.As(err, &lerr) || lerr.OverSize != 1 || errors.Is(err, ErrListTruncated) || errors.Is(err, ErrPermission) {
					t.Fatalf("err = %v, want OverSize 1", err)
				}
			case err != nil:
				t.Fatalf("err = %v", err)
			}
			if got := tgtRels(t, dir, files); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestLocalTargetListFileInfo(t *testing.T) {
	dir := tgtTree(t)
	files, err := NewLocalTarget().List(context.Background(), dir, ListOptions{MaxDepth: 0, Names: []string{"a.pem"}})
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	f := files[0]
	if f.Size == 0 || f.ModifiedAt == "" || f.IsDir || f.IsSymlink || f.Owner == "" {
		t.Fatalf("incomplete FileInfo: %+v", f)
	}
	if runtime.GOOS != "windows" {
		if f.Mode != 0o644 || f.WorldReadable == nil || !*f.WorldReadable || f.GroupReadable == nil || !*f.GroupReadable || f.Group == "" {
			t.Fatalf("unix permissions: %+v", f)
		}
		key, err := NewLocalTarget().Stat(context.Background(), filepath.Join(dir, "d1", "c.key"))
		if err != nil {
			t.Fatal(err)
		}
		if key.Mode != 0o600 || *key.WorldReadable || *key.GroupReadable {
			t.Fatalf("0600 file: %+v", key)
		}
	}
}

func TestLocalTargetSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	dir := tgtTree(t)
	outside := t.TempDir()
	tgtWrite(t, outside, "secret.pem", []byte("x"), 0o644)
	// A link out of root, a link loop, and a link to a directory inside root.
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink(outside, filepath.Join(dir, "out")))
	must(os.Symlink(filepath.Join(dir, "loop"), filepath.Join(dir, "loop")))
	must(os.Symlink(dir, filepath.Join(dir, "d1", "up")))
	must(os.Symlink("a.pem", filepath.Join(dir, "alias.pem")))

	files, err := NewLocalTarget().List(context.Background(), dir, ListOptions{MaxDepth: 20})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	links := map[string]FileInfo{}
	for _, f := range files {
		if strings.Contains(f.Path, "secret.pem") {
			t.Fatalf("walked out of root through a link: %s", f.Path)
		}
		if f.IsSymlink {
			r, _ := filepath.Rel(dir, f.Path)
			links[filepath.ToSlash(r)] = f
		}
	}
	for _, want := range []string{"out", "loop", "d1/up", "alias.pem"} {
		if _, ok := links[want]; !ok {
			t.Errorf("symlink %s not reported", want)
		}
	}
	if links["alias.pem"].LinkTarget != "a.pem" {
		t.Errorf("LinkTarget = %q", links["alias.pem"].LinkTarget)
	}
	if got := tgtRels(t, dir, files); len(got) != 7+4 {
		t.Errorf("got %d entries: %q", len(got), got)
	}

	// A root that is a link is reported, not followed.
	root, err := NewLocalTarget().List(context.Background(), filepath.Join(dir, "out"), ListOptions{MaxDepth: 5})
	if err != nil || len(root) != 1 || !root[0].IsSymlink {
		t.Fatalf("link root: %+v %v", root, err)
	}
}

func TestLocalTargetDeniedSubdirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not deny on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	dir := tgtTree(t)
	locked := filepath.Join(dir, "d1", "d2")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	files, err := NewLocalTarget().List(context.Background(), dir, ListOptions{MaxDepth: 10})
	var lerr *ListError
	if !errors.As(err, &lerr) || !errors.Is(err, ErrPermission) || errors.Is(err, ErrListTruncated) {
		t.Fatalf("err = %v, want a ListError matching ErrPermission only", err)
	}
	if lerr.DeniedCount != 1 || len(lerr.Denied) != 1 || lerr.Denied[0] != locked {
		t.Fatalf("denied = %+v", lerr)
	}
	if strings.Contains(err.Error(), "d2") {
		t.Fatalf("error message names a path: %q", err.Error())
	}
	// The rest of the tree is still there.
	if got := tgtRels(t, dir, files); strings.Join(got, ",") != "a.pem,b.txt,big.bin,d1/c.key,skip/g.pem" {
		t.Fatalf("got %q", got)
	}

	// Identify and ReadFile on an unreadable file are ErrPermission.
	key := filepath.Join(dir, "d1", "c.key")
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalTarget().Identify(context.Background(), key); !errors.Is(err, ErrPermission) {
		t.Errorf("Identify: %v", err)
	}
	if _, err := NewLocalTarget().ReadFile(context.Background(), key); !errors.Is(err, ErrPermission) {
		t.Errorf("ReadFile: %v", err)
	}
}

func TestLocalTargetCancellation(t *testing.T) {
	dir := tgtTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewLocalTarget().List(ctx, dir, ListOptions{MaxDepth: 10})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	for name, f := range map[string]func() error{
		"Identify": func() error { _, err := NewLocalTarget().Identify(ctx, filepath.Join(dir, "a.pem")); return err },
		"ReadFile": func() error { _, err := NewLocalTarget().ReadFile(ctx, filepath.Join(dir, "a.pem")); return err },
		"Stat":     func() error { _, err := NewLocalTarget().Stat(ctx, filepath.Join(dir, "a.pem")); return err },
	} {
		if err := f(); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLocalTargetErrorsAndReads(t *testing.T) {
	dir := tgtTree(t)
	lt := NewLocalTarget()
	ctx := context.Background()
	missing := filepath.Join(dir, "nope")
	if _, err := lt.Stat(ctx, missing); !errors.Is(err, ErrNotExist) {
		t.Errorf("Stat: %v", err)
	}
	if _, err := lt.List(ctx, missing, ListOptions{}); !errors.Is(err, ErrNotExist) {
		t.Errorf("List: %v", err)
	}
	if _, err := lt.Identify(ctx, missing); !errors.Is(err, ErrNotExist) {
		t.Errorf("Identify: %v", err)
	}
	if _, err := lt.ReadFile(ctx, missing); !errors.Is(err, ErrNotExist) {
		t.Errorf("ReadFile: %v", err)
	}
	if _, err := lt.ReadFile(ctx, dir); err == nil {
		t.Error("ReadFile of a directory succeeded")
	}

	// The 10 MiB read bound, both sides of it.
	at := tgtWrite(t, dir, "at.bin", make([]byte, defaultMaxFileBytes), 0o644)
	over := tgtWrite(t, dir, "over.bin", make([]byte, defaultMaxFileBytes+1), 0o644)
	if b, err := lt.ReadFile(ctx, at); err != nil || len(b) != defaultMaxFileBytes {
		t.Errorf("at the bound: %d bytes, %v", len(b), err)
	}
	if _, err := lt.ReadFile(ctx, over); !errors.Is(err, ErrFileTooLarge) {
		t.Errorf("over the bound: %v", err)
	}
	if !lt.Local() {
		t.Error("Local() = false")
	}
}

func TestLocalTargetIdentify(t *testing.T) {
	certPEM, keyPEM, certDER, _ := tgtMaterial(t)
	dir := t.TempDir()
	lt := NewLocalTarget()
	ctx := context.Background()
	cases := []struct {
		rel     string
		content []byte
		class   Class
	}{
		{"c.pem", certPEM, ClassCertificate},
		{"k.pem", keyPEM, ClassPrivateKey},
		{"both.pem", append(append([]byte(nil), certPEM...), keyPEM...), ClassMixed},
		{"c.der", certDER, ClassUnknown},
		{"c.p12", certDER, ClassKeystore},
		{"nginx.conf", []byte("server {\n listen 443 ssl;\n}\n"), ClassText},
	}
	for _, tc := range cases {
		p := tgtWrite(t, dir, tc.rel, tc.content, 0o644)
		id, err := lt.Identify(ctx, p)
		if err != nil {
			t.Fatalf("%s: %v", tc.rel, err)
		}
		if id.Class != tc.class {
			t.Errorf("%s: class %q, want %q", tc.rel, id.Class, tc.class)
		}
		if len(id.Magic) > MagicBytes {
			t.Errorf("%s: %d magic bytes", tc.rel, len(id.Magic))
		}
	}
}

// tgtLeaks reports whether any 16-byte window of secret appears in out raw,
// hex-encoded or base64-encoded.
func tgtLeaks(out, secret []byte) bool {
	s := string(out)
	for i := 0; i+16 <= len(secret); i++ {
		w := secret[i : i+16]
		if strings.Contains(s, string(w)) || strings.Contains(strings.ToLower(s), hex.EncodeToString(w)) {
			return true
		}
		// Base64 of a window at each of the three alignments.
		for off := 0; off < 3 && i+off+15 <= len(secret); off++ {
			chunk := secret[i+off : i+off+15]
			if strings.Contains(s, base64.StdEncoding.EncodeToString(chunk)) {
				return true
			}
		}
	}
	return false
}

// TestIdentifyProjection: what Identify returns for a private key file, PEM
// or DER, carries no run of the key's bytes. Mutation-checked by making
// LocalTarget.Identify return the whole scanned buffer as Magic.
func TestIdentifyProjection(t *testing.T) {
	_, keyPEM, _, keyDER := tgtMaterial(t)
	dir := t.TempDir()
	for name, content := range map[string][]byte{"k.pem": keyPEM, "k.der": keyDER, "k.key": keyDER} {
		p := tgtWrite(t, dir, name, content, 0o600)
		id, err := NewLocalTarget().Identify(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		if tgtLeaks(out, keyDER) {
			t.Fatalf("%s: Identity carries private key bytes", name)
		}
		if id.Public() {
			t.Fatalf("%s: a private key identified as public (%q)", name, id.Class)
		}
	}
}
