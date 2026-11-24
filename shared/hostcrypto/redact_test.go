package hostcrypto

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

func TestRedactTextRules(t *testing.T) {
	q := strings.Repeat("Q", RedactRunLength)
	cases := []struct {
		name, in, out string
		n             int
	}{
		{"short run kept", strings.Repeat("Q", RedactRunLength-1) + "\n", strings.Repeat("Q", RedactRunLength-1) + "\n", 0},
		{"run at the bound", q + "\n", RedactedMarker + "\n", 1},
		{"two runs", "k: " + q + " v: " + q + "x\n", "k: " + RedactedMarker + " v: " + RedactedMarker + "\n", 2},
		{"= is in the class", "k=" + q + "\n", RedactedMarker + "\n", 1},
		{"hex is a subset", strings.Repeat("ab12", 16) + "\n", RedactedMarker + "\n", 1},
		{"names are broken by separators", "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n", "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n", 0},
		{"private block dropped", "a\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\nb\n", "a\nb\n", 1},
		{"unterminated block to EOF", "a\n-----BEGIN EC PRIVATE KEY-----\nAAAA\nb\n", "a\n", 1},
		{"one-line block", "a\n-----BEGIN PRIVATE KEY----- AAAA -----END PRIVATE KEY-----\nb\n", "a\nb\n", 1},
		{"lowercase label dropped", "-----BEGIN OpenVPN Static key V1-----\n0123abcd\n-----END OpenVPN Static key V1-----\nremote x\n", "remote x\n", 1},
		{"public block kept, body runs redacted", "-----BEGIN CERTIFICATE-----\n" + q + "\n-----END CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\n" + RedactedMarker + "\n-----END CERTIFICATE-----\n", 1},
		{"crlf kept", "a: " + q + "\r\nb\r\n", "a: " + RedactedMarker + "\r\nb\r\n", 1},
		{"no final newline kept", "a\nb: " + q, "a\nb: " + RedactedMarker, 1},
		{"dropped last line without newline", "a\n-----BEGIN PRIVATE KEY-----", "a\n", 1},
		{"empty", "", "", 0},
		{"only newline", "\n", "\n", 0},
		{"latin-1 bytes", "caf\xe9 \xff:" + q + "\n", "caf\xe9 \xff:" + RedactedMarker + "\n", 1},
	}
	for _, tc := range cases {
		out, n := RedactText([]byte(tc.in))
		if string(out) != tc.out || n != tc.n {
			t.Errorf("%s: got %q (%d), want %q (%d)", tc.name, out, n, tc.out, tc.n)
		}
		again, k := RedactText(out)
		if k != 0 || !reflect.DeepEqual(again, out) {
			t.Errorf("%s: not idempotent", tc.name)
		}
	}
	if !textRefused([]byte("a\x00b")) || !textRefused(magicJKS) || !textRefused([]byte("SQLite format 3")) || textRefused([]byte("plain\n")) {
		t.Error("textRefused")
	}
}

// tgtSecrets are the secrets planted in the corpus, generated per run.
type tgtSecrets struct {
	wg, wgPeer, bind, pin, tor, blob []byte
	keyPEM, keyDER                   []byte
}

func tgtRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// tgtCorpus is the configuration corpus of the review: every file type the
// redaction must handle, with secrets generated in the test.
func tgtCorpus(t *testing.T) (map[string][]byte, tgtSecrets) {
	t.Helper()
	certPEM, keyPEM, _, keyDER := tgtMaterial(t)
	s := tgtSecrets{
		wg: tgtRandom(t, 32), wgPeer: tgtRandom(t, 32), bind: tgtRandom(t, 32), pin: tgtRandom(t, 32),
		tor: tgtRandom(t, 64), blob: tgtRandom(t, 48), keyPEM: keyPEM, keyDER: keyDER,
	}
	b64 := base64.StdEncoding.EncodeToString
	pemLines := func(der []byte) string {
		e := b64(der)
		var b strings.Builder
		for len(e) > 64 {
			b.WriteString(e[:64] + "\n")
			e = e[64:]
		}
		return b.String() + e + "\n"
	}
	wg := "[Interface]\nPrivateKey = " + b64(s.wg) + "\nAddress = 10.0.0.1/24\nListenPort = 51820\n\n[Peer]\nPublicKey = " + b64(s.wgPeer) + "\nAllowedIPs = 10.0.0.2/32\n"
	c := map[string][]byte{
		"wg0.conf":         []byte(wg),
		"wg0-crlf.conf":    []byte(strings.ReplaceAll(wg, "\n", "\r\n")),
		"wg0-nonl.conf":    []byte(strings.TrimSuffix(wg, "\n")),
		"admin.conf":       []byte("apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    certificate-authority-data: " + b64(certPEM) + "\n    server: https://10.0.0.1:6443\n  name: lab\nusers:\n- name: admin\n  user:\n    client-certificate-data: " + b64(certPEM) + "\n    client-key-data: " + b64(keyPEM) + "\n"),
		"dashlabel.key":    []byte("-----BEGIN X-PRIVATE KEY-----\n" + pemLines(keyDER) + "-----END X-PRIVATE KEY-----\n"),
		"Kexample.private": []byte("Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: " + b64(s.bind) + "\nCreated: 20260101000000\n"),
		"nginx.conf": []byte("server {\n    listen 443 ssl;\n    ssl_certificate /etc/ssl/a.pem;\n    ssl_certificate_key /etc/ssl/private/a.key;\n" +
			"    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305';\n" +
			"    add_header Public-Key-Pins 'pin-sha256=\"" + b64(s.pin) + "\"; max-age=5184000';\n}\n"),
		"sshd_config": []byte("Port 22\nHostKey /etc/ssh/ssh_host_ed25519_key\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512\n" +
			"Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n#PermitRootLogin prohibit-password\n"),
		"java.security": []byte("security.provider.1=SUN\njdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, DTLSv1.0, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, ECDH\n" +
			"jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224, SHA1 usage SignedJAR & denyAfter 2019-01-01\n"),
		"haproxy-bundle.pem":   append(append([]byte(nil), certPEM...), keyPEM...),
		"unterminated.conf":    []byte("a = 1\n-----BEGIN RSA PRIVATE KEY-----\n" + pemLines(keyDER) + "b = 2\n"),
		"openvpn.key":          []byte("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n" + strings.Repeat(hex.EncodeToString(s.blob[:16])+"\n", 4) + "-----END OpenVPN Static key V1-----\n"),
		"one-line.conf":        []byte("k = -----BEGIN PRIVATE KEY----- " + b64(s.blob) + " -----END PRIVATE KEY-----\nafter = 1\n"),
		"latin1.conf":          []byte("name = caf\xe9 \xff\nsecret = " + b64(s.blob) + "\n"),
		"long-line.conf":       []byte(strings.Repeat("opt=value; ", 20000) + "tail=" + b64(s.blob) + "\n"),
		"boundary.conf":        []byte("r39 = " + strings.Repeat("A", RedactRunLength-1) + "\nr40 = " + strings.Repeat("B", RedactRunLength) + "\nh40 = " + strings.Repeat("ab", RedactRunLength/2) + "\nr41: " + strings.Repeat("C", RedactRunLength+1) + "\n"),
		"empty.conf":           {},
		"newline.conf":         []byte("\n"),
		"cert_then_secret.pem": append(append([]byte(nil), certPEM...), "PrivateKey: "+b64(s.bind)+"\n"...),
	}
	return c, s
}

// tgtRefusedCorpus are files ReadText must refuse as not text.
func tgtRefusedCorpus(t *testing.T, s tgtSecrets) map[string][]byte {
	return map[string][]byte{
		"hs_ed25519_secret_key": append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), s.tor...),
		"store.jks":             append(append([]byte(nil), magicJKS...), 'a', 'b', 'c'),
		"utf16.conf":            []byte("\xff\xfek\x00=\x00v\x00"),
		"nul-late.conf":         append([]byte(strings.Repeat("a", 9000)), 0),
	}
}

// TestRedactTextProjection: no 16-byte window of any planted secret survives
// RedactText, raw, hex or base64.
func TestRedactTextProjection(t *testing.T) {
	corpus, s := tgtCorpus(t)
	for name, b := range corpus {
		out, _ := RedactText(b)
		for _, secret := range [][]byte{s.wg, s.wgPeer, s.bind, s.pin, s.blob, s.keyDER, s.keyPEM} {
			if tgtLeaks(out, secret) {
				t.Errorf("%s: a planted secret survived redaction", name)
			}
		}
	}
}

// tgtPathRunner runs a real runner with a PATH that puts dir first, so the
// awk program can be run by another awk implementation.
type tgtPathRunner struct {
	inner hostinventory.Runner
	path  string
}

func (r tgtPathRunner) Run(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	if len(argv) > 1 && argv[0] == "env" {
		argv = append([]string{"env", "PATH=" + r.path}, argv[1:]...)
	}
	return r.inner.Run(ctx, argv)
}

func (r tgtPathRunner) ReadFile(ctx context.Context, p string) ([]byte, error) {
	return r.inner.ReadFile(ctx, p)
}

// tgtAwks returns the runners to run the parity corpus through: the
// system's awk, and busybox awk when installed (a second, independent
// implementation, standing in for the BWK awk of macOS).
func tgtAwks(t *testing.T) map[string]hostinventory.Runner {
	runners := map[string]hostinventory.Runner{"system awk": hostinventory.NewLocalRunner()}
	for _, impl := range []string{"busybox", "original-awk", "gawk", "mawk"} {
		bin, err := exec.LookPath(impl)
		if err != nil {
			continue
		}
		dir := t.TempDir()
		if impl == "busybox" {
			if err := os.WriteFile(filepath.Join(dir, "awk"), []byte("#!/bin/sh\nexec "+bin+" awk \"$@\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Symlink(bin, filepath.Join(dir, "awk")); err != nil {
			t.Fatal(err)
		}
		runners[impl] = tgtPathRunner{inner: hostinventory.NewLocalRunner(), path: dir + string(os.PathListSeparator) + os.Getenv("PATH")}
	}
	return runners
}

// TestReadTextParity runs the real host script (identify, read and read
// text) through LocalRunner over the corpus and requires the remote answer to
// equal the Go rules byte for byte: the redacted text and its count, the
// inspection, and the public decision.
func TestReadTextParity(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("Linux POSIX tools not available")
	}
	corpus, s := tgtCorpus(t)
	refused := tgtRefusedCorpus(t, s)
	dir := t.TempDir()
	for name, b := range corpus {
		tgtWrite(t, dir, name, b, 0o644)
	}
	for name, b := range refused {
		tgtWrite(t, dir, name, b, 0o644)
	}
	certPEM, _, _, _ := tgtMaterial(t)
	tgtWrite(t, dir, "cert.pem", certPEM, 0o644)
	tgtWrite(t, dir, "id_ed25519.pub", []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC3x9g5sQ1oB7g5rQ8a8d7a3r0C2bWq3pXvJb2bq9N7a u@h\n"), 0o644)
	ctx := context.Background()
	lt := NewLocalTarget()

	for impl, runner := range tgtAwks(t) {
		rt := NewRemoteUnixTarget(runner, "linux")
		t.Run(impl, func(t *testing.T) {
			for name, b := range corpus {
				p := filepath.Join(dir, name)
				want, wn := RedactText(b)
				got, n, err := rt.ReadText(ctx, p)
				if err != nil {
					t.Errorf("%s: remote ReadText: %v", name, err)
					continue
				}
				if string(got) != string(want) || n != wn {
					t.Errorf("%s: remote and Go differ:\nremote %q (%d)\n    go %q (%d)", name, tgtShort(got), n, tgtShort(want), wn)
				}
				for _, secret := range [][]byte{s.wg, s.wgPeer, s.bind, s.pin, s.blob, s.keyDER, s.keyPEM} {
					if tgtLeaks(got, secret) {
						t.Errorf("%s: a planted secret crossed in ReadText", name)
					}
				}
				lgot, ln, err := lt.ReadText(ctx, p)
				if err != nil || string(lgot) != string(want) || ln != wn {
					t.Errorf("%s: local ReadText differs (%v)", name, err)
				}
			}
			for name := range refused {
				p := filepath.Join(dir, name)
				if _, _, err := rt.ReadText(ctx, p); !errors.Is(err, ErrNotPublic) {
					t.Errorf("%s: remote ReadText = %v, want ErrNotPublic", name, err)
				}
				if _, _, err := lt.ReadText(ctx, p); !errors.Is(err, ErrNotPublic) {
					t.Errorf("%s: local ReadText = %v, want ErrNotPublic", name, err)
				}
			}
			// Identify and the host's own read decision agree with Go.
			all := map[string][]byte{"cert.pem": certPEM}
			for k, v := range corpus {
				all[k] = v
			}
			for k, v := range refused {
				all[k] = v
			}
			for name, b := range all {
				p := filepath.Join(dir, name)
				want := inspect(b, int64(len(b)))
				got, err := rt.identify(ctx, p)
				if err != nil {
					t.Errorf("%s: identify: %v", name, err)
					continue
				}
				if want.nul {
					// Behind a NUL awk implementations differ; the flag
					// alone decides, and it is computed by tr, not awk.
					if !got.nul {
						t.Errorf("%s: NUL not seen", name)
					}
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s: inspection differs:\nremote %+v\n    go %+v", name, got, want)
				}
				_, _, hostExit, _ := runner.Run(ctx, rt.scriptArgv(readScript, p, remoteUnixReadMax))
				hostPublic := hostExit == 0
				goPublic := identityFrom(p, want).Public()
				if hostPublic != goPublic {
					t.Errorf("%s: host decision %v, Go %v", name, hostPublic, goPublic)
				}
			}
			if b, err := rt.ReadFile(ctx, filepath.Join(dir, "id_ed25519.pub")); err != nil || len(b) == 0 {
				t.Errorf("ssh .pub ReadFile: %v", err)
			}
		})
	}
}

func tgtShort(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "..."
	}
	return string(b)
}

// TestRemoteUnixSwapRace is the reviewer's swap loop: while ReadFile reads
// swap.pem over and over, another goroutine keeps replacing it, by rename,
// with a certificate and with a private key. On Linux the read is pinned to
// the inode the checks examined, so no read may be refused AFTER its bytes
// crossed ("content changed after identification"), and no key may be
// returned.
func TestRemoteUnixSwapRace(t *testing.T) {
	if !tgtRealToolsAvailable() {
		t.Skip("Linux POSIX tools not available")
	}
	certPEM, keyPEM, _, _ := tgtMaterial(t)
	dir := t.TempDir()
	swap := filepath.Join(dir, "swap.pem")
	tgtWrite(t, dir, "swap.pem", certPEM, 0o644)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			content := certPEM
			if i%2 == 1 {
				content = keyPEM
			}
			tmp := filepath.Join(dir, "next.tmp")
			if os.WriteFile(tmp, content, 0o644) == nil {
				_ = os.Rename(tmp, swap)
			}
		}
	}()

	rt := NewRemoteUnixTarget(hostinventory.NewLocalRunner(), "linux")
	ok, before, after, other := 0, 0, 0, 0
	for i := 0; i < 300; i++ {
		b, err := rt.ReadFile(context.Background(), swap)
		switch {
		case err == nil:
			ok++
			if string(b) != string(certPEM) {
				t.Fatalf("read %d returned something other than the certificate", i)
			}
		case strings.Contains(err.Error(), "content changed after identification"):
			after++
		case errors.Is(err, ErrNotPublic), errors.Is(err, errChanged):
			before++
		default:
			other++
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("swap race: ok=%d refused-before=%d refused-after-crossing=%d other=%d", ok, before, after, other)
	if after != 0 {
		t.Fatalf("%d reads were refused after their bytes crossed", after)
	}
	if ok == 0 {
		t.Fatal("no read succeeded; the test proves nothing")
	}
}

// TestFIFOsNeverHang: a FIFO named like a certificate hung the local target
// forever. Every target must refuse it as not a regular file, quickly.
func TestFIFOsNeverHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs in the Windows file namespace")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo.pem")
	if out, err := exec.Command("mkfifo", fifo).CombinedOutput(); err != nil {
		t.Skipf("mkfifo: %v %s", err, out)
	}
	targets := map[string]Target{"local": NewLocalTarget()}
	if tgtRealToolsAvailable() {
		targets["remote-unix"] = NewRemoteUnixTarget(hostinventory.NewLocalRunner(), "linux")
	}
	for name, tg := range targets {
		ops := map[string]func(ctx context.Context) error{
			"Identify": func(ctx context.Context) error { _, err := tg.Identify(ctx, fifo); return err },
			"ReadFile": func(ctx context.Context) error { _, err := tg.ReadFile(ctx, fifo); return err },
			"ReadText": func(ctx context.Context) error { _, _, err := tg.ReadText(ctx, fifo); return err },
		}
		for op, f := range ops {
			done := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			go func() { done <- f(ctx) }()
			select {
			case err := <-done:
				if !errors.Is(err, errNotRegular) || errors.Is(err, ErrNotPublic) || errors.Is(err, ErrNotExist) {
					t.Errorf("%s %s: %v, want only errNotRegular", name, op, err)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("%s %s hung on a FIFO", name, op)
			}
			cancel()
		}
		if _, err := tg.Stat(context.Background(), fifo); err != nil {
			t.Errorf("%s Stat of a FIFO: %v", name, err)
		}
		files, _ := tg.List(context.Background(), dir, ListOptions{MaxDepth: 1})
		if len(files) != 0 {
			t.Errorf("%s List returned a FIFO", name)
		}
	}
}

// TestLongPathIsCounted is the reviewer's 4,150-character path: stat cannot
// name it, so it must be counted as unreadable, not dropped.
func TestLongPathIsCounted(t *testing.T) {
	if runtime.GOOS != "linux" || !tgtRealToolsAvailable() {
		t.Skip("needs Linux tools to build the tree")
	}
	dir := t.TempDir()
	certPEM, _, _, _ := tgtMaterial(t)
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// 21 components of 200 characters: past PATH_MAX (4096), built with
	// os.Root, which works relative to an open directory.
	comp := strings.Repeat("L", 200)
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 21; i++ {
		if err := r.Mkdir(comp, 0o755); err != nil {
			t.Skipf("cannot build a deep tree: %v", err)
		}
		next, err := r.OpenRoot(comp)
		_ = r.Close()
		if err != nil {
			t.Skipf("cannot build a deep tree: %v", err)
		}
		r = next
	}
	if err := r.WriteFile("deep.pem", certPEM, 0o644); err != nil {
		t.Skipf("cannot write in the deep tree: %v", err)
	}
	_ = r.Close()
	for name, tg := range map[string]Target{
		"local":       NewLocalTarget(),
		"remote-unix": NewRemoteUnixTarget(hostinventory.NewLocalRunner(), "linux"),
	} {
		files, err := tg.List(context.Background(), dir, ListOptions{MaxDepth: 30})
		var lerr *ListError
		if !errors.As(err, &lerr) || lerr.Unreadable == 0 {
			t.Errorf("%s: err = %v; the long path vanished silently", name, err)
		}
		if len(files) != 1 {
			t.Errorf("%s: %d files", name, len(files))
		}
	}
}
