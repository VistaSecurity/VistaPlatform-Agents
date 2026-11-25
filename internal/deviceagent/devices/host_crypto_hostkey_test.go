package devices

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// hkServer is an SSH server on loopback that presents a generated host key
// and refuses every login.
func hkServer(t *testing.T) (addr string, pub ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, errors.New("no")
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _, _, _ = ssh.NewServerConn(c, cfg); _ = c.Close() }()
		}
	}()
	return l.Addr().String(), signer.PublicKey()
}

// The managed remote path's host-key behaviour, exactly the runner's: with
// the account's known_hosts present, a host it does not list (or lists with
// another key) is refused before any credential is offered, and the failure
// says how to pin it; with no known_hosts file the key is accepted on first
// contact (here the login is then refused, which is not a host-key error).
func TestRemoteHostKeyPolicyAndHint(t *testing.T) {
	addr, pub := hkServer(t)
	host, portS, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portS)
	params := map[string]interface{}{"ip_address": host, "ssh_port": float64(port)}
	creds := map[string]interface{}{"username": "u", "password": "p-123456"}
	dial := func(knownHosts string) error {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		if knownHosts != "" {
			if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(knownHosts), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		r, err := buildRemoteRunner(hostinventory.TransportSSH, params, creds)
		if err == nil {
			if c, ok := r.(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
		return err
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _ := ssh.NewPublicKey(other.Public())

	err := dial(knownhosts.Line([]string{"other.example.test"}, pub) + "\n")
	if hint := HostKeyHint(err); err == nil || !strings.Contains(hint, "not in the known_hosts") {
		t.Fatalf("an unlisted host with a known_hosts present: err %v, hint %q", err, hint)
	}
	err = dial(knownhosts.Line([]string{knownhosts.Normalize(addr)}, otherPub) + "\n")
	if hint := HostKeyHint(err); err == nil || !strings.Contains(hint, "not the one known_hosts lists") {
		t.Fatalf("a listed host with another key: err %v, hint %q", err, hint)
	}
	err = dial(knownhosts.Line([]string{knownhosts.Normalize(addr)}, pub) + "\n")
	if err == nil || HostKeyHint(err) != "" {
		t.Fatalf("a listed host with its key: the login should fail, not the host key: %v", err)
	}
	err = dial("")
	if err == nil || HostKeyHint(err) != "" {
		t.Fatalf("no known_hosts: first contact should pass the host key: %v (hint %q)", err, HostKeyHint(err))
	}
}
