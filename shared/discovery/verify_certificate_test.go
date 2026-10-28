package discovery

// The verify_certificate unit (#2746 slice 2) against real loopback listeners:
// the engine believes it is talking to enumTarget on the port under test and
// the recording dialer maps that port onto the listener, so every connection
// the unit makes is counted.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func verifyEngine(t *testing.T, rec *recordingDialer) *UnitEngine {
	t.Helper()
	e, err := NewUnitEngine(PaceNormal, nil, nil, WithDialer(rec))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// sniServer serves a fresh self-signed certificate for cn and records the SNI
// each client presented.
type sniServer struct {
	addr        string
	fingerprint string
	mu          sync.Mutex
	sni         []string
}

func startSNIServer(t *testing.T, cn string) *sniServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	srv := &sniServer{fingerprint: hex.EncodeToString(sum[:])}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			srv.mu.Lock()
			srv.sni = append(srv.sni, h.ServerName)
			srv.mu.Unlock()
			return nil, nil
		},
	}
	host, port := speakServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		_ = tc.Handshake()
	})
	srv.addr = net.JoinHostPort(host, fmt.Sprint(port))
	return srv
}

func (s *sniServer) presented() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sni...)
}

func TestVerifyCertificate_ObservedReturnsTheServedLeafWithPEM(t *testing.T) {
	srv := startSNIServer(t, "www.declared.test")
	rec := &recordingDialer{remap: map[uint16]string{8443: srv.addr}}
	out := verifyEngine(t, rec).VerifyCertificate(context.Background(), VerifyInput{Addr: enumTarget, Port: 8443, SNI: "www.declared.test"})

	v := out.Verification
	if v == nil || v.Outcome != VerifyOutcomeObserved {
		t.Fatalf("outcome = %+v, want observed", v)
	}
	if v.Leaf == nil || v.Leaf.FingerprintSHA256 != srv.fingerprint {
		t.Fatalf("leaf fingerprint = %v, want the served %s", v.Leaf, srv.fingerprint)
	}
	if !strings.Contains(v.Leaf.CertificatePEM, "BEGIN CERTIFICATE") || v.Leaf.ChainOrder != 0 {
		t.Errorf("leaf must carry its PEM in the canonical shape: %+v", v.Leaf)
	}
	if len(v.ServedChain) != 1 || v.Address != enumTarget.String() || v.Port != 8443 {
		t.Errorf("served chain / endpoint = %d, %s:%d", len(v.ServedChain), v.Address, v.Port)
	}
	if err := v.Validate(); err != nil {
		t.Errorf("a result the engine produced must validate: %v", err)
	}
	if got := srv.presented(); len(got) != 1 || got[0] != "www.declared.test" {
		t.Errorf("SNI presented = %v, want exactly [www.declared.test]", got)
	}
	// One connection, to the one port: a person asked for this endpoint to be
	// checked, not measured.
	if ports := rec.dialedPorts(); len(ports) != 1 || ports[0] != 8443 {
		t.Errorf("dials = %v, want exactly one to 8443", ports)
	}
	if out.Host.OpenCount != 1 || out.Host.PortsRequested != 1 {
		t.Errorf("host counts = %+v", out.Host)
	}
}

func TestVerifyCertificate_WrongCertificateIsReportedAsServed(t *testing.T) {
	// The unit reports what the endpoint served; deciding it is the "wrong"
	// certificate is the platform's job (it holds the declared row). The
	// fingerprint must be the served one, never something remembered.
	a := startSNIServer(t, "a.declared.test")
	b := startSNIServer(t, "b.declared.test")
	rec := &recordingDialer{remap: map[uint16]string{443: b.addr}}
	out := verifyEngine(t, rec).VerifyCertificate(context.Background(), VerifyInput{Addr: enumTarget, Port: 443, SNI: "a.declared.test"})
	v := out.Verification
	if v == nil || v.Outcome != VerifyOutcomeObserved || v.Leaf == nil {
		t.Fatalf("outcome = %+v", v)
	}
	if v.Leaf.FingerprintSHA256 == a.fingerprint || v.Leaf.FingerprintSHA256 != b.fingerprint {
		t.Errorf("fingerprint %s, want the served b (%s), not a (%s)", v.Leaf.FingerprintSHA256, b.fingerprint, a.fingerprint)
	}
	if !strings.Contains(v.Leaf.SubjectDN, "b.declared.test") {
		t.Errorf("subject = %q", v.Leaf.SubjectDN)
	}
}

func TestVerifyCertificate_RefusedIsNotObservable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	closed := ln.Addr().String()
	_ = ln.Close() // nothing listens there now: the connect is refused
	rec := &recordingDialer{remap: map[uint16]string{443: closed}}
	out := verifyEngine(t, rec).VerifyCertificate(context.Background(), VerifyInput{Addr: enumTarget, Port: 443})
	v := out.Verification
	if v == nil || v.Outcome != VerifyOutcomeNotObservable || v.ErrorClass != VerifyErrorRefused {
		t.Fatalf("outcome = %+v, want not_observable / refused", v)
	}
	if v.Leaf != nil || v.Error == "" {
		t.Errorf("a refused verification carries the reason and no certificate: %+v", v)
	}
	if out.Host.Closed != 1 {
		t.Errorf("a refused port counts closed: %+v", out.Host)
	}
	if err := v.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestVerifyCertificate_NoTLSIsNotObservable(t *testing.T) {
	host, port := speakServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		time.Sleep(200 * time.Millisecond)
	})
	rec := &recordingDialer{remap: map[uint16]string{443: net.JoinHostPort(host, fmt.Sprint(port))}}
	out := verifyEngine(t, rec).VerifyCertificate(context.Background(), VerifyInput{Addr: enumTarget, Port: 443, SNI: "www.declared.test"})
	v := out.Verification
	if v == nil || v.Outcome != VerifyOutcomeNotObservable {
		t.Fatalf("outcome = %+v, want not_observable", v)
	}
	if v.ErrorClass == "" || v.ErrorClass == VerifyErrorRefused {
		t.Errorf("a port that answered without TLS has a handshake error class, got %q", v.ErrorClass)
	}
	if out.Host.OpenCount != 1 {
		t.Errorf("the port answered, so it counts open: %+v", out.Host)
	}
}

func TestVerifyCertificateValidate(t *testing.T) {
	cases := map[string]CertificateVerification{
		"observed without a certificate": {Outcome: VerifyOutcomeObserved, Address: "10.0.0.1", Port: 443},
		"not observable without a class": {Outcome: VerifyOutcomeNotObservable, Address: "10.0.0.1", Port: 443},
		"unknown outcome":                {Outcome: "mismatch", Address: "10.0.0.1", Port: 443, ErrorClass: "x"},
		"bad address":                    {Outcome: VerifyOutcomeNotObservable, Address: "www.example.com", Port: 443, ErrorClass: "dns"},
		"bad port":                       {Outcome: VerifyOutcomeNotObservable, Address: "10.0.0.1", Port: 0, ErrorClass: "refused"},
	}
	for name, v := range cases {
		if err := v.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (VerifyCertificatePlan{CertificateID: "x", Port: 443}).Validate(); err != nil {
		t.Errorf("plan: %v", err)
	}
	if err := (VerifyCertificatePlan{Port: 443}).Validate(); err == nil {
		t.Error("plan without a certificate accepted")
	}
}
