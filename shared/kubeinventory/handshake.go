package kubeinventory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"
)

const kubeletDialTimeout = 5 * time.Second

// Handshake outcomes.
const (
	handshakeOK          = "ok"
	handshakeRefused     = "refused"
	handshakeTimeout     = "timeout"
	handshakeUnreachable = "unreachable"
	handshakeTLSError    = "tls_error"
)

// describeState fills a handshake from a completed TLS connection.
func describeState(h *Handshake, state *tls.ConnectionState, certs *certTable, roots *x509.CertPool) {
	h.Status = handshakeOK
	h.TLSVersion = tls.VersionName(state.Version)
	h.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	if state.CurveID != 0 {
		h.KeyExchangeGroup = clip(state.CurveID.String(), 64)
	}
	h.CertificateChain = certs.add(state.PeerCertificates)
	if len(state.PeerCertificates) > 0 && roots != nil {
		inter := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		// Whether it chains, not whether the name matches: a kubelet is
		// reached by address, and its certificate names the node.
		_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		h.ChainsToClusterCA = boolPtr(err == nil)
	}
}

// probeTLS completes one TLS handshake with address:port and closes the
// connection. It sends no request and presents no client certificate. The
// server's certificate is recorded, not trusted: verification is off because
// the point is to read whatever is served, a self-signed kubelet certificate
// included, and nothing is sent over the connection.
func probeTLS(ctx context.Context, address string, port int, certs *certTable, roots *x509.CertPool) Handshake {
	h := Handshake{Address: address, Port: port}
	ctx, cancel := context.WithTimeout(ctx, kubeletDialTimeout)
	defer cancel()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, //nolint:gosec // posture read: the certificate is recorded, nothing is sent
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		h.Status = classifyDialError(err)
		return h
	}
	defer func() { _ = conn.Close() }()
	state := conn.(*tls.Conn).ConnectionState()
	describeState(&h, &state, certs, roots)
	return h
}

func classifyDialError(err error) string {
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return handshakeRefused
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return handshakeTimeout
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return handshakeUnreachable
	}
	return handshakeTLSError
}
