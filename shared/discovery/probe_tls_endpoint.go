package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ContextDialFunc dials one address. It is the shape of net.Dialer.DialContext,
// so a caller's guarded dialer (dialguard, a sensor's own) plugs in directly.
type ContextDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// TLSEndpointOptions configures ProbeTLSEndpoint.
type TLSEndpointOptions struct {
	// Hostname is the SNI to present and the identity the certificate is
	// checked against. Empty means no SNI (the identity is then taken from the
	// certificate, see ResolveVerifyHost).
	Hostname string
	// Dial carries EVERY connection the probe makes: the main handshake, the
	// key-exchange support handshakes and the version enumeration. Nil means a
	// plain net.Dialer.
	Dial ContextDialFunc
	// EnumerateVersions also works out which TLS versions the server accepts
	// and which it refuses, one forced-version handshake per version the main
	// handshake did not already prove. A prober built WithoutSupportHandshakes
	// ignores it: that prober promised the target one handshake.
	EnumerateVersions bool
}

// ProbeTLSEndpoint handshakes host:port through opts.Dial and returns the
// shared TLS ProbeResult — certificates, validation, quality flags, OCSP, the
// negotiated key exchange (and, unless WithoutSupportHandshakes, classical /
// hybrid support), whether the server asked for a client certificate, and with
// EnumerateVersions the accepted and refused versions. Every handshake is bounded by the
// prober's timeout and by ctx.
//
// It is the entry point for a caller that already knows the endpoint — the
// standalone sensor's TLS enricher, device interrogation — as opposed to the
// scan engine, which identifies a port first. host is what opts.Dial is asked
// to reach: an address literal, or a name the caller's dialer resolves under
// its own guard.
func (p *Prober) ProbeTLSEndpoint(ctx context.Context, host string, port int, opts TLSEndpointOptions) (*ProbeResult, error) {
	dial := opts.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialOnce := func(ctx context.Context) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, p.timeout)
		defer cancel()
		return dial(dctx, "tcp", address)
	}

	conn, err := dialOnce(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	redial := func(timeout time.Duration) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return dial(dctx, "tcp", address)
	}
	res, err := probeTLSConn(ctx, p, conn, opts.Hostname, port, redial)
	if err != nil {
		return nil, err
	}
	if opts.EnumerateVersions && !p.noSupportHandshakes {
		_ = conn.Close() // the main handshake is done; hold one connection at a time
		accepted, refused := enumerateTLSVersions(ctx, dialOnce, opts.Hostname, p.timeout, negotiatedTLSVersion(res))
		applyTLSVersions(res, accepted)
		applyTLSVersionRefusals(res, refused)
	}
	return res, nil
}

// tlsVersionsNewestFirst is the order enumeration tests versions in, and the
// order an accepted list is reported in.
var tlsVersionsNewestFirst = []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10}

// MetaTLSVersionsRefused is the ProbeResult.Metadata key listing the TLS
// versions an enumeration saw the server refuse, newest first. It is absent
// when nothing was enumerated and when nothing was refused, so the absence of
// a version from it says nothing about that version.
const MetaTLSVersionsRefused = "tls_versions_refused"

// enumerateTLSVersions makes one forced-version handshake per TLS version,
// newest first, each over a fresh connection from dial and bounded by timeout
// and ctx, and returns the labels of the versions the server accepted and of
// those it refused. skip, when non-zero, is a version already proven (the
// negotiated one): it is neither tested again nor returned.
//
// A version can also be in neither list: untested. A connection that could not
// be made, a deadline that could not be set, a timeout, an EOF or a refusal of
// the cipher suites say nothing about the version. The two lists are kept
// apart because a reader acts on a refusal: "the server does not speak TLS 1.0"
// retires what a passive observation recorded, and "this probe could not tell"
// must not.
func enumerateTLSVersions(ctx context.Context, dial func(context.Context) (net.Conn, error), hostname string, timeout time.Duration, skip uint16) (accepted, refused []string) {
	for _, ver := range tlsVersionsNewestFirst {
		if ver == skip {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		switch tryTLSVersion(ctx, dial, hostname, timeout, ver) {
		case tlsVersionAccepted:
			accepted = append(accepted, TLSVersionName(ver))
		case tlsVersionRefused:
			refused = append(refused, TLSVersionName(ver))
		}
	}
	return accepted, refused
}

// tlsVersionAnswer is what one forced-version handshake says about its version.
type tlsVersionAnswer int

const (
	tlsVersionUntested tlsVersionAnswer = iota
	tlsVersionAccepted
	tlsVersionRefused
)

func tryTLSVersion(ctx context.Context, dial func(context.Context) (net.Conn, error), hostname string, timeout time.Duration, ver uint16) tlsVersionAnswer {
	conn, err := dial(ctx)
	if err != nil {
		return tlsVersionUntested
	}
	defer func() { _ = conn.Close() }()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // intentional — discovery probes any endpoint
		MinVersion:         ver,
		MaxVersion:         ver,
		// The same offer as the identifying handshake: a version is
		// accepted when the server will speak it with ANY suite we can.
		CipherSuites: measuringCipherSuites,
	})
	defer func() { _ = tlsConn.Close() }()
	// Without a deadline the handshake below can block indefinitely, so a
	// failure here means this version cannot be tested — skip it rather than
	// record an untested version as unaccepted.
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return tlsVersionUntested
	}
	switch err := tlsConn.HandshakeContext(ctx); {
	case err == nil:
		return tlsVersionAccepted
	case isVersionRefusal(err):
		return tlsVersionRefused
	}
	return tlsVersionUntested
}

// alertProtocolVersion is the protocol_version alert of RFC 8446 section 6.
const alertProtocolVersion tls.AlertError = 70

// isVersionRefusal reports whether a forced-version handshake failed on the
// version. Either the server said so with a protocol_version alert, which
// crypto/tls surfaces the way isGroupRefusal describes, or it answered with a
// version other than the one offered, which the client refuses itself.
func isVersionRefusal(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" && opErr.Err != nil {
		return opErr.Err.Error() == alertProtocolVersion.Error()
	}
	return strings.Contains(err.Error(), "server selected unsupported protocol version")
}

// negotiatedTLSVersion is the wire version of the result's main handshake, or 0.
func negotiatedTLSVersion(res *ProbeResult) uint16 {
	if v, ok := res.Metadata["tls_version_raw"].(uint16); ok {
		return v
	}
	return 0
}

// applyTLSVersions records enumerated versions on res. The negotiated version
// stays FIRST — it is what jobunits.TLSProbeMetadata reports as "version" —
// and the other accepted versions follow, newest first. For a server that
// negotiates its newest version, which is every conforming server, that is
// exactly the newest-first list the legacy enumeration reports.
func applyTLSVersions(res *ProbeResult, others []string) {
	if len(others) == 0 {
		return
	}
	versions := make([]string, 0, len(res.TLSVersions)+len(others))
	versions = append(versions, res.TLSVersions...)
	for _, v := range others {
		if !slices.Contains(versions, v) {
			versions = append(versions, v)
		}
	}
	res.TLSVersions = versions
}

// applyTLSVersionRefusals records the versions the server refused on res.
func applyTLSVersionRefusals(res *ProbeResult, refused []string) {
	if len(refused) == 0 {
		return
	}
	if res.Metadata == nil {
		res.Metadata = map[string]interface{}{}
	}
	res.Metadata[MetaTLSVersionsRefused] = refused
}
