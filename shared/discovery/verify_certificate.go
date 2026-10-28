package discovery

// The verify_certificate unit (#2746, declared certificates slice 2).
//
// A person declared a certificate and said where it is served (host, port,
// SNI). Verifying it is ONE TLS handshake to that one endpoint — not a port
// scan, not identification of anything else on the host — and the answer is
// recorded on the certificate, never as a sighting: a hostname a person typed
// into a certificate form is not an inventory asset (spec D5), so the result
// must not enter the identity pipeline.
//
// It is a unit of the one scan engine (UnitEngine), run by both runtimes from
// this source: the Platform Sensor's work units and a tenant sensor's planned
// job (sensordispatch/planrun). A plan carrying VerifyCertificate makes every
// unit of the job run VerifyCertificate instead of Run.
//
// The engine contacts only the address it is handed, on the one port the plan
// names: the caller authorized that address:port before it got here.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/certificates"
)

// Verification outcomes, as the executor reports them. "mismatch" is not one:
// whether the served certificate is the declared one is decided by the
// platform, which holds the declared row (inventory-service RecordObservation).
const (
	VerifyOutcomeObserved      = "observed"
	VerifyOutcomeNotObservable = "not_observable"
)

// Error classes a failed verification carries, beside the handshake classes of
// TLSHandshakeErrorClass. Bounded so the platform can say each in plain words.
const (
	VerifyErrorRefused       = "refused"
	VerifyErrorUnreachable   = "unreachable"
	VerifyErrorDNS           = "dns"
	VerifyErrorNoCertificate = "no_certificate"
)

// verifyProbeTimeout bounds each connect and the handshake. Longer than the
// identification timeout: a declared location is often across the internet.
const verifyProbeTimeout = 10 * time.Second

// verifyUnitDeadline is a verification unit's whole budget: one connect, one
// handshake, its OCSP fetch — and slack.
const verifyUnitDeadline = time.Minute

// maxVerifyErrorLen bounds the error text a result carries.
const maxVerifyErrorLen = 500

// VerifyCertificatePlan marks a scan plan as a certificate verification: every
// unit runs VerifyCertificate on Port with SNI, and its result is delivered to
// the certificate CertificateID instead of being stored as findings for
// inventory.
type VerifyCertificatePlan struct {
	CertificateID string `json:"certificate_id"`
	Port          int    `json:"port"`
	SNI           string `json:"sni,omitempty"`
}

// Validate checks the plan's shape.
func (p VerifyCertificatePlan) Validate() error {
	if strings.TrimSpace(p.CertificateID) == "" {
		return errors.New("verify_certificate: certificate_id is required")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("verify_certificate: port %d is out of range", p.Port)
	}
	if len(p.SNI) > 253 {
		return errors.New("verify_certificate: sni is too long")
	}
	return nil
}

// CertificateVerification is what one verification learned. Leaf and
// ServedChain are the canonical certificate shape (shared/certificates
// CertificateInfo: subject_dn, issuer_dn, fingerprint_sha256, certificate_pem,
// chain_order …) — the same shape every discovery path emits.
type CertificateVerification struct {
	Outcome    string `json:"outcome"`
	ErrorClass string `json:"error_class,omitempty"`
	Error      string `json:"error,omitempty"`

	Address string `json:"address"`
	Port    int    `json:"port"`
	SNI     string `json:"sni,omitempty"`

	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`

	// Leaf is the served end-entity certificate (chain_order 0), PEM included.
	Leaf *certificates.CertificateInfo `json:"certificate,omitempty"`
	// ServedChain is every certificate the server sent, leaf first.
	ServedChain []certificates.CertificateInfo `json:"served_chain,omitempty"`

	ObservedAt time.Time `json:"observed_at"`
}

// Validate refuses a result the engine could not have produced.
func (v CertificateVerification) Validate() error {
	if v.Port < 1 || v.Port > 65535 {
		return fmt.Errorf("verification: port %d is out of range", v.Port)
	}
	if _, err := netip.ParseAddr(v.Address); err != nil {
		return fmt.Errorf("verification: address %q is not an address", v.Address)
	}
	switch v.Outcome {
	case VerifyOutcomeObserved:
		if v.Leaf == nil || strings.TrimSpace(v.Leaf.CertificatePEM) == "" || v.Leaf.FingerprintSHA256 == "" {
			return errors.New("verification: an observed result must carry the served certificate")
		}
	case VerifyOutcomeNotObservable:
		if v.ErrorClass == "" {
			return errors.New("verification: a not_observable result must say why")
		}
	default:
		return fmt.Errorf("verification: outcome %q is not observed or not_observable", v.Outcome)
	}
	if len(v.Error) > maxVerifyErrorLen*2 || len(v.ServedChain) > 16 {
		return errors.New("verification: result is oversized")
	}
	return nil
}

// VerifyInput is one verification unit.
type VerifyInput struct {
	Addr netip.Addr
	Port int
	SNI  string
}

// VerifyCertificate handshakes Addr:Port once, presenting SNI, and reports the
// served certificate or why there was none. It never returns an error: a
// failure to observe is the answer, classified for the person who asked.
//
// The handshake is the shared TLS probe (ProbeTLSEndpoint) without its support
// handshakes and version enumeration: a person asked for this certificate to
// be checked, not for the endpoint to be measured, so the endpoint gets one
// connection (plus the probe's own OCSP fetch, through the engine's guard).
func (e *UnitEngine) VerifyCertificate(ctx context.Context, in VerifyInput) UnitOutput {
	out := UnitOutput{Deadline: verifyUnitDeadline}
	uctx, cancel := context.WithTimeout(ctx, verifyUnitDeadline)
	defer cancel()

	host := HostScan{Addr: in.Addr, Liveness: LivenessAssumedUp, LivenessEvidence: "assumed", PortsRequested: 1}
	v := &CertificateVerification{Address: in.Addr.Unmap().String(), Port: in.Port, SNI: in.SNI}

	prober := NewProber(verifyProbeTimeout).WithoutSupportHandshakes()
	if e.guard != nil {
		prober = prober.WithOutboundAddressGuard(e.guard)
	}
	var dialErr error
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := e.scanner.dialer.DialContext(ctx, network, address)
		if err != nil && dialErr == nil {
			dialErr = err
		}
		return c, err
	}
	res, err := prober.ProbeTLSEndpoint(uctx, v.Address, in.Port, TLSEndpointOptions{Hostname: in.SNI, Dial: dial})
	v.ObservedAt = time.Now().UTC()

	switch {
	case dialErr != nil:
		v.Outcome = VerifyOutcomeNotObservable
		v.ErrorClass = verifyDialErrorClass(dialErr)
		v.Error = boundVerifyError(dialErr)
		if v.ErrorClass == VerifyErrorRefused {
			host.Closed = 1
		} else {
			host.Filtered = 1
		}
	case err != nil:
		// It connected: the port is open, the handshake is what failed.
		v.Outcome = VerifyOutcomeNotObservable
		v.ErrorClass = TLSHandshakeErrorClass(err)
		v.Error = boundVerifyError(err)
		host.Open, host.OpenCount = []int{in.Port}, 1
	case res == nil || len(res.Certificates) == 0:
		v.Outcome = VerifyOutcomeNotObservable
		v.ErrorClass = VerifyErrorNoCertificate
		v.Error = "the server completed a TLS handshake without presenting a certificate"
		host.Open, host.OpenCount = []int{in.Port}, 1
	default:
		v.Outcome = VerifyOutcomeObserved
		leaf := res.Certificates[0]
		v.Leaf = &leaf
		v.ServedChain = append([]certificates.CertificateInfo(nil), res.Certificates...)
		if len(v.ServedChain) > 16 {
			v.ServedChain = v.ServedChain[:16]
		}
		if len(res.TLSVersions) > 0 {
			v.TLSVersion = res.TLSVersions[0]
		}
		v.CipherSuite = res.SelectedCipher
		host.Open, host.OpenCount = []int{in.Port}, 1
	}
	out.Host = host
	out.Verification = v
	out.DeadlineHit = ctx.Err() == nil && uctx.Err() != nil
	return out
}

// verifyDialErrorClass names why the connection was not made.
func verifyDialErrorClass(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return VerifyErrorDNS
	case errors.Is(err, syscall.ECONNREFUSED), strings.Contains(err.Error(), "connection refused"):
		return VerifyErrorRefused
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return "timeout"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		strings.Contains(err.Error(), "unreachable"), strings.Contains(err.Error(), "no route"):
		return VerifyErrorUnreachable
	}
	return "other"
}

func boundVerifyError(err error) string {
	msg := err.Error()
	if len(msg) > maxVerifyErrorLen {
		msg = msg[:maxVerifyErrorLen]
	}
	return msg
}

// CertificateObservation is what an executor delivers to inventory-service's
// internal route POST /internal/certificates/{id}/observation once a
// verification unit is stored: which job and executor answered, and the
// answer. The certificate id is the one the job's plan named — the platform's
// own record, never a value a sensor reported.
type CertificateObservation struct {
	JobID        string                  `json:"job_id"`
	Executor     string                  `json:"executor"`
	Verification CertificateVerification `json:"verification"`
}

// CertificateObservationPath is the internal route an observation is
// delivered to (HMAC-only, signed X-Tenant-ID; denied at the edge by the
// /inventory-service/internal/ prefix).
func CertificateObservationPath(certificateID string) string {
	return "/api/v1/inventory-service/internal/certificates/" + certificateID + "/observation"
}
