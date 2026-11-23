package planrun

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/probeconsent"
)

// reservedAddresses are refused by every rule, whatever names them.
var reservedAddresses = []string{
	"0.0.0.0", "::", "127.0.0.1", "127.9.9.9", "::1", "169.254.169.254", "fe80::1",
	"224.0.0.251", "239.1.2.3", "ff02::1", "255.255.255.255",
}

func TestNamedTargetsRule(t *testing.T) {
	rule := NamedTargetsRule([]netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/24"),
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("2001:db8::/120"),
		netip.MustParsePrefix("::ffff:198.51.100.0/120"), // an IPv4-mapped spelling of 198.51.100.0/24
		// Named on purpose: reserved space stays refused even when a target
		// covers it.
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("fe80::/10"),
	})
	for addr, allowed := range map[string]bool{
		"10.20.0.1": true, "10.20.0.255": true, "192.0.2.7": true, "2001:db8::ff": true,
		"198.51.100.9": true, "::ffff:10.20.0.9": true,
		"10.20.1.1": false, "192.0.2.8": false, "2001:db8::1:0": false, "10.0.0.1": false, "203.0.113.1": false,
	} {
		if err := rule(netip.MustParseAddr(addr)); (err == nil) != allowed {
			t.Errorf("rule(%s) = %v, want allowed=%v", addr, err, allowed)
		}
	}
	for _, addr := range reservedAddresses {
		err := rule(netip.MustParseAddr(addr))
		if !errors.Is(err, ErrForbiddenAddress) || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("rule(%s) = %v, want a reserved-address refusal although a target names it", addr, err)
		}
	}
	if err := rule(netip.Addr{}); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("rule(invalid) = %v", err)
	}
	if err := NamedTargetsRule(nil)(netip.MustParseAddr("10.20.0.1")); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("a rule with no targets allowed an address: %v", err)
	}
}

// The standalone and managed rules refuse exactly the same reserved set, for
// the same reason, so the two cannot drift apart.
func TestReservedRefusalsAreShared(t *testing.T) {
	everything := NamedTargetsRule([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	sensor := SensorRule(func() probeconsent.Scope { return probeconsent.Scope{} })
	endpoint := SensorEndpointRule(func() probeconsent.Scope { return probeconsent.Scope{} })
	for _, raw := range reservedAddresses {
		a := netip.MustParseAddr(raw)
		want := refuseReserved(a)
		if want == nil {
			t.Fatalf("refuseReserved(%s) allowed it", raw)
		}
		for name, err := range map[string]error{
			"NamedTargetsRule":   everything(a),
			"SensorRule":         sensor(a),
			"SensorEndpointRule": endpoint(netip.AddrPortFrom(a, 443)),
		} {
			if err == nil || err.Error() != want.Error() {
				t.Errorf("%s(%s) = %v, want %v", name, raw, err, want)
			}
		}
	}
	if err := everything(netip.MustParseAddr("203.0.113.1")); err != nil {
		t.Errorf("an ordinary address inside the targets was refused: %v", err)
	}
}

// serveTLSChain serves a leaf signed by its own CA, with the CA in the chain
// and an OCSP responder named in the leaf, so a probe that validates the
// chain asks for that responder.
func serveTLSChain(t *testing.T, ocspURL string) string {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "svc.example.test"}, DNSNames: []string{"svc.example.test"},
		OCSPServer: []string{ocspURL}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}}})
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = c.(*tls.Conn).Handshake()
			}(c)
		}
	}()
	return ln.Addr().String()
}

// Config.OutboundGuard reaches the engine: the OCSP responder a scanned
// certificate names is judged by it before any fetch. Without the wiring the
// probe would post to the responder unguarded.
func TestRun_OutboundGuardJudgesTheOCSPResponder(t *testing.T) {
	fake := newFakeNet()
	fake.host("10.60.0.5", map[uint16]string{443: serveTLSChain(t, "http://198.51.100.9/ocsp")})
	var mu sync.Mutex
	var asked []netip.Addr
	guard := func(a netip.Addr) error {
		mu.Lock()
		asked = append(asked, a)
		mu.Unlock()
		return errors.New("not a named target")
	}
	rec := &recorder{}
	p := plan(target(targetA, "10.60.0.5", "443"))
	if _, err := Run(context.Background(), p, Config{Allow: privateOnly(), OutboundGuard: guard, Reporter: rec, Dialer: fake}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	u, ok := rec.units()["10.60.0.5"]
	if !ok || u.Failed {
		t.Fatalf("host not scanned: %+v", u)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) == 0 || asked[0] != netip.MustParseAddr("198.51.100.9") {
		t.Fatalf("the outbound guard was asked about %v, want the OCSP responder 198.51.100.9", asked)
	}
}
