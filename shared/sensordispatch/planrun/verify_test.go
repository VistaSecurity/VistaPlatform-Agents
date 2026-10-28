package planrun

// Certificate verification on a tenant sensor (#2746 slice 2): a plan carrying
// VerifyCertificate runs one TLS handshake per unit, judged by the sensor's
// ENDPOINT rule, and reports the answer as the unit's Verification.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform-agents/shared/discovery"
	"github.com/vistasecurity/vistaplatform-agents/shared/probeconsent"
	"github.com/vistasecurity/vistaplatform-agents/shared/sensordispatch"
)

func serveTLS(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
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

func verifyPlan(addr string, port int) sensordispatch.PlanPayload {
	p := plan(target(targetA, addr, strconv.Itoa(port)))
	p.VerifyCertificate = &discovery.VerifyCertificatePlan{CertificateID: "c1", Port: port, SNI: "www.partner.test"}
	return p
}

func endpointScope(endpoints ...string) func() probeconsent.Scope {
	scope, _ := probeconsent.Parse(probeconsent.OwnedNetworks{Endpoints: endpoints})
	return func() probeconsent.Scope { return scope }
}

func TestRun_VerifyHandshakesTheRegisteredEndpointAndReportsTheCertificate(t *testing.T) {
	fake := newFakeNet()
	fake.host("203.0.113.50", map[uint16]string{8443: serveTLS(t, "www.partner.test")})
	rec := &recorder{}
	scope := endpointScope("203.0.113.50:8443")
	sum, err := Run(context.Background(), verifyPlan("203.0.113.50", 8443), Config{
		Allow: SensorRule(scope), AllowEndpoint: SensorEndpointRule(scope), Reporter: rec, Dialer: fake,
	})
	if err != nil || sum.Done != 1 {
		t.Fatalf("Run = %+v, %v", sum, err)
	}
	u := rec.units()["203.0.113.50"]
	if u.Failed || u.Verification == nil || u.Verification.Outcome != discovery.VerifyOutcomeObserved {
		t.Fatalf("unit = %+v", u)
	}
	if u.Verification.Leaf == nil || u.Verification.Leaf.CertificatePEM == "" {
		t.Errorf("the served certificate travels with its PEM: %+v", u.Verification.Leaf)
	}
	if len(u.TCP) != 0 {
		t.Errorf("a verification reports no observations (they would be ingested as findings): %d", len(u.TCP))
	}
	if _, err := u.Output(); err != nil {
		t.Errorf("the platform must accept what the sensor reported: %v", err)
	}
	if n := fake.dialed()[netip.MustParseAddr("203.0.113.50")]; n != 1 {
		t.Errorf("%d dials, want exactly one handshake", n)
	}
}

// Without the registration the sensor's own rule refuses: the address is a
// third party's, and only the person's verification made that one port the
// tenant's to probe.
func TestRun_VerifyRefusesAnEndpointThatIsNotRegistered(t *testing.T) {
	fake := newFakeNet()
	fake.host("203.0.113.50", map[uint16]string{8443: serveTLS(t, "www.partner.test")})
	rec := &recorder{}
	// Registered on another port: nothing else on the host is authorized.
	scope := endpointScope("203.0.113.50:443")
	sum, err := Run(context.Background(), verifyPlan("203.0.113.50", 8443), Config{
		Allow: SensorRule(scope), AllowEndpoint: SensorEndpointRule(scope), Reporter: rec, Dialer: fake,
	})
	if err != nil || sum.Failed != 1 {
		t.Fatalf("Run = %+v, %v", sum, err)
	}
	if u := rec.units()["203.0.113.50"]; !u.Failed || u.Verification != nil {
		t.Errorf("unit = %+v, want failed by the sensor's rule", u)
	}
	if len(fake.dialed()) != 0 {
		t.Error("the refused endpoint was contacted")
	}
}

func TestRun_VerifyNeedsTheEndpointRule(t *testing.T) {
	if _, err := Run(context.Background(), verifyPlan("10.0.0.5", 443), Config{Allow: privateOnly(), Reporter: &recorder{}, Dialer: newFakeNet()}); err == nil {
		t.Fatal("a verification without the endpoint rule ran")
	}
}

func TestSensorEndpointRule(t *testing.T) {
	scope, _ := probeconsent.Parse(probeconsent.OwnedNetworks{
		Prefixes: []string{"198.51.100.0/24"}, Endpoints: []string{"203.0.113.9:8443"}, Excluded: []string{"10.1.2.0/24"},
	})
	rule := SensorEndpointRule(func() probeconsent.Scope { return scope })
	for ap, allowed := range map[string]bool{
		"10.1.1.5:443": true, "198.51.100.7:8443": true, "203.0.113.9:8443": true,
		"203.0.113.9:443": false, "203.0.113.10:8443": false, "10.1.2.5:443": false,
		"127.0.0.1:443": false, "169.254.169.254:80": false, "10.1.1.5:0": false,
	} {
		if err := rule(netip.MustParseAddrPort(ap)); (err == nil) != allowed {
			t.Errorf("rule(%s) = %v, want allowed=%v", ap, err, allowed)
		}
	}
}
