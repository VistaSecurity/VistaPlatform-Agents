package deviceinterrogation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sslVPNNetwork is the interface table of a small FortiGate: one WAN, one LAN
// and a route-based tunnel interface that holds no address.
func sslVPNNetwork() *NetworkObservation {
	return &NetworkObservation{Interfaces: []ObservedInterface{
		{Name: "wan1", Addresses: []ObservedAddress{{Address: "198.51.100.2/30"}}},
		{Name: "internal", Addresses: []ObservedAddress{{Address: "192.0.2.1/24"}}},
		{Name: "Site-A", Type: "virtual"},
	}}
}

// fortinetSSLVPNSettingsResponse is the shape FortiOS 7.x returns for the
// SINGLETON endpoint `cmdb/vpn.ssl/settings`: `results` is one object, not an
// array. Values are illustrative; the poison values sit in fields nothing
// reads and must never reach the asset.
const fortinetSSLVPNSettingsResponse = `{
  "http_method": "GET", "revision": "5f2", "vdom": "root", "path": "vpn.ssl", "name": "settings",
  "status": "success", "http_status": 200, "serial": "FGT00000000000", "version": "v7.4.8", "build": 2795,
  "results": {
    "status": "enable", "reqclientcert": "disable", "ssl-max-proto-ver": "tls1-3", "ssl-min-proto-ver": "tls1-2",
    "algorithm": "high", "servercert": "Fortinet_Factory", "port": 10443,
    "source-interface": [{"name": "wan1", "q_origin_key": "wan1"}],
    "tunnel-ip-pools": [{"name": "SSLVPN_TUNNEL_ADDR1", "q_origin_key": "SSLVPN_TUNNEL_ADDR1"}],
    "auth-timeout": 28800, "login-attempt-limit": 2,
    "deflate-compression-level": 6, "banned-cipher": "",
    "saml-redirect-port": 8020, "dtls-tunnel": "enable",
    "x-custom-header": "MUST-NOT-BE-COLLECTED", "radius-secret": "MUST-NOT-BE-COLLECTED"
  }
}`

// Mutation: decode `results` only as an array (drop the object arm of
// fortinetResults.UnmarshalJSON) → the request fails to parse, red.
func TestFortinetSSLVPNSettings_SingletonResultsAreRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fortinetSSLVPNSettingsResponse))
	}))
	defer srv.Close()
	c := newFortinetClient(srv.URL, fortinetTokenUsername, "token", false)
	settings, err := c.getResults(context.Background(), "/api/v2/cmdb/vpn.ssl/settings")
	if err != nil {
		t.Fatalf("getResults: %v", err)
	}
	if len(settings) != 1 {
		t.Fatalf("settings = %d rows, want the one singleton", len(settings))
	}
	got := fortinetSSLVPNListeners(c.convertSSLVPNToAsset(settings[0]), settings[0], sslVPNNetwork())
	if len(got) != 1 {
		t.Fatalf("listeners = %+v", got)
	}
	a := got[0]
	if a.IPAddress != "198.51.100.2" || a.Port != 10443 || a.ProtocolVersion == nil || *a.ProtocolVersion != "TLS 1.2" ||
		a.Metadata["certificate_name"] != "Fortinet_Factory" || a.Metadata["vpn_service"] != "remote_access" {
		t.Errorf("portal = %s:%d version %v metadata %v", a.IPAddress, a.Port, a.ProtocolVersion, a.Metadata)
	}
	assertNoPoison(t, "fortinet sslvpn settings", a)
	for _, k := range []string{"radius-secret", "x-custom-header", "tunnel-ip-pools"} {
		if _, ok := a.Metadata[k]; ok {
			t.Errorf("%q reached the asset's metadata", k)
		}
	}
}

// A table endpoint still decodes as rows, and null as none; any other shape
// is an error, never silently no rows.
func TestFortinetResults_TableNullAndRefused(t *testing.T) {
	for _, c := range []struct {
		body string
		rows int
		bad  bool
	}{
		{`{"results":[{"name":"a"},{"name":"b"}]}`, 2, false},
		{`{"results":{"name":"one"}}`, 1, false},
		{`{"results":null}`, 0, false},
		{`{}`, 0, false},
		{`{"results":"nope"}`, 0, true},
	} {
		var r fortinetAPIResponse
		err := json.Unmarshal([]byte(c.body), &r)
		if (err != nil) != c.bad || len(r.Results) != c.rows {
			t.Errorf("%s: rows %d err %v, want rows %d bad %v", c.body, len(r.Results), err, c.rows, c.bad)
		}
	}
}

// Mutation: drop the source-interface loop → the portal has no address, red.
func TestFortinetSSLVPNListeners_OnePerListeningInterface(t *testing.T) {
	c := &fortinetClient{}
	settings := map[string]interface{}{
		"port": float64(10443), "tls_version": "TLS 1.2", "cipher": "high",
		"source-interface": []interface{}{map[string]interface{}{"name": "wan1"}, map[string]interface{}{"name": "Site-A"}},
		"servercert":       "Fortinet_Factory",
	}
	got := fortinetSSLVPNListeners(c.convertSSLVPNToAsset(settings), settings, sslVPNNetwork())
	// Site-A holds no address, so only wan1 is a listener.
	if len(got) != 1 {
		t.Fatalf("listeners = %+v, want one on wan1", got)
	}
	a := got[0]
	if a.IPAddress != "198.51.100.2" || a.Port != 10443 || a.Protocol != "SSL VPN" || a.Metadata["vpn_service"] != "remote_access" || a.Metadata["listen_interface"] != "wan1" {
		t.Errorf("portal = %s:%d %s %v", a.IPAddress, a.Port, a.Protocol, a.Metadata)
	}
	assertNoPoison(t, "fortinet sslvpn listener", a)

	// No interface table: one address-less portal.
	if alone := fortinetSSLVPNListeners(c.convertSSLVPNToAsset(settings), settings, nil); len(alone) != 1 || alone[0].IPAddress != "" {
		t.Errorf("portal without an interface table = %+v", alone)
	}
}

// Every FortiGate answers `vpn.ssl/settings` whether SSL-VPN is used or not.
// Reading the singleton must not turn an unused portal into a service with a
// weak-protocol finding.
//
// Mutation: drop either early return of fortinetSSLVPNListeners → red.
func TestFortinetSSLVPNListeners_APortalThatIsOffIsNoService(t *testing.T) {
	c := &fortinetClient{}
	off := map[string]interface{}{"status": "disable", "port": float64(10443), "ssl-min-proto-ver": "tls1-0",
		"source-interface": []interface{}{map[string]interface{}{"name": "wan1"}}, "radius-secret": poison}
	if got := fortinetSSLVPNListeners(c.convertSSLVPNToAsset(off), off, sslVPNNetwork()); len(got) != 0 {
		t.Errorf("a disabled portal produced %+v", got)
	}
	unused := map[string]interface{}{"port": float64(10443), "ssl-min-proto-ver": "tls1-0", "servercert": "Fortinet_Factory"}
	if got := fortinetSSLVPNListeners(c.convertSSLVPNToAsset(unused), unused, sslVPNNetwork()); len(got) != 0 {
		t.Errorf("a portal listening nowhere produced %+v", got)
	}
}

// The wiring: the whole collector, against the singleton answer, reads the
// portal with no collection warning and places it on the interface table the
// same run read.
//
// Mutation: revert the collector to c.convertSSLVPNToAsset(vpn) → the portal
// has no listener address, red.
func TestFortinetInterrogate_SSLVPNSingletonReachesTheAssets(t *testing.T) {
	handler := fortinetConformanceHandler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/cmdb/vpn.ssl/settings":
			w.Header().Set("Content-Type", "application/json")
			// The operations fixture's WAN is port1.
			_, _ = w.Write([]byte(strings.ReplaceAll(fortinetSSLVPNSettingsResponse, "wan1", "port1")))
		default:
			handler.ServeHTTP(w, r)
		}
	}))
	defer srv.Close()
	c := newFortinetClient(srv.URL, fortinetTokenUsername, "token", false)
	result, err := c.interrogate(context.Background())
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}
	for _, w := range result.Warnings {
		if w.Endpoint == "/api/v2/cmdb/vpn.ssl/settings" {
			t.Errorf("collection warning on the singleton: %+v", w)
		}
	}
	var portals []CryptoAsset
	for _, a := range result.Assets {
		if a.Protocol == "SSL VPN" {
			portals = append(portals, a)
		}
	}
	if len(portals) != 1 {
		t.Fatalf("SSL VPN assets = %+v, want the one portal", portals)
	}
	if portals[0].Metadata["listen_interface"] != "port1" || portals[0].IPAddress != "203.0.113.2" {
		t.Errorf("portal not placed on port1: %s %v", portals[0].IPAddress, portals[0].Metadata)
	}
}
