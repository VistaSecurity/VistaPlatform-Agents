package hostcrypto

import (
	"reflect"
	"testing"
)

const cfgHAProxyStock = `global
    log /dev/log local0
    maxconn 4096
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-server-options ssl-min-ver TLSv1.2
    tune.ssl.default-dh-param 2048
    ssl-dh-param-file /etc/haproxy/dhparam.pem
    crt-base /etc/haproxy/certs
    ca-base /etc/ssl/certs
    stats socket /run/haproxy.sock mode 660 level admin # admin socket

defaults
    mode http
    timeout connect 5s

frontend https_in
    bind :443 ssl crt /etc/haproxy/certs/site.pem alpn h2,http/1.1 ssl-max-ver TLSv1.3
    bind :8443 ssl crt site2.pem ca-file client-ca.pem verify required no-tlsv12 ciphers HIGH:!aNULL tls-ticket-keys /etc/haproxy/SECRETTICKETS ca-sign-pass SECRETSIGNPASS ca-sign-file /etc/haproxy/SECRETSIGN.pem
    bind :80
    default_backend app

backend app
    server a1 10.0.0.1:8080 ssl verify required ca-file internal-ca.pem ssl-min-ver TLSv1.2 check
    server a2 10.0.0.2:8080 check
`

func TestHAProxyStock(t *testing.T) {
	cfgs := cfgT(cfgParseHAProxy, []byte(cfgHAProxyStock))
	if len(cfgs) != 4 {
		t.Fatalf("want global, two TLS binds and the backend, got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[0], CryptoConfig{
		Product: "haproxy", Context: "global",
		MinProtocol:  "TLSv1.2", // only a minimum is stated: no Protocols list is invented
		CipherString: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
		CipherSuites: []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
		Settings: map[string]string{
			"ca-base": "/etc/ssl/certs", "crt-base": "/etc/haproxy/certs",
			"ssl-default-bind-options":   "ssl-min-ver TLSv1.2 no-tls-tickets",
			"ssl-default-server-options": "ssl-min-ver TLSv1.2",
			"tune.ssl.default-dh-param":  "2048",
		},
		References: []ConfigReference{{Kind: "dh_params", Directive: "ssl-dh-param-file", Path: "/etc/haproxy/dhparam.pem"}},
	})
	cfgWantEqual(t, cfgs[1], CryptoConfig{
		Product: "haproxy", Context: "frontend https_in bind :443",
		Protocols:    []string{"TLSv1.2", "TLSv1.3"},
		MinProtocol:  "TLSv1.2",
		MaxProtocol:  "TLSv1.3",
		CipherString: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
		CipherSuites: []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
		Settings:     map[string]string{"bind": ":443", "alpn": "h2,http/1.1", "bind ssl-options": "ssl-max-ver TLSv1.3"},
		References: []ConfigReference{
			{Kind: "certificate", Directive: "bind crt", Path: "/etc/haproxy/certs/site.pem"},
			{Kind: "private_key", Directive: "bind crt", Path: "/etc/haproxy/certs/site.pem"},
		},
	})
	cfgWantEqual(t, cfgs[2], CryptoConfig{
		Product: "haproxy", Context: "frontend https_in bind :8443",
		// no-tlsv12 beside a minimum is ignored by HAProxy: it narrows
		// nothing and disables nothing here; the text stays in Settings.
		MinProtocol:  "TLSv1.2",
		CipherString: "HIGH:!aNULL",
		CipherSuites: []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
		Settings:     map[string]string{"bind": ":8443", "verify": "required", "bind ssl-options": "no-tlsv12"},
		References: []ConfigReference{
			{Kind: "certificate", Directive: "bind crt", Path: "/etc/haproxy/certs/site2.pem"},
			{Kind: "private_key", Directive: "bind crt", Path: "/etc/haproxy/certs/site2.pem"},
			{Kind: "trust_store", Directive: "bind ca-file", Path: "/etc/ssl/certs/client-ca.pem"},
		},
	})
	cfgWantEqual(t, cfgs[3], CryptoConfig{
		Product: "haproxy", Context: "backend app",
		Settings: map[string]string{
			"server.1 name": "a1", "server.1 ssl": "true", "server.1 verify": "required",
			"server.1 ca-file":     "/etc/ssl/certs/internal-ca.pem",
			"server.1 ssl-min-ver": "TLSv1.2",
		},
		References: []ConfigReference{{Kind: "trust_store", Directive: "server ca-file", Path: "/etc/ssl/certs/internal-ca.pem"}},
	})
	cfgNoSecrets(t, cfgs, "SECRETTICKETS", "SECRETSIGNPASS", "SECRETSIGN")
}

func TestHAProxyProtocolResolution(t *testing.T) {
	type want struct {
		allowed, disabled []string
		min, max          string
	}
	for in, w := range map[string]want{
		"ssl": {},
		// Only exclusions: the allowed set is the product's default, not ours.
		"ssl no-sslv3":                      {disabled: []string{"SSLv3"}},
		"ssl no-sslv3 no-tlsv10 no-tlsv11":  {disabled: []string{"SSLv3", "TLSv1.0", "TLSv1.1"}},
		"ssl ssl-min-ver TLSv1.2":           {min: "TLSv1.2"},
		"ssl ssl-max-ver TLSv1.2":           {max: "TLSv1.2"},
		"ssl ssl-min-ver TLSv1.1 no-tlsv12": {min: "TLSv1.1"},
		// Both bounds, or a force: the set is stated.
		"ssl ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.2": {allowed: []string{"TLSv1.2"}, min: "TLSv1.2", max: "TLSv1.2"},
		"ssl ssl-min-ver TLSv1.1 ssl-max-ver TLSv1.3 no-tlsv12": { // no-* beside a bound is ignored
			allowed: []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}, min: "TLSv1.1", max: "TLSv1.3"},
		"ssl force-tlsv13":      {allowed: []string{"TLSv1.3"}, min: "TLSv1.3", max: "TLSv1.3"},
		"ssl ssl-min-ver Bogus": {},
	} {
		allowed, disabled, minP, maxP := cfgHAProtocols(cfgHAOptions(cfgFields(in, true)))
		got := want{allowed, disabled, minP, maxP}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("%q: got %+v want %+v", in, got, w)
		}
	}
}

func TestHAProxyListenAndDefaultServer(t *testing.T) {
	cfgs := cfgT(cfgParseHAProxy, []byte(`defaults tcp
    default-server ssl verify none
listen mysql
    bind *:3306 ssl crt /c.pem
    server db1 10.1.1.1:3306 ca-file /ca.pem
    server db2 10.1.1.2:3306 no-sslv3
`))
	b := cfgFind(t, cfgs, "listen mysql bind *:3306")
	if b.Settings["bind"] != "*:3306" {
		t.Errorf("bind: %s", cfgJSON(t, b))
	}
	// A defaults section's default-server applies to the sections after it,
	// so both servers of the listen section use TLS to the origin; the second
	// one's own option is added to the default.
	d := cfgFind(t, cfgs, "defaults tcp")
	cfgWantEqual(t, d.Settings, map[string]string{"default-server ssl": "true", "default-server verify": "none"})
	l := cfgFind(t, cfgs, "listen mysql servers")
	cfgWantEqual(t, l.Settings, map[string]string{
		"server.1 name": "db1", "server.1 ssl": "true", "server.1 verify": "none", "server.1 ca-file": "/ca.pem",
		"server.2 name": "db2", "server.2 ssl": "true", "server.2 verify": "none", "server.2 no-sslv3": "true",
	})
}

func TestHAProxyServerTemplateAndDefaultServerReplace(t *testing.T) {
	cfgs := cfgParseHAProxy([]byte(`backend b
    default-server ssl verify none
    default-server verify required ca-file /ca.pem
    server-template web 3 web.example.com:443 ssl-min-ver TLSv1.2 check
    server s1 10.0.0.1:443
`), nil)
	b := cfgFind(t, cfgs, "backend b")
	// The address field is not an option; a later default-server replaces an
	// earlier one's verify; the template's options start after its address.
	cfgWantEqual(t, b.Settings, map[string]string{
		"default-server ssl": "true", "default-server verify": "required", "default-server ca-file": "/ca.pem",
		"server.1 name": "web", "server.1 ssl": "true", "server.1 verify": "required", "server.1 ca-file": "/ca.pem", "server.1 ssl-min-ver": "TLSv1.2",
		"server.2 name": "s1", "server.2 ssl": "true", "server.2 verify": "required", "server.2 ca-file": "/ca.pem",
	})
}

func TestHAProxySecretsAreDropped(t *testing.T) {
	cfgs := cfgT(cfgParseHAProxy, []byte(`global
    ssl-default-bind-ciphers HIGH
    ssl-server-verify none
    stats auth admin:SECRETSTATS
    tune.ssl.cachesize 1000
userlist L1
    user bob password SECRETUSERLIST
frontend f
    bind :443 ssl crt /c.pem ca-sign-pass SECRETPASS2 crt-ignore-err all tls-ticket-keys /SECRETKEYS
    http-request set-header X-Auth SECRETHEADER
backend b
    server s 1.2.3.4:5 ssl check-sni SECRETSNI sni str(SECRETSNI2) verify required
`))
	cfgNoSecrets(t, cfgs, "SECRETSTATS", "SECRETUSERLIST", "SECRETPASS2", "SECRETKEYS", "SECRETHEADER", "SECRETSNI")
}

func TestHAProxyHostile(t *testing.T) {
	cfgCheckBounds(t, cfgT(cfgParseHAProxy, []byte("frontend\nbind\nbind :1 ssl crt\nbackend\nserver\nserver x\nglobal\nssl-default-bind-options ssl-min-ver\n")))
	cfgs := cfgT(cfgParseHAProxy, []byte("\xef\xbb\xbfglobal\r\n  ssl-default-bind-ciphers HIGH\r\nfrontend f\r\n bind :443 ssl \"crt\" /c.pem\r\n"))
	if len(cfgs) != 2 || cfgs[0].CipherString != "HIGH" {
		t.Errorf("BOM and CRLF: %s", cfgJSON(t, cfgs))
	}
}
