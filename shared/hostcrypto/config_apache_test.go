package hostcrypto

import (
	"testing"
)

const cfgApacheMozilla = `ServerRoot "/etc/httpd"
Listen 443 https
<IfModule mod_ssl.c>
SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder     off
SSLSessionTickets       off
SSLUseStapling On
SSLPassPhraseDialog exec:/usr/local/bin/SECRETDIALOG
</IfModule>
IncludeOptional conf.d/*.conf

<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    SSLCertificateFile /etc/pki/tls/certs/example.crt
    SSLCertificateKeyFile "/etc/pki/tls/private/example.key"
    SSLCertificateChainFile /etc/pki/tls/certs/chain.crt
    SSLCACertificateFile /etc/pki/tls/ca.crt
    SSLOpenSSLConfCmd DHParameters "/etc/pki/tls/dh.pem"
    SSLOpenSSLConfCmd Groups X25519:P-256
    Header always set Strict-Transport-Security "max-age=63072000"
    <Directory /var/www>
        SSLVerifyClient require
    </Directory>
</VirtualHost>
`

func TestApacheMozillaIntermediate(t *testing.T) {
	cfgs := cfgT(cfgParseApache, []byte(cfgApacheMozilla))
	if len(cfgs) != 2 {
		t.Fatalf("want the server level and the TLS virtual host, got %s", cfgJSON(t, cfgs))
	}
	server := cfgs[0]
	cfgWantEqual(t, server, CryptoConfig{
		Product:           "apache",
		DisabledProtocols: []string{"SSLv3", "TLSv1.0", "TLSv1.1"}, // "all" is not resolved
		CipherString:      "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
		Settings: map[string]string{
			"SSLProtocol":         "all -SSLv3 -TLSv1 -TLSv1.1",
			"SSLHonorCipherOrder": "off",
			"SSLSessionTickets":   "off",
			"SSLUseStapling":      "On",
		},
		References: []ConfigReference{{Kind: "include", Directive: "IncludeOptional", Path: "conf.d/*.conf"}},
	})
	cfgWantEqual(t, cfgs[1], CryptoConfig{
		Product:      "apache",
		Context:      "VirtualHost *:443 ServerName example.com",
		Protocols:    []string{"TLSv1.2", "TLSv1.3"},
		CipherString: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256", // inherited
		CipherSuites: []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		Settings: map[string]string{
			"SSLProtocol":               "-all +TLSv1.2 +TLSv1.3",
			"SSLEngine":                 "on",
			"SSLHonorCipherOrder":       "off", // inherited
			"SSLSessionTickets":         "off", // inherited
			"SSLUseStapling":            "On",  // inherited
			"SSLOpenSSLConfCmd Groups":  "X25519:P-256",
			"Strict-Transport-Security": "max-age=63072000",
		},
		References: []ConfigReference{
			{Kind: "certificate", Directive: "SSLCertificateFile", Path: "/etc/pki/tls/certs/example.crt"},
			{Kind: "private_key", Directive: "SSLCertificateKeyFile", Path: "/etc/pki/tls/private/example.key"},
			{Kind: "certificate", Directive: "SSLCertificateChainFile", Path: "/etc/pki/tls/certs/chain.crt"},
			{Kind: "trust_store", Directive: "SSLCACertificateFile", Path: "/etc/pki/tls/ca.crt"},
			{Kind: "dh_params", Directive: "SSLOpenSSLConfCmd DHParameters", Path: "/etc/pki/tls/dh.pem"},
		},
	})
}

func TestApacheSSLProtocolResolution(t *testing.T) {
	for _, tc := range []struct {
		in             string
		allowed, minus []string
	}{
		// "all" is whatever the OpenSSL build has: only what is removed after
		// it is known.
		{"all", nil, nil},
		{"all -SSLv3 -TLSv1 -TLSv1.1", nil, []string{"SSLv3", "TLSv1.0", "TLSv1.1"}},
		{"-TLSv1.2 all", nil, nil}, // "all" after the removal: nothing disabled
		{"all -TLSv1.2 +TLSv1.2", nil, nil},
		// The set starts empty and is built left to right.
		{"+TLSv1.3", []string{"TLSv1.3"}, nil},
		{"+TLSv1.2 +TLSv1.3", []string{"TLSv1.2", "TLSv1.3"}, nil},
		{"TLSv1.2", []string{"TLSv1.2"}, nil},
		{"TLSv1.2 TLSv1.3", []string{"TLSv1.3"}, nil}, // a bare name sets the set
		{"-all +TLSv1.3", []string{"TLSv1.3"}, nil},
		{"-all +TLSv1.2 +TLSv1.3", []string{"TLSv1.2", "TLSv1.3"}, nil},
		{"-all +TLSv1 +SSLv3", []string{"SSLv3", "TLSv1.0"}, nil},
		{"all -all +TLSv1.2 -TLSv1.2", nil, nil},
		{"+Bogus", nil, nil},
	} {
		allowed, minus := cfgApacheProtocols(splitFields(tc.in))
		cfgWantEqual(t, allowed, tc.allowed)
		cfgWantEqual(t, minus, tc.minus)
		if t.Failed() {
			t.Errorf("for %q", tc.in)
			return
		}
	}
}

func splitFields(s string) []string { return cfgFields(s, false) }

func TestApacheSkippedSections(t *testing.T) {
	cfgs := cfgT(cfgParseApache, []byte(`<IfModule !mod_ssl.c>
SSLProtocol SSLv3
</IfModule>
<IfVersion >= 2.4>
SSLProtocol SSLv3
</IfVersion>
<Directory "/x">
<IfModule mod_ssl.c>
SSLProtocol SSLv3
</IfModule>
SSLProtocol SSLv3
</Directory>
<IfDefine SSL>
SSLProtocol TLSv1.2
</IfDefine>
<IfModule mod_ssl.c>
<IfModule !mod_foo.c>
SSLHonorCipherOrder on
</IfModule>
SSLSessionTickets off
</IfModule>
</Directory></Directory>
`))
	if len(cfgs) != 1 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[0].Protocols, []string{"TLSv1.2"})
	cfgWantEqual(t, cfgs[0].Settings, map[string]string{"SSLProtocol": "TLSv1.2", "SSLSessionTickets": "off"})
}

func TestApacheGnuTLSAndFIPSAndKeyURIs(t *testing.T) {
	cfgs := cfgT(cfgParseApache, []byte(`<VirtualHost *:8443>
GnuTLSEnable on
GnuTLSPriorities NORMAL:!VERS-SSL3.0
GnuTLSCertificateFile /etc/g/cert.pem
GnuTLSKeyFile /etc/g/key.pem
GnuTLSP12File /etc/g/bundle.p12
GnuTLSP12Password SECRETP12
</VirtualHost>
SSLFIPS on
<VirtualHost *:9443>
SSLEngine on
SSLCertificateKeyFile "pkcs11:token=t;object=o;pin-value=SECRETPIN"
SSLCertificateFile "pkcs11:token=t;object=c"
</VirtualHost>
`))
	g := cfgFind(t, cfgs, "VirtualHost *:8443")
	if g.Policy != "NORMAL:!VERS-SSL3.0" {
		t.Errorf("policy %q", g.Policy)
	}
	cfgWantEqual(t, g.References, []ConfigReference{
		{Kind: "certificate", Directive: "GnuTLSCertificateFile", Path: "/etc/g/cert.pem"},
		{Kind: "private_key", Directive: "GnuTLSKeyFile", Path: "/etc/g/key.pem"},
		{Kind: "keystore", Directive: "GnuTLSP12File", Path: "/etc/g/bundle.p12"},
	})
	p := cfgFind(t, cfgs, "VirtualHost *:9443")
	if p.FIPS == nil || !*p.FIPS {
		t.Error("SSLFIPS on at server level is inherited")
	}
	cfgWantEqual(t, p.Settings["SSLCertificateKeyFile_source"], "pkcs11")
	if len(p.References) != 0 {
		t.Errorf("a pkcs11 URI is not a path: %+v", p.References)
	}
	cfgNoSecrets(t, cfgs, "SECRETP12", "SECRETPIN")
}

func TestApacheSecretsAreDropped(t *testing.T) {
	cfgs := cfgT(cfgParseApache, []byte(`SSLPassPhraseDialog "exec:/usr/local/bin/get-pass SECRETARG"
SSLPassPhraseDialog builtin
SSLRandomSeed startup file:/dev/urandom 512
SSLSessionCache "shmcb:/run/SECRETCACHE(512000)"
AuthUserFile /etc/SECRETHTPASSWD
SetEnv API_TOKEN SECRETTOKEN
SSLProxyMachineCertificateFile /etc/m.pem
SSLProtocol TLSv1.2
<VirtualHost *:443>
SSLEngine on
SSLCertificateKeyFile /k.pem
SSLCARevocationPath /crl
SSLProxyCipherSuite HIGH
SSLVerifyClient optional
SSLRequire %{SSL_CLIENT_S_DN_CN} eq "SECRETDN"
</VirtualHost>
`))
	cfgNoSecrets(t, cfgs, "SECRETARG", "SECRETCACHE", "SECRETHTPASSWD", "SECRETTOKEN", "SECRETDN", "get-pass", "builtin")
	s := cfgFind(t, cfgs, "")
	if len(s.References) != 1 || s.References[0].Kind != "certificate" {
		t.Errorf("the proxy machine certificate is a reference: %+v", s.References)
	}
}

func TestApacheHostileSyntax(t *testing.T) {
	cfgs := cfgT(cfgParseApache, []byte("<VirtualHost *:443\nSSLProtocol TLSv1.2\n</VirtualHost>\n<VirtualHost *:444>\nSSLProtocol \"TLSv1.3\n\r\n"))
	cfgCheckBounds(t, cfgs)
	cfgs = cfgT(cfgParseApache, []byte("\xef\xbb\xbf<VirtualHost *:443>\r\nSSLProtocol TLSv1.2\r\n</VirtualHost>\r\n"))
	if len(cfgs) != 1 || cfgs[0].Protocols[0] != "TLSv1.2" {
		t.Errorf("BOM and CRLF: %s", cfgJSON(t, cfgs))
	}
}

func FuzzConfigApache(f *testing.F) {
	f.Add([]byte(cfgApacheMozilla))
	f.Add([]byte("<VirtualHost *:443>\nSSLProtocol all -SSLv3\n<IfModule mod_ssl.c>\nSSLCipherSuite TLSv1.3 a:b\n"))
	f.Add([]byte("SSLCertificateKeyFile pkcs11:x\n</Directory>\n<IfModule !x>\n\\\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		cfgCheckBounds(t, cfgT(cfgParseApache, b))
	})
}
