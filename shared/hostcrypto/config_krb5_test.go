package hostcrypto

import (
	"testing"
)

func TestKrb5Libdefaults(t *testing.T) {
	cfgs := cfgT(cfgParseKrb5, []byte(`includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log

[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    default_realm = EXAMPLE.COM
    permitted_enctypes = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128,aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha384-192
    default_tkt_enctypes = aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96
    allow_weak_crypto = false
    default_ccache_name = KEYRING:persistent:%{uid}
    default_keytab_name = FILE:/etc/krb5.keytab
    default_client_keytab_name = KEYRING:client
    spake_preauth_groups = edwards25519, P-256
    pkinit_anchors = FILE:/etc/pki/ca-trust/source/anchors/kdc-ca.pem
    pkinit_identities = FILE:/etc/pki/tls/certs/user.pem,/etc/pki/tls/private/user.key
    password = SECRETKRB5

[realms]
 EXAMPLE.COM = {
     kdc = kdc.example.com
     master_key_name = SECRETMASTER
     pkinit_anchors = FILE:/realm/ca.pem
 }

[domain_realm]
 .example.com = EXAMPLE.COM
`))
	cfgWantEqual(t, cfgs, []CryptoConfig{{
		Product: "krb5",
		CipherSuites: []string{
			"aes256-cts-hmac-sha384-192", "aes128-cts-hmac-sha256-128", "aes256-cts-hmac-sha1-96",
		},
		Groups: []string{"edwards25519", "P-256"},
		Settings: map[string]string{
			"permitted_enctypes":                "aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128,aes256-cts-hmac-sha1-96",
			"default_tgs_enctypes":              "aes256-cts-hmac-sha384-192",
			"default_tkt_enctypes":              "aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96",
			"allow_weak_crypto":                 "false",
			"default_ccache_name":               "keyring", // only the type of a cache or keytab name that is not a file
			"default_client_keytab_name_source": "keyring",
		},
		References: []ConfigReference{
			{Kind: "include", Directive: "includedir", Path: "/etc/krb5.conf.d/"},
			{Kind: "keystore", Directive: "default_keytab_name", Path: "/etc/krb5.keytab"},
			{Kind: "trust_store", Directive: "pkinit_anchors", Path: "/etc/pki/ca-trust/source/anchors/kdc-ca.pem"},
			{Kind: "certificate", Directive: "pkinit_identities", Path: "/etc/pki/tls/certs/user.pem"},
			{Kind: "private_key", Directive: "pkinit_identities", Path: "/etc/pki/tls/private/user.key"},
		},
	}})
	cfgNoSecrets(t, cfgs, "SECRETKRB5", "SECRETMASTER", "kdc.example.com", "/realm/ca.pem")
}

func TestKrb5PKINITForms(t *testing.T) {
	cfgs := cfgT(cfgParseKrb5, []byte(`[libdefaults]
pkinit_identities = PKCS11:module_name=/usr/lib/opensc-pkcs11.so:pin=SECRETPKCS11
pkinit_anchors = ENV:SECRETENV
`))
	if cfgs != nil {
		t.Errorf("PKCS11 and ENV forms are dropped, got %s", cfgJSON(t, cfgs))
	}
	cfgs = cfgT(cfgParseKrb5, []byte("[libdefaults]\npkinit_identities = PKCS12:/etc/u.p12\npkinit_anchors = DIR:/etc/anchors\n"))
	cfgWantEqual(t, cfgs[0].References, []ConfigReference{
		{Kind: "keystore", Directive: "pkinit_identities", Path: "/etc/u.p12"},
		{Kind: "trust_store", Directive: "pkinit_anchors", Path: "/etc/anchors"},
	})
}

func TestKrb5Hostile(t *testing.T) {
	cfgCheckBounds(t, cfgT(cfgParseKrb5, []byte("[libdefaults\npermitted_enctypes\n=\n[libdefaults]\n{\n}\nincludedir\n")))
	cfgs := cfgT(cfgParseKrb5, []byte("\xef\xbb\xbf[libdefaults]\r\nallow_weak_crypto = true\r\n"))
	if len(cfgs) != 1 || cfgs[0].Settings["allow_weak_crypto"] != "true" {
		t.Errorf("BOM and CRLF: %s", cfgJSON(t, cfgs))
	}
}
