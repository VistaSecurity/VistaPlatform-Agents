package hostcrypto

import (
	"testing"
)

const cfgOpenSSL3 = `HOME = .
openssl_conf = openssl_init

[ openssl_init ]
providers = provider_sect
ssl_conf = ssl_sect
alg_section = algorithm_sect
engines = engine_sect

[ provider_sect ]
default = default_sect
fips = fips_sect
legacy = legacy_sect
oqsprovider = oqs_sect

[ default_sect ]
activate = 1

[ fips_sect ]
activate = 1
.include /etc/ssl/fipsmodule.cnf

[ legacy_sect ]
# present but not activated

[ oqs_sect ]
activate = yes
module = /usr/lib/ossl-modules/oqsprovider.so

[ algorithm_sect ]
default_properties = fips=yes

[ engine_sect ]
pkcs11 = pkcs11_section

[ pkcs11_section ]
engine_id = pkcs11
PIN = SECRETENGINEPIN

[ ssl_sect ]
system_default = system_default_sect

[ system_default_sect ]
MinProtocol = TLSv1.2
MaxProtocol = TLSv1.3
CipherString = DEFAULT:@SECLEVEL=2
Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
Groups = X25519MLKEM768:X25519:P-256
SignatureAlgorithms = ECDSA+SHA256:RSA-PSS+SHA256
Options = ServerPreference,-SessionTicket

[ req ]
default_bits = 2048
input_password = SECRETINPUT
output_password = SECRETOUTPUT
`

func TestOpenSSL3WithProviders(t *testing.T) {
	cfgs := cfgT(cfgParseOpenSSL, []byte(cfgOpenSSL3))
	cfgWantEqual(t, cfgs, []CryptoConfig{{
		Product:             "openssl",
		Context:             "system_default_sect",
		MinProtocol:         "TLSv1.2",
		MaxProtocol:         "TLSv1.3",
		CipherString:        "DEFAULT:@SECLEVEL=2",
		CipherSuites:        []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		Groups:              []string{"X25519MLKEM768", "X25519", "P-256"},
		SignatureAlgorithms: []string{"ECDSA+SHA256", "RSA-PSS+SHA256"},
		Policy:              "SECLEVEL=2",
		FIPS:                cfgBoolPtr(true),
		Settings: map[string]string{
			"Options":   "ServerPreference,-SessionTicket",
			"providers": "default,fips,oqsprovider",
			"engines":   "pkcs11",
		},
		References: []ConfigReference{{Kind: "include", Directive: ".include", Path: "/etc/ssl/fipsmodule.cnf"}},
	}})
	cfgNoSecrets(t, cfgs, "SECRETENGINEPIN", "SECRETINPUT", "SECRETOUTPUT")
}

func TestOpenSSLFIPSOnlyByRequirement(t *testing.T) {
	// "?fips=yes" is a preference, "fips=no" a refusal: neither turns FIPS on.
	for _, props := range []string{"?fips=yes", "fips=no", "provider=default"} {
		cfgs := cfgT(cfgParseOpenSSL, []byte("openssl_conf = i\n[i]\nalg_section = a\nssl_conf = s\n[a]\ndefault_properties = "+props+"\n[s]\nsystem_default = d\n[d]\nMinProtocol = TLSv1.2\n"))
		if len(cfgs) != 1 || cfgs[0].FIPS != nil {
			t.Errorf("%q: FIPS must stay unset: %s", props, cfgJSON(t, cfgs))
		}
	}
	cfgs := cfgT(cfgParseOpenSSL, []byte("openssl_conf = i\n[i]\nalg_section = a\n[a]\ndefault_properties = provider=fips, fips=yes\n"))
	if len(cfgs) != 1 || cfgs[0].FIPS == nil || !*cfgs[0].FIPS {
		t.Errorf("fips=yes in a list must turn it on: %s", cfgJSON(t, cfgs))
	}
}

func TestOpenSSLVariablesAndFragment(t *testing.T) {
	cfgs := cfgT(cfgParseOpenSSL, []byte(`dir = /etc/pki
level = 2
[s]
CipherString = HIGH:@SECLEVEL=${level}
Certificate = $dir/server.pem
PrivateKey = ${s::dir}/unknown.pem
VerifyCAFile = $ENV::HOME/ca.pem
MinProtocol = TLSv1
openssl_conf = x
`))
	// No openssl_conf chain reaches [s], and the default section holds no SSL
	// key, so nothing is read from it. That is the honest answer.
	if len(cfgs) != 0 {
		t.Errorf("an unreachable section must not be read: %s", cfgJSON(t, cfgs))
	}
	// Values are reported as written: nothing is expanded, so no other
	// value of the file can reach a kept field.
	cfgs = cfgT(cfgParseOpenSSL, []byte(`dir = /etc/pki
level = 2
openssl_conf = init
[init]
ssl_conf = ssl
[ssl]
system_default = sd
other = app
[sd]
CipherString = HIGH:@SECLEVEL=${level}
Certificate = $dir/server.pem
VerifyCAFile = $ENV::HOME/ca.pem
MinProtocol = TLSv1
TLS.MaxProtocol = TLSv1.3
DTLS.MinProtocol = DTLSv1.2
[app]
MinProtocol = SSLv3
`))
	cfgWantEqual(t, cfgs, []CryptoConfig{{
		Product: "openssl", Context: "sd",
		MinProtocol: "TLSv1.0", MaxProtocol: "TLSv1.3",
		CipherString: "HIGH:@SECLEVEL=${level}",
		Settings:     map[string]string{"DTLS.MinProtocol": "DTLSv1.2"},
		References: []ConfigReference{
			{Kind: "certificate", Directive: "Certificate", Path: "$dir/server.pem"},
		},
	}})
}

func TestOpenSSLRHELBackendFragment(t *testing.T) {
	// RHEL's generated back-ends/opensslcnf.config has no sections at all.
	cfgs := keepCPBackend("/etc/crypto-policies/back-ends/opensslcnf.config", []byte(`CipherString = @SECLEVEL=2:kEECDH:kRSA:kEDH:-aDSS:-3DES:!DES:!RC4:!RC2:!IDEA:-SEED:!eNULL:!aNULL:!MD5:-SHA384:-CAMELLIA:-ARIA:-AESCCM8
Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
TLS.MinProtocol = TLSv1.2
TLS.MaxProtocol = TLSv1.3
DTLS.MinProtocol = DTLSv1.2
DTLS.MaxProtocol = DTLSv1.2
SignatureAlgorithms = ECDSA+SHA256:ECDSA+SHA384:rsa_pss_pss_sha256
Groups = X25519:secp256r1
`))
	if len(cfgs) != 1 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	c := cfgs[0]
	if c.Product != "crypto-policies" || c.Context != "back-end opensslcnf" {
		t.Errorf("product/context: %q %q", c.Product, c.Context)
	}
	if c.MinProtocol != "TLSv1.2" || c.MaxProtocol != "TLSv1.3" || c.Policy != "SECLEVEL=2" {
		t.Errorf("fragment fields: %s", cfgJSON(t, c))
	}
	cfgWantEqual(t, c.CipherSuites, []string{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"})
	cfgWantEqual(t, c.Settings, map[string]string{"DTLS.MinProtocol": "DTLSv1.2", "DTLS.MaxProtocol": "DTLSv1.2"})
}

func TestOpenSSLIncludeForms(t *testing.T) {
	cfgs := cfgT(cfgParseOpenSSL, []byte(".include /a.cnf\n.include = /b.cnf\n.include=/c.cnf\n.pragma dollarid:on\n[x]\n.include \"/d.cnf\"\n"))
	if len(cfgs) != 1 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	var paths []string
	for _, r := range cfgs[0].References {
		paths = append(paths, r.Path)
	}
	cfgWantEqual(t, paths, []string{"/a.cnf", "/b.cnf", "/c.cnf", "/d.cnf"})
}

func TestOpenSSLSecretsAreDropped(t *testing.T) {
	cfgs := cfgT(cfgParseOpenSSL, []byte(`openssl_conf = i
[i]
ssl_conf = s
providers = p
[p]
pkcs11 = pk
[pk]
activate = 1
pkcs11-module-pin = SECRETMODPIN
[s]
system_default = sd
[sd]
MinProtocol = TLSv1.2
Passphrase = SECRETPASS
PIN = SECRETPIN
PrivateKey = /etc/k.pem
Password = SECRETPW
[ca]
private_key = /etc/ca/SECRETCAKEY.pem
[req]
challengePassword = SECRETCHALLENGE
`))
	cfgNoSecrets(t, cfgs, "SECRETMODPIN", "SECRETPASS", "SECRETPIN", "SECRETPW", "SECRETCAKEY", "SECRETCHALLENGE")
}

func TestOpenSSLHostile(t *testing.T) {
	cfgs := cfgT(cfgParseOpenSSL, []byte("[\n[]\n[unterminated\nk\n=\n= v\nCipherString = \"unterminated\nopenssl_conf = $openssl_conf\n"))
	cfgCheckBounds(t, cfgs)
	cfgs = cfgT(cfgParseOpenSSL, []byte("\xef\xbb\xbfopenssl_conf = i\r\n[i]\r\nssl_conf = s\r\n[s]\r\nsystem_default = d\r\n[d]\r\nMinProtocol = TLSv1.2\r\n"))
	if len(cfgs) != 1 || cfgs[0].MinProtocol != "TLSv1.2" {
		t.Errorf("BOM and CRLF: %s", cfgJSON(t, cfgs))
	}
}

func FuzzConfigOpenSSL(f *testing.F) {
	f.Add([]byte(cfgOpenSSL3))
	f.Add([]byte("openssl_conf=i\n[i]\nssl_conf=$i\nproviders=${i::providers}\n.include /x\n"))
	f.Add([]byte("a=$a$a\n[s]\nCipherString=$a\n[\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		cfgCheckBounds(t, cfgT(cfgParseOpenSSL, b))
	})
}
