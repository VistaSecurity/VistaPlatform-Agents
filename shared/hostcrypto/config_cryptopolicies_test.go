package hostcrypto

import (
	"testing"
)

func TestCryptoPoliciesConfig(t *testing.T) {
	for in, want := range map[string]string{
		"DEFAULT\n":                  "DEFAULT",
		"# comment\n\nFIPS\n":        "FIPS",
		"DEFAULT:SHA1\r\n":           "DEFAULT:SHA1",
		"\xef\xbb\xbfLEGACY":         "LEGACY",
		"DEFAULT:NO-SHA1:OSPP # why": "DEFAULT:NO-SHA1:OSPP",
	} {
		cfgs := cfgT(cfgParseCryptoPoliciesConfig, []byte(in))
		if len(cfgs) != 1 || cfgs[0].Policy != want || cfgs[0].Product != "crypto-policies" || cfgs[0].FIPS != nil {
			t.Errorf("%q: got %s", in, cfgJSON(t, cfgs))
		}
	}
	for _, in := range []string{"", "# only a comment\n", "has spaces in it", "a=b", "$(evil)"} {
		if got := cfgT(cfgParseCryptoPoliciesConfig, []byte(in)); got != nil {
			t.Errorf("%q must yield nothing, got %s", in, cfgJSON(t, got))
		}
	}
}

func TestCryptoPolicyBackends(t *testing.T) {
	t.Run("opensshserver (RHEL 9 style)", func(t *testing.T) {
		cfgs := ParseCryptoPolicyBackend("opensshserver.config", []byte(`Ciphers aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-256,hmac-sha2-512
GSSAPIKexAlgorithms gss-curve25519-sha256-
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
PubkeyAcceptedAlgorithms ssh-ed25519
CASignatureAlgorithms ssh-ed25519
RequiredRSASize 2048
`))
		cfgWantEqual(t, cfgs, []CryptoConfig{{
			Product: "crypto-policies", Context: "back-end opensshserver",
			CipherSuites:        []string{"aes256-gcm@openssh.com", "aes256-ctr"},
			MACs:                []string{"hmac-sha2-256", "hmac-sha2-512"},
			KeyExchanges:        []string{"curve25519-sha256", "ecdh-sha2-nistp256"},
			HostKeyAlgorithms:   []string{"ssh-ed25519", "rsa-sha2-512"},
			SignatureAlgorithms: []string{"ssh-ed25519"},
			Settings: map[string]string{
				"GSSAPIKexAlgorithms": "gss-curve25519-sha256-", "PubkeyAcceptedAlgorithms": "ssh-ed25519",
				"CASignatureAlgorithms": "ssh-ed25519", "RequiredRSASize": "2048",
			},
		}})
	})
	t.Run("openssh (RHEL 8 CRYPTO_POLICY style)", func(t *testing.T) {
		cfgs := ParseCryptoPolicyBackend("openssh", []byte(`CRYPTO_POLICY='-oCiphers=aes256-ctr,aes128-ctr -oMACs=hmac-sha2-256 -oKexAlgorithms=ecdh-sha2-nistp256 -oSomethingElse=x'
`))
		if len(cfgs) != 1 || cfgs[0].CipherSuites[1] != "aes128-ctr" || cfgs[0].MACs[0] != "hmac-sha2-256" ||
			cfgs[0].KeyExchanges[0] != "ecdh-sha2-nistp256" || cfgs[0].Context != "back-end openssh" {
			t.Errorf("got %s", cfgJSON(t, cfgs))
		}
	})
	t.Run("gnutls", func(t *testing.T) {
		cfgs := ParseCryptoPolicyBackend("gnutls.config", []byte(`[priorities]
SYSTEM=NONE:+AES-256-GCM:+AES-128-GCM:+VERS-TLS1.3:+VERS-TLS1.2:%PROFILE_MEDIUM

[overrides]
# generated
insecure-hash = md5
insecure-sig-for-cert = rsa-sha1
disabled-curve = secp192r1
tls-disabled-cipher = 3DES-CBC
tls-disabled-cipher = RC4-128
tls-session-hash = 1
password = SECRETGNUTLS
`))
		if len(cfgs) != 1 {
			t.Fatalf("got %s", cfgJSON(t, cfgs))
		}
		c := cfgs[0]
		if c.Policy != "NONE:+AES-256-GCM:+AES-128-GCM:+VERS-TLS1.3:+VERS-TLS1.2:%PROFILE_MEDIUM" {
			t.Errorf("policy %q", c.Policy)
		}
		cfgWantEqual(t, c.DisabledAlgorithms, []string{"md5", "rsa-sha1", "secp192r1", "3DES-CBC", "RC4-128"})
		cfgWantEqual(t, c.Settings["tls-disabled-cipher"], "3DES-CBC,RC4-128")
		cfgNoSecrets(t, cfgs, "SECRETGNUTLS")
	})
	t.Run("java", func(t *testing.T) {
		cfgs := ParseCryptoPolicyBackend("java.config", []byte("jdk.tls.disabledAlgorithms=SSLv3, TLSv1\nkeystore.type=pkcs12\n"))
		if len(cfgs) != 1 || cfgs[0].Context != "back-end java" || len(cfgs[0].DisabledAlgorithms) != 2 {
			t.Errorf("got %s", cfgJSON(t, cfgs))
		}
	})
	t.Run("nss", func(t *testing.T) {
		cfgs := ParseCryptoPolicyBackend("nss.config", []byte(`name=Policy
library=
NSS=flags=policyOnly,moduleDB
config="disallow=ALL allow=HMAC-SHA256:HMAC-SHA1:AES256-GCM:tls-version-min=tls1.2:dtls-version-min=dtls1.2"
`))
		if len(cfgs) != 1 || cfgs[0].MinProtocol != "TLSv1.2" || cfgs[0].Settings["dtls-version-min"] != "DTLSv1.2" ||
			cfgs[0].Settings["config"] == "" || cfgs[0].Context != "back-end nss" {
			t.Errorf("got %s", cfgJSON(t, cfgs))
		}
	})
	t.Run("krb5", func(t *testing.T) {
		cfgs := ParseCryptoPolicyBackend("/etc/crypto-policies/back-ends/krb5.config", []byte("[libdefaults]\npermitted_enctypes = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128\n"))
		if len(cfgs) != 1 || len(cfgs[0].CipherSuites) != 2 || cfgs[0].Context != "back-end krb5" {
			t.Errorf("got %s", cfgJSON(t, cfgs))
		}
	})
}
