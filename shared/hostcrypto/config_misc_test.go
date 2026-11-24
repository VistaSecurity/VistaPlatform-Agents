package hostcrypto

import (
	"testing"
)

func TestGnuTLSSystemConfig(t *testing.T) {
	cfgs := cfgT(cfgParseGnuTLS, []byte(`# /etc/gnutls/config
[global]
override-mode = allowlist

[priorities]
SYSTEM = NORMAL:-VERS-TLS1.0:-VERS-TLS1.1
OTHER = NONE

[overrides]
insecure-sig = rsa-md5
insecure-hash = sha1
disabled-version = tls1.0, tls1.1
enabled-curve = secp256r1
min-verification-profile = medium
private-key = SECRETGNUTLSKEY
`))
	if len(cfgs) != 1 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	c := cfgs[0]
	if c.Product != "gnutls" || c.Policy != "NORMAL:-VERS-TLS1.0:-VERS-TLS1.1" {
		t.Errorf("product/policy: %s", cfgJSON(t, c))
	}
	cfgWantEqual(t, c.DisabledAlgorithms, []string{"rsa-md5", "sha1", "tls1.0", "tls1.1"})
	cfgWantEqual(t, c.Settings, map[string]string{
		"override-mode": "allowlist", "insecure-sig": "rsa-md5", "insecure-hash": "sha1",
		"disabled-version": "tls1.0, tls1.1", "enabled-curve": "secp256r1",
		"min-verification-profile": "medium",
	})
	cfgNoSecrets(t, cfgs, "SECRETGNUTLSKEY", "NONE")
}

const cfgPostfixMain = `myhostname = mail.example.com
smtpd_tls_cert_file = /etc/pki/tls/certs/mail.crt
smtpd_tls_key_file = /etc/pki/tls/private/mail.key
smtpd_tls_CAfile = /etc/pki/tls/ca.crt
smtpd_tls_dh1024_param_file = /etc/postfix/dh2048.pem
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1,
    !TLSv1.1
smtpd_tls_mandatory_protocols = >=TLSv1.2
smtpd_tls_ciphers = medium
smtpd_tls_mandatory_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, RC4
smtpd_tls_eecdh_grade = auto
smtp_tls_security_level = verify
smtp_tls_mandatory_protocols = >=TLSv1.2, <=TLSv1.3
smtp_tls_CAfile = $config_directory/ca.pem
smtp_tls_cert_file = $client_dir/cert.pem
client_dir = /etc/postfix/client
tls_high_cipherlist = ECDHE+AESGCM
tls_ssl_options = NO_COMPRESSION
smtpd_tls_loglevel = 1
smtpd_sasl_password_maps = hash:/etc/postfix/SECRETSASL
smtp_sasl_password_maps = hash:/etc/postfix/SECRETRELAY
relayhost = [smtp.relay.example]:587
`

func TestPostfixMainCF(t *testing.T) {
	cfgs := cfgT(cfgParsePostfix, []byte(cfgPostfixMain))
	if len(cfgs) != 2 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[0], CryptoConfig{
		Product: "postfix", Context: "smtpd",
		CipherString:       "medium",
		DisabledProtocols:  []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"},
		DisabledAlgorithms: []string{"aNULL", "MD5", "RC4"},
		Settings: map[string]string{
			"smtpd_tls_protocols":           "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
			"smtpd_tls_mandatory_protocols": ">=TLSv1.2",
			"smtpd_tls_ciphers":             "medium",
			"smtpd_tls_mandatory_ciphers":   "high",
			"smtpd_tls_exclude_ciphers":     "aNULL, MD5, RC4",
			"smtpd_tls_security_level":      "may",
			"smtpd_tls_eecdh_grade":         "auto",
			"tls_high_cipherlist":           "ECDHE+AESGCM",
			"tls_ssl_options":               "NO_COMPRESSION",
		},
		References: []ConfigReference{
			{Kind: "certificate", Directive: "smtpd_tls_cert_file", Path: "/etc/pki/tls/certs/mail.crt"},
			{Kind: "private_key", Directive: "smtpd_tls_key_file", Path: "/etc/pki/tls/private/mail.key"},
			{Kind: "trust_store", Directive: "smtpd_tls_CAfile", Path: "/etc/pki/tls/ca.crt"},
			{Kind: "dh_params", Directive: "smtpd_tls_dh1024_param_file", Path: "/etc/postfix/dh2048.pem"},
		},
	})
	cfgWantEqual(t, cfgs[1], CryptoConfig{
		Product: "postfix", Context: "smtp",
		MinProtocol: "TLSv1.2", MaxProtocol: "TLSv1.3",
		Settings: map[string]string{
			"smtp_tls_mandatory_protocols": ">=TLSv1.2, <=TLSv1.3",
			"smtp_tls_security_level":      "verify",
			"tls_high_cipherlist":          "ECDHE+AESGCM",
			"tls_ssl_options":              "NO_COMPRESSION",
		},
		References: []ConfigReference{
			{Kind: "certificate", Directive: "smtp_tls_cert_file", Path: "$client_dir/cert.pem"},
			{Kind: "trust_store", Directive: "smtp_tls_CAfile", Path: "$config_directory/ca.pem"},
		},
	})
	cfgNoSecrets(t, cfgs, "SECRETSASL", "SECRETRELAY", "smtp.relay.example", "mail.example.com")
}

func TestPostfixHostile(t *testing.T) {
	cfgCheckBounds(t, cfgT(cfgParsePostfix, []byte(" leading\n=\nx\n  \ta = b\nsmtpd_tls_protocols =\n smtpd_tls_protocols = $smtpd_tls_protocols\n")))
	cfgs := cfgT(cfgParsePostfix, []byte("\xef\xbb\xbfsmtpd_tls_security_level = encrypt\r\n"))
	if len(cfgs) != 1 || cfgs[0].Settings["smtpd_tls_security_level"] != "encrypt" {
		t.Errorf("BOM and CRLF: %s", cfgJSON(t, cfgs))
	}
}
