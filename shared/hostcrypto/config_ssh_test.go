package hostcrypto

import (
	"testing"
)

const cfgSSHDRHEL9 = `Include /etc/ssh/sshd_config.d/*.conf

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub

PermitRootLogin no
PubkeyAuthentication yes
AuthorizedKeysFile	.ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
GSSAPIAuthentication yes
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms=curve25519-sha256,sntrup761x25519-sha512@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
PubkeyAcceptedAlgorithms +ssh-rsa
CASignatureAlgorithms ssh-ed25519
RequiredRSASize 3072
TrustedUserCAKeys /etc/ssh/user_ca.pub
RevokedKeys /etc/ssh/revoked
Subsystem	sftp	/usr/libexec/openssh/sftp-server
AuthorizedKeysCommand /usr/bin/SECRETCMD --token SECRETTOKEN
Banner /etc/issue.SECRETBANNER

# The first value of a keyword wins.
Ciphers aes128-ctr

Match User backup
    PasswordAuthentication yes
    PubkeyAcceptedAlgorithms +ssh-rsa
    Ciphers aes128-cbc
Match Address 10.0.0.0/8 exec "test -f /secret/SECRETEXEC"
    PermitRootLogin prohibit-password
Match all
`

func TestSSHDRHEL9(t *testing.T) {
	cfgs := cfgT(cfgParseSSHD, []byte(cfgSSHDRHEL9))
	if len(cfgs) != 3 {
		t.Fatalf("want global and two Match blocks (the empty `Match all` is not reported), got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[0], CryptoConfig{
		Product:             "sshd",
		CipherSuites:        []string{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"},
		MACs:                []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"},
		KeyExchanges:        []string{"curve25519-sha256", "sntrup761x25519-sha512@openssh.com"},
		HostKeyAlgorithms:   []string{"ssh-ed25519", "rsa-sha2-512"},
		SignatureAlgorithms: []string{"+ssh-rsa", "ssh-ed25519"},
		Settings: map[string]string{
			"PermitRootLogin":              "no",
			"PubkeyAuthentication":         "yes",
			"AuthorizedKeysFile":           ".ssh/authorized_keys",
			"PasswordAuthentication":       "no",
			"KbdInteractiveAuthentication": "no",
			"GSSAPIAuthentication":         "yes",
			"PubkeyAcceptedAlgorithms":     "+ssh-rsa",
			"CASignatureAlgorithms":        "ssh-ed25519",
			"RequiredRSASize":              "3072",
		},
		References: []ConfigReference{
			{Kind: "include", Directive: "Include", Path: "/etc/ssh/sshd_config.d/*.conf"},
			{Kind: "private_key", Directive: "HostKey", Path: "/etc/ssh/ssh_host_rsa_key"},
			{Kind: "private_key", Directive: "HostKey", Path: "/etc/ssh/ssh_host_ecdsa_key"},
			{Kind: "private_key", Directive: "HostKey", Path: "/etc/ssh/ssh_host_ed25519_key"},
			{Kind: "certificate", Directive: "HostCertificate", Path: "/etc/ssh/ssh_host_ed25519_key-cert.pub"},
			{Kind: "trust_store", Directive: "TrustedUserCAKeys", Path: "/etc/ssh/user_ca.pub"},
			{Kind: "crl", Directive: "RevokedKeys", Path: "/etc/ssh/revoked"},
		},
	})
	cfgWantEqual(t, cfgs[1], CryptoConfig{
		Product: "sshd", Context: "Match User backup",
		// Ciphers is not allowed inside a Match block by sshd, so it is dropped.
		SignatureAlgorithms: []string{"+ssh-rsa"},
		Settings:            map[string]string{"PasswordAuthentication": "yes", "PubkeyAcceptedAlgorithms": "+ssh-rsa"},
	})
	cfgWantEqual(t, cfgs[2], CryptoConfig{
		Product: "sshd", Context: "Match Address 10.0.0.0/8 exec",
		Settings: map[string]string{"PermitRootLogin": "prohibit-password"},
	})
	cfgNoSecrets(t, cfgs, "SECRETCMD", "SECRETTOKEN", "SECRETBANNER", "SECRETEXEC", "sftp-server")
}

func TestSSHClientConfig(t *testing.T) {
	cfgs := cfgT(cfgParseSSHClient, []byte(`Host *.corp.example.com corp
    IdentityFile ~/.ssh/id_ed25519
    IdentityFile none
    IdentityFile ~/.ssh/id_rsa
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    Protocol 2,1
    StrictHostKeyChecking = yes
    UserKnownHostsFile ~/.ssh/known_hosts.corp
    PKCS11Provider /usr/lib/opensc-pkcs11.so
    ProxyCommand ssh -W %h:%p SECRETJUMP
    SetEnv TOKEN=SECRETENV
    VerifyHostKeyDNS ask
    FingerprintHash sha256
    RekeyLimit 1G 1h
Host *
    Ciphers aes256-ctr,aes192-ctr
    KexAlgorithms -diffie-hellman-group1-sha1
    HostKeyAlgorithms ^ssh-ed25519
    PubkeyAcceptedKeyTypes ssh-ed25519
`))
	if len(cfgs) != 2 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[0], CryptoConfig{
		Product: "ssh", Context: "Host *.corp.example.com corp",
		Protocols: []string{"SSHv2", "SSHv1"},
		Settings: map[string]string{
			"StrictHostKeyChecking": "yes", "UserKnownHostsFile": "~/.ssh/known_hosts.corp",
			"PKCS11Provider": "/usr/lib/opensc-pkcs11.so", "VerifyHostKeyDNS": "ask",
			"FingerprintHash": "sha256", "RekeyLimit": "1G 1h",
		},
		References: []ConfigReference{
			{Kind: "private_key", Directive: "IdentityFile", Path: "~/.ssh/id_ed25519"},
			{Kind: "private_key", Directive: "IdentityFile", Path: "~/.ssh/id_rsa"},
			{Kind: "certificate", Directive: "CertificateFile", Path: "~/.ssh/id_ed25519-cert.pub"},
		},
	})
	cfgWantEqual(t, cfgs[1], CryptoConfig{
		Product: "ssh", Context: "Host *",
		CipherSuites:        []string{"aes256-ctr", "aes192-ctr"},
		KeyExchanges:        []string{"-diffie-hellman-group1-sha1"},
		HostKeyAlgorithms:   []string{"^ssh-ed25519"},
		SignatureAlgorithms: []string{"ssh-ed25519"},
		Settings:            map[string]string{"PubkeyAcceptedKeyTypes": "ssh-ed25519"},
	})
	cfgNoSecrets(t, cfgs, "SECRETJUMP", "SECRETENV")
}

func TestSSHDIgnoresHostBlocks(t *testing.T) {
	// `Host` is a client keyword; sshd does not start a block on it, and an
	// unknown keyword is dropped.
	cfgs := cfgT(cfgParseSSHD, []byte("Host evil\nCiphers aes128-ctr\n"))
	if len(cfgs) != 1 || cfgs[0].Context != "" || len(cfgs[0].CipherSuites) != 1 {
		t.Errorf("got %s", cfgJSON(t, cfgs))
	}
}

func TestSSHHostile(t *testing.T) {
	cfgs := cfgT(cfgParseSSHD, []byte("\xef\xbb\xbfCiphers aes256-ctr\r\nMatch User \"unterminated\r\nPermitRootLogin no\r\n"))
	if len(cfgs) != 2 || cfgs[0].CipherSuites[0] != "aes256-ctr" || cfgs[1].Context != "Match User unterminated" {
		t.Errorf("BOM, CRLF and an unterminated quote: %s", cfgJSON(t, cfgs))
	}
	cfgCheckBounds(t, cfgT(cfgParseSSHD, []byte("Ciphers\nMACs=\n=\nMatch\nMatch exec\nInclude\n")))
}

func FuzzConfigSSH(f *testing.F) {
	f.Add([]byte(cfgSSHDRHEL9))
	f.Add([]byte("Host a b\nProtocol 2,1\nIdentityFile x\nMatch exec \"x\"\nCiphers=+a\n"))
	f.Add([]byte("Match \"\nciphers \\\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		cfgCheckBounds(t, cfgT(cfgParseSSHD, b))
		cfgCheckBounds(t, cfgT(cfgParseSSHClient, b))
	})
}
