package hostcrypto

// Fixtures written for this repository. They model the file layouts (which
// file includes which, where a directive sits) of the distributions the tests
// name; the values and the text are our own. Keys are paths below the
// directory's prefix, see cfgFixtureTree.
var cfgOwn = map[string]map[string]string{
	"rocky9": {
		"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n" +
			"AuthorizedKeysFile .ssh/authorized_keys\n" +
			"Subsystem sftp /usr/libexec/openssh/sftp-server\n",
		"etc/ssh/sshd_config.d/50-redhat.conf": "Include /etc/crypto-policies/back-ends/opensshserver.config\n" +
			"ChallengeResponseAuthentication no\n" +
			"GSSAPIAuthentication yes\n" +
			"UsePAM yes\n",
		"etc/krb5.conf": "includedir /etc/krb5.conf.d/\n" +
			"[logging]\n default = FILE:/var/log/krb5libs.log\n" +
			"[libdefaults]\n" +
			"    dns_lookup_realm = false\n" +
			"    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt\n" +
			"    spake_preauth_groups = edwards25519\n" +
			"    default_ccache_name = KEYRING:persistent:%{uid}\n" +
			"[realms]\n",
		"etc/krb5.conf.d/crypto-policies": "[libdefaults]\n" +
			"permitted_enctypes = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n",
		"etc/crypto-policies/back-ends/opensshserver.config": "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr\n" +
			"MACs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512\n" +
			"GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-nistp256-sha256-,gss-group14-sha256-,gss-group16-sha512-\n" +
			"KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\n" +
			"HostKeyAlgorithms ecdsa-sha2-nistp256,ssh-ed25519,rsa-sha2-256,rsa-sha2-512\n" +
			"PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ssh-ed25519,rsa-sha2-256,rsa-sha2-512\n" +
			"CASignatureAlgorithms ecdsa-sha2-nistp256,ssh-ed25519,rsa-sha2-512\n" +
			"RequiredRSASize 2048\n",
		"etc/crypto-policies/back-ends/openssh.config": "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr\n" +
			"KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n",
		"etc/crypto-policies/back-ends/libssh.config": "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr\n" +
			"MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512\n" +
			"KexAlgorithms curve25519-sha256,ecdh-sha2-nistp384\n" +
			"HostKeyAlgorithms ssh-ed25519,rsa-sha2-512\n" +
			"PubkeyAcceptedKeyTypes ssh-ed25519,rsa-sha2-512\n",
		"etc/crypto-policies/back-ends/gnutls.config": "[global]\noverride-mode = allowlist\n\n[overrides]\n" +
			"secure-hash = SHA256\nsecure-hash = SHA384\n" +
			"tls-enabled-mac = AEAD\ntls-enabled-mac = SHA1\n" +
			"tls-enabled-group = GROUP-X25519\ntls-enabled-group = GROUP-SECP256R1\n" +
			"secure-sig = ECDSA-SHA256\nsecure-sig = EdDSA-Ed25519\n",
		"etc/crypto-policies/back-ends/openssl_fips.config": "[fips_sect]\ntls1-prf-ems-check = 1\nactivate = 1\n",
		"etc/crypto-policies/back-ends/openssl.config":      "@SECLEVEL=2:kEECDH:kRSA:-aDSS:!RC4:!MD5\n",
		"etc/crypto-policies/back-ends/opensslcnf.config": "CipherString = @SECLEVEL=2:kEECDH:kRSA:-aDSS:!RC4:!MD5\n" +
			"Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256\n" +
			"TLS.MinProtocol = TLSv1.2\nTLS.MaxProtocol = TLSv1.3\nDTLS.MinProtocol = DTLSv1.2\nDTLS.MaxProtocol = DTLSv1.2\n" +
			"SignatureAlgorithms = ECDSA+SHA256:ed25519:rsa_pss_rsae_sha256\n" +
			"Groups = *X25519:secp256r1:ffdhe2048\n",
		"etc/crypto-policies/back-ends/java.config": "jdk.certpath.disabledAlgorithms=MD2, MD5withRSA, RSA keySize < 2048\n" +
			"jdk.tls.disabledAlgorithms=MD5withRSA, SHA1withDSA, DH keySize < 2048, include jdk.disabled.namedCurves\n" +
			"jdk.disabled.namedCurves=secp112r1, sect113r1\n" +
			"jdk.tls.legacyAlgorithms=\n",
		"etc/crypto-policies/back-ends/javasystem.config": "jdk.tls.ephemeralDHKeySize=2048\njdk.tls.namedGroups=x25519, secp256r1, ffdhe2048\n",
		"etc/crypto-policies/back-ends/nss.config": "library=\nname=Policy\nNSS=flags=policyOnly,moduleDB\n" +
			"config=\"disallow=ALL allow=HMAC-SHA256:aes256-gcm:ECDHE-RSA:tls-version-min=tls1.2:dtls-version-min=dtls1.2\"\n",
		"etc/crypto-policies/back-ends/krb5.config": "[libdefaults]\n" +
			"permitted_enctypes = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n",
	},
	"rocky8": {
		"etc/crypto-policies/back-ends/gnutls.config":        "SYSTEM=NONE:+MAC-ALL:-MD5:+GROUP-ALL:+SIGN-ALL:-SIGN-RSA-MD5:+CIPHER-ALL:-3DES-CBC:+ECDHE-RSA\n",
		"etc/crypto-policies/back-ends/openssh.config":       "CRYPTO_POLICY='-oCiphers=aes256-ctr,aes128-ctr -oMACs=hmac-sha2-256 -oKexAlgorithms=ecdh-sha2-nistp256'\n",
		"etc/crypto-policies/back-ends/opensshserver.config": "CRYPTO_POLICY='-oCiphers=aes256-ctr,aes128-ctr -oMACs=hmac-sha2-512'\n",
		"etc/crypto-policies/back-ends/libssh.config":        "Ciphers aes256-ctr,aes128-ctr\nMACs hmac-sha2-256\n",
		"etc/crypto-policies/back-ends/opensslcnf.config":    "CipherString = @SECLEVEL=2:kEECDH:!RC4\nMinProtocol = TLSv1.2\n",
		"etc/crypto-policies/back-ends/java.config":          "jdk.tls.disabledAlgorithms=MD5withRSA, DH keySize < 2048\n",
		"etc/crypto-policies/back-ends/nss.config":           "config=\"disallow=ALL allow=aes256-gcm:tls-version-min=tls1.2\"\n",
		"etc/crypto-policies/back-ends/krb5.config":          "[libdefaults]\npermitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n",
	},
	"rocky": {
		"etc/pki/tls/openssl.cnf": "openssl_conf = openssl_init\n\n" +
			"[openssl_init]\nproviders = provider_sect\nssl_conf = ssl_module\nalg_section = evp_properties\n\n" +
			"[evp_properties]\n\n" +
			"[provider_sect]\ndefault = default_sect\n\n" +
			"[default_sect]\nactivate = 1\n.include /etc/pki/tls/openssl.d\n\n" +
			"[ssl_module]\nsystem_default = crypto_policy\n\n" +
			"[crypto_policy]\n.include = /etc/crypto-policies/back-ends/opensslcnf.config\n\n" +
			"[ca]\ndefault_ca = CA_default\n\n[CA_default]\ndir = /etc/pki/CA\nprivate_key = $dir/private/cakey.pem\n",
	},
	"debian": {
		"etc/nginx/nginx.conf": "user www-data;\nworker_processes auto;\n" +
			"include /etc/nginx/modules-enabled/*.conf;\n" +
			"events { worker_connections 512; }\n" +
			"http {\n\tsendfile on;\n\tinclude /etc/nginx/mime.types;\n" +
			"\tssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n\tssl_prefer_server_ciphers on;\n" +
			"\tinclude /etc/nginx/conf.d/*.conf;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n",
		"etc/nginx/sites-available/default": "server {\n\tlisten 80 default_server;\n\tlisten [::]:80 default_server;\n" +
			"\troot /srv/www;\n\tserver_name _;\n\tlocation / { try_files $uri =404; }\n}\n",
		"etc/apache2/mods-available/ssl.conf": "<IfModule mod_ssl.c>\n" +
			"\tSSLPassPhraseDialog exec:/usr/share/apache2/ask-for-passphrase\n" +
			"\tSSLSessionCache shmcb:${APACHE_RUN_DIR}/ssl_scache(512000)\n" +
			"\tSSLCipherSuite HIGH:!aNULL\n\tSSLProtocol all -SSLv3\n\tSSLSessionTickets off\n</IfModule>\n",
		"etc/apache2/sites-available/default-ssl.conf": "<IfModule mod_ssl.c>\n<VirtualHost *:443>\n" +
			"\tDocumentRoot /srv/www\n\tSSLEngine on\n" +
			"\tSSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem\n" +
			"\tSSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key\n" +
			"\t<Directory /usr/lib/cgi-bin>\n\t\tSSLOptions +StdEnvVars\n\t</Directory>\n" +
			"</VirtualHost>\n</IfModule>\n",
		"etc/haproxy/haproxy.cfg": "global\n\tlog /dev/log local0\n\tca-base /etc/ssl/certs\n\tcrt-base /etc/ssl/private\n" +
			"\tssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n" +
			"\tssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384\n" +
			"\tssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets\n\n" +
			"defaults\n\tlog global\n\tmode http\n\ttimeout connect 5000\n",
		"etc/postfix/main.cf": "myhostname = mail.example.test\nsmtpd_tls_security_level = may\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\n",
	},
	"nginx": {
		"nginx/nginx.conf":          "worker_processes 1;\nevents { worker_connections 512; }\nhttp {\n\tinclude /etc/nginx/conf.d/*.conf;\n}\n",
		"nginx/conf.d/default.conf": "server {\n\tlisten 80;\n\tserver_name localhost;\n}\n",
	},
	"httpd": {
		"conf/httpd.conf": "ServerRoot \"/usr/local/apache2\"\nListen 80\n#Include conf/extra/httpd-ssl.conf\nInclude conf/extra/httpd-ssl.conf\n",
		"conf/extra/httpd-ssl.conf": "Listen 443\nSSLPassPhraseDialog builtin\nSSLProtocol all -SSLv3\n" +
			"<VirtualHost _default_:443>\nServerName www.example.com:443\nSSLEngine on\n" +
			"SSLCipherSuite HIGH:!aNULL:!MD5\n" +
			"SSLCertificateFile \"/usr/local/apache2/conf/server.crt\"\n" +
			"SSLCertificateKeyFile \"/usr/local/apache2/conf/server.key\"\n</VirtualHost>\n",
	},
	"temurin8": {
		"java.security": "security.provider.1=sun.security.provider.Sun\nsecurity.provider.2=sun.security.rsa.SunRsaSign\n" +
			"keystore.type=jks\n" +
			"jdk.certpath.disabledAlgorithms=MD2, MD5, RSA keySize < 1024\n" +
			"jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, MD5withRSA, DH keySize < 1024\n",
	},
	"temurin21": {
		"java.security": "security.provider.1=SUN\nsecurity.provider.2=SunRsaSign\nsecurity.provider.3=SunEC\n" +
			"keystore.type=pkcs12\n" +
			"jdk.serialFilter=java.base/javax.crypto.spec.SecretKeySpec;java.base/java.security.KeyRep$Type;!*\n" +
			"jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024\n" +
			"jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, include jdk.disabled.namedCurves\n" +
			"jdk.disabled.namedCurves=secp112r1, secp112r2, sect113r1\n",
	},
}
