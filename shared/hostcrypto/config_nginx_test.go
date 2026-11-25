package hostcrypto

import (
	"strings"
	"testing"
)

const cfgNginxStock = `user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
}

http {
	sendfile on;
	tcp_nopush on;
	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
	ssl_prefer_server_ciphers on;

	access_log /var/log/nginx/access.log;
	gzip on;

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
`

const cfgNginxSite = `server {
	listen 80;
	server_name example.com;
	return 301 https://$host$request_uri;
}

server {
	listen 443 ssl http2;
	listen [::]:443 ssl http2;
	server_name example.com www.example.com;

	ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
	ssl_trusted_certificate /etc/ssl/chain.pem;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
	ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
	ssl_conf_command Options PrioritizeChaCha;
	ssl_conf_command SomethingElse nope;
	ssl_ecdh_curve X25519:secp384r1;
	ssl_session_tickets off;
	ssl_session_timeout 1d;
	ssl_stapling on;
	ssl_stapling_verify on;
	ssl_dhparam /etc/ssl/dhparam.pem;
	add_header Strict-Transport-Security "max-age=63072000" always;
	add_header X-Frame-Options DENY;

	location / {
		proxy_pass https://backend;
		proxy_ssl_verify on;
	}
}
`

func TestNginxStockMain(t *testing.T) {
	cfgs := cfgT(cfgParseNginx, []byte(cfgNginxStock))
	if len(cfgs) != 2 {
		t.Fatalf("want main and http, got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[0], CryptoConfig{
		Product: "nginx", Context: "main",
		References: []ConfigReference{{Kind: "include", Directive: "include", Path: "/etc/nginx/modules-enabled/*.conf"}},
	})
	cfgWantEqual(t, cfgs[1], CryptoConfig{
		Product: "nginx", Context: "http",
		Protocols: []string{"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
		Settings:  map[string]string{"ssl_prefer_server_ciphers": "on"},
		References: []ConfigReference{
			{Kind: "include", Directive: "include", Path: "/etc/nginx/mime.types"},
			{Kind: "include", Directive: "include", Path: "/etc/nginx/conf.d/*.conf"},
			{Kind: "include", Directive: "include", Path: "/etc/nginx/sites-enabled/*"},
		},
	})
}

func TestNginxTLSSite(t *testing.T) {
	cfgs := cfgT(cfgParseNginx, []byte(cfgNginxSite))
	if len(cfgs) != 1 {
		t.Fatalf("only the TLS server is reported, got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[0], CryptoConfig{
		Product:      "nginx",
		Context:      "server_name example.com www.example.com; listen 443 ssl http2; listen [::]:443 ssl http2",
		Protocols:    []string{"TLSv1.2", "TLSv1.3"},
		CipherString: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
		CipherSuites: []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		Groups:       []string{"X25519", "secp384r1"},
		Settings: map[string]string{
			"ssl_conf_command Ciphersuites": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
			"ssl_conf_command Options":      "PrioritizeChaCha",
			"ssl_session_tickets":           "off",
			"ssl_session_timeout":           "1d",
			"ssl_stapling":                  "on",
			"ssl_stapling_verify":           "on",
			"Strict-Transport-Security":     "max-age=63072000",
		},
		References: []ConfigReference{
			{Kind: "certificate", Directive: "ssl_certificate", Path: "/etc/letsencrypt/live/example.com/fullchain.pem"},
			{Kind: "private_key", Directive: "ssl_certificate_key", Path: "/etc/letsencrypt/live/example.com/privkey.pem"},
			{Kind: "trust_store", Directive: "ssl_trusted_certificate", Path: "/etc/ssl/chain.pem"},
			{Kind: "dh_params", Directive: "ssl_dhparam", Path: "/etc/ssl/dhparam.pem"},
		},
	})
}

func TestNginxServerInheritsHTTP(t *testing.T) {
	cfgs := cfgT(cfgParseNginx, []byte(`http {
	ssl_protocols TLSv1.2;
	ssl_ciphers HIGH:!aNULL:!MD5;
	ssl_session_tickets off;
	server {
		listen 443 ssl;
		server_name a;
		ssl_protocols TLSv1.3;
		ssl_certificate /c.pem;
	}
	server {
		listen 8080;
		server_name plain;
	}
}`))
	if len(cfgs) != 2 {
		t.Fatalf("want http and one server, got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[1], CryptoConfig{
		Product: "nginx", Context: "server_name a; listen 443 ssl",
		Protocols:    []string{"TLSv1.3"},
		CipherString: "HIGH:!aNULL:!MD5",
		Settings:     map[string]string{"ssl_session_tickets": "off"},
		References:   []ConfigReference{{Kind: "certificate", Directive: "ssl_certificate", Path: "/c.pem"}},
	})
	// The http entry itself keeps its own values.
	cfgWantEqual(t, cfgs[0].Protocols, []string{"TLSv1.2"})
}

func TestNginxStreamMailAndProxy(t *testing.T) {
	cfgs := cfgT(cfgParseNginx, []byte(`stream { server { listen 12345 ssl; ssl_certificate /s.pem; ssl_protocols TLSv1.2; proxy_ssl on; proxy_ssl_protocols TLSv1.3; proxy_ssl_trusted_certificate /ca.pem; } }
mail { server { listen 993 ssl; ssl_certificate /m.pem; } }`))
	s := cfgFind(t, cfgs, "stream: listen 12345 ssl")
	cfgWantEqual(t, s.Settings, map[string]string{"proxy_ssl_protocols": "TLSv1.3"})
	cfgWantEqual(t, s.References, []ConfigReference{
		{Kind: "certificate", Directive: "ssl_certificate", Path: "/s.pem"},
		{Kind: "trust_store", Directive: "proxy_ssl_trusted_certificate", Path: "/ca.pem"},
	})
	cfgFind(t, cfgs, "mail: listen 993 ssl")
}

func TestNginxKeySources(t *testing.T) {
	cfgs := cfgT(cfgParseNginx, []byte(`server { listen 443 ssl;
	ssl_certificate_key "engine:pkcs11:pkcs11:token=tok;pin-value=SECRETPIN";
}
server { listen 444 ssl; ssl_certificate_key data:$ssl_key_var; ssl_certificate data:SECRETCERT; }`))
	a := cfgFind(t, cfgs, "listen 443 ssl")
	cfgWantEqual(t, a.Settings, map[string]string{"ssl_certificate_key_source": "engine"})
	if len(a.References) != 0 {
		t.Errorf("an engine key is not a path: %+v", a.References)
	}
	b := cfgFind(t, cfgs, "listen 444 ssl")
	cfgWantEqual(t, b.Settings, map[string]string{"ssl_certificate_key_source": "data", "ssl_certificate_source": "data"})
	cfgNoSecrets(t, cfgs, "SECRETPIN", "SECRETCERT", "ssl_key_var")
}

func TestNginxSecretsAreDropped(t *testing.T) {
	cfgs := cfgT(cfgParseNginx, []byte(`http {
	ssl_password_file /etc/nginx/SECRETFILE.pass;
	server {
		listen 443 ssl;
		ssl_certificate /c.pem;
		ssl_certificate_key /k.pem;
		ssl_password_file /etc/nginx/SECRETFILE2.pass;
		ssl_session_ticket_key /etc/nginx/SECRETTICKET.key;
		proxy_ssl_password_file /SECRETPROXY;
		grpc_ssl_password_file /SECRETGRPC;
		uwsgi_ssl_certificate_key engine:e:SECRETUWSGI;
		auth_basic_user_file /SECRETBASIC;
		set $token SECRETVAR;
	}
}`))
	cfgNoSecrets(t, cfgs, "SECRETFILE", "SECRETTICKET", "SECRETPROXY", "SECRETGRPC", "SECRETBASIC", "SECRETVAR")
	if !strings.Contains(cfgJSON(t, cfgs), "/c.pem") {
		t.Error("the allowlisted certificate path must still be reported")
	}
}

func TestNginxHostileSyntax(t *testing.T) {
	// Tolerated, not rejected: what can be read is read.
	cfgs := cfgT(cfgParseNginx, []byte("server { listen 443 ssl; ssl_protocols TLSv1.3"))
	if len(cfgs) != 1 || len(cfgs[0].Protocols) != 0 {
		t.Errorf("a directive with no terminator is not a directive: %s", cfgJSON(t, cfgs))
	}
	cfgs = cfgT(cfgParseNginx, []byte("server { listen 443 ssl; ssl_protocols TLSv1.3; "))
	if len(cfgs) != 1 || len(cfgs[0].Protocols) != 1 {
		t.Errorf("an unclosed block ends at the end of the file: %s", cfgJSON(t, cfgs))
	}
	cfgs = cfgT(cfgParseNginx, []byte("} } server { listen 443 ssl; } }"))
	if len(cfgs) != 1 {
		t.Errorf("stray closers are ignored: %s", cfgJSON(t, cfgs))
	}
	cfgs = cfgT(cfgParseNginx, []byte("\xef\xbb\xbfserver {\r\n listen 443 ssl;\r\n ssl_protocols TLSv1.2;\r\n}\r\n"))
	if len(cfgs) != 1 || cfgs[0].Protocols[0] != "TLSv1.2" {
		t.Errorf("BOM and CRLF: %s", cfgJSON(t, cfgs))
	}
}

func FuzzConfigNginx(f *testing.F) {
	f.Add([]byte(cfgNginxStock))
	f.Add([]byte(cfgNginxSite))
	f.Add([]byte(`server { listen 443 ssl; ssl_certificate_key "engine:x:y"; ssl_conf_command Options a; } stream {`))
	f.Add([]byte("http { ${var} {{ }} \"unterminated"))
	f.Fuzz(func(t *testing.T, b []byte) {
		cfgCheckBounds(t, cfgT(cfgParseNginx, b))
	})
}
