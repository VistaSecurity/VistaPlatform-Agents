package hostcrypto

import (
	"testing"
)

const cfgJDK17 = `security.provider.1=SUN
security.provider.2=SunRsaSign
security.provider.4=SunJSSE
security.provider.3=SunEC
security.provider.5=SunPKCS11 ${java.home}/conf/security/nss.cfg
securerandom.source=file:/dev/random
securerandom.strongAlgorithms=NativePRNGBlocking:SUN,DRBG:SUN
login.configuration.provider=sun.security.provider.ConfigFile
keystore.type=pkcs12
! also a comment
jdk.certpath.disabledAlgorithms=MD2, MD5, SHA1 jdkCA & usage TLSServer, \
    RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224, \
    SHA1 usage SignedJAR & denyAfter 2019-01-01
jdk.security.legacyAlgorithms=RSA keySize < 2048, DSA keySize < 2048, \
    DES, DESede, MD5, RC2, ARCFOUR
jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, \
    DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, \
    include jdk.disabled.namedCurves
jdk.tls.keyLimits=AES/GCM/NoPadding KeyUpdate 2^37, \
      ChaCha20-Poly1305 KeyUpdate 2^37
crypto.policy=unlimited
jdk.tls.namedGroups = x25519, secp256r1
jdk.tls.client.protocols=TLSv1.3,TLSv1.2
javax.net.ssl.keyStorePassword=SECRETKSPW
keystore.password : SECRETKS2
fips.provider.1=SunPKCS11 ${java.home}/conf/security/nss.fips.cfg
fips.provider.2=SUN
security.useSystemPropertiesFile=false
com.redhat.fips=false
`

func TestJDK17SecurityProperties(t *testing.T) {
	cfgs := cfgT(cfgParseJava, []byte(cfgJDK17))
	cfgWantEqual(t, cfgs, []CryptoConfig{{
		Product:   "java",
		Protocols: []string{"TLSv1.3", "TLSv1.2"},
		Groups:    []string{"x25519", "secp256r1"},
		Policy:    "unlimited",
		FIPS:      cfgBoolPtr(false),
		// Only jdk.tls.disabledAlgorithms is the TLS deny list; the other
		// lists stay in Settings. "include jdk.disabled.namedCurves" has no
		// such property in this excerpt, so it stays as written.
		DisabledAlgorithms: []string{
			"SSLv3", "TLSv1", "TLSv1.1", "RC4", "DES", "MD5withRSA", "DH keySize < 1024",
			"EC keySize < 224", "3DES_EDE_CBC", "anon", "NULL", "include jdk.disabled.namedCurves",
		},
		Settings: map[string]string{
			"jdk.tls.disabledAlgorithms":       "SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, include jdk.disabled.namedCurves",
			"jdk.certpath.disabledAlgorithms":  "MD2, MD5, SHA1 jdkCA & usage TLSServer, RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224, SHA1 usage SignedJAR & denyAfter 2019-01-01",
			"jdk.security.legacyAlgorithms":    "RSA keySize < 2048, DSA keySize < 2048, DES, DESede, MD5, RC2, ARCFOUR",
			"jdk.tls.keyLimits":                "AES/GCM/NoPadding KeyUpdate 2^37, ChaCha20-Poly1305 KeyUpdate 2^37",
			"jdk.tls.namedGroups":              "x25519, secp256r1",
			"jdk.tls.client.protocols":         "TLSv1.3,TLSv1.2",
			"keystore.type":                    "pkcs12",
			"securerandom.source":              "file:/dev/random",
			"securerandom.strongAlgorithms":    "NativePRNGBlocking:SUN,DRBG:SUN",
			"crypto.policy":                    "unlimited",
			"com.redhat.fips":                  "false",
			"security.useSystemPropertiesFile": "false",
			"providers":                        "SUN,SunRsaSign,SunEC,SunJSSE,SunPKCS11",
			"fips.providers":                   "SunPKCS11,SUN",
		},
	}})
	cfgNoSecrets(t, cfgs, "SECRETKSPW", "SECRETKS2", "login.configuration")
}

func TestJavaPropertiesLastWinsAndFIPS(t *testing.T) {
	cfgs := cfgT(cfgParseJava, []byte("jdk.tls.disabledAlgorithms=SSLv3\njdk.tls.disabledAlgorithms=TLSv1\ncom.redhat.fips=true\n"))
	if len(cfgs) != 1 {
		t.Fatalf("got %s", cfgJSON(t, cfgs))
	}
	cfgWantEqual(t, cfgs[0].DisabledAlgorithms, []string{"TLSv1"})
	if cfgs[0].FIPS == nil || !*cfgs[0].FIPS {
		t.Error("com.redhat.fips=true")
	}
	if cfgT(cfgParseJava, []byte("# nothing\nunrelated.key=1\n")) != nil {
		t.Error("a file with nothing allowlisted yields nothing")
	}
}

func TestJavaOptions(t *testing.T) {
	cfgs := cfgT(cfgParseJavaOptions, []byte(`JAVA_OPTS="-Xmx2g -Djavax.net.ssl.keyStore=/etc/app/keystore.p12 -Djavax.net.ssl.keyStorePassword=SECRETKS \
  -Djavax.net.ssl.trustStore=/etc/app/trust.jks -Djavax.net.ssl.trustStorePassword=SECRETTS"
-Dhttps.protocols=TLSv1.2,TLSv1.3
-Djavax.net.ssl.keyStoreType=PKCS12
-Djdk.tls.client.cipherSuites=TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256
-Djava.security.properties==/etc/app/extra.security
-Djavax.net.ssl.keyStorePassword=SECRETKS3
-Dcom.sun.net.ssl.checkRevocation=true
-Dsome.other=1
`))
	cfgWantEqual(t, cfgs, []CryptoConfig{{
		Product: "java", Context: "jvm-options",
		Protocols:    []string{"TLSv1.2", "TLSv1.3"},
		CipherSuites: []string{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"},
		Settings: map[string]string{
			"https.protocols":                 "TLSv1.2,TLSv1.3",
			"javax.net.ssl.keyStoreType":      "PKCS12",
			"jdk.tls.client.cipherSuites":     "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256",
			"com.sun.net.ssl.checkRevocation": "true",
		},
		References: []ConfigReference{
			{Kind: "keystore", Directive: "-Djavax.net.ssl.keyStore", Path: "/etc/app/keystore.p12"},
			{Kind: "trust_store", Directive: "-Djavax.net.ssl.trustStore", Path: "/etc/app/trust.jks"},
			{Kind: "include", Directive: "-Djava.security.properties", Path: "/etc/app/extra.security"},
		},
	}})
	cfgNoSecrets(t, cfgs, "SECRETKS", "SECRETTS", "SECRETKS3")
}

func TestJavaHostile(t *testing.T) {
	cfgCheckBounds(t, cfgT(cfgParseJava, []byte("jdk.tls.disabledAlgorithms=\\\n\\\n\\\nx, \\\n")))
	cfgCheckBounds(t, cfgT(cfgParseJavaOptions, []byte(`"-Dhttps.protocols=TLSv1.2 '-Djavax.net.ssl.trustStore=`)))
	cfgs := cfgT(cfgParseJava, []byte("\xef\xbb\xbfcrypto.policy=unlimited\r\nkeystore.type=jks\r\n"))
	if len(cfgs) != 1 || cfgs[0].Policy != "unlimited" || cfgs[0].Settings["keystore.type"] != "jks" {
		t.Errorf("BOM and CRLF: %s", cfgJSON(t, cfgs))
	}
}
