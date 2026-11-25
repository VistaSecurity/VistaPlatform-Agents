package hostcrypto

import (
	"testing"
)

func TestSchannelConfig(t *testing.T) {
	fips := false
	c := SchannelConfig(map[string]uint32{
		`Protocols\TLS 1.0\Server\Enabled`:                           0,
		`Protocols\TLS 1.0\Server\DisabledByDefault`:                 1,
		`Protocols\TLS 1.2\Server\Enabled`:                           1,
		`Protocols\TLS 1.2\Server\DisabledByDefault`:                 0,
		`Protocols\TLS 1.3\Server\Enabled`:                           0xffffffff,
		`Protocols\TLS 1.1\Server\Enabled`:                           1,
		`Protocols\TLS 1.1\Server\DisabledByDefault`:                 1, // available on request only: not "enabled"
		`Protocols\SSL 3.0\Server\Enabled`:                           0,
		`Protocols\TLS 1.2\Client\Enabled`:                           1,
		`Ciphers\RC4 128/128\Enabled`:                                0,
		`Ciphers\AES 256/256\Enabled`:                                0xffffffff,
		`Hashes\MD5\Enabled`:                                         0,
		`KeyExchangeAlgorithms\Diffie-Hellman\Enabled`:               0xffffffff,
		`KeyExchangeAlgorithms\Diffie-Hellman\ServerMinKeyBitLength`: 2048,
		`KeyExchangeAlgorithms\PKCS\Enabled`:                         0,
		// Not on the allowlist, so never kept:
		`Protocols\TLS 1.2\Server\Whatever`:      7,
		`Ciphers\Made Up\Enabled`:                0,
		`Secrets\Password`:                       1,
		`Protocols\Imaginary 9.9\Server\Enabled`: 1,
	}, []string{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"}, []string{"curve25519", "NistP384"}, &fips)
	cfgWantEqual(t, c, CryptoConfig{
		Product: "schannel", Context: "SCHANNEL",
		Protocols:          []string{"TLSv1.2", "TLSv1.3"},
		CipherSuites:       []string{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"},
		Groups:             []string{"curve25519", "NistP384"},
		DisabledAlgorithms: []string{"RC4 128/128", "MD5", "PKCS"},
		FIPS:               &fips,
		Settings: map[string]string{
			`Protocols\TLS 1.0\Server\Enabled`:                           "0",
			`Protocols\TLS 1.0\Server\DisabledByDefault`:                 "1",
			`Protocols\TLS 1.1\Server\Enabled`:                           "1",
			`Protocols\TLS 1.1\Server\DisabledByDefault`:                 "1",
			`Protocols\TLS 1.2\Server\Enabled`:                           "1",
			`Protocols\TLS 1.2\Server\DisabledByDefault`:                 "0",
			`Protocols\TLS 1.2\Client\Enabled`:                           "1",
			`Protocols\TLS 1.3\Server\Enabled`:                           "1",
			`Protocols\SSL 3.0\Server\Enabled`:                           "0",
			`Ciphers\RC4 128/128\Enabled`:                                "0",
			`Ciphers\AES 256/256\Enabled`:                                "1",
			`Hashes\MD5\Enabled`:                                         "0",
			`KeyExchangeAlgorithms\Diffie-Hellman\Enabled`:               "1",
			`KeyExchangeAlgorithms\Diffie-Hellman\ServerMinKeyBitLength`: "2048",
			`KeyExchangeAlgorithms\PKCS\Enabled`:                         "0",
		},
	})
}

func TestSchannelAbsentMeansDefault(t *testing.T) {
	c := SchannelConfig(nil, nil, nil, nil)
	cfgWantEqual(t, c, CryptoConfig{Product: "schannel", Context: "SCHANNEL"})
	// A protocol with only DisabledByDefault=0 is not reported enabled: the
	// operating system's default decides.
	c = SchannelConfig(map[string]uint32{`Protocols\TLS 1.2\Server\DisabledByDefault`: 0}, nil, nil, nil)
	if len(c.Protocols) != 0 || len(c.DisabledAlgorithms) != 0 {
		t.Errorf("an absent Enabled is neither on nor off: %s", cfgJSON(t, c))
	}
	// Case-insensitive names, and the full registry path, are accepted.
	c = SchannelConfig(map[string]uint32{
		`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\protocols\tls 1.2\SERVER\enabled`: 1,
	}, nil, nil, nil)
	cfgWantEqual(t, c.Protocols, []string{"TLSv1.2"})
	if c.FIPS != nil {
		t.Error("FIPS stays unset when the collector could not read it")
	}
}
