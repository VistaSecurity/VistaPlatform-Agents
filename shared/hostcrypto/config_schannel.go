package hostcrypto

import (
	"sort"
	"strconv"
	"strings"
)

// Windows Schannel policy, from registry values the caller has already read.
//
// Unlike every other parser this one takes no file: Schannel is configured
// under
//
//	HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
//
// and the collector (a later slice) reads the values it cares about, over
// PowerShell or locally, and hands them here.
//
// READ THIS BEFORE USING Protocols: it means "EXPLICITLY ENABLED IN THE
// REGISTRY", nothing more. A protocol that is not in the list is not
// disallowed; it may well be on, because Windows enables TLS 1.2 (and, on
// current builds, 1.3) by default and the registry need not say so. An empty
// Protocols is therefore the answer "the registry does not configure the
// server protocols", never "no protocol is allowed".
//
// ABSENT MEANS "THE OPERATING SYSTEM'S DEFAULT". A protocol, cipher, hash or
// key exchange with no registry value is neither enabled nor disabled in this
// report: what Windows does then depends on its version and on updates, and
// guessing it would turn "not configured" into a claim. Only a value that IS
// present is reported, and only the allowlisted subkeys below are read, so a
// stray value cannot become a Setting.
//
// The keys are relative to SCHANNEL, with backslashes, as in
// `Protocols\TLS 1.0\Server\Enabled`; a prefix up to and including "SCHANNEL\"
// is accepted. Names are matched without regard to case and reported in the
// canonical spelling.
//
// What is reported:
//
//   - Protocols: the SERVER protocols that are explicitly on: Enabled is
//     nonzero and DisabledByDefault is absent or 0. (Enabled=1 with
//     DisabledByDefault=1 means "available if an application asks for it
//     explicitly" and is NOT listed as enabled.)
//   - DisabledAlgorithms: every cipher, hash and key exchange whose Enabled
//     is 0.
//   - Settings: every allowlisted value that is present, by its relative
//     key, as "0"/"1" for Enabled and DisabledByDefault (any nonzero Enabled,
//     such as 0xffffffff, is "1") and as decimal for the key-length minimums.
//     Client-side protocol values are here, not in Protocols.
//   - CipherSuites and Groups: the configured suite and curve orders, as the
//     collector read them (empty when the policy does not set them).
//   - FIPS: the FipsAlgorithmPolicy switch, when the collector read it.

var cfgSchannelProtocols = map[string]string{
	"ssl 2.0": "SSLv2", "ssl 3.0": "SSLv3", "tls 1.0": "TLSv1.0", "tls 1.1": "TLSv1.1",
	"tls 1.2": "TLSv1.2", "tls 1.3": "TLSv1.3", "dtls 1.0": "DTLSv1.0", "dtls 1.2": "DTLSv1.2",
}

// The canonical spellings of the protocol subkeys, by catalogue name.
var cfgSchannelProtocolKey = map[string]string{
	"SSLv2": "SSL 2.0", "SSLv3": "SSL 3.0", "TLSv1.0": "TLS 1.0", "TLSv1.1": "TLS 1.1",
	"TLSv1.2": "TLS 1.2", "TLSv1.3": "TLS 1.3", "DTLSv1.0": "DTLS 1.0", "DTLSv1.2": "DTLS 1.2",
}

var cfgSchannelProtocolOrder = []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "DTLSv1.0", "DTLSv1.2"}

func cfgLowerSet(names ...string) map[string]string {
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = n
	}
	return m
}

var (
	cfgSchannelCiphers = cfgLowerSet("NULL", "DES 56/56", "RC2 40/128", "RC2 56/128", "RC2 128/128",
		"RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128", "Triple DES 168", "Triple DES 168/168",
		"AES 128/128", "AES 256/256")
	cfgSchannelHashes = cfgLowerSet("MD5", "SHA", "SHA256", "SHA384", "SHA512")
	cfgSchannelKex    = cfgLowerSet("Diffie-Hellman", "ECDH", "PKCS")
)

// SchannelConfig builds the "schannel" entry from registry values (see the
// comment above for the key spelling and, above all, for what an absent
// value means). cipherSuiteOrder and curveOrder are the policy's configured
// orders, or nil; fipsEnabled is nil when the collector could not read
// FipsAlgorithmPolicy.
func SchannelConfig(values map[string]uint32, cipherSuiteOrder []string, curveOrder []string, fipsEnabled *bool) CryptoConfig {
	c := CryptoConfig{Product: "schannel", Context: "SCHANNEL"}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	type protoState struct {
		enabled, disabledByDefault *uint32
	}
	server := map[string]*protoState{}
	disabled := map[string][]string{} // category -> names, in key order

	for _, k := range keys {
		v := values[k]
		rel := k
		if i := strings.Index(strings.ToLower(rel), `schannel\`); i >= 0 {
			rel = rel[i+len(`schannel\`):]
		}
		parts := strings.Split(strings.Trim(rel, `\`), `\`)
		switch strings.ToLower(parts[0]) {
		case "protocols":
			if len(parts) != 4 {
				continue
			}
			proto, ok := cfgSchannelProtocols[strings.ToLower(parts[1])]
			if !ok {
				continue
			}
			role := strings.ToLower(parts[2])
			if role != "server" && role != "client" {
				continue
			}
			var value string
			switch strings.ToLower(parts[3]) {
			case "enabled":
				value = "Enabled"
			case "disabledbydefault":
				value = "DisabledByDefault"
			default:
				continue
			}
			canonRole := map[string]string{"server": "Server", "client": "Client"}[role]
			name := `Protocols\` + cfgSchannelProtocolKey[proto] + `\` + canonRole + `\` + value
			cfgSet(&c, name, cfgSchannelFlag(v))
			if role == "server" {
				st := server[proto]
				if st == nil {
					st = &protoState{}
					server[proto] = st
				}
				vv := v
				if value == "Enabled" {
					st.enabled = &vv
				} else {
					st.disabledByDefault = &vv
				}
			}
		case "ciphers", "hashes", "keyexchangealgorithms":
			if len(parts) != 3 {
				continue
			}
			var table map[string]string
			var cat string
			switch strings.ToLower(parts[0]) {
			case "ciphers":
				table, cat = cfgSchannelCiphers, "Ciphers"
			case "hashes":
				table, cat = cfgSchannelHashes, "Hashes"
			default:
				table, cat = cfgSchannelKex, "KeyExchangeAlgorithms"
			}
			canon, ok := table[strings.ToLower(parts[1])]
			if !ok {
				continue
			}
			switch strings.ToLower(parts[2]) {
			case "enabled":
				cfgSet(&c, cat+`\`+canon+`\Enabled`, cfgSchannelFlag(v))
				if v == 0 {
					disabled[cat] = append(disabled[cat], canon)
				}
			case "serverminkeybitlength":
				if cat == "KeyExchangeAlgorithms" {
					cfgSet(&c, cat+`\`+canon+`\ServerMinKeyBitLength`, strconv.FormatUint(uint64(v), 10))
				}
			case "clientminkeybitlength":
				if cat == "KeyExchangeAlgorithms" {
					cfgSet(&c, cat+`\`+canon+`\ClientMinKeyBitLength`, strconv.FormatUint(uint64(v), 10))
				}
			}
		}
	}

	for _, p := range cfgSchannelProtocolOrder {
		st := server[p]
		if st == nil || st.enabled == nil || *st.enabled == 0 {
			continue
		}
		if st.disabledByDefault != nil && *st.disabledByDefault != 0 {
			continue
		}
		cfgAppend(&c.Protocols, p)
	}
	for _, cat := range []string{"Ciphers", "Hashes", "KeyExchangeAlgorithms"} {
		cfgAppend(&c.DisabledAlgorithms, disabled[cat]...)
	}
	cfgAppend(&c.CipherSuites, cipherSuiteOrder...)
	cfgAppend(&c.Groups, curveOrder...)
	if fipsEnabled != nil {
		c.FIPS = cfgBoolPtr(*fipsEnabled)
	}
	return c
}

func cfgSchannelFlag(v uint32) string {
	if v == 0 {
		return "0"
	}
	return "1"
}
