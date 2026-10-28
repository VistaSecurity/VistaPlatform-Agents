package cryptoparse

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
)

// Every case below is a spelling some producer in this tree actually emits, or
// an enum value in its own canonical spelling. The point of the table is that
// the LEFT column is what the wire/vendor/collector gave us and the RIGHT column
// is the single form that reaches the database, no matter which path wrote it.
func TestNormalizeProtocol(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// --- enum values normalize to themselves (identity) ---
		{"TLS", "TLS"},
		{"SSH", "SSH"},
		{"IPSec", "IPSec"},
		{"VPN", "VPN"},
		{"Database", "Database"},
		{"API", "API"},
		{"SMB", "SMB"},
		{"Kerberos", "Kerberos"},
		{"Modbus", "Modbus"},
		{"DNP3", "DNP3"},
		{"MMS", "MMS"},
		{"ICCP", "ICCP"},
		{"IEC62351", "IEC62351"},
		{"OPC_UA", "OPC_UA"},
		{"EtherNet_IP", "EtherNet_IP"},
		{"BACnet", "BACnet"},
		{"BACnet_SC", "BACnet_SC"},
		{"HART_IP", "HART_IP"},
		{"S7", "S7"},

		// --- case variants producers emit (qa-platform, sensor, cloud paths) ---
		{"tls", "TLS"},
		{"ssh", "SSH"},
		{"MODBUS", "Modbus"},
		{"BACNET", "BACnet"},
		{"ipsec", "IPSec"},
		{"kerberos", "Kerberos"},

		// --- the separator variants that started this: these upper-case to
		// something no service_identification_rules row can match ---
		{"EtherNet/IP", "EtherNet_IP"},
		{"EtherNet_IP", "EtherNet_IP"},
		{"ETHERNET-IP", "EtherNet_IP"},
		{"ethernet ip", "EtherNet_IP"},
		{"ENIP", "EtherNet_IP"},
		{"OPC UA", "OPC_UA"},
		{"OPC-UA", "OPC_UA"},
		{"OPCUA", "OPC_UA"},
		{"opc.ua", "OPC_UA"},
		{"ModbusTCP", "Modbus"},
		{"Modbus/TCP", "Modbus"},
		{"MODBUS_TCP", "Modbus"},
		{"BACnet.SC", "BACnet_SC"},
		{"BACNET_SC", "BACnet_SC"}, // the sensor's TLS assembler ALPN path
		{"BACnet/SC", "BACnet_SC"},
		{"BACNET-SC", "BACnet_SC"},
		{"BACnet/IP", "BACnet"},
		{"HART-IP", "HART_IP"},
		{"HARTIP", "HART_IP"},
		{"DNP3.0", "DNP3"},
		{"DNP3-SAv5", "DNP3"},
		{"DNP3_SAv6", "DNP3"},
		{"S7comm", "S7"},
		{"S7-PLUS", "S7"},
		{"TASE.2", "ICCP"},
		{"TASE-2", "ICCP"},
		{"IEC61850-MMS", "MMS"},
		{"IEC-62351", "IEC62351"},
		{"IP-SEC", "IPSec"},

		// --- whitespace is trimmed ---
		{"  TLS  ", "TLS"},
		{"\tEtherNet/IP\n", "EtherNet_IP"},

		// --- QUIC and PPTP are now enum values, so they normalise to
		// themselves for a different reason than the block below: they are
		// RECOGNISED, and their canonical spelling happens to be what producers
		// already emit. Kept explicit so a future spelling change to either
		// enum value fails here rather than silently in the free-text columns.
		{"QUIC", "QUIC"},
		{"quic", "QUIC"},
		{"PPTP", "PPTP"},
		{"pptp", "PPTP"},

		// --- UNRECOGNISED VALUES SURVIVE. Each of these is emitted somewhere in
		// the tree and is genuinely not a protocol_type value. Losing the string
		// is worse than storing it un-normalised — it is the only record the
		// observation happened. And none of them may be coerced to a default.
		//
		// NOTE the division of labour, which is the whole point of this file:
		// "SSL VPN", "L2TP/IPSec" and "STARTTLS" ARE mapped onto the enum by
		// inventory-service's resolveProtocol, on the way into
		// crypto_implementations. They are not mapped HERE, because this
		// function only respells and those are cross-protocol judgements — the
		// free-text columns keep what the producer actually observed.
		{"SNMP", "SNMP"},
		{"STARTTLS", "STARTTLS"},
		{"WireGuard", "WireGuard"},
		{"OpenVPN", "OpenVPN"},
		{"L2TP/IPSec", "L2TP/IPSec"},
		{"IKEv2", "IKEv2"},
		{"IKE", "IKE"},
		{"SSL VPN", "SSL VPN"},
		// nmap names the cluster port-scanner passes through verbatim.
		{"tcp", "tcp"},
		{"udp", "udp"},
		{"ftp", "ftp"},
		// SENTINELS. "AT-REST" marks a cloud resource that is not a network
		// endpoint at all and "NONE" means a database with SSL switched off;
		// both are matched downstream by exact/EqualFold comparison, so
		// rewriting either would silently break the check that keeps a bucket
		// out of Inventory as a phantom TLS endpoint.
		{"AT-REST", "AT-REST"},
		{"NONE", "NONE"},

		// --- cross-protocol relabelling is NOT this function's job. HTTPS and
		// SSL stay as observed; mapping them onto TLS is a semantic decision made
		// later, where a row crosses into the enum-typed column.
		{"HTTPS", "HTTPS"},
		{"SSL", "SSL"},
		{"DoT", "DoT"},

		// --- empty stays empty (callers treat "" as "not observed") ---
		{"", ""},
		{"   ", ""},
	}

	for _, c := range cases {
		got := NormalizeProtocol(c.in)
		if got != c.want {
			t.Errorf("NormalizeProtocol(%q) = %q, want %q", c.in, got, c.want)
		}
		// Idempotence: normalizing an already-stored value must be a no-op, or
		// a re-ingest of the same row would produce a different string than the
		// first write did.
		if again := NormalizeProtocol(got); again != got {
			t.Errorf("NormalizeProtocol is not idempotent for %q: %q -> %q", c.in, got, again)
		}
	}
}

// enumValues reads the "enum" list of a schema under schemas/managed/v1/enums/.
func enumValues(t *testing.T, name string) []string {
	t.Helper()
	path := repo.Path(t, "schemas", "managed", "v1", "enums", name)
	raw, err := os.ReadFile(path) //nolint:gosec // fixed path under the module root
	if err != nil {
		t.Fatalf("read %s: %v (the platform's enumeration is the source of truth; "+
			"if it moved, update this test rather than deleting it)", path, err)
	}
	var doc struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Enum) == 0 {
		t.Fatalf("%s holds no values", path)
	}
	return doc.Enum
}

// TestNormalizeProtocol_MatchesSchemaEnum is what makes canonicalProtocols a
// copy rather than a second opinion. The platform's protocol_type enum, exported
// to schemas/managed/v1/enums/protocol_type.json, is the vocabulary; if a value
// is added there and not here, this function would pass the new protocol
// through un-normalised while the platform's enum column accepts it.
func TestNormalizeProtocol_MatchesSchemaEnum(t *testing.T) {
	fromSchema := enumValues(t, "protocol_type.json")

	inGo := make(map[string]bool, len(canonicalProtocols))
	for _, p := range canonicalProtocols {
		inGo[p] = true
	}
	inSchema := make(map[string]bool, len(fromSchema))
	for _, p := range fromSchema {
		inSchema[p] = true
		if !inGo[p] {
			t.Errorf("protocol_type enum has %q but cryptoparse.canonicalProtocols does not — "+
				"that protocol will be stored with whatever spelling its producer used", p)
		}
	}
	for _, p := range canonicalProtocols {
		if !inSchema[p] {
			t.Errorf("cryptoparse.canonicalProtocols has %q but the protocol_type enum does not", p)
		}
	}
}

// TestFoldProtocol pins the comparison key shared/discovery's prober registry
// depends on.
func TestFoldProtocol(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"OPC UA", "OPCUA"},
		{"OPC-UA", "OPCUA"},
		{"OPC_UA", "OPCUA"},
		{"opc.ua", "OPCUA"},
		{"EtherNet/IP", "ETHERNETIP"},
		{"  TLS ", "TLS"},
		{"", ""},
	} {
		if got := FoldProtocol(c.in); got != c.want {
			t.Errorf("FoldProtocol(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
