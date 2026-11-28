// Package otsecurity defines the bounded, factual OT observation object that
// is carried in CryptoDiscovery.RawMetadata. It contains parser evidence only;
// policy evaluation remains a Platform concern.
package otsecurity

import (
	"strings"
	"time"
)

const (
	Key    = "ot_security"
	Schema = "vista.ot-security-observation/v1"
)

const (
	DirectionUnknown        = "unknown"
	DirectionClientToServer = "client_to_server"
	DirectionServerToClient = "server_to_client"
)

// New returns the normalized object for a complete parser observation. The
// caller supplies only values established by that parser; omitted values are
// represented as unknown so consumers do not confuse absence with success.
func New(observedAt time.Time) map[string]interface{} {
	return NewWithDirection(observedAt, DirectionUnknown)
}

// NewWithDirection returns the normalized object with packet-flow provenance.
// Callers must pass unknown when the parser cannot establish the direction;
// this field is provenance, not a role guess derived from a protocol name.
func NewWithDirection(observedAt time.Time, direction string) map[string]interface{} {
	if direction == "" {
		direction = DirectionUnknown
	}
	return map[string]interface{}{
		"schema":                          Schema,
		"ot_confidentiality_state":        "unknown",
		"ot_confidentiality_capability":   "unknown",
		"ot_message_authentication_state": "unknown",
		"parser_status":                   "complete",
		"direction":                       direction,
		"observed_at":                     observedAt.UTC().Format(time.RFC3339Nano),
	}
}

// DNP3 returns evidence for one decoded DNP3 frame. A complete frame without
// Secure Authentication is clear-frame evidence, but the absence of an SA
// object in one frame cannot establish session-wide authentication absence.
func DNP3(observedAt time.Time, plaintext, secureAuthentication bool) map[string]interface{} {
	return DNP3WithDirection(observedAt, plaintext, secureAuthentication, DirectionUnknown)
}

// DNP3WithDirection returns evidence for one decoded DNP3 frame and preserves
// the packet direction supplied by the capture assembler.
func DNP3WithDirection(observedAt time.Time, plaintext, secureAuthentication bool, direction string) map[string]interface{} {
	observation := NewWithDirection(observedAt, direction)
	observation["observation_scope"] = "frame"
	if plaintext {
		observation["ot_confidentiality_state"] = "clear"
		observation["ot_confidentiality_evidence"] = "clear_frame"
	}
	if secureAuthentication {
		observation["ot_message_authentication_state"] = "present"
		observation["ot_message_authentication_evidence"] = "dnp3_sa"
	}
	return observation
}

// OPCUA returns evidence for an OPC UA observation. A SecurityPolicy URI is
// intentionally not used to infer MessageSecurityMode; the current parser does
// not decode that mode from a message.
func OPCUA(observedAt time.Time) map[string]interface{} {
	return OPCUAWithDirection(observedAt, DirectionUnknown)
}

// OPCUAWithDirection returns an OPC UA observation with packet provenance.
func OPCUAWithDirection(observedAt time.Time, direction string) map[string]interface{} {
	observation := NewWithDirection(observedAt, direction)
	// The parser records an OPC UA security-policy observation, but does not
	// decode MessageSecurityMode. Keep that scope explicit while leaving both
	// policy states unavailable.
	observation["observation_scope"] = "message_security_mode"
	return observation
}

// TLS returns selected-suite capability evidence. A ServerHello alone does
// not prove protected application traffic, so the confidentiality state stays
// unknown. Unknown or absent suite names remain unknown. NULL suites are a
// known no-encryption capability, while every other known suite is non-NULL.
func TLS(observedAt time.Time, cipherSuite string) map[string]interface{} {
	return TLSWithDirection(observedAt, cipherSuite, DirectionUnknown)
}

// TLSWithDirection returns selected-suite capability evidence with packet
// provenance for the ServerHello that established the selected suite.
func TLSWithDirection(observedAt time.Time, cipherSuite, direction string) map[string]interface{} {
	observation := NewWithDirection(observedAt, direction)
	observation["observation_scope"] = "selected_suite_capability"
	observation["ot_confidentiality_evidence"] = "protected_capability"
	normalizedCipher := strings.ToLower(strings.TrimSpace(cipherSuite))
	switch {
	case normalizedCipher == "" || strings.HasPrefix(normalizedCipher, "unknown-") || strings.HasPrefix(normalizedCipher, "0x"):
		observation["ot_confidentiality_capability"] = "unknown"
	case strings.Contains(cipherSuite, "_NULL_") || strings.HasPrefix(cipherSuite, "TLS_NULL_"):
		observation["ot_confidentiality_capability"] = "none"
	default:
		observation["ot_confidentiality_capability"] = "non_null"
	}
	return observation
}
