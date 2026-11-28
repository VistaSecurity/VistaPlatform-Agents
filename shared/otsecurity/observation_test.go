package otsecurity

import (
	"testing"
	"time"
)

func TestDNP3SeparatesFrameCleartextFromAuthentication(t *testing.T) {
	now := time.Date(2026, time.November, 28, 12, 0, 0, 0, time.UTC)
	plain := DNP3(now, true, false)
	if plain["schema"] != Schema || plain["parser_status"] != "complete" || plain["observation_scope"] != "frame" {
		t.Fatalf("plain observation = %#v", plain)
	}
	if plain["ot_confidentiality_state"] != "clear" || plain["ot_confidentiality_evidence"] != "clear_frame" {
		t.Fatalf("plain confidentiality = %#v", plain)
	}
	if plain["ot_message_authentication_state"] != "unknown" {
		t.Fatalf("plain SA absence became a negative authentication fact: %#v", plain)
	}

	sa := DNP3WithDirection(now, true, true, DirectionServerToClient)
	if sa["ot_message_authentication_state"] != "present" || sa["ot_message_authentication_evidence"] != "dnp3_sa" {
		t.Fatalf("SA evidence = %#v", sa)
	}
	if sa["ot_confidentiality_state"] != "clear" || sa["ot_confidentiality_evidence"] != "clear_frame" {
		t.Fatalf("decoded SA frame did not preserve clear confidentiality: %#v", sa)
	}
	if sa["direction"] != DirectionServerToClient {
		t.Fatalf("SA direction = %#v", sa["direction"])
	}
}

func TestTLSClassifiesCapabilityWithoutTrafficVerdict(t *testing.T) {
	now := time.Date(2026, time.November, 28, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, cipher, capability string
	}{
		{name: "known encrypted", cipher: "TLS_AES_128_GCM_SHA256", capability: "non_null"},
		{name: "known null", cipher: "TLS_NULL_WITH_NULL_NULL", capability: "none"},
		{name: "unknown passive name", cipher: "Unknown-0xBEEF", capability: "unknown"},
		{name: "unknown active numeric", cipher: "0xBEEF", capability: "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := TLS(now, test.cipher)
			if got["ot_confidentiality_capability"] != test.capability || got["ot_confidentiality_state"] != "unknown" {
				t.Fatalf("TLS observation = %#v", got)
			}
		})
	}
}

func TestNewDefaultsDirectionToUnknown(t *testing.T) {
	got := New(time.Date(2026, time.November, 28, 12, 0, 0, 0, time.UTC))
	if got["direction"] != DirectionUnknown {
		t.Fatalf("default direction = %#v, want %q", got["direction"], DirectionUnknown)
	}
}

func TestOPCUAURIHasNoModeInference(t *testing.T) {
	got := OPCUA(time.Date(2026, time.November, 28, 12, 0, 0, 0, time.UTC))
	if got["ot_confidentiality_state"] != "unknown" || got["ot_message_authentication_state"] != "unknown" {
		t.Fatalf("URI-only observation inferred a security mode: %#v", got)
	}
}
