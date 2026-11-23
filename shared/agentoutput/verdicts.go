package agentoutput

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Standalone mode collects; it does not assess (docs/design/standalone-mode.md).
// The decoders and collectors it shares with managed mode attach a few labels
// that are judgements rather than observations, for the platform's benefit:
// a compliance verdict against IEC 62351, a "weak" signature or key, a risk
// score. Write removes them from every record, wherever they are nested, so a
// standalone result holds only what was observed. The facts each label was
// derived from (the protocol version, the cipher suite, the signature
// algorithm, the key size, the OPC UA policy, the DNP3 MAC) stay.
//
// Managed mode is unaffected: it does not write through this package.

// VerdictKeys are the keys Write removes. A key starting with
// VerdictKeyPrefix is removed too.
var VerdictKeys = []string{
	"cert_weak_signature",  // shared/discovery quality flag: a judgement of the signature algorithm
	"cert_weak_public_key", // shared/discovery quality flag: a judgement of the key size
	"risk_score",           // database collector and sensor models
	"risk_level",
	"risk_factors",
	"highest_risk",
	"compliance_status",
}

// VerdictKeyPrefix marks the IEC 62351 classification the passive TLS decoder
// adds to every observation (iec62351_overall, iec62351_cipher_compliant, ...).
const VerdictKeyPrefix = "iec62351_"

// weakSecurity is the one verdict value among facts: the OT decoders' "security"
// key is "none" or "present" (observed) or "weak" (judged). Write reports a
// weak mechanism as "present"; the mechanism itself is in the record.
const weakSecurity = "weak"

func isVerdictKey(k string) bool {
	if strings.HasPrefix(k, VerdictKeyPrefix) {
		return true
	}
	for _, v := range VerdictKeys {
		if k == v {
			return true
		}
	}
	return false
}

// withoutVerdicts returns data as plain JSON values with every verdict
// removed. Numbers keep their exact text (json.Number), so a 64-bit integer
// survives the round trip.
func withoutVerdicts(data any) (any, error) {
	if data == nil {
		return nil, nil
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("re-reading the record: %w", err)
	}
	return scrubVerdicts(v), nil
}

func scrubVerdicts(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isVerdictKey(k) {
				delete(t, k)
				continue
			}
			if k == "security" && val == weakSecurity {
				t[k] = "present"
				continue
			}
			t[k] = scrubVerdicts(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = scrubVerdicts(t[i])
		}
		return t
	default:
		return v
	}
}
