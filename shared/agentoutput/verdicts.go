package agentoutput

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Standalone mode collects; it does not assess (docs/design/standalone-mode.md).
// Producers now emit facts rather than policy judgments. Write still removes
// retired verdict keys wherever they are nested so legacy or mixed-version
// input cannot leak assessments into standalone output. The observed facts
// from which policy can decide (versions, algorithms, sizes and OT mechanisms)
// stay.
//
// Managed mode is unaffected: it does not write through this package.

// VerdictKeys are retired producer verdicts that Write removes defensively.
var VerdictKeys = []string{
	"cert_weak_signature",  // shared/discovery quality flag: a judgement of the signature algorithm
	"cert_weak_public_key", // shared/discovery quality flag: a judgement of the key size
	"risk_score",           // database collector and sensor models
	"risk_level",
	"risk_factors",
	"highest_risk",
	"compliance_status",
	"iec62351_tls_version_compliant",
	"iec62351_cipher_compliant",
	"iec62351_cert_compliant",
	"iec62351_overall",
	"iec62351_noncompliance",
}

// weakSecurity is retained only to remove a legacy generic OT verdict. It is
// not rewritten to a replacement strength because that would invent a fact.
const weakSecurity = "weak"

func isVerdictKey(k string) bool {
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
				delete(t, k)
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
