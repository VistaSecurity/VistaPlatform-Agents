package agentoutput

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteRemovesVerdictsAndKeepsFacts(t *testing.T) {
	w, stdout, _ := open(t, Options{Format: FormatJSONL})
	data := map[string]any{
		"version":      "TLS 1.2",
		"cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
		"key_size":     1024,
		"sequence":     uint64(1<<63 + 5), // must survive exactly
		"raw_metadata": map[string]any{
			"iec62351_overall":           "noncompliant",
			"iec62351_cipher_compliant":  false,
			"iec62351_noncompliance":     []string{"cipher"},
			"key_exchange_algorithm":     "RSA",
			"cert_weak_signature":        "SHA-1",
			"cert_weak_public_key":       "RSA-1024",
			"signature_alg":              "SHA1-RSA",
			"security":                   "weak",
			"security_policy_short":      "Basic128Rsa15",
			"certificates":               []any{map[string]any{"risk_score": 80, "key_size": 1024}},
			"nested_list_of_lists":       []any{[]any{map[string]any{"risk_level": "high", "port": 443}}},
			"compliance_status":          map[string]any{"pci": "fail"},
			"security_mode_unrelated_ok": "weak", // only the key "security" is rewritten
		},
		"device_info": map[string]any{"risk_score": 3, "risk_factors": []string{"x"}, "highest_risk": 9, "risk_level": "low", "db_version": "16.2"},
	}
	if err := w.Write(KindScanHost, data); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(false, ""); err != nil {
		t.Fatal(err)
	}
	line := strings.Split(strings.TrimSpace(stdout.String()), "\n")[1]
	gone := []string{`"` + VerdictKeyPrefix, `"security":"weak"`}
	for _, k := range VerdictKeys {
		gone = append(gone, `"`+k+`"`)
	}
	for _, g := range gone {
		if strings.Contains(line, g) {
			t.Errorf("verdict %s left in the output: %s", g, line)
		}
	}
	for _, kept := range []string{`"version":"TLS 1.2"`, `"key_size":1024`, `"key_exchange_algorithm":"RSA"`, `"signature_alg":"SHA1-RSA"`,
		`"security":"present"`, `"security_policy_short":"Basic128Rsa15"`, `"port":443`, `"db_version":"16.2"`,
		`"sequence":9223372036854775813`, `"security_mode_unrelated_ok":"weak"`} {
		if !strings.Contains(line, kept) {
			t.Errorf("fact %s missing from the output: %s", kept, line)
		}
	}
	var rec Record
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatal(err)
	}
}

func TestWriteKeepsTypedDataShape(t *testing.T) {
	type obs struct {
		Port  int               `json:"port"`
		Meta  map[string]string `json:"meta,omitempty"`
		Empty *int              `json:"empty"`
	}
	w, stdout, _ := open(t, Options{Format: FormatJSONL})
	if err := w.Write(KindPassiveObservation, obs{Port: 22, Meta: map[string]string{"iec62351_overall": "x", "sni": "a"}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(KindPassiveObservation, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = w.Close(false, "")
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if want := `"data":{"empty":null,"meta":{"sni":"a"},"port":22}`; !strings.Contains(lines[1], want) {
		t.Errorf("got %s; want it to contain %s", lines[1], want)
	}
	if !strings.Contains(lines[2], `"data":null`) {
		t.Errorf("nil data: %s", lines[2])
	}
}
