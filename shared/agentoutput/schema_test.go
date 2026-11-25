package agentoutput

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/outputschema"
)

// Every kind the writer emits satisfies the published schema.
func TestRecordsSatisfyPublishedSchema(t *testing.T) {
	w, stdout, _ := open(t, Options{Format: FormatJSONL})
	_ = w.Write(KindPassiveObservation, map[string]any{"protocol": "tls"})
	_ = w.Write(KindScanHost, map[string]any{"address": "10.0.0.1"})
	_ = w.Write(KindDeviceInterrogation, map[string]any{"assets": []any{}})
	_ = w.Write(KindHostInventory, map[string]any{"report": map[string]any{}})
	_ = w.Write(KindHostCrypto, map[string]any{"report": map[string]any{
		"collected": "2026-11-23T14:00:00Z", "mode": "local", "platform": "linux", "sections": map[string]any{"platform": "ok"},
	}})
	_ = w.Error("10.0.0.9", "scan", "refused")
	w.Warn("a warning")
	if _, err := w.Close(false, "5 addresses"); err != nil {
		t.Fatal(err)
	}
	kinds := outputschema.ValidateJSONL(t, stdout.Bytes())
	if strings.Join(kinds, ",") != "run,passive_observation,scan_host,device_interrogation,host_inventory,host_crypto,error,summary" {
		t.Errorf("kinds = %v", kinds)
	}
}

// The schema is not inert: records the writer must never produce fail it.
func TestPublishedSchemaRefusesBadRecords(t *testing.T) {
	s := outputschema.Compile(t)
	good := `{"schema":"vista.agent-output/v1","kind":"scan_host","agent":"crypto-sensor","agent_version":"1","run_id":"6f1c2f3e-9d0a-4b7e-8a52-0f3c1d2e4b5a","observed_at":"2026-11-23T14:00:00Z","data":{}}`
	if err := outputschema.Validate(s, []byte(good)); err != nil {
		t.Fatalf("good record refused: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown kind":                   strings.Replace(good, `"scan_host"`, `"finding"`, 1),
		"wrong schema":                   strings.Replace(good, `v1"`, `v2"`, 1),
		"no run id":                      strings.Replace(good, `"run_id":"6f1c2f3e-9d0a-4b7e-8a52-0f3c1d2e4b5a",`, ``, 1),
		"extra field":                    strings.Replace(good, `"data":{}`, `"data":{},"risk_score":90`, 1),
		"error with no why":              strings.Replace(strings.Replace(good, `"scan_host"`, `"error"`, 1), `"data":{}`, `"data":{"target":"x"}`, 1),
		"summary incomplete":             strings.Replace(good, `"scan_host"`, `"summary"`, 1),
		"host_crypto without its report": strings.Replace(good, `"scan_host"`, `"host_crypto"`, 1),
		"host_crypto with a key as a certificate": strings.Replace(strings.Replace(good, `"scan_host"`, `"host_crypto"`, 1), `"data":{}`,
			`"data":{"report":{"collected":"x","mode":"local","platform":"linux","sections":{},"certificates":[{"certificate_pem":"-----BEGIN PRIVATE KEY-----"}]}}`, 1),
	} {
		if err := outputschema.Validate(s, []byte(bad)); err == nil {
			t.Errorf("%s: accepted %s", name, bad)
		}
	}
}
