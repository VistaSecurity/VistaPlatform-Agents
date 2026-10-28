// Package protocoltest helps tests whose stand-in platform is not the fake
// control plane (internal/testsupport/fakeplatform) speak managed protocol 1.
//
// A test that exercises a protocol rule itself drives the real client against
// fakeplatform; these helpers are for the many tests about something else (a
// config exchange, a retry queue, a host block) whose stub platform must
// simply be a protocol-1 platform for the agent to act on its answers at all.
package protocoltest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"

	"github.com/vistasecurity/vistaplatform-agents/shared/managedprotocol"
)

// AllCapabilities is every capability either agent of this build knows.
var AllCapabilities = []string{"device_discovery", "identity_dns_v1", "scan_plan_v1", "verify_certificate_v1"}

// V1 is a protocol-1 object naming every capability.
func V1() *managedprotocol.Protocol {
	return &managedprotocol.Protocol{Version: managedprotocol.Version, Capabilities: append([]string(nil), AllCapabilities...)}
}

// Open records that the platform answered with protocol 1 and every
// capability, as a first heartbeat would, so a test can submit straight away.
func Open(g *managedprotocol.Gate) {
	g.Compatible(managedprotocol.Intersect(g.Own(), AllCapabilities))
}

// Speak1 wraps a stub platform so every answer speaks protocol 1: the
// Vista-Agent-Protocol header on every answer, and the protocol object added to
// every JSON-object body that does not already carry one. The wrapped handler's
// status and other headers are kept.
func Speak1(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		var obj map[string]json.RawMessage
		if len(bytes.TrimSpace(body)) > 0 && json.Unmarshal(body, &obj) == nil && obj != nil {
			if _, has := obj["protocol"]; !has {
				p, _ := json.Marshal(V1())
				obj["protocol"] = p
				if out, err := json.Marshal(obj); err == nil {
					body = out
				}
			}
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Set(managedprotocol.Header, managedprotocol.FormatHeader(*V1()))
		if len(body) > 0 {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
}
