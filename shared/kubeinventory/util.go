package kubeinventory

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vistasecurity/vistaplatform-agents/shared/redact"
)

// The record's schema bounds every string and patterns some. The API server
// already holds most of these values to the same syntax; the helpers here make
// the record valid whatever an object says, by cutting what is too long and
// leaving out what does not fit.

var (
	uidRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	nameRE     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$`)
	kindRE     = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	groupRE    = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]*[a-z0-9])?)?$`)
	durationRE = regexp.MustCompile(`^[0-9hms.]+$`)
	labelKeyRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]*[a-z0-9])?/)?[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	labelValRE = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)
)

// clip cuts s to at most n characters.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

func clipAll(in []string, n int) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = clip(s, n)
	}
	return out
}

// limit cuts a list to at most n entries.
func limit[T any](in []T, n int) []T {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// message prepares free text written by a controller or the API server:
// redacted, then cut.
func message(s string) string { return clip(redact.Text(s), maxMessageLen) }

func cleanUID(s string) string {
	if uidRE.MatchString(s) {
		return s
	}
	return ""
}

// cleanName returns s when it is a valid object name for the record, else "".
func cleanName(s string) string {
	if len(s) <= 253 && nameRE.MatchString(s) {
		return s
	}
	return ""
}

func cleanKind(s string) string {
	if len(s) <= 63 && kindRE.MatchString(s) {
		return s
	}
	return ""
}

func cleanGroup(s string) string {
	if len(s) <= 253 && groupRE.MatchString(s) {
		return s
	}
	return ""
}

func cleanDuration(s string) string {
	if len(s) <= 32 && durationRE.MatchString(s) {
		return s
	}
	return ""
}

// groupOf is the API group of an apiVersion ("apps/v1" -> "apps", "v1" -> "").
func groupOf(apiVersion string) string {
	if i := strings.IndexByte(apiVersion, '/'); i >= 0 {
		return cleanGroup(apiVersion[:i])
	}
	return ""
}

// cleanIPs keeps the valid addresses, in canonical form.
func cleanIPs(in []string, max int) []string {
	var out []string
	for _, s := range in {
		if addr, err := netip.ParseAddr(s); err == nil && addr.Zone() == "" {
			out = append(out, addr.String())
		}
	}
	return limit(out, max)
}

func cleanIP(s string) string {
	if v := cleanIPs([]string{s}, 1); len(v) == 1 {
		return v[0]
	}
	return ""
}

func cleanCIDRs(in []string, max int) []string {
	var out []string
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.String())
		}
	}
	return limit(out, max)
}

func cleanPort(n int) int {
	if n >= 1 && n <= 65535 {
		return n
	}
	return 0
}

func cleanProtocol(s string) string {
	switch s {
	case "UDP", "SCTP":
		return s
	}
	return "TCP"
}

func utc(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func intPtr(n int) *int    { return &n }
func boolPtr(b bool) *bool { return &b }

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// The label keys reported without being asked for. Everything else a cluster
// puts in labels stays in the cluster unless a job names the key.
var builtinLabelKeys = map[string]bool{
	"app":                              true,
	"k8s-app":                          true,
	"app.kubernetes.io/name":           true,
	"app.kubernetes.io/instance":       true,
	"app.kubernetes.io/version":        true,
	"app.kubernetes.io/component":      true,
	"app.kubernetes.io/part-of":        true,
	"app.kubernetes.io/managed-by":     true,
	"helm.sh/chart":                    true,
	"kubernetes.io/os":                 true,
	"kubernetes.io/arch":               true,
	"node.kubernetes.io/instance-type": true,
	"topology.kubernetes.io/region":    true,
	"topology.kubernetes.io/zone":      true,
	"istio-injection":                  true,
	"istio.io/rev":                     true,
	"istio.io/dataplane-mode":          true,
	"kubernetes.io/metadata.name":      true,
}

// labelFilter reports the allowed labels of an object.
type labelFilter struct{ extra map[string]bool }

func newLabelFilter(extraKeys []string) labelFilter {
	f := labelFilter{extra: map[string]bool{}}
	for _, k := range limit(extraKeys, 32) {
		f.extra[k] = true
	}
	return f
}

func (f labelFilter) pick(labels map[string]string) map[string]string {
	var out map[string]string
	for k, v := range labels {
		if !builtinLabelKeys[k] && !f.extra[k] {
			continue
		}
		if !validLabel(k, v) {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out
}

func validLabel(k, v string) bool {
	return len(k) <= 317 && len(v) <= 63 && labelKeyRE.MatchString(k) && labelValRE.MatchString(v)
}

// selectorLabels is a policy's label selector as written, held to label
// syntax and to the schema's size.
func selectorLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]string{}
	for _, k := range limit(keys, 64) {
		if validLabel(k, in[k]) {
			out[k] = in[k]
		}
	}
	return out
}

// selects reports whether every label of selector is on labels. An empty
// selector selects nothing here: callers decide what "no selector" means.
func selects(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}
