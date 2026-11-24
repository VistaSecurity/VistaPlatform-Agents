package kubeinventory

import (
	"fmt"
	"time"
)

// Parameters are a kubernetes_inventory job's parameters
// (schemas/managed/v1/defs/kubernetes-inventory-parameters.json).
type Parameters struct {
	Options      Options
	MaxPartBytes int
	Timeout      time.Duration
}

// forbiddenParameters would name another cluster or supply a credential. A
// job carrying one is refused: this collector describes the cluster it runs
// in, with its own service account, and nothing else.
var forbiddenParameters = []string{
	"kubeconfig", "token", "bearer_token", "api_server", "server", "ca_data",
	"client_certificate", "client_key", "username", "password",
}

// ParseParameters reads a job's parameters. It never enables reading TLS
// Secrets: no parameter does, and a parameter that looks as if it should is
// ignored like any other unknown one.
func ParseParameters(params map[string]any) (Parameters, error) {
	out := Parameters{MaxPartBytes: DefaultMaxPartBytes, Timeout: DefaultTimeout}
	for _, name := range forbiddenParameters {
		if _, ok := params[name]; ok {
			return out, fmt.Errorf("a kubernetes_inventory job cannot carry %q: the agent describes only the cluster it runs in, with its own service account", name)
		}
	}
	if raw, ok := params["classes"]; ok && raw != nil {
		list, ok := raw.([]any)
		if !ok {
			return out, fmt.Errorf("parameters.classes must be a list")
		}
		for _, v := range list {
			class, _ := v.(string)
			if !contains(Classes, class) {
				return out, fmt.Errorf("parameters.classes names an unknown class %q", fmt.Sprint(v))
			}
			out.Options.Classes = append(out.Options.Classes, class)
		}
	}
	if v, ok := params["probe_kubelets"].(bool); ok {
		out.Options.SkipKubeletProbe = !v
	}
	if v, ok := params["include_certificate_pem"].(bool); ok {
		out.Options.OmitCertificatePEM = !v
	}
	if raw, ok := params["extra_label_keys"].([]any); ok {
		for _, v := range raw {
			if key, _ := v.(string); key != "" && len(key) <= 317 && labelKeyRE.MatchString(key) {
				out.Options.ExtraLabelKeys = append(out.Options.ExtraLabelKeys, key)
			}
		}
		out.Options.ExtraLabelKeys = limit(out.Options.ExtraLabelKeys, 32)
	}
	if n, ok := number(params["max_items_per_class"]); ok && n >= 1 && n <= 1000000 {
		out.Options.MaxItemsPerClass = n
	}
	if n, ok := number(params["max_part_bytes"]); ok && n >= MinMaxPartBytes && n <= MaxMaxPartBytes {
		out.MaxPartBytes = n
	}
	if n, ok := number(params["timeout_seconds"]); ok && n >= 30 && n <= 3600 {
		out.Timeout = time.Duration(n) * time.Second
	}
	return out, nil
}

// number reads a JSON number.
func number(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), n == float64(int(n))
	case int:
		return n, true
	}
	return 0, false
}
