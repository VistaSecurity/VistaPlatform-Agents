package protocolschema

// Structural guards on the Kubernetes inventory result schema
// (schemas/managed/v1/defs/kubernetes-inventory.json). The fixture test proves
// particular documents are refused; these prove the schema leaves no room:
//
//   - every object is closed, so a field the schema does not name (a Secret's
//     data, a pod's environment) cannot ride along;
//   - every string is bounded and no string but certificate_pem is long
//     enough to hold a key, and certificate_pem admits one CERTIFICATE block
//     and nothing else;
//   - the only members with "key" in their name are the ones listed here,
//     each of which describes a key and none of which holds one;
//   - a certificate entry uses the field names of the one certificate format.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
)

const kubernetesInventoryDef = "defs/kubernetes-inventory.json"

// longestOrdinaryString is the largest maxLength any string but
// certificate_pem may declare. The smallest private key in use, a PEM Ed25519
// key, is 119 characters, so length alone does not keep a key out; closed
// objects and the absence of any free-form member do. This bound keeps a new
// member from quietly becoming a place for a blob.
const longestOrdinaryString = 2048

// keyNamedMembers are the members whose name contains "key". Adding one is a
// reviewed change to this list.
var keyNamedMembers = []string{
	"extended_key_usage", "key_algorithm", "key_exchange_group", "key_request", "key_size", "key_usage",
}

func loadSchemaFile(t *testing.T, rel string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(repo.Path(t, filepath.Join(filepath.FromSlash(Dir), filepath.FromSlash(rel))))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return doc
}

func hasType(node map[string]any, want string) bool {
	switch v := node["type"].(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if e == want {
				return true
			}
		}
	}
	return false
}

// walkSchema calls visit for node and every subschema under it. name is the
// property name the subschema is declared under, or "" for any other position.
func walkSchema(path, name string, node any, visit func(path, name string, node map[string]any)) {
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	visit(path, name, m)
	for _, key := range []string{"properties", "$defs"} {
		if children, ok := m[key].(map[string]any); ok {
			for childName, child := range children {
				n := childName
				if key == "$defs" {
					n = ""
				}
				walkSchema(path+"/"+key+"/"+childName, n, child, visit)
			}
		}
	}
	for _, key := range []string{"items", "additionalProperties", "propertyNames", "if", "then", "else", "not"} {
		walkSchema(path+"/"+key, "", m[key], visit)
	}
	for _, key := range []string{"anyOf", "allOf", "oneOf"} {
		if list, ok := m[key].([]any); ok {
			for _, child := range list {
				walkSchema(path+"/"+key, "", child, visit)
			}
		}
	}
}

func TestKubernetesInventorySchemaIsClosedAndBounded(t *testing.T) {
	doc := loadSchemaFile(t, kubernetesInventoryDef)
	objects, stringsSeen := 0, 0
	var keyNamed []string
	seenKey := map[string]bool{}

	walkSchema("", "", doc, func(path, name string, node map[string]any) {
		if strings.Contains(name, "key") && !seenKey[name] {
			seenKey[name] = true
			keyNamed = append(keyNamed, name)
		}
		if hasType(node, "object") {
			objects++
			switch ap := node["additionalProperties"].(type) {
			case bool:
				if ap {
					t.Errorf("%s: object is open (additionalProperties true)", path)
				}
			case map[string]any:
				// A map (labels): its values must be short, patterned strings.
				max, _ := ap["maxLength"].(float64)
				if !hasType(ap, "string") || max == 0 || max > 63 || ap["pattern"] == nil {
					t.Errorf("%s: a map's values must be strings of at most 63 characters with a pattern", path)
				}
				if node["propertyNames"] == nil || node["maxProperties"] == nil {
					t.Errorf("%s: a map must bound its keys (propertyNames, maxProperties)", path)
				}
			default:
				t.Errorf("%s: object does not say additionalProperties false", path)
			}
		}
		if hasType(node, "string") {
			stringsSeen++
			if node["enum"] != nil || node["const"] != nil || node["format"] != nil {
				return
			}
			max, ok := node["maxLength"].(float64)
			if !ok {
				t.Errorf("%s: string has no maxLength", path)
				return
			}
			if name == "certificate_pem" {
				pattern, _ := node["pattern"].(string)
				re, err := regexp.Compile(pattern)
				if err != nil || pattern == "" {
					t.Fatalf("%s: certificate_pem needs a pattern that compiles: %v", path, err)
				}
				const cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
				const key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
				if !re.MatchString(cert) {
					t.Errorf("%s: the pattern refuses a certificate block", path)
				}
				for _, bad := range []string{key, cert + key, key + cert, cert + cert, "AAAA", strings.Replace(cert, "CERTIFICATE", "EC PRIVATE KEY", 2)} {
					if re.MatchString(bad) {
						t.Errorf("%s: the pattern admits %q", path, bad)
					}
				}
				return
			}
			if max > longestOrdinaryString {
				t.Errorf("%s: maxLength %v; only certificate_pem may exceed %d", path, max, longestOrdinaryString)
			}
		}
	})

	if objects < 30 || stringsSeen < 100 {
		t.Fatalf("walked %d objects and %d strings; the walk is not reaching the schema", objects, stringsSeen)
	}
	sort.Strings(keyNamed)
	if strings.Join(keyNamed, ",") != strings.Join(keyNamedMembers, ",") {
		t.Errorf("members named *key*: %v, want exactly %v", keyNamed, keyNamedMembers)
	}
	for _, forbidden := range []string{"data", "string_data", "private_key", "private_key_pem", "key_pem", "tls_key", "token", "password", "env", "annotations"} {
		walkSchema("", "", doc, func(path, name string, _ map[string]any) {
			if name == forbidden {
				t.Errorf("%s: the schema must not have a member named %q", path, forbidden)
			}
		})
	}
}

func TestKubernetesInventoryCertificateUsesTheCertificateFormat(t *testing.T) {
	canonical := loadSchemaFile(t, "defs/certificate.json")["properties"].(map[string]any)
	entry := loadSchemaFile(t, kubernetesInventoryDef)["$defs"].(map[string]any)["certificate"].(map[string]any)
	for name := range entry["properties"].(map[string]any) {
		if _, ok := canonical[name]; !ok {
			t.Errorf("certificate member %q is not a field of defs/certificate.json", name)
		}
	}
}

// Every class the result answers for can be asked for by name, and nothing
// else can.
func TestKubernetesInventoryParametersNameTheSameClasses(t *testing.T) {
	result := loadSchemaFile(t, kubernetesInventoryDef)
	required := result["properties"].(map[string]any)["sections"].(map[string]any)["required"].([]any)
	params := loadSchemaFile(t, "defs/kubernetes-inventory-parameters.json")
	classes := params["properties"].(map[string]any)["classes"].(map[string]any)["items"].(map[string]any)["enum"].([]any)
	join := func(in []any) string {
		out := make([]string, len(in))
		for i, v := range in {
			out[i] = v.(string)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if join(required) != join(classes) {
		t.Errorf("sections: %s\nclasses:  %s", join(required), join(classes))
	}
}
