package protocolschema

// The public contract test: every synthetic fixture under fixtures/managed/v1/
// against its message schema under schemas/managed/v1/.
//
//   fixtures/managed/v1/<message>/valid*.json    must validate
//   fixtures/managed/v1/<message>/refused*.json  must validate: well-formed,
//                                                and the agent must refuse it
//                                                (the client tests prove that)
//   fixtures/managed/v1/<message>/invalid*.json  must NOT validate
//
// It fails on a schema with no valid fixture, a fixture directory with no
// schema, a fixture file named outside those three kinds, and (through Load)
// a $ref that does not resolve to a local v1 schema.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
)

// FixtureDir is the fixture directory, relative to the module root.
const FixtureDir = "fixtures/managed/v1"

func TestEveryFixtureMatchesItsSchema(t *testing.T) {
	set, err := Shared()
	if err != nil {
		t.Fatalf("load schemas: %v", err)
	}
	dir := repo.Path(t, filepath.FromSlash(FixtureDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	known := map[string]bool{}
	for _, m := range set.Messages() {
		known[m] = true
	}
	validFor := map[string]int{}
	for _, e := range entries {
		if !e.IsDir() {
			if e.Name() != "README.md" {
				t.Errorf("%s: a fixture outside a message directory", e.Name())
			}
			continue
		}
		message := e.Name()
		if !known[message] {
			t.Errorf("fixtures/%s: no schema %s%s for it", message, message, MessageSuffix)
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, message))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			name := f.Name()
			path := filepath.Join(dir, message, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(name, ".json") || !json.Valid(data) {
				t.Errorf("%s/%s: not a JSON fixture", message, name)
				continue
			}
			verr := set.ValidateJSON(message, data)
			switch {
			case strings.HasPrefix(name, "valid"):
				validFor[message]++
				if verr != nil {
					t.Errorf("%s/%s should validate: %v", message, name, verr)
				}
			case strings.HasPrefix(name, "refused"):
				if verr != nil {
					t.Errorf("%s/%s is well-formed (the agent refuses it, the schema does not): %v", message, name, verr)
				}
			case strings.HasPrefix(name, "invalid"):
				if verr == nil {
					t.Errorf("%s/%s should NOT validate against %s%s", message, name, message, MessageSuffix)
				}
			default:
				t.Errorf("%s/%s: a fixture is named valid*, refused* or invalid*", message, name)
			}
		}
	}
	for _, m := range set.Messages() {
		if validFor[m] == 0 {
			t.Errorf("schema %s%s has no valid fixture under %s/%s/", m, MessageSuffix, FixtureDir, m)
		}
	}
}

// The schemas carry the protocol rules the agents enforce. The fixtures above
// exercise them one by one; this names the ones a refactor of a schema must
// not lose, so losing one fails with its reason rather than a file name.
func TestTheSchemasCarryTheProtocolRules(t *testing.T) {
	set, err := Shared()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		message, fixture, rule string
	}{
		{"heartbeat.response", "invalid-missing-protocol", "a heartbeat answer names the platform's protocol"},
		{"heartbeat.response", "invalid-protocol-version-2", "version 1 is the only version of v1/"},
		{"job.device-agent", "invalid-missing-protocol", "a job names the platform's protocol"},
		{"job.device-agent", "invalid-unsealed-credentials", "credentials travel sealed only"},
		{"registration.request", "invalid-no-csr", "registration always carries a CSR"},
		{"registration.response", "invalid-server-generated-key", "the platform never returns a private key"},
		{"registration.response", "invalid-missing-agent-secret", "enrollment always issues the agent secret"},
		{"discovery-job.payload", "invalid-legacy-shape", "the scan plan is the only job shape"},
		{"discovery-batch", "invalid-private-key-in-certificate", "collect posture, never key material"},
		{"error", "invalid-426-without-supported", "a 426 says what the platform supports"},
	} {
		data, err := os.ReadFile(repo.Path(t, filepath.FromSlash(FixtureDir), c.message, c.fixture+".json"))
		if err != nil {
			t.Fatalf("%s: %v (the fixture that pins %q)", c.message, err, c.rule)
		}
		if set.ValidateJSON(c.message, data) == nil {
			t.Errorf("%s/%s validates: the schema no longer says %q", c.message, c.fixture, c.rule)
		}
	}
}

// The discovery-shape golden the sensor's capture test produces is the single
// certificate format as it rides in a discovery's raw_metadata, so it must be a
// valid raw_metadata of the envelope schema.
func TestTheDiscoveryShapeGoldenIsAValidEnvelopeMetadata(t *testing.T) {
	set, err := Shared()
	if err != nil {
		t.Fatal(err)
	}
	sch, err := set.CompileDef("defs/envelope.json#/$defs/raw_metadata")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(repo.Path(t, "fixtures", "discovery-shapes", "passive-tls-capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("the passive capture golden is not a valid raw_metadata: %v", err)
	}
}

// Load refuses a reference that leaves the local v1 schemas: a remote or
// dangling $ref cannot pass unnoticed.
func TestAnUnknownRefDoesNotCompile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(Dir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]string{
		"dangling.schema.json": "defs/no-such-def.json",
		"remote.schema.json":   "https://example.test/elsewhere.json",
	} {
		_ = os.RemoveAll(dir)
		_ = os.MkdirAll(dir, 0o755)
		doc := `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"` + BaseURI + name + `","$ref":"` + ref + `"}`
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(root); err == nil {
			t.Errorf("%s: a $ref to %s compiled", name, ref)
		}
	}
}
