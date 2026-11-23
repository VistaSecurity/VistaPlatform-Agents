// Package outputschema validates standalone output (schemas/output/v1) in
// tests, so every command's records are held to the published envelope.
package outputschema

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
)

// SchemaPath is the record schema, relative to the module root.
const SchemaPath = "schemas/output/v1/record.schema.json"

// Compile loads the record schema. Nothing is fetched: the schema has no
// remote reference.
func Compile(t testing.TB) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo.MustRoot(t), filepath.FromSlash(SchemaPath)))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	if err := c.AddResource("record.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("record.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Validate reports whether one encoded record satisfies the schema.
func Validate(s *jsonschema.Schema, record []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(record))
	if err != nil {
		return err
	}
	return s.Validate(v)
}

// ValidateJSONL validates every line of JSON Lines output and returns the
// records' kinds in order.
func ValidateJSONL(t testing.TB, out []byte) []string {
	t.Helper()
	s := Compile(t)
	var kinds []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if err := Validate(s, line); err != nil {
			t.Fatalf("record does not satisfy %s: %v\n%s", SchemaPath, err, line)
		}
		var head struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(line, &head)
		kinds = append(kinds, head.Kind)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return kinds
}
