// Package protocolschema loads the managed protocol v1 message schemas
// (schemas/managed/v1/) for tests: the fixture test, and the fake control
// plane, which validates everything an agent sends and everything it answers.
//
// Schemas are read from this module's tree only. A $ref that names anything
// that is not a file of schemas/managed/v1/ fails to compile, so a dangling or
// remote reference cannot pass unnoticed, and nothing is ever fetched.
package protocolschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
)

// BaseURI is the $id prefix of every v1 schema. It is an identifier, not a
// location: nothing is fetched from it.
const BaseURI = "https://schemas.vistasecurity.io/agents/managed/v1/"

// Dir is the schema directory, relative to the module root.
const Dir = "schemas/managed/v1"

// MessageSuffix ends the file name of every message schema.
const MessageSuffix = ".schema.json"

// Set is the compiled message schemas, by message name ("heartbeat.response").
type Set struct {
	Root    string
	schemas map[string]*jsonschema.Schema
}

// localLoader resolves a BaseURI URL to its file under dir and refuses
// everything else.
type localLoader struct{ dir string }

func (l localLoader) Load(url string) (any, error) {
	rel, ok := strings.CutPrefix(url, BaseURI)
	if !ok || rel == "" || strings.Contains(rel, "..") {
		return nil, fmt.Errorf("protocolschema: %q is not a schema of %s; only local v1 schemas may be referenced", url, Dir)
	}
	data, err := os.ReadFile(filepath.Join(l.dir, filepath.FromSlash(rel)))
	if err != nil {
		return nil, fmt.Errorf("protocolschema: %s: %w", url, err)
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(data))
}

// Load compiles every message schema of the module rooted at root.
func Load(root string) (*Set, error) {
	dir := filepath.Join(root, filepath.FromSlash(Dir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseLoader(localLoader{dir: dir})
	set := &Set{Root: root, schemas: map[string]*jsonschema.Schema{}}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, MessageSuffix) {
			continue
		}
		var head struct {
			ID string `json:"$id"`
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &head); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if head.ID != BaseURI+name {
			return nil, fmt.Errorf("%s: $id is %q, want %q", name, head.ID, BaseURI+name)
		}
		sch, err := c.Compile(head.ID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		set.schemas[strings.TrimSuffix(name, MessageSuffix)] = sch
	}
	if len(set.schemas) == 0 {
		return nil, fmt.Errorf("no message schemas in %s", dir)
	}
	return set, nil
}

// CompileDef compiles one schema of defs/ (or a fragment of one, "defs/x.json#/$defs/y").
func (s *Set) CompileDef(rel string) (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseLoader(localLoader{dir: filepath.Join(s.Root, filepath.FromSlash(Dir))})
	return c.Compile(BaseURI + rel)
}

var (
	once    sync.Once
	shared  *Set
	loadErr error
)

// Shared is the module's schema set, compiled once per test binary.
func Shared() (*Set, error) {
	once.Do(func() {
		root, err := repo.Root()
		if err != nil {
			loadErr = err
			return
		}
		shared, loadErr = Load(root)
	})
	return shared, loadErr
}

// Messages lists the message names, sorted.
func (s *Set) Messages() []string {
	out := make([]string, 0, len(s.schemas))
	for name := range s.schemas {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ErrUnknownMessage is returned for a message name with no schema.
var ErrUnknownMessage = errors.New("no schema for this message")

// ValidateJSON validates data, one JSON document, against message's schema.
func (s *Set) ValidateJSON(message string, data []byte) error {
	sch, ok := s.schemas[message]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownMessage, message)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: not JSON: %w", message, err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("%s: %w", message, err)
	}
	return nil
}

// Validate marshals v and validates it against message's schema.
func (s *Set) Validate(message string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.ValidateJSON(message, data)
}
