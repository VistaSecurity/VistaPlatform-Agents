// Package identityvectors loads fixtures/identity/identifier-vectors.json:
// the identifier kinds the platform accepts and normalisation vectors it
// computed. An identifier an agent emits must normalise the way the platform
// stores it, so the agents' own normalisation is tested against this file.
package identityvectors

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/testsupport/repo"
)

// Accepted is an input the platform accepts, with the canonical form it stores.
type Accepted struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Canonical string `json:"canonical"`
}

// Rejected is an input the platform refuses to store as an identity.
type Rejected struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Vectors is the fixture.
type Vectors struct {
	Kinds    []string   `json:"kinds"`
	Accepted []Accepted `json:"accepted"`
	Rejected []Rejected `json:"rejected"`
}

// ValidKind reports whether kind is one of the platform's identifier kinds.
func (v Vectors) ValidKind(kind string) bool {
	for _, k := range v.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Load reads the fixture; a missing or empty one fails the test.
func Load(t testing.TB) Vectors {
	t.Helper()
	p := repo.Path(t, "fixtures", "identity", "identifier-vectors.json")
	raw, err := os.ReadFile(p) //nolint:gosec // fixture path under the module root
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var v Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", p, err)
	}
	if len(v.Kinds) == 0 || len(v.Accepted) == 0 || len(v.Rejected) == 0 {
		t.Fatalf("%s holds no kinds or vectors", p)
	}
	return v
}
