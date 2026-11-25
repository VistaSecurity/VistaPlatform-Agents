package main

import (
	"os"
	"path/filepath"
	"testing"
)

// With DATA_PATH set (a container), the agent finds the enrollment it saved
// there on its next start instead of enrolling again with a spent key.
func TestFindDefaultConfigFile_HonoursDataPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(t.TempDir())
	t.Setenv("DATA_PATH", dir)
	if got := findDefaultConfigFile(); got != "" {
		t.Fatalf("found %q in an empty data directory", got)
	}
	path := filepath.Join(dir, "agent-config.yaml")
	if err := os.WriteFile(path, []byte("agent_id: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := findDefaultConfigFile(); got != path {
		t.Errorf("findDefaultConfigFile() = %q, want %q", got, path)
	}
	t.Setenv("DATA_PATH", "")
	if got := configuredDataPath(); got != getDefaultDataPath() {
		t.Errorf("without DATA_PATH: %q", got)
	}
}
