package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetEnvIfPresent(t *testing.T) {
	const key = "TEST_GET_ENV_IF_PRESENT"

	t.Run("unset uses fallback", func(t *testing.T) {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("failed to unset %s: %v", key, err)
		}
		if got := GetEnvIfPresent(key, "fallback"); got != "fallback" {
			t.Fatalf("got %q, want fallback", got)
		}
	})

	t.Run("empty string is preserved", func(t *testing.T) {
		t.Setenv(key, "")
		if got := GetEnvIfPresent(key, "fallback"); got != "" {
			t.Fatalf("got %q, want empty string", got)
		}
	})

	t.Run("non-empty value is returned", func(t *testing.T) {
		t.Setenv(key, "http://example:8080")
		if got := GetEnvIfPresent(key, "fallback"); got != "http://example:8080" {
			t.Fatalf("got %q, want explicit value", got)
		}
	})
}

func TestLinuxDataPath(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "vista")
	legacy := filepath.Join(dir, "crypto")

	if got := LinuxDataPath(current, legacy); got != current {
		t.Errorf("neither exists: got %s, want the current name", got)
	}
	if err := os.Mkdir(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := LinuxDataPath(current, legacy); got != legacy {
		t.Errorf("only the legacy directory exists: got %s, an existing host must keep it", got)
	}
	if err := os.Mkdir(current, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := LinuxDataPath(current, legacy); got != current {
		t.Errorf("both exist: got %s, want the current name", got)
	}
}
