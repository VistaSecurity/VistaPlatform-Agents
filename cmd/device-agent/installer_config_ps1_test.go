package main

// scripts/install-device-agent.ps1 writes the agent's config and relies on the
// agent to enroll itself, exactly like install-device-agent.sh (see
// installer_config_test.go). The same two hand-offs, for the Windows
// installer: the config it writes leaves the agent unenrolled with its key,
// URL and a data path inside the install directory; and the installer reads
// the agent's own rewrite of that file to see the enrollment and, on a
// re-run, to keep it.
//
// This runs the installer's own functions (the `#region agent-config` block)
// under PowerShell against the agent's real loader and writer. PowerShell 7
// (pwsh) is on GitHub's Linux runners; without it the test skips.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/internal/deviceagent/config"
)

const deviceAgentPs1 = "../../scripts/install-device-agent.ps1"

func ps1Region(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(deviceAgentPs1)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	s := string(raw)
	start := strings.Index(s, "#region "+name)
	end := strings.Index(s, "#endregion "+name)
	if start < 0 || end < start {
		t.Fatalf("#region %s not found in %s", name, deviceAgentPs1)
	}
	return s[start:end]
}

// runPwsh runs script after the installer's functions, with env set.
func runPwsh(t *testing.T, functions, script string, env ...string) string {
	t.Helper()
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh not available")
	}
	cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference = 'Stop'\n"+functions+"\n"+script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pwsh failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestInstallerPs1Config_AgentEnrollsItselfAndInstallerSeesIt(t *testing.T) {
	fns := ps1Region(t, "agent-config")
	installDir := t.TempDir()
	cfgPath := filepath.Join(installDir, "device-agent.yaml")
	dataDir := filepath.Join(installDir, "data")
	// Awkward on purpose: a quote, "#", ": " and a backslash must survive.
	const url = `https://control.example.test/p#frag: x`
	const key = `REG-a'b#c: "d"\e`
	env := []string{"CFG=" + cfgPath, "URL=" + url, "KEY=" + key, "DATA=" + dataDir}
	runPwsh(t, fns, `[System.IO.File]::WriteAllText($env:CFG, (New-AgentConfigText $env:URL $env:KEY $env:DATA), (New-Object System.Text.UTF8Encoding $false))`, env...)

	// Hand-off 1: the agent loads it, unenrolled, with the installer's values.
	cfg, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("agent cannot load the installer's config: %v", err)
	}
	if cfg.AgentID != "" {
		t.Fatalf("the installer's config names an agent (%q); the agent would never enroll", cfg.AgentID)
	}
	if cfg.PlatformURL != url || cfg.RegistrationKey != key {
		t.Fatalf("url/key = %q/%q, want %q/%q", cfg.PlatformURL, cfg.RegistrationKey, url, key)
	}
	if cfg.DataPath != dataDir {
		t.Fatalf("DataPath = %q, want %q (inside the install directory)", cfg.DataPath, dataDir)
	}
	if got := runPwsh(t, fns, `Test-EnrolledWithKey $env:CFG $env:KEY`, env...); got != "False" {
		t.Fatalf("an unenrolled config reads as enrolled (%s): a re-run would never enroll", got)
	}

	// Hand-off 2: the agent records its enrollment the way main does.
	const id = "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59"
	cfg.AgentID = id
	if err := saveConfigFile(cfgPath, cfg); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}
	if got := runPwsh(t, fns, `Get-ConfigValue $env:CFG 'agent_id'`, env...); got != id {
		t.Fatalf("installer read agent_id %q, want %q: a successful install would be reported as a failure", got, id)
	}
	if got := runPwsh(t, fns, `Get-ConfigValue $env:CFG 'registration_key'`, env...); got != key {
		t.Fatalf("installer read registration_key %q, want %q", got, key)
	}
	if got := runPwsh(t, fns, `Test-EnrolledWithKey $env:CFG $env:KEY`, env...); got != "True" {
		t.Fatalf("a re-run with the same key does not see the enrollment (%s): it would discard it", got)
	}
	if got := runPwsh(t, fns, `Test-EnrolledWithKey $env:CFG 'REG-another-key'`, env...); got != "False" {
		t.Fatalf("a different key reads as this enrollment (%s): it would never enroll fresh", got)
	}

	// Once the platform has issued the agent secret, the agent keeps only the
	// key's SHA-256; the installer must still recognise it.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "registration_key:") {
			kept = append(kept, line)
		}
	}
	kept = append(kept, `registration_key_sha256: "`+config.HashRegistrationKey(key)+`"`)
	if err := os.WriteFile(cfgPath, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runPwsh(t, fns, `Test-EnrolledWithKey $env:CFG $env:KEY`, env...); got != "True" {
		t.Fatalf("an enrollment that keeps only the key's fingerprint is not recognised (%s)", got)
	}
}

// The installer accepts the binary under the package's name or the release's
// own name, and refuses to guess between several release files.
func TestInstallerPs1_FindsTheBinaryByEitherName(t *testing.T) {
	fns := ps1Region(t, "agent-config")
	find := `try { Find-AgentBinary $env:DIR } catch { "ERROR: " + $_.Exception.Message }`

	dir := t.TempDir()
	touch := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := runPwsh(t, fns, find, "DIR="+dir)
	if !strings.HasPrefix(got, "ERROR: ") || !strings.Contains(got, "device-agent.exe") || !strings.Contains(got, "vista-device-agent_*_windows_*.exe") {
		t.Fatalf("no binary: %q, want an error naming both file names", got)
	}

	touch("vista-device-agent_5.4.0_windows_amd64.exe")
	if got := runPwsh(t, fns, find, "DIR="+dir); got != filepath.Join(dir, "vista-device-agent_5.4.0_windows_amd64.exe") {
		t.Fatalf("one release-named binary: %q", got)
	}

	touch("vista-device-agent_5.3.0_windows_amd64.exe")
	if got := runPwsh(t, fns, find, "DIR="+dir); !strings.HasPrefix(got, "ERROR: Found 2 files") {
		t.Fatalf("two release-named binaries: %q, want a refusal to guess", got)
	}

	touch("device-agent.exe")
	if got := runPwsh(t, fns, find, "DIR="+dir); got != filepath.Join(dir, "device-agent.exe") {
		t.Fatalf("installed name present: %q, want it preferred", got)
	}
}
