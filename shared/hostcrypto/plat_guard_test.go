package hostcrypto

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// platAllCommands is every argv and program text the platform files send,
// by name. A new command belongs here; TestPlatCommandsRecorded checks that
// a collection sends nothing that is not.
func platAllCommands() map[string]string {
	m := map[string]string{}
	add := func(name string, argv []string) { m[name] = strings.Join(argv, " ") }
	add("id", []string{"id", "-u"})
	add("lsblk", platLsblkArgv)
	add("dm", platSh(platDMScript))
	add("cryptsetup", platCryptsetupArgv("NAME"))
	add("tpm", platSh(platTPMScript))
	add("secureboot", platSh(platSecureBootScript))
	add("mokutil", platMokutilArgv)
	add("fips", platSh(platFIPSScript))
	add("p11-kit", platP11Argv)
	add("diskutil", platDiskutilArgv)
	add("mount", platMountArgv)
	add("fdesetup", platFdesetupArgv)
	add("sysctl", platArm64Argv)
	add("system_profiler", platIBridgeArgv)
	add("pluginkit", platCTKTokensArgv)
	add("fda", platSh(platDarwinFDA))
	add("login-keychains", platSh(platDarwinUserKeychains))
	add("find-certificate", platKeychainCertsArgv("KEYCHAIN"))
	add("find-identity", platKeychainIdentitiesArgv("KEYCHAIN"))
	add("packages", platSh(platPkgScript))
	add("openssl", platSh(platOpenSSLScript))
	add("libfiles", platSh(platLinuxLibFilesScript))
	add("brew", platSh(platBrewScript))
	add("sw_vers", platSwVersArgv)
	add("running-linux", platSh(platLinuxRunningScript))
	add("running-darwin", platSh(platDarwinRunningScript))
	for name, body := range platPSPrograms() {
		m["ps-"+name] = platPSPrelude + body
	}
	return m
}

// TestPlatCommandsCarryNoSecretWords: no command or program contains a word
// that makes a tool print key material, recovery material or a secret, or
// that reads the environment.
func TestPlatCommandsCarryNoSecretWords(t *testing.T) {
	for name, cmd := range platAllCommands() {
		if w := platForbidden(cmd); w != "" {
			t.Errorf("%s contains %q", name, w)
		}
	}
	// The check fires on each word it lists.
	for _, w := range platForbiddenWords {
		if platForbidden("x "+w+" y") == "" {
			t.Errorf("the check passes %q", w)
		}
	}
	for _, bad := range []string{"cryptsetup luksDump /dev/sda2", "security find-generic-password -g", "$k.ExportParameters($true)",
		"manage-bde -protectors -get C:", "[Convert]::ToBase64String($v.KeyProtector.RecoveryPassword)", "security export -k x", "cat /proc/1/environ"} {
		if platForbidden(bad) == "" {
			t.Errorf("the check passes %q", bad)
		}
	}
	if w := platForbidden("$skN.ExportPolicy; $skI.Exportable"); w != "" {
		t.Errorf("the check refuses reading a policy: %q", w)
	}
}

// TestPlatCommandsRecorded runs every platform's passes on a fake host where
// every command answers and records what was sent: each must be one of
// platAllCommands (cryptsetup and the keychain commands with their argument
// replaced).
func TestPlatCommandsRecorded(t *testing.T) {
	known := map[string]bool{}
	for _, c := range platAllCommands() {
		known[c] = true
	}
	normalise := func(call string) string {
		for _, p := range []string{"cryptsetup status ", "security find-certificate -a -p ", "security find-identity "} {
			if strings.HasPrefix(call, p) {
				arg := "NAME"
				if strings.HasPrefix(p, "security") {
					arg = "KEYCHAIN"
				}
				return p + arg
			}
		}
		return call
	}
	k := platNewKey(t, "rec")
	for _, platform := range []string{hostinventory.PlatformLinux, hostinventory.PlatformDarwin} {
		ft := platLinuxFake(false, true, true)
		if platform == hostinventory.PlatformDarwin {
			ft = platDarwinFake(t, false, k, k, false)
		}
		platCollect(t, ft, Options{Platform: platform, HomeDirectories: true})
		for _, call := range ft.recorded() {
			if !strings.HasPrefix(call, "run ") {
				continue
			}
			if c := normalise(strings.TrimPrefix(call, "run ")); !known[c] {
				t.Errorf("%s: an unlisted command was sent: %.120q", platform, c)
			}
		}
	}
	ft := newPlatFakeWin(t, false)
	platCollect(t, ft, Options{Platform: hostinventory.PlatformWindows, HomeDirectories: true})
	sort.Strings(ft.sent)
	if strings.Join(ft.sent, ",") != "libraries,protection,running,stores" {
		t.Fatalf("windows programs: %v", ft.sent)
	}
}

// TestPlatPSAvoidTheTraps holds the PowerShell programs to the Windows
// target's rules (psTraps, psNameCollisions): no automatic variable, no
// case-insensitive comparison or hashtable, no two names differing by case.
func TestPlatPSAvoidTheTraps(t *testing.T) {
	for name, body := range platPSPrograms() {
		full := platPSPrelude + body
		if msg := psTraps(full); msg != "" {
			t.Errorf("%s: %s", name, msg)
		}
		if msg := psNameCollisions(full); msg != "" {
			t.Errorf("%s: %s", name, msg)
		}
		if n := strings.Count(full, "[Console]::Out.Write("); n != 1 {
			t.Errorf("%s writes %d times; only plOut writes", name, n)
		}
		if strings.Count(body, "plOut (") != 1 {
			t.Errorf("%s answers more or less than once", name)
		}
	}
}

var platPSMemberRE = regexp.MustCompile(`\$(skK|skN|skI|prP|prV|rnW|rnP|rnM)\.([A-Za-z]+)`)

// TestPlatPSMembersAllowlisted: on the objects that could reach a secret (a
// key handle, a BitLocker protector, a process), the programs touch only
// these members. A protector's RecoveryPassword or KeyPackage, a key's
// Export*, a container's UniqueName and a process's environment are not
// among them.
func TestPlatPSMembersAllowlisted(t *testing.T) {
	allowed := map[string]bool{
		"skK.GetType": true, "skK.Key": true, "skK.CspKeyContainerInfo": true, "skK.KeySize": true, "skK.Dispose": true,
		"skN.Provider": true, "skN.Algorithm": true, "skN.KeySize": true, "skN.ExportPolicy": true,
		"skI.ProviderName": true, "skI.Exportable": true, "skI.HardwareDevice": true,
		"prP.KeyProtectorType": true,
		"prV.KeyProtector":     true, "prV.MountPoint": true, "prV.VolumeStatus": true, "prV.EncryptionMethod": true, "prV.ProtectionStatus": true,
		"rnW.CommandLine": true, "rnW.ProcessId": true,
		"rnP.ProcessName": true, "rnP.Modules": true,
		"rnM.FileName": true,
	}
	check := func(script string) []string {
		var bad []string
		for _, m := range platPSMemberRE.FindAllStringSubmatch(script, -1) {
			if !allowed[m[1]+"."+m[2]] {
				bad = append(bad, m[0])
			}
		}
		return bad
	}
	for name, body := range platPSPrograms() {
		if bad := check(body); len(bad) > 0 {
			t.Errorf("%s touches %v", name, bad)
		}
	}
	if len(check("$prP.RecoveryPassword; $skK.ExportParameters")) != 2 {
		t.Fatal("the member check passes a secret member")
	}
	// The command line is read only into the filter: never into an answer.
	answers := regexp.MustCompile(`\[pscustomobject\]@\{[^}]*(rnCmd|CommandLine|rnTok|rnT\b)`)
	if answers.MatchString(platPSRunning) {
		t.Fatal("the running program answers a command line")
	}
	if !answers.MatchString(`[pscustomobject]@{ Id = 1; Line = $rnCmd[1] }`) {
		t.Fatal("the answer check passes a command line")
	}
}

// TestPlatSecretFilterBothSides: the PowerShell filter and Go's check use
// the same secret-option words as the awk filter, so the three agree.
func TestPlatSecretFilterBothSides(t *testing.T) {
	words := "(pass|secret|pin|token|cred|pwd)"
	if !strings.Contains(platArgsAwk, words) || !strings.Contains(platPSRunning, "'"+words+"'") || platSecretOption.String() != "(?i)"+words {
		t.Fatal("the secret-option words differ between the host filters and Go")
	}
	for _, e := range platCryptoExts {
		if !strings.Contains(platArgsAwk, e) || !strings.Contains(platPSRunning, e) {
			t.Fatalf("extension %s missing from a host filter", e)
		}
	}
}
