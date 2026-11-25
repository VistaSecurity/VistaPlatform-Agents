package hostcrypto

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// Hand-written outputs, in the shapes the real tools print. Device names
// and identifiers are made up.

const platLsblkSample = `{
   "blockdevices": [
      {"name": "/dev/loop0", "type": "loop", "fstype": "squashfs", "mountpoint": "/snap/core/1"},
      {"name": "/dev/sda", "type": "disk", "fstype": null, "mountpoint": null,
         "children": [
            {"name": "/dev/sda1", "type": "part", "fstype": "vfat", "mountpoint": "/boot/efi"},
            {"name": "/dev/sda2", "type": "part", "fstype": "crypto_LUKS", "mountpoint": null,
               "children": [
                  {"name": "/dev/mapper/sda2_crypt", "type": "crypt", "fstype": "LVM2_member", "mountpoint": null,
                     "children": [
                        {"name": "/dev/mapper/vg-root", "type": "lvm", "fstype": "ext4", "mountpoint": "/"},
                        {"name": "/dev/mapper/vg-swap", "type": "lvm", "fstype": "swap", "mountpoint": "[SWAP]"}
                     ]
                  }
               ]
            },
            {"name": "/dev/sda3", "type": "part", "fstype": null, "mountpoint": null,
               "children": [
                  {"name": "/dev/mapper/scratch", "type": "crypt", "fstype": "xfs", "mountpoint": "/scratch"}
               ]
            }
         ]
      },
      {"name": "/dev/loop9", "type": "loop", "fstype": "crypto_LUKS", "mountpoint": null,
         "children": [{"name": "/dev/mapper/vault", "type": "crypt", "fstype": "ext4", "mountpoint": "/vault"}]}
   ]
}`

const platCryptsetupSample = `/dev/mapper/sda2_crypt is active and is in use.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 512 bits
  key location: keyring
  device:  /dev/sda2
  sector size:  512
  offset:  32768 sectors
  size:    1000000 sectors
  mode:    read/write
`

func TestPlatParseLsblk(t *testing.T) {
	vols, crypt, err := platParseLsblk([]byte(platLsblkSample))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]VolumeEncryption{}
	for _, v := range vols {
		got[v.MountPoint] = v
	}
	if _, ok := got["/snap/core/1"]; ok {
		t.Fatal("a plain loop device was listed")
	}
	for mp, want := range map[string]bool{"/boot/efi": false, "/": true, "[SWAP]": true, "/scratch": true, "/vault": true} {
		v, ok := got[mp]
		if !ok || v.Encrypted == nil || *v.Encrypted != want {
			t.Errorf("%s: %+v", mp, v)
		}
	}
	if crypt["sda2_crypt"] != "luks" || crypt["scratch"] != "" || crypt["vault"] != "luks" {
		t.Fatalf("crypt: %v", crypt)
	}
	if _, _, err := platParseLsblk([]byte("not json")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestPlatParseDMKindsAndStatus(t *testing.T) {
	kinds := platParseDMKinds([]byte("CRYPT-LUKS2 sda2_crypt\nCRYPT-PLAIN scratch\nLVM-abc vg-root\nCRYPT-BITLK win\nweird\n"))
	if kinds["sda2_crypt"] != "luks2" || kinds["scratch"] != "dm-crypt-plain" || kinds["win"] != "bitlocker" || len(kinds) != 3 {
		t.Fatalf("%v", kinds)
	}
	info, ok := platParseCryptsetupStatus([]byte(platCryptsetupSample))
	if !ok || info.method != "luks2" || info.cipher != "aes-xts-plain64" || info.keyBits != 512 {
		t.Fatalf("%+v", info)
	}
	// Anything not on the three-field list is dropped, whatever it holds.
	leak := platCryptsetupSample + "  key:     0123456789abcdef0123456789abcdef\n  cipher:  aes-xts-plain64 0123456789abcdef0123456789abcdef\n"
	info2, _ := platParseCryptsetupStatus([]byte(leak))
	if strings.Contains(platJSON(t, map[string]any{"c": info2.cipher, "m": info2.method}), "0123456789abcdef") {
		t.Fatal("a key-looking value was kept")
	}
}

func TestPlatParseLinuxTPMSecureBootFIPSTokens(t *testing.T) {
	tpm := platParseLinuxTPM([]byte("dev tpm0\nmajor 2\nclass\n"))
	if !tpm.Present || tpm.Version != "2.0" {
		t.Fatalf("%+v", tpm)
	}
	tpm = platParseLinuxTPM([]byte("dev tpm0\nmajor 1\nenabled 1\ncaps Manufacturer: 0x49465800\ncaps TCG version: 1.2\n"))
	if !tpm.Present || tpm.Version != "1.2" || tpm.Manufacturer != "IFX" || tpm.Enabled == nil || !*tpm.Enabled {
		t.Fatalf("%+v", tpm)
	}
	if tpm := platParseLinuxTPM([]byte("class\n")); tpm.Present {
		t.Fatal("no device, present")
	}

	for in, want := range map[string][2]bool{
		"legacy\n":                      {false, true},
		"efivar   6   0   0   0   1 \n": {true, true},
		"efivar   6   0   0   0   0 \n": {false, true},
		"vars   1 \n":                   {true, true},
		"unknown\n":                     {false, false},
		"":                              {false, false},
	} {
		on, ok := platParseLinuxSecureBoot([]byte(in))
		if on != want[0] || ok != want[1] {
			t.Errorf("%q: %v %v", in, on, ok)
		}
	}
	for in, want := range map[string][2]bool{
		"SecureBoot enabled\n": {true, true}, "SecureBoot disabled\n": {false, true},
		"EFI variables are not supported on this system\n": {false, true}, "huh": {false, false},
	} {
		on, ok := platParseMokutil([]byte(in))
		if on != want[0] || ok != want[1] {
			t.Errorf("mokutil %q: %v %v", in, on, ok)
		}
	}
	for in, want := range map[string][2]bool{"fips 1\n": {true, true}, "fips 0\n": {false, true}, "absent\n": {false, true}, "fips x": {false, false}} {
		on, ok := platParseLinuxFIPS([]byte(in))
		if on != want[0] || ok != want[1] {
			t.Errorf("fips %q: %v %v", in, on, ok)
		}
	}

	p11 := "module: p11-kit-trust\n    path: /usr/lib/pkcs11/p11-kit-trust.so\n    uri: pkcs11:library-description=x\n    token: System Trust\n        serial-number: SN-12345\n        path: /tmp/not-a-module\nmodule: opensc\n    path: /usr/lib/opensc-pkcs11.so\n"
	toks := platParseP11Kit([]byte(p11))
	if len(toks) != 2 || toks[0].Name != "p11-kit-trust" || toks[0].Path != "/usr/lib/pkcs11/p11-kit-trust.so" || toks[1].Path != "/usr/lib/opensc-pkcs11.so" {
		t.Fatalf("%+v", toks)
	}
	if strings.Contains(platJSON(t, toks), "SN-12345") || strings.Contains(platJSON(t, toks), "System Trust") {
		t.Fatal("token details were kept")
	}
}

// platLinuxFake scripts the Linux protection commands.
func platLinuxFake(local, root, cryptsetup bool) *tgtFakeTarget {
	ft := newTgtFakeTarget(local)
	uid := "1000\n"
	if root {
		uid = "0\n"
	}
	ft.script([]string{"id", "-u"}, tgtResult{stdout: uid})
	ft.script(platLsblkArgv, tgtResult{stdout: platLsblkSample})
	ft.script(platSh(platDMScript), tgtResult{stdout: "CRYPT-LUKS2 sda2_crypt\nCRYPT-PLAIN scratch\nCRYPT-LUKS1 vault\n"})
	if cryptsetup {
		for _, n := range []string{"sda2_crypt", "scratch", "vault"} {
			if root {
				ft.script(platCryptsetupArgv(n), tgtResult{stdout: platCryptsetupSample})
			} else {
				ft.script(platCryptsetupArgv(n), tgtResult{stderr: "Cannot initialize device-mapper.", exit: 4})
			}
		}
	}
	ft.script(platSh(platTPMScript), tgtResult{stdout: "dev tpm0\nmajor 2\nclass\n"})
	ft.script(platSh(platSecureBootScript), tgtResult{stdout: "unknown\n"})
	ft.script(platMokutilArgv, tgtResult{stdout: "SecureBoot enabled\n"})
	ft.script(platSh(platFIPSScript), tgtResult{stdout: "fips 0\n"})
	ft.script(platP11Argv, tgtResult{stdout: "module: p11-kit-trust\n    path: /usr/lib/pkcs11/p11-kit-trust.so\n"})
	return ft
}

func TestPlatLinuxProtection(t *testing.T) {
	for _, local := range []bool{true, false} {
		// Root: everything read.
		c := tgtCollection(platLinuxFake(local, true, true), Options{Platform: hostinventory.PlatformLinux})
		platElevatedUnix(t.Context(), c)
		platLinuxProtection(t.Context(), c)
		rep := c.report
		for _, s := range []string{SectionDiskEncryption, SectionTPM, SectionSecureBoot, SectionTokens} {
			if rep.Sections[s] != SectionOK {
				t.Fatalf("local=%v root: %s = %q (%+v)", local, s, rep.Sections[s], rep.Errors)
			}
		}
		pr := rep.Protection
		if pr.SecureBoot == nil || !*pr.SecureBoot || pr.FIPSMode == nil || *pr.FIPSMode || pr.TPM == nil || pr.TPM.Version != "2.0" || len(pr.Tokens) != 1 {
			t.Fatalf("protection: %+v", pr)
		}
		var root VolumeEncryption
		for _, v := range pr.Volumes {
			if v.MountPoint == "/" {
				root = v
			}
		}
		if root.Method != "luks2" || root.Cipher != "aes-xts-plain64" || root.KeySizeBits != 512 {
			t.Fatalf("root volume: %+v", root)
		}

		// Not root: the cipher needs root; the section says partial and why.
		c = tgtCollection(platLinuxFake(local, false, true), Options{Platform: hostinventory.PlatformLinux})
		platElevatedUnix(t.Context(), c)
		platLinuxProtection(t.Context(), c)
		if c.report.Sections[SectionDiskEncryption] != SectionPartial || !platErrorsContain(c.report, SectionDiskEncryption, "root") {
			t.Fatalf("non-root: %v %+v", c.report.Sections, c.report.Errors)
		}
		for _, v := range c.report.Protection.Volumes {
			if v.MountPoint == "/vault" && (v.Method != "luks1" || v.Cipher != "") {
				t.Fatalf("vault: %+v", v)
			}
		}

		// No tools at all: unsupported, never an empty "ok".
		c = tgtCollection(newTgtFakeTarget(local), Options{Platform: hostinventory.PlatformLinux})
		platLinuxProtection(t.Context(), c)
		for _, s := range []string{SectionDiskEncryption, SectionTPM, SectionTokens} {
			if c.report.Sections[s] != SectionUnsupported {
				t.Fatalf("no tools: %s = %q", s, c.report.Sections[s])
			}
		}
		if c.report.Sections[SectionSecureBoot] != SectionPartial || c.report.Protection.SecureBoot != nil {
			t.Fatalf("no tools: secure boot %v", c.report.Sections)
		}
	}
}

// A crypt mapping name from the host is an argument, and one that is not a
// plain name is not sent at all.
func TestPlatCryptNameNotSent(t *testing.T) {
	ft := newTgtFakeTarget(true)
	bad := `{"blockdevices":[{"name":"/dev/sdb","type":"part","fstype":"crypto_LUKS","mountpoint":null,"children":[{"name":"/dev/mapper/x;reboot","type":"crypt","fstype":"ext4","mountpoint":"/x"}]}]}`
	ft.script(platLsblkArgv, tgtResult{stdout: bad})
	c := tgtCollection(ft, Options{Platform: hostinventory.PlatformLinux})
	platLinuxVolumes(t.Context(), c)
	for _, call := range ft.recorded() {
		if strings.Contains(call, "cryptsetup") {
			t.Fatalf("sent %q", call)
		}
	}
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

const platAPFSSample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Containers</key>
	<array>
		<dict>
			<key>APFSContainerUUID</key><string>00000000-0000-0000-0000-000000000001</string>
			<key>CapacityCeiling</key><integer>1000</integer>
			<key>Volumes</key>
			<array>
				<dict>
					<key>DeviceIdentifier</key><string>disk3s1</string>
					<key>Encryption</key><true/>
					<key>FileVault</key><true/>
					<key>Locked</key><false/>
					<key>Name</key><string>Somebody's Disk</string>
					<key>Roles</key><array><string>System</string></array>
				</dict>
				<dict>
					<key>DeviceIdentifier</key><string>disk3s5</string>
					<key>Encryption</key><true/>
					<key>FileVault</key><false/>
					<key>Locked</key><true/>
				</dict>
				<dict>
					<key>DeviceIdentifier</key><string>disk3s6</string>
					<key>Encryption</key><false/>
					<key>FileVault</key><false/>
				</dict>
				<dict>
					<key>DeviceIdentifier</key><string>../etc</string>
				</dict>
			</array>
		</dict>
	</array>
</dict>
</plist>`

const platMountSample = `/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
devfs on /dev (devfs, local, nobrowse)
/dev/disk3s6 on /System/Volumes/VM (apfs, local, noexec, journaled, noatime, nobrowse)
/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse, protect)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)
`

const platIBridgeSample = `Controller:

      Model Identifier: Mac00,0
      Firmware Version: fw-1
      Boot UUID: 00000000-0000-0000-0000-000000000000
      Boot Policy:
        Secure Boot: Reduced Security
        System Integrity Protection: Enabled
`

func TestPlatParseDarwin(t *testing.T) {
	vols, err := platParseAPFSList([]byte(platAPFSSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 3 || vols[0].Method != "filevault" || vols[1].Method != "apfs" || vols[1].Status != "Locked" || *vols[2].Encrypted {
		t.Fatalf("%+v", vols)
	}
	if strings.Contains(platJSON(t, vols), "Somebody") || strings.Contains(platJSON(t, vols), "00000000") {
		t.Fatal("a name or UUID was kept")
	}
	m := platParseDarwinMounts([]byte(platMountSample))
	if m["disk3s1"] != "/" || m["disk3s5"] != "/System/Volumes/Data" || m["disk3s6"] != "/System/Volumes/VM" {
		t.Fatalf("mounts: %v", m)
	}
	for in, want := range map[string]string{"FileVault is On.\n": "On", "FileVault is Off.\n": "Off",
		"FileVault is On.\nEncryption in progress: Percent completed = 12.3\n": "EncryptionInProgress", "?": ""} {
		if got := platParseFdesetup([]byte(in)); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	t2, ctl, sb := platParseIBridge([]byte(platIBridgeSample))
	if t2 || !ctl || sb == nil || !*sb {
		t.Fatalf("ibridge: %v %v %v", t2, ctl, sb)
	}
	t2, _, sb = platParseIBridge([]byte("Apple T2 Security Chip:\n\n      Model Name: Apple T2 Security Chip\n      Secure Boot: Permissive Security\n"))
	if !t2 || sb == nil || *sb {
		t.Fatalf("t2: %v %v", t2, sb)
	}
	toks := platParseCTKTokens([]byte("     com.apple.CryptoTokenKit.pivtoken(1.0)\n+    com.example.token(2)\nnot a token line\n"))
	if len(toks) != 2 || toks[0].Name != "com.apple.CryptoTokenKit.pivtoken" || toks[1].Name != "com.example.token" {
		t.Fatalf("tokens: %+v", toks)
	}
	if _, err := platParseAPFSList([]byte("<plist><dict><key>a</key>")); err == nil {
		t.Fatal("broken plist accepted")
	}
}

func TestPlatDarwinProtection(t *testing.T) {
	for _, local := range []bool{true, false} {
		ft := newTgtFakeTarget(local)
		ft.script(platDiskutilArgv, tgtResult{stdout: platAPFSSample})
		ft.script(platMountArgv, tgtResult{stdout: platMountSample})
		ft.script(platFdesetupArgv, tgtResult{stdout: "FileVault is On.\n"})
		ft.script(platArm64Argv, tgtResult{stdout: "1\n"})
		ft.script(platIBridgeArgv, tgtResult{stdout: platIBridgeSample})
		ft.script(platCTKTokensArgv, tgtResult{stdout: "     com.apple.CryptoTokenKit.pivtoken(1.0)\n"})
		c := tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin})
		platDarwinProtection(t.Context(), c)
		rep := c.report
		for _, s := range []string{SectionDiskEncryption, SectionTPM, SectionSecureBoot, SectionTokens} {
			if rep.Sections[s] != SectionOK {
				t.Fatalf("%s = %q", s, rep.Sections[s])
			}
		}
		pr := rep.Protection
		if pr.TPM == nil || !pr.TPM.Present || pr.TPM.Version != "secure-enclave" || pr.SecureBoot == nil || !*pr.SecureBoot || pr.FIPSMode != nil {
			t.Fatalf("%+v", pr)
		}
		if pr.Volumes[0].MountPoint != "/" || pr.Volumes[0].Status != "On" {
			t.Fatalf("volumes: %+v", pr.Volumes)
		}

		// An Intel Mac without a T2: no Secure Enclave, no Secure Boot.
		ft = newTgtFakeTarget(local)
		ft.script(platArm64Argv, tgtResult{stdout: "0\n"})
		ft.script(platIBridgeArgv, tgtResult{stdout: ""})
		c = tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin})
		platDarwinProtection(t.Context(), c)
		if c.report.Protection.TPM == nil || c.report.Protection.TPM.Present || c.report.Protection.SecureBoot == nil || *c.report.Protection.SecureBoot {
			t.Fatalf("intel: %+v", c.report.Protection)
		}
		if c.report.Sections[SectionDiskEncryption] != SectionUnsupported {
			t.Fatalf("no diskutil: %v", c.report.Sections)
		}
	}
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

func platWinProtSample(t *testing.T, elevated bool) string {
	ans := map[string]any{
		"Elevated": elevated,
		"Bl": map[string]any{"Error": "", "Vols": []map[string]any{
			{"Mount": "C:", "Status": "FullyEncrypted", "Method": "XtsAes256", "Prot": "On", "Kinds": []string{"Tpm", "RecoveryPassword"},
				// Were a recovery password ever in the answer, it is not a
				// field the parser reads.
				"RecoveryPassword": "111111-222222-333333-444444-555555-666666-777777-888888"},
			{"Mount": "D:", "Status": "FullyDecrypted", "Method": "None", "Prot": "Off", "Kinds": []string{}},
			{"Mount": "E:", "Status": "FullyEncrypted", "Method": "Aes128", "Prot": "Off", "Kinds": "ExternalKey"},
			{"Mount": "not a mount", "Status": "FullyEncrypted"},
		}},
		"Tpm":        map[string]any{"Error": "", "Present": true, "Enabled": true, "Maker": "XYZ ", "Spec": "2.0, 0, 1.59", "Pnp": []string{}},
		"Sb":         map[string]any{"Reg": 1, "RegError": "", "Uefi": nil, "UefiError": "denied"},
		"Fips":       map[string]any{"Value": nil, "Error": "not_found"},
		"Cards":      map[string]any{"Name": "Identity Device (PIV)", "Dll": `C:\Windows\System32\msclmd.dll`},
		"CardsError": "",
	}
	if !elevated {
		ans["Bl"] = map[string]any{"Error": "other", "Vols": nil}
		ans["Tpm"] = map[string]any{"Error": "denied", "Present": nil, "Pnp": "Trusted Platform Module 2.0", "Spec": ""}
	}
	return platJSON(t, ans)
}

func TestPlatParseWindowsProtection(t *testing.T) {
	r, err := platParseWindowsProtection([]byte(platWinProtSample(t, true)))
	if err != nil {
		t.Fatal(err)
	}
	if r.diskErr != nil || r.tpmErr != nil || r.sbErr != nil || r.tokErr != nil || r.fipsErr != nil {
		t.Fatalf("errors: %+v", r)
	}
	v := r.prot.volumes
	if len(v) != 3 || v[0].Cipher != "XTS-AES 256" || v[0].KeySizeBits != 256 || strings.Join(v[0].Protectors, ",") != "recovery_key,tpm" ||
		*v[1].Encrypted || v[2].Status != "FullyEncrypted, ProtectionOff" || strings.Join(v[2].Protectors, ",") != "key_file" {
		t.Fatalf("volumes: %+v", v)
	}
	if strings.Contains(platJSON(t, v), "111111") {
		t.Fatal("a recovery password reached the record")
	}
	if r.prot.tpm == nil || r.prot.tpm.Version != "2.0" || r.prot.tpm.Manufacturer != "XYZ" || r.prot.secureBoot == nil || !*r.prot.secureBoot ||
		r.prot.fips == nil || *r.prot.fips || len(r.prot.tokens) != 1 {
		t.Fatalf("%+v", r.prot)
	}

	// Without elevation: BitLocker refused (said so), the TPM from the PnP
	// list, Secure Boot from the registry.
	r, err = platParseWindowsProtection([]byte(platWinProtSample(t, false)))
	if err != nil {
		t.Fatal(err)
	}
	if r.diskErr == nil || !strings.Contains(r.diskErr.Error(), "elevated") || r.tpmErr == nil || r.prot.tpm == nil || !r.prot.tpm.Present || r.prot.tpm.Version != "2.0" {
		t.Fatalf("non-elevated: %+v", r)
	}
}

func TestPlatWindowsProtectionThroughCollect(t *testing.T) {
	for _, local := range []bool{true, false} {
		ft := newPlatFakeWin(t, local)
		ft.answers["protection"] = platWinProtSample(t, false)
		c := tgtCollection(ft, Options{Platform: hostinventory.PlatformWindows})
		platWindowsProtection(t.Context(), c)
		s := c.report.Sections
		if s[SectionDiskEncryption] != SectionPartial || s[SectionTPM] != SectionPartial || s[SectionSecureBoot] != SectionOK || s[SectionTokens] != SectionOK {
			t.Fatalf("%v", s)
		}

		// A program the host cannot run fails the four sections.
		ft = newPlatFakeWin(t, local)
		c = tgtCollection(ft, Options{Platform: hostinventory.PlatformWindows})
		platWindowsProtection(t.Context(), c)
		if c.report.Sections[SectionTPM] != SectionFailed {
			t.Fatalf("%v", c.report.Sections)
		}
	}
}

// ---------------------------------------------------------------------------
// Real tools, on this machine, no root
// ---------------------------------------------------------------------------

func TestPlatRealLinuxProtection(t *testing.T) {
	if _, err := exec.LookPath("lsblk"); err != nil {
		t.Skip("lsblk not installed")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	c := tgtCollection(NewLocalTarget(), Options{Platform: hostinventory.PlatformLinux})
	platElevatedUnix(t.Context(), c)
	platLinuxProtection(t.Context(), c)
	rep := c.report
	if rep.Sections[SectionDiskEncryption] == SectionFailed || rep.Sections[SectionDiskEncryption] == "" {
		t.Fatalf("disk encryption: %v %+v", rep.Sections, rep.Errors)
	}
	if rep.Sections[SectionTPM] != SectionOK || rep.Protection.TPM == nil {
		t.Fatalf("tpm: %v", rep.Sections)
	}
	if rep.Protection.FIPSMode == nil {
		t.Fatalf("fips: %+v", rep.Errors)
	}
	b, _ := json.Marshal(rep.Protection)
	t.Logf("%s", b)
}
