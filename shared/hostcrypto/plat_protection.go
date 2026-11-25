package hostcrypto

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Platform protection: disk encryption per volume, the TPM (on macOS the
// Secure Enclave), Secure Boot, the operating system's FIPS switch, and the
// PKCS#11 modules and smart-card providers. Every value is a state or a
// name; nothing here reads a volume key, a recovery key, a key slot or a
// PIN.
//
// The FIPS switch has no section of its own in the Report: Protection.FIPSMode
// is nil when it could not be read, and the reason is a StepError named
// platStepFIPS.

const platStepFIPS = "fips_mode"

// platProtection collects one platform's protection facts before they are
// written to the Report under the lock.
type platProtection struct {
	volumes    []VolumeEncryption
	tpm        *TPM
	secureBoot *bool
	fips       *bool
	tokens     []Token
}

// apply writes p into the Report, bounding the lists.
func (p platProtection) apply(c *collection) {
	max := c.opts.maxRecordsPerSection()
	vols, toks := p.volumes, p.tokens
	if len(vols) > max {
		vols = vols[:max]
		c.limit(SectionDiskEncryption, "max_records", fmt.Sprintf("kept the first %d volumes", max))
	}
	if len(toks) > max {
		toks = toks[:max]
		c.limit(SectionTokens, "max_records", fmt.Sprintf("kept the first %d tokens", max))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pr := &c.report.Protection
	pr.Volumes = append(pr.Volumes, vols...)
	if p.tpm != nil {
		pr.TPM = p.tpm
	}
	if p.secureBoot != nil {
		pr.SecureBoot = p.secureBoot
	}
	if p.fips != nil {
		pr.FIPSMode = p.fips
	}
	pr.Tokens = append(pr.Tokens, toks...)
}

// platOutcome marks a section from a step's error: ok when there is none,
// unsupported for a missing tool, partial for a refusal (rights) and failed
// otherwise. The error is recorded.
func platOutcome(c *collection, section string, err error) {
	switch {
	case err == nil:
		c.mark(section, SectionOK)
	case errors.Is(err, errPlatNoTool):
		c.mark(section, SectionUnsupported)
		c.note(section, err)
	case errors.Is(err, ErrPermission):
		c.partial(section, err)
	default:
		c.fail(section, err)
	}
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

// platLsblkArgv lists block devices as a JSON tree with their kind,
// filesystem type and mount point. It needs no rights.
var platLsblkArgv = []string{"lsblk", "-J", "-p", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"}

// platDMScript prints, for each device-mapper device that is a crypt target,
// its kind ("CRYPT-LUKS2", "CRYPT-PLAIN", ...) and its name, from
// /sys/block/dm-*/dm, which anyone may read. The UUID that follows the kind
// is cut off on the host.
const platDMScript = `for f in /sys/block/dm-*/dm; do
  [ -r "$f/uuid" ] && [ -r "$f/name" ] || continue
  u=$(cat "$f/uuid"); n=$(cat "$f/name")
  case "$u" in CRYPT-*) printf '%s %s\n' "$(printf '%s\n' "$u" | cut -d- -f1,2)" "$n" ;; esac
done
exit 0`

// platCryptsetupArgv asks for an active mapping's type, cipher and key size.
// "status" reads the device-mapper table's PUBLIC fields; it never prints
// the volume key (that takes luksDump with a key-dump flag, which is never
// sent). Needs root.
func platCryptsetupArgv(name string) []string { return []string{"cryptsetup", "status", name} }

// platTPMScript describes /sys/class/tpm: each device, its major version,
// TPM 1.2's enabled flag and the two public lines of its caps file. PCR
// values are not read.
const platTPMScript = `for d in /sys/class/tpm/tpm[0-9]*; do
  [ -e "$d" ] || continue
  printf 'dev %s\n' "${d##*/}"
  [ -r "$d/tpm_version_major" ] && printf 'major %s\n' "$(cat "$d/tpm_version_major")"
  [ -r "$d/device/enabled" ] && printf 'enabled %s\n' "$(cat "$d/device/enabled")"
  [ -r "$d/device/caps" ] && grep -E '^(Manufacturer|TCG version):' "$d/device/caps" | sed 's/^/caps /'
done
[ -d /sys/class/tpm ] && echo class
exit 0`

// platSecureBootScript reads the SecureBoot EFI variable (world readable)
// as decimal bytes, or says the host booted without UEFI.
const platSecureBootScript = `if [ ! -d /sys/firmware/efi ]; then echo legacy; exit 0; fi
f=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
if [ -r "$f" ]; then printf 'efivar '; od -An -tu1 "$f" | tr '\n' ' '; echo; exit 0; fi
f=/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data
if [ -r "$f" ]; then printf 'vars '; od -An -tu1 "$f" | tr '\n' ' '; echo; exit 0; fi
echo unknown`

var platMokutilArgv = []string{"mokutil", "--sb-state"}

// platFIPSScript reads the kernel's FIPS switch.
const platFIPSScript = `if [ -r /proc/sys/crypto/fips_enabled ]; then printf 'fips %s\n' "$(cat /proc/sys/crypto/fips_enabled)"; else echo absent; fi`

// platP11Argv lists the PKCS#11 modules p11-kit loads. Its token lines
// (labels, serial numbers) are not kept.
var platP11Argv = []string{"p11-kit", "list-modules"}

type platLsblkDev struct {
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	FSType     *string        `json:"fstype"`
	MountPoint *string        `json:"mountpoint"`
	Children   []platLsblkDev `json:"children"`
}

func platStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// platCryptInfo is what is known of one crypt mapping.
type platCryptInfo struct {
	method  string
	cipher  string
	keyBits int
}

// platParseLsblk turns lsblk's tree into one record per mounted volume
// (swap included), with Encrypted true when a crypt mapping lies between it
// and the disk. Loop and optical devices are left out unless they hold a
// crypt mapping. A volume reached twice (LVM over two devices) is encrypted
// only if every path to it is. crypt names the crypt mappings met, by name,
// with the method the parent's filesystem type says.
func platParseLsblk(b []byte) (vols []VolumeEncryption, crypt map[string]string, err error) {
	var doc struct {
		BlockDevices []platLsblkDev `json:"blockdevices"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, errors.New("hostcrypto: unreadable lsblk answer")
	}
	crypt = map[string]string{}
	index := map[string]int{}
	var walk func(d platLsblkDev, parentFS string, under string, depth int)
	walk = func(d platLsblkDev, parentFS string, under string, depth int) {
		if depth > 16 {
			return
		}
		if d.Type == "crypt" {
			name := path.Base(d.Name)
			method := ""
			switch parentFS {
			case "crypto_LUKS":
				method = "luks"
			case "BitLocker":
				method = "bitlocker"
			}
			if _, ok := crypt[name]; !ok {
				crypt[name] = method
			}
			under = name
		}
		mp := platStr(d.MountPoint)
		if mp != "" && (under != "" || (d.Type != "loop" && d.Type != "rom")) {
			v := VolumeEncryption{Device: d.Name, MountPoint: mp}
			if under != "" {
				v.Encrypted = platBoolPtr(true)
				v.Method = under // resolved to the method by the caller
			} else {
				v.Encrypted = platBoolPtr(false)
			}
			if i, ok := index[d.Name+"\x00"+mp]; ok {
				if !*v.Encrypted {
					vols[i].Encrypted = platBoolPtr(false)
					vols[i].Method = ""
				}
			} else {
				index[d.Name+"\x00"+mp] = len(vols)
				vols = append(vols, v)
			}
		}
		for _, ch := range d.Children {
			walk(ch, platStr(d.FSType), under, depth+1)
		}
	}
	for _, d := range doc.BlockDevices {
		walk(d, "", "", 0)
	}
	return vols, crypt, nil
}

// platParseDMKinds parses platDMScript: crypt mapping name to method.
func platParseDMKinds(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		var m string
		switch f[0] {
		case "CRYPT-LUKS1":
			m = "luks1"
		case "CRYPT-LUKS2":
			m = "luks2"
		case "CRYPT-PLAIN":
			m = "dm-crypt-plain"
		case "CRYPT-BITLK":
			m = "bitlocker"
		case "CRYPT-TCRYPT":
			m = "tcrypt"
		default:
			continue
		}
		out[f[1]] = m
	}
	return out
}

// platParseCryptsetupStatus keeps three fields of `cryptsetup status`:
// type, cipher and key size. Every other line is dropped.
func platParseCryptsetupStatus(b []byte) (platCryptInfo, bool) {
	var info platCryptInfo
	ok := false
	for _, line := range strings.Split(string(b), "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "type":
			switch strings.ToUpper(v) {
			case "LUKS1":
				info.method = "luks1"
			case "LUKS2":
				info.method = "luks2"
			case "PLAIN":
				info.method = "dm-crypt-plain"
			case "BITLK":
				info.method = "bitlocker"
			case "TCRYPT":
				info.method = "tcrypt"
			}
			ok = true
		case "cipher":
			if platCipherRE.MatchString(v) {
				info.cipher = v
				ok = true
			}
		case "keysize":
			f := strings.Fields(v)
			if len(f) >= 1 {
				if n, err := strconv.Atoi(f[0]); err == nil && n > 0 && n <= 4096 {
					info.keyBits = n
					ok = true
				}
			}
		}
	}
	return info, ok
}

// platCipherRE is what a cipher specification looks like: names and dashes,
// short. Anything else is not kept.
var platCipherRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9:]+){0,4}$`)

var platCryptNameRE = regexp.MustCompile(`^[A-Za-z0-9_.+:@-]{1,128}$`)

// platParseLinuxTPM parses platTPMScript.
func platParseLinuxTPM(b []byte) *TPM {
	t := &TPM{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "dev":
			t.Present = true
		case "major":
			switch strings.TrimSpace(v) {
			case "2":
				if t.Version == "" {
					t.Version = "2.0"
				}
			case "1":
				if t.Version == "" {
					t.Version = "1.2"
				}
			}
		case "enabled":
			switch strings.TrimSpace(v) {
			case "1":
				t.Enabled = platBoolPtr(true)
			case "0":
				t.Enabled = platBoolPtr(false)
			}
		case "caps":
			name, val, _ := strings.Cut(v, ":")
			val = strings.TrimSpace(val)
			switch name {
			case "Manufacturer":
				t.Manufacturer = platTPMVendor(val)
			case "TCG version":
				if val == "1.2" || val == "1.1" {
					t.Version = val
				}
			}
		}
	}
	return t
}

// platTPMVendor turns a TPM 1.2 manufacturer id ("0x49465800") into its
// four ASCII letters ("IFX"); anything else is kept only when it is short
// printable text.
func platTPMVendor(v string) string {
	if strings.HasPrefix(v, "0x") && len(v) == 10 {
		if n, err := strconv.ParseUint(v[2:], 16, 32); err == nil {
			var s []byte
			for i := 3; i >= 0; i-- {
				ch := byte(n >> (8 * i))
				if ch >= 0x20 && ch < 0x7f {
					s = append(s, ch)
				}
			}
			return strings.TrimSpace(string(s))
		}
	}
	if len(v) <= 32 && platPrintable(v) {
		return v
	}
	return ""
}

func platPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// platParseLinuxSecureBoot parses platSecureBootScript. ok is false when
// the answer was "unknown" (efivars not mounted).
func platParseLinuxSecureBoot(b []byte) (on bool, ok bool) {
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return false, false
	}
	switch f[0] {
	case "legacy":
		// Booted without UEFI: there is no Secure Boot.
		return false, true
	case "efivar", "vars":
		if len(f) < 2 {
			return false, false
		}
		last, err := strconv.Atoi(f[len(f)-1])
		if err != nil {
			return false, false
		}
		return last == 1, true
	}
	return false, false
}

// platParseMokutil parses `mokutil --sb-state`.
func platParseMokutil(b []byte) (on bool, ok bool) {
	s := strings.ToLower(string(b))
	switch {
	case strings.Contains(s, "secureboot enabled"):
		return true, true
	case strings.Contains(s, "secureboot disabled"):
		return false, true
	case strings.Contains(s, "not supported"):
		return false, true
	}
	return false, false
}

// platParseLinuxFIPS parses platFIPSScript. An absent switch is a kernel
// built without FIPS support: FIPS mode is off.
func platParseLinuxFIPS(b []byte) (on bool, ok bool) {
	f := strings.Fields(string(b))
	switch {
	case len(f) == 1 && f[0] == "absent":
		return false, true
	case len(f) == 2 && f[0] == "fips":
		switch f[1] {
		case "0":
			return false, true
		case "1":
			return true, true
		}
	}
	return false, false
}

// platParseP11Kit keeps each module's name and path from `p11-kit
// list-modules`; the token lines beneath them (labels, serial numbers) are
// not kept.
func platParseP11Kit(b []byte) []Token {
	var toks []Token
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "module: ") {
			toks = append(toks, Token{Name: platCap(strings.TrimSpace(strings.TrimPrefix(line, "module: ")), 128)})
			continue
		}
		if len(toks) > 0 && strings.HasPrefix(line, "    path: ") && !strings.HasPrefix(line, "     ") {
			p := strings.TrimSpace(strings.TrimPrefix(line, "    path: "))
			if strings.HasPrefix(p, "/") && len(p) <= 4096 {
				toks[len(toks)-1].Path = p
			}
		}
	}
	return toks
}

// platLinuxProtection runs the Linux protection steps.
func platLinuxProtection(ctx context.Context, c *collection) {
	var p platProtection
	p.volumes = platLinuxVolumes(ctx, c)

	// TPM.
	if out, stderr, exit, err := platRun(ctx, c.target, platSh(platTPMScript)); err == nil && exit == 0 {
		p.tpm = platParseLinuxTPM(out)
		c.mark(SectionTPM, SectionOK)
	} else {
		if err == nil {
			err = platStderr("tpm", stderr, exit)
		}
		platOutcome(c, SectionTPM, err)
	}

	// Secure Boot.
	var sbErr error
	out, stderr, exit, err := platRun(ctx, c.target, platSh(platSecureBootScript))
	on, ok := false, false
	if err == nil && exit == 0 {
		on, ok = platParseLinuxSecureBoot(out)
	}
	if !ok {
		mout, mstderr, mexit, merr := platRun(ctx, c.target, platMokutilArgv)
		if merr == nil {
			on, ok = platParseMokutil(append(mout, mstderr...))
			if !ok {
				sbErr = platStderr("mokutil", mstderr, mexit)
			}
		} else if err != nil {
			sbErr = err
		} else {
			sbErr = fmt.Errorf("secure boot: the EFI variable is not readable and %w", merr)
			if exit != 0 {
				sbErr = platStderr("secure boot", stderr, exit)
			}
		}
	}
	if ok {
		p.secureBoot = platBoolPtr(on)
		c.mark(SectionSecureBoot, SectionOK)
	} else {
		c.partial(SectionSecureBoot, sbErr)
	}

	// FIPS.
	if out, _, exit, err := platRun(ctx, c.target, platSh(platFIPSScript)); err == nil && exit == 0 {
		if on, ok := platParseLinuxFIPS(out); ok {
			p.fips = platBoolPtr(on)
		} else {
			c.note(platStepFIPS, errors.New("unreadable FIPS switch"))
		}
	} else if err != nil {
		c.note(platStepFIPS, err)
	}

	// Tokens.
	if out, stderr, exit, err := platRun(ctx, c.target, platP11Argv); err == nil && exit == 0 {
		p.tokens = platParseP11Kit(out)
		c.mark(SectionTokens, SectionOK)
	} else {
		if err == nil {
			err = platStderr("p11-kit", stderr, exit)
		}
		platOutcome(c, SectionTokens, err)
	}
	p.apply(c)
}

// platLinuxVolumes reads lsblk, the crypt mapping kinds and each crypt
// mapping's status, and marks SectionDiskEncryption.
func platLinuxVolumes(ctx context.Context, c *collection) []VolumeEncryption {
	out, stderr, exit, err := platRun(ctx, c.target, platLsblkArgv)
	if err == nil && exit != 0 {
		err = platStderr("lsblk", stderr, exit)
	}
	if err != nil {
		platOutcome(c, SectionDiskEncryption, err)
		return nil
	}
	vols, crypt, err := platParseLsblk(out)
	if err != nil {
		c.fail(SectionDiskEncryption, err)
		return nil
	}
	if len(crypt) == 0 {
		c.mark(SectionDiskEncryption, SectionOK)
		return vols
	}
	kinds := map[string]string{}
	if dout, _, dexit, derr := platRun(ctx, c.target, platSh(platDMScript)); derr == nil && dexit == 0 {
		kinds = platParseDMKinds(dout)
	}
	names := make([]string, 0, len(crypt))
	for n := range crypt {
		names = append(names, n)
	}
	sort.Strings(names)
	infos := map[string]platCryptInfo{}
	var reason error
	for i, n := range names {
		info := platCryptInfo{method: kinds[n]}
		if info.method == "" {
			info.method = crypt[n]
		}
		if i >= 64 || !platCryptNameRE.MatchString(n) {
			infos[n] = info
			continue
		}
		sout, sstderr, sexit, serr := platRun(ctx, c.target, platCryptsetupArgv(n))
		switch {
		case serr != nil:
			reason = fmt.Errorf("crypt volumes: cipher not read: %w", serr)
		case sexit != 0:
			reason = platStderr("cryptsetup status", sstderr, sexit)
			if !platIsElevated(c) {
				reason = fmt.Errorf("crypt volumes: cipher not read: %w (cryptsetup needs root)", ErrPermission)
			}
		default:
			if st, ok := platParseCryptsetupStatus(sout); ok {
				if st.method != "" {
					info.method = st.method
				}
				info.cipher, info.keyBits = st.cipher, st.keyBits
			}
		}
		infos[n] = info
	}
	for i := range vols {
		if vols[i].Encrypted != nil && *vols[i].Encrypted {
			info := infos[vols[i].Method]
			vols[i].Method, vols[i].Cipher, vols[i].KeySizeBits = info.method, info.cipher, info.keyBits
		}
	}
	if reason != nil {
		c.partial(SectionDiskEncryption, reason)
	} else {
		c.mark(SectionDiskEncryption, SectionOK)
	}
	return vols
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

var (
	platDiskutilArgv      = []string{"diskutil", "apfs", "list", "-plist"}
	platMountArgv         = []string{"mount"}
	platFdesetupArgv      = []string{"fdesetup", "status"}
	platArm64Argv         = []string{"sysctl", "-n", "hw.optional.arm64"}
	platIBridgeArgv       = []string{"system_profiler", "SPiBridgeDataType"}
	platCTKTokensArgv     = []string{"pluginkit", "-m", "-p", "com.apple.ctk-tokens"}
	platDarwinMountLineRE = regexp.MustCompile(`^/dev/(disk[0-9]+s[0-9]+(?:s[0-9]+)?) on (/.*) \(`)
)

// platPlist decodes an XML property list into Go values: map[string]any,
// []any, string, int64, bool. Data, dates and reals decode as strings.
func platPlist(b []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, errors.New("hostcrypto: unreadable property list")
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "plist" {
			for {
				tok, err := d.Token()
				if err != nil {
					return nil, errors.New("hostcrypto: unreadable property list")
				}
				if se, ok := tok.(xml.StartElement); ok {
					return platPlistValue(d, se, 0)
				}
			}
		}
	}
}

func platPlistValue(d *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("hostcrypto: property list too deep")
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		key := ""
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					var k string
					if err := d.DecodeElement(&k, &t); err != nil {
						return nil, err
					}
					key = k
					continue
				}
				v, err := platPlistValue(d, t, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		var a []any
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := platPlistValue(d, t, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			case xml.EndElement:
				return a, nil
			}
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	case "integer":
		var s string
		if err := d.DecodeElement(&s, &se); err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, err
		}
		return n, nil
	default:
		var s string
		if err := d.DecodeElement(&s, &se); err != nil {
			return nil, err
		}
		return s, nil
	}
}

func platMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func platArr(v any) []any {
	a, _ := v.([]any)
	return a
}

// platParseAPFSList turns `diskutil apfs list -plist` into one record per
// APFS volume: its device, whether APFS encrypts it, and whether that is
// FileVault. Names, UUIDs and sizes are not kept.
func platParseAPFSList(b []byte) ([]VolumeEncryption, error) {
	root, err := platPlist(b)
	if err != nil {
		return nil, err
	}
	var vols []VolumeEncryption
	for _, ct := range platArr(platMap(root)["Containers"]) {
		for _, vv := range platArr(platMap(ct)["Volumes"]) {
			v := platMap(vv)
			dev, _ := v["DeviceIdentifier"].(string)
			if !platDiskIDRE.MatchString(dev) {
				continue
			}
			rec := VolumeEncryption{Device: "/dev/" + dev}
			if enc, ok := v["Encryption"].(bool); ok {
				rec.Encrypted = platBoolPtr(enc)
				if enc {
					rec.Method = "apfs"
				}
			}
			if fv, ok := v["FileVault"].(bool); ok && fv {
				rec.Method = "filevault"
			}
			if locked, ok := v["Locked"].(bool); ok && locked {
				rec.Status = "Locked"
			}
			vols = append(vols, rec)
		}
	}
	return vols, nil
}

var (
	platDiskIDRE         = regexp.MustCompile(`^disk[0-9]+s[0-9]+$`)
	platDarwinSnapshotRE = regexp.MustCompile(`^(disk[0-9]+s[0-9]+)s[0-9]+$`)
)

// platParseDarwinMounts maps a volume device ("disk3s5") to its mount
// point from `mount`. A snapshot's device ("disk3s1s1") counts for its
// volume.
func platParseDarwinMounts(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		m := platDarwinMountLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		dev := m[1]
		if v := platDarwinSnapshotRE.FindStringSubmatch(dev); v != nil {
			dev = v[1]
		}
		if _, ok := out[dev]; !ok {
			out[dev] = m[2]
		}
	}
	return out
}

// platParseFdesetup reads `fdesetup status` into a status word: "On",
// "Off", "EncryptionInProgress", "DecryptionInProgress", or "".
func platParseFdesetup(b []byte) string {
	s := string(b)
	switch {
	case strings.Contains(s, "Encryption in progress"):
		return "EncryptionInProgress"
	case strings.Contains(s, "Decryption in progress"):
		return "DecryptionInProgress"
	case strings.Contains(s, "FileVault is On"):
		return "On"
	case strings.Contains(s, "FileVault is Off"):
		return "Off"
	}
	return ""
}

// platParseIBridge reads `system_profiler SPiBridgeDataType`: whether the
// controller is a T2, and its Secure Boot policy. The model identifier,
// firmware version and boot UUID are not kept.
func platParseIBridge(b []byte) (t2 bool, controller bool, secureBoot *bool) {
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Controller":
			controller = true
		case "Model Name":
			if strings.Contains(v, "T2") {
				t2 = true
				controller = true
			}
		case "Secure Boot":
			controller = true
			switch {
			case strings.HasPrefix(v, "Full Security"), strings.HasPrefix(v, "Medium Security"), strings.HasPrefix(v, "Reduced Security"):
				secureBoot = platBoolPtr(true)
			case strings.HasPrefix(v, "Permissive Security"), strings.HasPrefix(v, "No Security"):
				secureBoot = platBoolPtr(false)
			}
		}
	}
	return t2, controller, secureBoot
}

var platCTKRE = regexp.MustCompile(`^\s*[+\-!=?]?\s*([A-Za-z0-9][A-Za-z0-9.\-]{0,127})\(`)

// platParseCTKTokens keeps the bundle identifiers of the CryptoTokenKit
// token drivers `pluginkit` lists.
func platParseCTKTokens(b []byte) []Token {
	var toks []Token
	for _, line := range strings.Split(string(b), "\n") {
		if m := platCTKRE.FindStringSubmatch(line); m != nil {
			toks = append(toks, Token{Name: m[1]})
		}
	}
	return toks
}

// platDarwinProtection runs the macOS protection steps.
func platDarwinProtection(ctx context.Context, c *collection) {
	var p platProtection

	out, stderr, exit, err := platRun(ctx, c.target, platDiskutilArgv)
	if err == nil && exit != 0 {
		err = platStderr("diskutil", stderr, exit)
	}
	if err == nil {
		vols, perr := platParseAPFSList(out)
		if perr != nil {
			c.fail(SectionDiskEncryption, perr)
		} else {
			mounts := map[string]string{}
			if mout, _, mexit, merr := platRun(ctx, c.target, platMountArgv); merr == nil && mexit == 0 {
				mounts = platParseDarwinMounts(mout)
			}
			fv := ""
			if fout, _, fexit, ferr := platRun(ctx, c.target, platFdesetupArgv); ferr == nil && fexit == 0 {
				fv = platParseFdesetup(fout)
			}
			for i := range vols {
				vols[i].MountPoint = mounts[strings.TrimPrefix(vols[i].Device, "/dev/")]
				if vols[i].Method == "filevault" && fv != "" && vols[i].Status == "" {
					vols[i].Status = fv
				}
			}
			p.volumes = vols
			c.mark(SectionDiskEncryption, SectionOK)
		}
	} else {
		platOutcome(c, SectionDiskEncryption, err)
	}

	// The Secure Enclave stands where a TPM stands elsewhere: Apple
	// silicon always has one, an Intel Mac has one with a T2 chip.
	arm := false
	if aout, _, aexit, aerr := platRun(ctx, c.target, platArm64Argv); aerr == nil && aexit == 0 {
		arm = strings.TrimSpace(string(aout)) == "1"
	}
	iout, istderr, iexit, ierr := platRun(ctx, c.target, platIBridgeArgv)
	if ierr == nil && iexit != 0 {
		ierr = platStderr("system_profiler", istderr, iexit)
	}
	if ierr != nil {
		platOutcome(c, SectionTPM, ierr)
		platOutcome(c, SectionSecureBoot, ierr)
	} else {
		t2, controller, sb := platParseIBridge(iout)
		switch {
		case arm:
			p.tpm = &TPM{Present: true, Manufacturer: "Apple", Version: "secure-enclave"}
		case t2:
			p.tpm = &TPM{Present: true, Manufacturer: "Apple", Version: "secure-enclave (T2)"}
		default:
			p.tpm = &TPM{Present: false}
		}
		c.mark(SectionTPM, SectionOK)
		switch {
		case sb != nil:
			p.secureBoot = sb
			c.mark(SectionSecureBoot, SectionOK)
		case !arm && !controller:
			// An Intel Mac without a T2 has no Secure Boot.
			p.secureBoot = platBoolPtr(false)
			c.mark(SectionSecureBoot, SectionOK)
		default:
			c.partial(SectionSecureBoot, errors.New("secure boot: the policy was not reported"))
		}
	}

	// macOS has no system-wide FIPS switch: FIPSMode stays nil.

	tout, tstderr, texit, terr := platRun(ctx, c.target, platCTKTokensArgv)
	if terr == nil && texit != 0 {
		terr = platStderr("pluginkit", tstderr, texit)
	}
	if terr == nil {
		p.tokens = platParseCTKTokens(tout)
	}
	platOutcome(c, SectionTokens, terr)
	p.apply(c)
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

// platPSProtection reads BitLocker (per volume: status, method, protection
// status and the protector TYPES; the protector objects carry recovery
// material, so only their KeyProtectorType is touched), the TPM (Get-Tpm,
// and Win32_Tpm for the specification version; the PnP device list when
// those are refused), Secure Boot (the State registry value anyone may
// read, then Confirm-SecureBootUEFI), the FIPS policy registry value and
// the registered smart-card types.
const platPSProtection = `$prBl = [pscustomobject]@{ Error = ''; Vols = @() }
try {
  $prVols = New-Object 'System.Collections.Generic.List[object]'
  foreach ($prV in @(Get-BitLockerVolume -ErrorAction Stop)) {
    $prKinds = New-Object 'System.Collections.Generic.List[string]'
    foreach ($prP in @($prV.KeyProtector)) { if ($null -ne $prP) { [void]$prKinds.Add([string]$prP.KeyProtectorType) } }
    [void]$prVols.Add([pscustomobject]@{ Mount = [string]$prV.MountPoint; Status = [string]$prV.VolumeStatus; Method = [string]$prV.EncryptionMethod; Prot = [string]$prV.ProtectionStatus; Kinds = $prKinds.ToArray() })
  }
  $prBl.Vols = $prVols.ToArray()
} catch { $prBl.Error = (plErr $_.Exception) }
$prTpm = [pscustomobject]@{ Error = ''; Present = $null; Enabled = $null; Maker = ''; Spec = ''; Pnp = @() }
try {
  $prT = Get-Tpm -ErrorAction Stop
  $prTpm.Present = [bool]$prT.TpmPresent
  if ($null -ne $prT.TpmEnabled) { $prTpm.Enabled = [bool]$prT.TpmEnabled }
  $prTpm.Maker = [string]$prT.ManufacturerIdTxt
} catch { $prTpm.Error = (plErr $_.Exception) }
try {
  foreach ($prW in @(Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop)) { $prTpm.Spec = [string]$prW.SpecVersion }
} catch { $prSpecErr = (plErr $_.Exception) }
$prPnp = New-Object 'System.Collections.Generic.List[string]'
try {
  foreach ($prD in @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='SecurityDevices'" -ErrorAction Stop)) { [void]$prPnp.Add([string]$prD.Name) }
} catch { $prPnpErr = (plErr $_.Exception) }
$prTpm.Pnp = $prPnp.ToArray()
$prSb = [pscustomobject]@{ Reg = $null; RegError = ''; Uefi = $null; UefiError = '' }
try {
  $prK = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop
  if ($null -ne $prK.UEFISecureBootEnabled) { $prSb.Reg = [int]$prK.UEFISecureBootEnabled }
} catch { $prSb.RegError = (plErr $_.Exception) }
try { $prSb.Uefi = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
catch { $prX = $_.Exception; $prSb.UefiError = (plErr $prX); if ($prX -is [System.PlatformNotSupportedException]) { $prSb.UefiError = 'legacy' } }
$prFips = [pscustomobject]@{ Value = $null; Error = '' }
try {
  $prF = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -ErrorAction Stop
  if ($null -ne $prF.Enabled) { $prFips.Value = [int]$prF.Enabled } else { $prFips.Value = 0 }
} catch { $prFips.Error = (plErr $_.Exception) }
$prCards = New-Object 'System.Collections.Generic.List[object]'
$prCardsErr = ''
try {
  foreach ($prC in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards' -ErrorAction Stop)) {
    $prDll = ''
    try { $prDll = [string]$prC.GetValue('80000001') } catch { $prDll = '' }
    if ($prCards.Count -lt 256) { [void]$prCards.Add([pscustomobject]@{ Name = [string]$prC.PSChildName; Dll = $prDll }) }
  }
} catch { $prCardsErr = (plErr $_.Exception) }
plOut ([pscustomobject]@{ Elevated = (plElevated); Bl = $prBl; Tpm = $prTpm; Sb = $prSb; Fips = $prFips; Cards = $prCards.ToArray(); CardsError = $prCardsErr })
`

type platWinProtAnswer struct {
	Elevated *bool `json:"Elevated"`
	Bl       struct {
		Error string          `json:"Error"`
		Vols  json.RawMessage `json:"Vols"`
	} `json:"Bl"`
	Tpm struct {
		Error   string          `json:"Error"`
		Present *bool           `json:"Present"`
		Enabled *bool           `json:"Enabled"`
		Maker   string          `json:"Maker"`
		Spec    string          `json:"Spec"`
		Pnp     json.RawMessage `json:"Pnp"`
	} `json:"Tpm"`
	Sb struct {
		Reg       *int   `json:"Reg"`
		RegError  string `json:"RegError"`
		Uefi      *bool  `json:"Uefi"`
		UefiError string `json:"UefiError"`
	} `json:"Sb"`
	Fips struct {
		Value *int   `json:"Value"`
		Error string `json:"Error"`
	} `json:"Fips"`
	Cards      json.RawMessage `json:"Cards"`
	CardsError string          `json:"CardsError"`
}

type platWinVol struct {
	Mount  string          `json:"Mount"`
	Status string          `json:"Status"`
	Method string          `json:"Method"`
	Prot   string          `json:"Prot"`
	Kinds  json.RawMessage `json:"Kinds"`
}

type platWinCard struct {
	Name string `json:"Name"`
	Dll  string `json:"Dll"`
}

// platWinProtResult is the parsed protection answer with each section's
// error (nil when it read in full).
type platWinProtResult struct {
	elevated                       *bool
	prot                           platProtection
	diskErr, tpmErr, sbErr, tokErr error
	fipsErr                        error
}

// platBitLockerMethods maps EncryptionMethod to a cipher and key size.
var platBitLockerMethods = map[string]struct {
	cipher string
	bits   int
}{
	"Aes128":         {"AES-CBC 128", 128},
	"Aes256":         {"AES-CBC 256", 256},
	"Aes128Diffuser": {"AES-CBC 128 with Diffuser", 128},
	"Aes256Diffuser": {"AES-CBC 256 with Diffuser", 256},
	"XtsAes128":      {"XTS-AES 128", 128},
	"XtsAes256":      {"XTS-AES 256", 256},
	"Hardware":       {"hardware", 0},
}

// platBitLockerProtectors maps KeyProtectorType to the Report's names.
var platBitLockerProtectors = map[string]string{
	"Tpm": "tpm", "TpmPin": "tpm+pin", "TpmStartupKey": "tpm+key_file", "TpmPinStartupKey": "tpm+pin+key_file",
	"RecoveryPassword": "recovery_key", "ExternalKey": "key_file", "Password": "passphrase",
	"AdAccountOrGroup": "ad_account", "PublicKey": "certificate", "TpmNetworkKey": "tpm+network_key",
}

var platWinMountRE = regexp.MustCompile(`^(?:[A-Za-z]:\\?|\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\)$`)

// platParseWindowsProtection parses platPSProtection's answer. Only named
// fields are decoded: a protector's recovery password or key package, were
// it ever in the answer, is not a field here and is dropped.
func platParseWindowsProtection(b []byte) (platWinProtResult, error) {
	var r platWinProtResult
	var ans platWinProtAnswer
	if err := json.Unmarshal(b, &ans); err != nil {
		return r, errors.New("hostcrypto: unreadable protection answer")
	}
	r.elevated = ans.Elevated
	notElevated := ans.Elevated != nil && !*ans.Elevated

	// BitLocker.
	if ans.Bl.Error != "" {
		if notElevated && ans.Bl.Error != "missing" {
			ans.Bl.Error = "denied"
		}
		r.diskErr = platPSError("BitLocker", ans.Bl.Error)
	} else {
		vols, err := psArray[platWinVol](ans.Bl.Vols)
		if err != nil {
			r.diskErr = errors.New("BitLocker: unreadable answer")
		}
		for _, v := range vols {
			if !platWinMountRE.MatchString(v.Mount) {
				continue
			}
			rec := VolumeEncryption{MountPoint: v.Mount, Status: platCap(v.Status, 64)}
			switch v.Status {
			case "FullyDecrypted":
				rec.Encrypted = platBoolPtr(false)
			case "":
			default:
				rec.Encrypted = platBoolPtr(true)
				rec.Method = "bitlocker"
			}
			if m, ok := platBitLockerMethods[v.Method]; ok {
				rec.Cipher, rec.KeySizeBits = m.cipher, m.bits
			}
			if v.Prot == "Off" && rec.Encrypted != nil && *rec.Encrypted {
				rec.Status += ", ProtectionOff"
			}
			kinds, _ := psArray[string](v.Kinds)
			for _, k := range kinds {
				if n, ok := platBitLockerProtectors[k]; ok {
					rec.Protectors = append(rec.Protectors, n)
				} else if k != "" {
					rec.Protectors = append(rec.Protectors, "unknown")
				}
			}
			rec.Protectors = unionStrings(nil, rec.Protectors)
			r.prot.volumes = append(r.prot.volumes, rec)
		}
	}

	// TPM.
	switch {
	case ans.Tpm.Error == "" && ans.Tpm.Present != nil:
		t := &TPM{Present: *ans.Tpm.Present, Enabled: ans.Tpm.Enabled, Manufacturer: platCap(strings.TrimSpace(ans.Tpm.Maker), 32)}
		t.Version = platTPMSpec(ans.Tpm.Spec)
		r.prot.tpm = t
	default:
		pnp, _ := psArray[string](ans.Tpm.Pnp)
		for _, n := range pnp {
			if strings.Contains(n, "Trusted Platform Module") {
				t := &TPM{Present: true}
				switch {
				case strings.Contains(n, "2.0"):
					t.Version = "2.0"
				case strings.Contains(n, "1.2"):
					t.Version = "1.2"
				}
				r.prot.tpm = t
				break
			}
		}
		word := ans.Tpm.Error
		if word == "" || notElevated {
			word = "denied"
		}
		r.tpmErr = platPSError("TPM", word)
	}

	// Secure Boot: the registry value first (no rights needed).
	switch {
	case ans.Sb.Reg != nil:
		r.prot.secureBoot = platBoolPtr(*ans.Sb.Reg == 1)
	case ans.Sb.UefiError == "legacy":
		r.prot.secureBoot = platBoolPtr(false)
	case ans.Sb.Uefi != nil && ans.Sb.UefiError == "":
		r.prot.secureBoot = ans.Sb.Uefi
	case ans.Sb.RegError == "not_found" && ans.Sb.UefiError == "denied":
		r.sbErr = platPSError("Secure Boot", "denied")
	default:
		r.sbErr = platPSError("Secure Boot", "other")
	}

	// FIPS: an absent policy key is the default, off.
	switch {
	case ans.Fips.Value != nil:
		r.prot.fips = platBoolPtr(*ans.Fips.Value != 0)
	case ans.Fips.Error == "not_found":
		r.prot.fips = platBoolPtr(false)
	default:
		r.fipsErr = platPSError("FIPS policy", ans.Fips.Error)
		if r.fipsErr == nil {
			r.fipsErr = errors.New("FIPS policy: could not be read")
		}
	}

	// Smart-card types.
	if ans.CardsError != "" && ans.CardsError != "not_found" {
		r.tokErr = platPSError("smart cards", ans.CardsError)
	} else {
		cards, _ := psArray[platWinCard](ans.Cards)
		for _, cd := range cards {
			if cd.Name == "" || !platPrintable(cd.Name) {
				continue
			}
			tok := Token{Name: platCap(cd.Name, 128), ConfiguredIn: `HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards`}
			if platPrintable(cd.Dll) && len(cd.Dll) <= 260 {
				tok.Path = cd.Dll
			}
			r.prot.tokens = append(r.prot.tokens, tok)
		}
	}
	return r, nil
}

// platTPMSpec takes the first item of Win32_Tpm's SpecVersion ("2.0, 0,
// 1.59").
func platTPMSpec(s string) string {
	first, _, _ := strings.Cut(s, ",")
	first = strings.TrimSpace(first)
	switch first {
	case "2.0", "1.2", "1.1":
		return first
	}
	return ""
}

// platWindowsProtection runs the Windows protection program.
func platWindowsProtection(ctx context.Context, c *collection) {
	b, err := platPS(ctx, c.target, platPSProtection, struct {
		V int `json:"V"`
	}{1})
	if err != nil {
		for _, s := range []string{SectionDiskEncryption, SectionTPM, SectionSecureBoot, SectionTokens} {
			c.fail(s, fmt.Errorf("protection: %w", err))
		}
		return
	}
	r, err := platParseWindowsProtection(b)
	if err != nil {
		for _, s := range []string{SectionDiskEncryption, SectionTPM, SectionSecureBoot, SectionTokens} {
			c.fail(s, err)
		}
		return
	}
	platSetElevated(c, r.elevated)
	platOutcome(c, SectionDiskEncryption, r.diskErr)
	platOutcome(c, SectionTPM, r.tpmErr)
	platOutcome(c, SectionSecureBoot, r.sbErr)
	platOutcome(c, SectionTokens, r.tokErr)
	if r.fipsErr != nil {
		c.note(platStepFIPS, r.fipsErr)
	}
	r.prot.apply(c)
}
