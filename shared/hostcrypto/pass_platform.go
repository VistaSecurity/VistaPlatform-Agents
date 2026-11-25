package hostcrypto

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

// The platform part of pass 1: what the operating system itself holds and
// provides, learned from the operating system's own commands rather than
// from files. Windows certificate stores and the keys behind them, macOS
// keychains (plat_stores.go); disk encryption, TPM, Secure Boot, FIPS mode and
// tokens (plat_protection.go); the cryptographic libraries (plat_libraries.go).
//
// Every fact here comes from a command run through [Target.Run] and a pure
// parser of its output, the shape of host inventory. The commands are the same
// in local and remote mode, and which set runs is chosen from the REPORT's
// platform, never from runtime.GOOS: a Linux agent collecting a Windows host
// runs the Windows set over SSH.
//
// # No command may print secret material
//
// Each command and each flag was chosen so that its output holds no private
// key, passphrase, PIN, recovery key or volume key, and each parser keeps
// only named fields, so a field the command adds in a later version is
// dropped. The words that would make one print secrets (an export, a key
// dump, a recovery password) are refused by platForbiddenWords, which a test
// runs over every script and argv in these files.

func init() { passes = append(passes, platPass) }

// platPass runs the platform part of pass 1.
func platPass(ctx context.Context, c *collection) {
	switch c.opts.Platform {
	case hostinventory.PlatformLinux:
		platElevatedUnix(ctx, c)
		platLinuxProtection(ctx, c)
		platLinuxLibraries(ctx, c)
		// Linux has no platform certificate store: its trust store is a
		// directory, which the known-locations table covers.
	case hostinventory.PlatformDarwin:
		platElevatedUnix(ctx, c)
		platDarwinKeychains(ctx, c)
		platDarwinProtection(ctx, c)
		platDarwinLibraries(ctx, c)
	case hostinventory.PlatformWindows:
		platWindowsStores(ctx, c)
		platWindowsProtection(ctx, c)
		platWindowsLibraries(ctx, c)
	}
}

// errPlatNoTool is a command the host does not have. A section whose only
// source it is says unsupported.
var errPlatNoTool = errors.New("hostcrypto: the command is not installed on the host")

// platSh is the argv of a fixed POSIX sh program with its arguments as
// positional parameters ($1...). Host data is only ever an argument, never
// program text, as in the remote Unix target.
func platSh(script string, args ...string) []string {
	return append([]string{"env", "LC_ALL=C", "sh", "-c", script, "sh"}, args...)
}

// platRun runs argv and returns its stdout, stderr and exit status. A
// program that does not exist is errPlatNoTool, however the transport says
// so: a local exec error, or the shell's 127.
func platRun(ctx context.Context, t Target, argv []string) ([]byte, []byte, int, error) {
	out, stderr, exit, err := t.Run(ctx, argv)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "executable file not found") {
			return nil, nil, -1, errPlatNoTool
		}
		return out, stderr, exit, err
	}
	if exit == 127 {
		return out, stderr, exit, errPlatNoTool
	}
	return out, stderr, exit, nil
}

// platStderr is a bounded one-line reason from a command's stderr, for a
// StepError. Commands here print no secret to stderr; it is still cut short,
// because a reason needs one line.
func platStderr(name string, stderr []byte, exit int) error {
	msg := strings.TrimSpace(string(stderr))
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 160 {
		msg = msg[:160]
	}
	if msg == "" {
		return fmt.Errorf("%s exited %d", name, exit)
	}
	return fmt.Errorf("%s exited %d: %s", name, exit, msg)
}

// platRunner is the runner a PowerShell program goes through: the target
// itself when it takes stdin, else the runner beneath a Windows or local
// target, which does.
func platRunner(t Target) hostinventory.Runner {
	if _, ok := t.(hostinventory.InputRunner); ok {
		return t
	}
	switch v := t.(type) {
	case *RemoteWindowsTarget:
		return v.runner
	case *LocalTarget:
		return v.runner
	}
	return t
}

// platPS runs one of this file set's PowerShell programs (platPSPrelude +
// script) with args and returns its JSON answer. It goes the way the
// Windows target sends its own programs: on stdin when the runner takes
// stdin, else as -EncodedCommand, with the same answer encoding (psDecode).
func platPS(ctx context.Context, t Target, script string, args any) ([]byte, error) {
	rt := &RemoteWindowsTarget{runner: platRunner(t)}
	return rt.psJSON(ctx, platPSPrelude+script, args)
}

// platPSPrelude decodes the arguments and defines the three helpers every
// program here uses: plOut writes the one answer, plErr names an exception
// ("not_found", "denied", "missing" for a command the host lacks, "other"),
// plElevated says whether the account holds an elevated administrator
// token. It follows target_remote_win.go's rules: per-function variable
// prefixes, no automatic variable assigned, case-sensitive comparisons.
const platPSPrelude = `$ErrorActionPreference='Stop'
$a = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($vistaArgs)) | ConvertFrom-Json
function plOut($poX) { [Console]::Out.Write('J:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Compress -Depth 6 -InputObject $poX)))) }
function plErr($peX) {
  while ($peX -is [System.Management.Automation.MethodInvocationException] -and $peX.InnerException) { $peX = $peX.InnerException }
  if ($peX -is [System.Management.Automation.CommandNotFoundException]) { return 'missing' }
  if ($peX -is [System.Management.Automation.ItemNotFoundException] -or $peX -is [System.IO.FileNotFoundException] -or $peX -is [System.IO.DirectoryNotFoundException]) { return 'not_found' }
  if ($peX -is [System.UnauthorizedAccessException] -or $peX -is [System.Security.SecurityException]) { return 'denied' }
  $peH = 0
  try { $peH = [int]$peX.HResult } catch { $peH = 0 }
  if ($peH -eq -2147024891) { return 'denied' }
  try { if ([string]$peX.GetType().Name -ceq 'CimException' -and [int]$peX.NativeErrorCode -eq 2) { return 'denied' } } catch { $peH = 0 }
  return 'other'
}
function plElevated() {
  try {
    $pvI = [Security.Principal.WindowsIdentity]::GetCurrent()
    return [bool](New-Object Security.Principal.WindowsPrincipal($pvI)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $null }
}
`

// platPSError turns an answer's error word into an error for a step.
func platPSError(what, word string) error {
	switch word {
	case "":
		return nil
	case "denied":
		return fmt.Errorf("%s: %w (needs an elevated administrator)", what, ErrPermission)
	case "missing":
		return fmt.Errorf("%s: %w", what, errPlatNoTool)
	case "not_found":
		return fmt.Errorf("%s: %w", what, ErrNotExist)
	}
	return fmt.Errorf("%s: could not be read", what)
}

// platSetElevated records Access.Elevated once, from whichever command
// first learned it.
func platSetElevated(c *collection, v *bool) {
	if v == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.report.Access.Elevated == nil {
		b := *v
		c.report.Access.Elevated = &b
	}
}

// platElevated reads Access.Elevated: nil when it is not known.
func platElevated(c *collection) *bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.report.Access.Elevated
}

// platIsElevated is Access.Elevated, false when unknown.
func platIsElevated(c *collection) bool {
	e := platElevated(c)
	return e != nil && *e
}

// platElevatedUnix learns whether the collector runs as root from `id -u`.
func platElevatedUnix(ctx context.Context, c *collection) {
	out, _, exit, err := platRun(ctx, c.target, []string{"id", "-u"})
	if err != nil || exit != 0 {
		return
	}
	v := strings.TrimSpace(string(out)) == "0"
	platSetElevated(c, &v)
}

// platBoolPtr returns a pointer to b.
func platBoolPtr(b bool) *bool { return &b }

// platForbiddenWords are what no command or program in the platform files
// may contain, because each makes a tool print secret material or prompt:
// exports of keys and certificates with keys, key dumps, BitLocker recovery
// material, keychain secrets. platForbidden is the check; the tests run it
// over every script and argv the platform files send, and show it fires.
var platForbiddenWords = []string{
	// Windows: key export and recovery material.
	".Export(", ".ExportParameters", ".ExportCspBlob", ".ExportPkcs8", ".ExportRSA", ".ExportEC", ".ExportSubjectPublic",
	"ToXmlString", "Export-PfxCertificate", "Export-Certificate", "RecoveryPassword", "KeyPackage", "manage-bde",
	"BackupToAAD", "Backup-BitLocker", "UniqueName", "KeyContainerName", "Get-BitLockerVolumeKey",
	// Linux: volume keys and key slots.
	"--dump-master-key", "--dump-volume-key", "luksDump", "dmsetup", "showkeys", "/proc/keys",
	// macOS: keychain secrets, exports and anything that prompts.
	"find-generic-password", "find-internet-password", "dump-keychain", "export", "unlock-keychain", " -g ", " -w ",
	// Never the environment.
	"/environ", "printenv", "Get-ChildItem Env:", "$env:",
}

// platForbidden returns the first forbidden word in s, or "".
func platForbidden(s string) string {
	for _, w := range platForbiddenWords {
		if strings.Contains(s, w) {
			return w
		}
	}
	return ""
}
