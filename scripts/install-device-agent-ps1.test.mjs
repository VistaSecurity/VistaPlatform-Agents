// scripts/install-device-agent.ps1: the entry checks, run for real under
// PowerShell 7 without installing anything (pwsh is on GitHub's Linux
// runners; the run tests skip without it), and the guards on how it installs
// and enrolls, read from the script.
//
// What the config it writes does once it reaches the agent is tested in Go,
// through pwsh: cmd/device-agent/installer_config_ps1_test.go.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const installer = fileURLToPath(new URL('./install-device-agent.ps1', import.meta.url));
const pwsh = spawnSync('pwsh', ['-NoProfile', '-Command', 'exit 0']).status === 0 ? 'pwsh' : null;
const needsPwsh = { skip: !pwsh && 'pwsh not available' };

// A stand-in binary: answers -version like the agent, fails anything else.
const works = '#!/bin/sh\n[ "$1" = -version ] || exit 90\necho "Vista Platform Device Agent v9.9.9"\n';

function run(t, { binary = works, name = 'device-agent.exe', args = [], env = {}, input = '' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'device-agent-ps1-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  copyFileSync(installer, join(dir, 'install-device-agent.ps1'));
  if (binary !== null) writeFileSync(join(dir, name), binary, { mode: 0o755 });
  const cleanEnv = { ...process.env, ...env };
  if (!('VISTA_REGISTRATION_KEY' in env)) delete cleanEnv.VISTA_REGISTRATION_KEY;
  const r = spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-File', join(dir, 'install-device-agent.ps1'), ...args],
    { cwd: dir, encoding: 'utf8', timeout: 30000, input, env: cleanEnv });
  assert.ifError(r.error);
  return { ...r, output: r.stdout + r.stderr };
}

test('check mode needs neither Administrator nor a key and only asks for the version', needsPwsh, t => {
  const r = run(t, { args: ['-CheckDependencies'] });
  assert.equal(r.status, 0, r.output);
  assert.match(r.output, /v9\.9\.9 runs on this host/);
});

test('the release file name is accepted as downloaded', needsPwsh, t => {
  const r = run(t, { name: 'vista-device-agent_9.9.9_windows_amd64.exe', args: ['-CheckDependencies'] });
  assert.equal(r.status, 0, r.output);
});

test('a missing binary names both file names it looks for', needsPwsh, t => {
  const r = run(t, { binary: null, args: ['-CheckDependencies'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /device-agent\.exe/);
  assert.match(r.output, /vista-device-agent_\*_windows_\*\.exe/);
});

test('a binary that cannot run stops before anything changes', needsPwsh, t => {
  const r = run(t, { binary: '#!/bin/sh\nexit 3\n', args: ['-Url', 'https://p.example', '-Key', 'REG-x'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /cannot run on this host/);
  assert.doesNotMatch(r.output, /Administrator|Installing/);
});

test('url and key are required', needsPwsh, t => {
  const r = run(t, { args: ['-Key', 'REG-x'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /-Url and a registration key are required/);
});

for (const [how, opts] of [
  ['the environment', { env: { VISTA_REGISTRATION_KEY: 'REG-from-env' } }],
  ['standard input', { args: ['-KeyStdin'], input: 'REG-from-stdin\n' }],
]) {
  test(`a key from ${how} satisfies the key requirement`, needsPwsh, t => {
    const r = run(t, { ...opts, args: ['-Url', 'https://p.example', ...(opts.args || [])] });
    // It goes on to the Administrator check, which fails off Windows.
    assert.doesNotMatch(r.output, /registration key are required/, r.output);
  });
}

test('a malformed CA fingerprint is refused before anything changes', needsPwsh, t => {
  const r = run(t, { args: ['-Url', 'https://p.example', '-Key', 'REG-x', '-CaFingerprint', 'abc'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /-CaFingerprint must be a SHA-256 fingerprint/);
});

// Comments explain the history and may name what is forbidden; only code counts.
const raw = readFileSync(installer, 'utf8');
const code = raw.replace(/<#[\s\S]*?#>/g, '').split('\n').filter(l => !l.trimStart().startsWith('#')).join('\n');

test('the installer leaves enrollment to the agent', () => {
  assert.doesNotMatch(code, /agents\/register/, 'installer calls the register endpoint itself');
  assert.doesNotMatch(code, /-register\b/, 'installer runs the agent with -register');
  assert.match(code, /\[0-9a-fA-F\]\{8\}-\[0-9a-fA-F\]\{4\}/, 'no UUID check on the enrolled agent_id');
  assert.match(code, /-interactive=false/, 'the service would wait at a prompt');
});

test('the config is readable by Administrators and SYSTEM only, before it is written', () => {
  const acl = code.indexOf('/inheritance:r');
  assert.ok(acl > 0, 'the install directory keeps the inherited Program Files ACL (Users can read)');
  assert.match(code, /"\*S-1-5-18:\(OI\)\(CI\)F" "\*S-1-5-32-544:\(OI\)\(CI\)F"/, 'not SYSTEM and Administrators by SID');
  for (const write of ['WriteAllText', 'Copy-Item']) {
    assert.ok(code.indexOf(write) > acl, `${write} runs before the directory is protected`);
  }
  assert.match(code, /\/reset \/T/, 'files an earlier install left keep their old ACL');
});

test('the service starts on boot, restarts on failure and passes the CA fingerprint', () => {
  assert.match(code, /-StartupType Automatic/);
  assert.match(code, /sc\.exe failure \$ServiceName reset= 86400 actions= restart/);
  // The agent honours a console restart with a failure exit code
  // (shared/agentservice ExitRestart); the SCM acts on it only with this flag.
  assert.match(code, /sc\.exe failureflag \$ServiceName 1/);
  assert.match(code, /\$binPath \+= " -ca-fingerprint \$CaFingerprint"/);
  assert.match(code, /\$ServiceName = "VistaDeviceAgent"/);
  assert.match(code, /\$env:ProgramFiles\\VistaDeviceAgent/);
});

test('a rejected key stops and disables the service; the key is never printed', () => {
  // The lines the agent prints (cmd/device-agent/enrollment.go).
  const enrollment = readFileSync(new URL('../cmd/device-agent/enrollment.go', import.meta.url), 'utf8');
  for (const line of ['Registration was REJECTED', 'cannot store its enrollment']) {
    assert.ok(enrollment.includes(line), `the agent no longer prints "${line}"`);
    assert.ok(code.includes(line), `the installer does not look for "${line}"`);
  }
  assert.ok(code.indexOf('-StartupType Disabled') > 0, 'a rejected key leaves the service restarting');
  assert.match(code, /try \{\s*Start-Service -Name \$ServiceName\s*\} catch/, 'Start-Service is not guarded');
  const unmasked = code.replace(/\$Key\.Substring\(\$Key\.Length - 4\)/g, '');
  assert.doesNotMatch(unmasked, /Write-(Info|Warn|Err|Host)[^\n]*\$Key\b/, 'the key is printed in full');
});

test('install-device-agent.ps1 is pure ASCII without a BOM', () => {
  // Windows PowerShell 5.1 reads a BOM-less file in the ANSI code page; a
  // UTF-8 dash in a string unbalances its quotes.
  assert.doesNotMatch(raw, /^﻿/);
  const offenders = raw.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => /[^\x00-\x7F]/.test(l));
  assert.deepEqual(offenders, []);
});

// --- Reconfiguring an existing service --------------------------------------
// Under Windows PowerShell 5.1, `sc.exe config <name> binPath= "<quoted path>"`
// printed its usage text and changed nothing (exit 1639, output discarded), so
// a re-run never re-enabled a service the installer had disabled and a new
// command line never reached an existing service. PowerShell 7, which these
// tests run, passes the quotes intact, so the bug itself cannot be reproduced
// here: what is tested is that the installer reads the service back and fails
// when the change did not take, which a no-op cannot pass.
const serviceRegion = raw.slice(raw.indexOf('#region service-config'), raw.indexOf('#endregion service-config'));

// Runs Set-ServiceStartup against a stand-in Win32_Service whose Change
// behaves as `change` says, starting Disabled with an old command line.
function setServiceStartup(change) {
  const script = `${serviceRegion}
$state = @{ PathName = 'C:\\old.exe'; StartMode = 'Disabled' }
$get = { param($n) if ($n -eq 'Svc') { [pscustomobject]$state } }
$change = {
  param($svc, $path)
  switch ($env:CHANGE) {
    'works'  { $state.PathName = $path; $state.StartMode = 'Auto'; 0 }
    'noop'   { 0 }
    'path'   { $state.PathName = $path; 0 }
    'denied' { 2 }
  }
}
try { Set-ServiceStartup 'Svc' $env:WANT -Get $get -Change $change; "OK $($state.PathName) $($state.StartMode)" }
catch { "ERROR: " + $_.Exception.Message }`;
  const want = '"C:\\Program Files\\Vista Agent\\agent.exe" -config "C:\\Program Files\\Vista Agent\\a b.yaml" -ca-fingerprint ab';
  const r = spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-Command', script],
    { encoding: 'utf8', env: { ...process.env, CHANGE: change, WANT: want } });
  return { out: (r.stdout + r.stderr).trim(), want };
}

test('reconfiguring a service sets its command line and start mode and reads them back', needsPwsh, () => {
  const { out, want } = setServiceStartup('works');
  assert.equal(out, `OK ${want} Auto`);
});

test('a reconfigure that changes nothing fails loudly', needsPwsh, () => {
  assert.match(setServiceStartup('noop').out, /^ERROR: Service Svc was not reconfigured/);
  assert.match(setServiceStartup('path').out, /^ERROR: Service Svc was not reconfigured/, 'a service left Disabled passed');
  assert.match(setServiceStartup('denied').out, /^ERROR: Could not reconfigure service Svc: Win32_Service.Change returned 2/);
});

test('both the new and the existing service go through the checked reconfigure', () => {
  assert.doesNotMatch(code, /sc(\.exe)?\s+config\b/, 'sc.exe config is back: Windows PowerShell 5.1 mangles its quoted binPath');
  const set = code.indexOf('Set-ServiceStartup $ServiceName $binPath');
  assert.ok(set > code.indexOf('New-Service'), 'a new service is not read back');
  assert.ok(set > code.indexOf('Service already exists'), 'an existing service is not reconfigured through Set-ServiceStartup');
  assert.ok(set < code.indexOf('Start-Service'), 'the service starts before it is reconfigured');
});

// A native command that changes the host must have its exit status checked
// on the next line: its output is discarded, so nothing else would show it
// did nothing.
test('no state-changing native command has its exit status ignored', () => {
  const lines = code.split('\n');
  const unchecked = [];
  lines.forEach((line, i) => {
    if (/^\s*(&\s*)?(sc|icacls)(\.exe)?\s/i.test(line) && !/^\s*if \(\$LASTEXITCODE -ne 0\)/.test(lines[i + 1] || '')) {
      unchecked.push(line.trim());
    }
  });
  assert.deepEqual(unchecked, []);
  assert.ok(lines.filter((l) => /^\s*(&\s*)?(sc|icacls)(\.exe)?\s/i.test(l)).length >= 3, 'the guard matches nothing');
});

// --- No default platform, keyless upgrade, -Uninstall ------------------------

const region = (name) => {
  const start = raw.indexOf(`#region ${name}`);
  const end = raw.indexOf(`#endregion ${name}`);
  assert.ok(start >= 0 && end > start, `no #region ${name}`);
  return raw.slice(start, end);
};

test('a first install without -Url says the URL is the customer\'s own console', needsPwsh, t => {
  const r = run(t, { args: ['-Key', 'REG-x'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /-Url is the address of your own Vista Platform console, as shown in your browser/);
  assert.doesNotMatch(raw, /app\.vistasecurity\.io/);
});

function agentConfig(t, script, env = {}) {
  const r = spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-Command', `$ErrorActionPreference = 'Stop'\n${region('agent-config')}\n${script}`],
    { encoding: 'utf8', env: { ...process.env, ...env } });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
}

test('an enrolled host is recognised with no key, and the keep decision uses it', needsPwsh, t => {
  const dir = mkdtempSync(join(tmpdir(), 'device-agent-ps1-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const enrolled = join(dir, 'a.yaml');
  writeFileSync(enrolled, 'agent_id: "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59"\nplatform_url: "https://p.example"\nregistration_key_sha256: "00"\n');
  const pending = join(dir, 'b.yaml');
  writeFileSync(pending, "platform_url: 'https://p.example'\nregistration_key: 'REG-x'\n");
  assert.equal(agentConfig(t, 'Test-Enrolled $env:CFG', { CFG: enrolled }), 'True');
  assert.equal(agentConfig(t, 'Test-Enrolled $env:CFG', { CFG: pending }), 'False');
  assert.equal(agentConfig(t, 'Test-Enrolled $env:CFG', { CFG: join(dir, 'missing.yaml') }), 'False');
  assert.equal(agentConfig(t, "Get-ConfigValue $env:CFG 'platform_url'", { CFG: enrolled }), 'https://p.example');
  // The installer keeps an enrolled host's identity when it brings no key,
  // refuses a keyless run of a host that is not enrolled, and falls back to
  // the platform in the config.
  assert.match(code, /\$keepEnrollment = \(\$enrolled -and \[string\]::IsNullOrWhiteSpace\(\$Key\)\) -or \(Test-EnrolledWithKey \$ConfigPath \$Key\)/);
  assert.match(code, /if \(\[string\]::IsNullOrWhiteSpace\(\$Key\) -and -not \$enrolled\) \{/);
  assert.match(code, /if \(\[string\]::IsNullOrWhiteSpace\(\$Url\)\) \{ \$Url = Get-ConfigValue \$ConfigPath 'platform_url' \}/);
  assert.equal((code.match(/if \(-not \$keepEnrollment\) \{/g) || []).length, 2, 'the certificates or the config are replaced on a kept enrollment');
});

test('a CA fingerprint is normalised the way the agent compares it, and must be 64 hex digits', needsPwsh, t => {
  const hex = 'cd'.repeat(32);
  const conv = (v) => agentConfig(t, '$r = ConvertTo-CaFingerprint $env:FP; if ($null -eq $r) { "NULL" } else { $r }', { FP: v });
  assert.equal(conv(`sha256:${hex.toUpperCase().match(/../g).join(':')}`), hex);
  for (const bad of ['abc', `${hex}0`, 'g'.repeat(64)]) assert.equal(conv(bad), 'NULL', bad);
  assert.match(code, /\$normalized = ConvertTo-CaFingerprint \$CaFingerprint/);
});

function uninstall(t, { service = false, files = null } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'device-agent-ps1-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const installDir = join(dir, 'VistaDeviceAgent');
  if (files) {
    mkdirSync(join(installDir, 'data', 'certs'), { recursive: true });
    for (const f of files) writeFileSync(join(installDir, f), 'x');
  }
  const log = join(dir, 'calls.log');
  const script = `$ErrorActionPreference = 'Stop'
$ServiceName = 'VistaDeviceAgent'; $InstallDir = $env:DIR; $ConfigPath = Join-Path $InstallDir 'device-agent.yaml'; $InstalledBinaryName = 'device-agent.exe'
function Write-Info { param($m) Write-Host "[INFO]  $m" }
function Write-Warn { param($m) Write-Host "[WARN]  $m" }
function Write-Err { param($m) Write-Host "[ERROR] $m" }
function Assert-Administrator { Add-Content $env:LOG 'admin' }
function Test-ServiceInstalled { param($n) $env:SERVICE -eq '1' }
function Stop-Service { Add-Content $env:LOG 'stop' }
function sc.exe { Add-Content $env:LOG "sc $args"; $global:LASTEXITCODE = 0 }
${region('uninstall')}
Invoke-Uninstall`;
  const r = spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-Command', script],
    { encoding: 'utf8', env: { ...process.env, DIR: installDir, LOG: log, SERVICE: service ? '1' : '0' } });
  return { ...r, output: r.stdout + r.stderr, installDir, calls: existsSync(log) ? readFileSync(log, 'utf8') : '' };
}

test('-Uninstall stops and deletes the service and the install directory; nothing installed is not an error', needsPwsh, t => {
  const r = uninstall(t, { service: true, files: ['device-agent.yaml', 'device-agent.exe'] });
  assert.equal(r.status, 0, r.output);
  assert.equal(r.calls, 'admin\nstop\nsc delete VistaDeviceAgent\n');
  assert.ok(!existsSync(r.installDir), 'the directory with the config and private key is still there');
  const none = uninstall(t);
  assert.equal(none.status, 0, none.output);
  assert.match(none.output, /Nothing to remove/);
  const theirs = uninstall(t, { files: ['their-file'] });
  assert.ok(existsSync(join(theirs.installDir, 'their-file')), 'a directory without an agent install was deleted');
});

test('-Uninstall needs neither a binary nor a key, and the final output gives it', needsPwsh, t => {
  const r = run(t, { binary: null, args: ['-Uninstall'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /Windows Principal functionality is not supported|must be run from an elevated/, r.output);
  assert.doesNotMatch(r.output, /No device agent binary|required/);
  assert.match(code, /Write-Host "  Uninstall: & '\$PSCommandPath' -Uninstall"/);
  assert.doesNotMatch(code, /Uninstall: Stop-Service/);
  assert.ok(code.indexOf('if ($Uninstall) { Invoke-Uninstall }') < code.indexOf('Find-AgentBinary $PSScriptRoot'));
});
