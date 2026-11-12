// scripts/install-sensor.ps1: how it takes the registration key, the CA
// fingerprint and the binary. The entry checks run for real under PowerShell
// 7 (pwsh is on GitHub's Linux runners; these skip without it) and stop at
// the Administrator check, which fails off Windows, before anything changes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const installer = fileURLToPath(new URL('./install-sensor.ps1', import.meta.url));
const pwsh = spawnSync('pwsh', ['-NoProfile', '-Command', 'exit 0']).status === 0 ? 'pwsh' : null;
const needsPwsh = { skip: !pwsh && 'pwsh not available' };
const raw = readFileSync(installer, 'utf8');

const works = '#!/bin/sh\necho "Vista Platform Network Sensor v9.9.9"\n';

function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), 'sensor-ps1-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// A first install's -Url and -IP; tests that are about them pass base: [].
const FIRST = ['-Url', 'https://p.example', '-IP', '10.0.0.10'];

function run(t, { binary = works, name = 'crypto-sensor.exe', base = FIRST, args = [], env = {}, input = '' } = {}) {
  const dir = tempDir(t);
  copyFileSync(installer, join(dir, 'install-sensor.ps1'));
  if (binary !== null) writeFileSync(join(dir, name), binary, { mode: 0o755 });
  const cleanEnv = { ...process.env, ...env };
  if (!('VISTA_REGISTRATION_KEY' in env)) delete cleanEnv.VISTA_REGISTRATION_KEY;
  const r = spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-File', join(dir, 'install-sensor.ps1'), ...base, ...args],
    { cwd: dir, encoding: 'utf8', timeout: 30000, input, env: cleanEnv });
  assert.ifError(r.error);
  return { ...r, output: r.stdout + r.stderr };
}

// It went past every argument check to the Administrator check, which is the
// first thing that cannot pass off Windows.
const reachedAdminCheck = /Windows Principal functionality is not supported|must be run from an elevated/;

test('a missing binary names both file names it looks for', needsPwsh, t => {
  const r = run(t, { binary: null, args: ['-Key', 'REG-x'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /crypto-sensor\.exe/);
  assert.match(r.output, /vista-sensor_\*_windows_\*\.exe/);
});

test('the release file name is accepted as downloaded', needsPwsh, t => {
  const r = run(t, { name: 'vista-sensor_9.9.9_windows_amd64.exe', args: ['-Key', 'REG-x'] });
  assert.match(r.output, reachedAdminCheck, r.output);
});

test('the binary is found by either name, and two release files are refused', needsPwsh, t => {
  const region = raw.slice(raw.indexOf('#region sensor-binary'), raw.indexOf('#endregion sensor-binary'));
  assert.ok(region.length > 0, 'no #region sensor-binary');
  const dir = tempDir(t);
  const find = () => spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-Command',
    `${region}\ntry { Find-SensorBinary $env:DIR } catch { "ERROR: " + $_.Exception.Message }`],
  { encoding: 'utf8', env: { ...process.env, DIR: dir } }).stdout.trim();
  writeFileSync(join(dir, 'vista-sensor_9.9.9_windows_amd64.exe'), 'x');
  assert.equal(find(), join(dir, 'vista-sensor_9.9.9_windows_amd64.exe'));
  writeFileSync(join(dir, 'vista-sensor_9.9.9_windows_386.exe'), 'x');
  assert.match(find(), /^ERROR: Found 2 files/);
  writeFileSync(join(dir, 'crypto-sensor.exe'), 'x');
  assert.equal(find(), join(dir, 'crypto-sensor.exe'), 'the installed name is not preferred');
});

test('a registration key is required', needsPwsh, t => {
  const r = run(t);
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /A registration key is required/);
});

for (const [how, opts] of [
  ['the environment', { env: { VISTA_REGISTRATION_KEY: 'REG-from-env' } }],
  ['standard input', { args: ['-KeyStdin'], input: 'REG-from-stdin\n' }],
]) {
  test(`a key from ${how} satisfies the key requirement`, needsPwsh, t => {
    const r = run(t, opts);
    assert.doesNotMatch(r.output, /registration key is required/, r.output);
    assert.match(r.output, reachedAdminCheck, r.output);
  });
}

test('a malformed CA fingerprint is refused; a well-formed one is accepted', needsPwsh, t => {
  const bad = run(t, { args: ['-Key', 'REG-x', '-CaFingerprint', 'abc'] });
  assert.equal(bad.status, 1, bad.output);
  assert.match(bad.output, /-CaFingerprint must be a SHA-256 fingerprint/);
  const good = run(t, { args: ['-Key', 'REG-x', '-CaFingerprint', `SHA256:${'AB:'.repeat(31)}AB`] });
  assert.match(good.output, reachedAdminCheck, good.output);
});

// Comments explain the history and may name what is forbidden; only code counts.
const code = raw.replace(/<#[\s\S]*?#>/g, '').split('\n').filter(l => !l.trimStart().startsWith('#')).join('\n');
// The install path: the code without the -Uninstall function, which runs
// instead of it.
const region = (name) => {
  const start = raw.indexOf(`#region ${name}`);
  const end = raw.indexOf(`#endregion ${name}`);
  assert.ok(start >= 0 && end > start, `no #region ${name}`);
  return raw.slice(start, end);
};
const installCode = raw.replace(region('uninstall'), '').replace(/<#[\s\S]*?#>/g, '')
  .split('\n').filter(l => !l.trimStart().startsWith('#')).join('\n');

test('the CA fingerprint reaches the sensor the way install-device-agent.sh passes it', () => {
  assert.match(readFileSync(new URL('../cmd/sensor/main.go', import.meta.url), 'utf8'), /flag\.String\("ca-fingerprint"/,
    'the sensor no longer takes -ca-fingerprint');
  assert.match(code, /\$binPath \+= " -ca-fingerprint \$CaFingerprint"/);
});

test('the key is never printed, and is not a mandatory (prompted) parameter', () => {
  assert.doesNotMatch(code, /Write-(Info|Warn|Err|Host)[^\n]*\$Key\b/, 'the key is printed');
  assert.doesNotMatch(raw.slice(raw.indexOf('param('), raw.indexOf('[string]$Key')), /Mandatory = \$true\)\]\s*$/,
    'a mandatory -Key makes PowerShell prompt with echo instead of -KeyStdin');
});

test('the argument checks come before anything on the host changes', () => {
  const lastCheck = installCode.indexOf('-CaFingerprint must be');
  assert.ok(lastCheck > 0);
  for (const sideEffect of ['Stop-Service', 'New-Item', 'Copy-Item', 'New-Service', 'WriteAllText', 'Remove-Item']) {
    assert.ok(installCode.indexOf(sideEffect) > lastCheck, `${sideEffect} runs before the argument checks`);
  }
  // ...and so does the decision to keep or replace the enrolment.
  const decided = installCode.indexOf('$decision = Get-EnrollmentDecision $ConfigPath $Key');
  assert.ok(decided > lastCheck && decided < installCode.indexOf('Stop-Service'), 'the enrolment is decided after the host changes');
  // -Uninstall runs before the binary is looked for or a key is read.
  assert.ok(code.indexOf('if ($Uninstall) { Invoke-Uninstall }') < code.indexOf('Find-SensorBinary $PSScriptRoot'));
});

test('the config and the private key are readable by Administrators and SYSTEM only', () => {
  const acl = code.indexOf('/inheritance:r');
  assert.ok(acl > 0, 'the install directory keeps the inherited Program Files ACL (Users can read)');
  assert.match(code, /"\*S-1-5-18:\(OI\)\(CI\)F" "\*S-1-5-32-544:\(OI\)\(CI\)F"/, 'not SYSTEM and Administrators by SID');
  for (const write of ['WriteAllText', 'Copy-Item']) {
    assert.ok(code.indexOf(write) > acl, `${write} runs before the directory is protected`);
  }
  assert.match(code, /\/reset \/T/, 'files an earlier install left keep their old ACL');
});

// --- No default platform, keyless upgrade, -Uninstall, -CheckDependencies ----

test('a first install needs -Url, named as the address of the customer\'s own console', needsPwsh, t => {
  const r = run(t, { base: ['-IP', '10.0.0.10'], args: ['-Key', 'REG-x'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /-Url is required: the address of your own Vista Platform console, as shown in your browser/);
  assert.doesNotMatch(r.output, /vistasecurity\.io/);
});

test('a first install needs -IP', needsPwsh, t => {
  const r = run(t, { base: ['-Url', 'https://p.example'], args: ['-Key', 'REG-x'] });
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /-IP is required on a first install/);
});

test('there is no default platform URL, and -IP is not a prompted parameter', () => {
  assert.doesNotMatch(raw, /app\.vistasecurity\.io/);
  assert.match(raw, /\[string\]\$Url = ""/);
  const ipParam = raw.slice(raw.indexOf('param('), raw.indexOf('[string]$IP'));
  assert.doesNotMatch(ipParam, /Mandatory = \$true\)\]\s*$/, 'a mandatory -IP makes a keyless upgrade prompt for it');
});

// Runs the installer's #region sensor-enrollment functions.
function enrollment(t, script, env = {}) {
  const r = spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-Command',
    `$ErrorActionPreference = 'Stop'\n$uuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'\n${region('sensor-enrollment')}\n${script}`],
  { encoding: 'utf8', env: { ...process.env, ...env } });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
}

test('an enrolled host keeps its identity with no key or its own key; another key enrolls afresh', needsPwsh, t => {
  const dir = tempDir(t);
  const id = '3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59';
  const key = 'REG-0123456789abcdef-secret';
  const sha = (k) => enrollment(t, `Get-KeySha256 '${k}'`);
  const cfg = (name, text) => { const f = join(dir, name); writeFileSync(f, text); return f; };
  const enrolledSha = cfg('a.yaml', `sensorId: "${id}"\ncontrolPlaneUrl: "https://p.example"\nregistrationKeySha256: "${sha(key)}"\n`);
  const enrolledKey = cfg('b.yaml', `sensorId: '${id}'\nregistrationKey: '${key}'\n`);
  const pending = cfg('c.yaml', `sensorId: 'sensor-1'\nregistrationKey: '${key}'\n`);
  const decide = (path, k) => enrollment(t, 'Get-EnrollmentDecision $env:CFG $env:KEY', { CFG: path, KEY: k });
  assert.equal(decide(enrolledSha, ''), 'keep', 'a keyless re-run of an enrolled host re-enrolls');
  assert.equal(decide(enrolledSha, key), 'keep');
  assert.equal(decide(enrolledKey, key), 'keep');
  assert.equal(decide(enrolledSha, 'REG-another'), 'enroll');
  assert.equal(decide(pending, ''), 'needs-key');
  assert.equal(decide(pending, key), 'enroll');
  assert.equal(decide(join(dir, 'missing.yaml'), ''), 'needs-key');
  assert.equal(decide(join(dir, 'missing.yaml'), key), 'enroll');
  assert.equal(enrollment(t, `Get-ConfigValue 'controlPlaneUrl' $env:CFG`, { CFG: enrolledSha }), 'https://p.example');
});

test('the keep decision decides whether the config and certificates are replaced', () => {
  assert.match(installCode, /\$keepEnrolment = \(\$decision -eq 'keep'\)/);
  assert.equal((installCode.match(/if \(-not \$keepEnrolment\) \{/g) || []).length, 2, 'the certificates or the config are replaced on a kept enrolment');
  assert.match(installCode, /if \(\$decision -eq 'needs-key'\) \{/);
  assert.match(installCode, /if \(\[string\]::IsNullOrWhiteSpace\(\$IP\)\) \{ \$IP = Get-ServiceSensorIP \}/, 'a re-run does not reuse the address');
});

test('a CA fingerprint is normalised the way the sensor compares it, and must be 64 hex digits', needsPwsh, t => {
  const hex = 'ab'.repeat(32);
  const conv = (v) => enrollment(t, '$r = ConvertTo-CaFingerprint $env:FP; if ($null -eq $r) { "NULL" } else { $r }', { FP: v });
  assert.equal(conv(`SHA256:${hex.toUpperCase().match(/../g).join(':')}`), hex);
  assert.equal(conv(` sha256:${hex} `), hex);
  for (const bad of ['abc', `${hex}00`, 'zz'.repeat(32)]) assert.equal(conv(bad), 'NULL', bad);
});

// Runs Invoke-Uninstall with stand-ins for the service and the elevation check.
function uninstall(t, { service = false, files = null } = {}) {
  const dir = tempDir(t);
  const installDir = join(dir, 'VistaSensor');
  if (files) {
    mkdirSync(join(installDir, 'data', 'certs'), { recursive: true });
    for (const f of files) writeFileSync(join(installDir, f), 'x');
  }
  const log = join(dir, 'calls.log');
  const script = `$ErrorActionPreference = 'Stop'
$ServiceName = 'VistaSensor'; $InstallDir = $env:DIR; $ConfigPath = Join-Path $InstallDir 'sensor-config.yaml'; $InstalledBinaryName = 'crypto-sensor.exe'
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

test('-Uninstall stops and deletes the service and the install directory', needsPwsh, t => {
  const r = uninstall(t, { service: true, files: ['sensor-config.yaml', 'crypto-sensor.exe'] });
  assert.equal(r.status, 0, r.output);
  assert.equal(r.calls, 'admin\nstop\nsc delete VistaSensor\n', 'not elevated first, or the service is not stopped then deleted');
  assert.ok(!existsSync(r.installDir), 'the directory with the config and private key is still there');
  assert.match(r.output, /Removed the service VistaSensor/);
  assert.match(r.output, /Removed .*VistaSensor \(configuration, certificates and private key\)/);
});

test('-Uninstall on a host with nothing installed succeeds, and leaves a directory that is not a sensor install', needsPwsh, t => {
  const none = uninstall(t);
  assert.equal(none.status, 0, none.output);
  assert.match(none.output, /Nothing to remove/);
  const theirs = uninstall(t, { files: ['their-file'] });
  assert.equal(theirs.status, 0, theirs.output);
  assert.ok(existsSync(join(theirs.installDir, 'their-file')), 'a directory without a sensor install was deleted');
  assert.match(theirs.output, /Left .* in place/);
});

test('-Uninstall needs neither a binary nor a key, and the final output says how to uninstall', needsPwsh, t => {
  const r = run(t, { binary: null, base: [], args: ['-Uninstall'] });
  assert.match(r.output, reachedAdminCheck, r.output);
  assert.doesNotMatch(r.output, /No sensor binary|registration key is required/);
  assert.match(code, /Write-Host "  Uninstall: & '\$PSCommandPath' -Uninstall"/);
});

function systemRoot(t, withNpcap) {
  const root = tempDir(t);
  mkdirSync(join(root, 'System32', 'Npcap'), { recursive: true });
  if (withNpcap) writeFileSync(join(root, 'System32', 'Npcap', 'wpcap.dll'), 'x');
  return root;
}

test('-CheckDependencies needs neither Administrator nor a key, and checks the binary and Npcap', needsPwsh, t => {
  const ok = run(t, { base: [], args: ['-CheckDependencies'], env: { SystemRoot: systemRoot(t, true) } });
  assert.equal(ok.status, 0, ok.output);
  assert.match(ok.output, /Sensor v9\.9\.9 runs on this host/);
  assert.match(ok.output, /Npcap is installed/);
  const noNpcap = run(t, { base: [], args: ['-CheckDependencies'], env: { SystemRoot: systemRoot(t, false) } });
  assert.equal(noNpcap.status, 1, noNpcap.output);
  assert.match(noNpcap.output, /Npcap is not installed/);
  const broken = run(t, { binary: '#!/bin/sh\nexit 3\n', base: [], args: ['-CheckDependencies'], env: { SystemRoot: systemRoot(t, true) } });
  assert.equal(broken.status, 1, broken.output);
  assert.match(broken.output, /cannot run on this host/);
  assert.doesNotMatch(ok.output + noNpcap.output + broken.output, /Administrator|elevated/);
});
