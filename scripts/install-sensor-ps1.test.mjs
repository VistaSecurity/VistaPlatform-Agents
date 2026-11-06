// scripts/install-sensor.ps1: how it takes the registration key, the CA
// fingerprint and the binary. The entry checks run for real under PowerShell
// 7 (pwsh is on GitHub's Linux runners; these skip without it) and stop at
// the Administrator check, which fails off Windows, before anything changes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

function run(t, { binary = works, name = 'crypto-sensor.exe', args = [], env = {}, input = '' } = {}) {
  const dir = tempDir(t);
  copyFileSync(installer, join(dir, 'install-sensor.ps1'));
  if (binary !== null) writeFileSync(join(dir, name), binary, { mode: 0o755 });
  const cleanEnv = { ...process.env, ...env };
  if (!('VISTA_REGISTRATION_KEY' in env)) delete cleanEnv.VISTA_REGISTRATION_KEY;
  const r = spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-File', join(dir, 'install-sensor.ps1'), '-IP', '10.0.0.10', ...args],
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
  const lastCheck = code.indexOf('-CaFingerprint must be');
  assert.ok(lastCheck > 0);
  for (const sideEffect of ['Stop-Service', 'New-Item', 'Copy-Item', 'New-Service', 'WriteAllText']) {
    assert.ok(code.indexOf(sideEffect) > lastCheck, `${sideEffect} runs before the argument checks`);
  }
});
