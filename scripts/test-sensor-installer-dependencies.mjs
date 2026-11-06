#!/usr/bin/env node
// Exercise the real installer entrypoint without installing anything on the host.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const installer = fileURLToPath(new URL('./install-sensor.sh', import.meta.url));
function run(t, binary, args = ['--check-dependencies'], mode = 0o755) {
  const cwd = mkdtempSync(join(tmpdir(), 'sensor-dependencies-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  if (binary !== null) writeFileSync(join(cwd, 'crypto-sensor'), binary, { mode });
  const result = spawnSync('bash', [installer, ...args], {
    cwd, encoding: 'utf8', timeout: 5000, input: '',
  });
  assert.ifError(result.error);
  return { ...result, output: result.stdout + result.stderr };
}

test('check mode needs neither root nor registration and only asks for version', t => {
  const result = run(t, '#!/bin/sh\n[ "$#" = 1 ] && [ "$1" = --version ] || exit 90\necho Sensor v1\n');
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /runtime dependencies are available/);
});

test('missing binary identifies the expected download location', t => {
  const result = run(t, null);
  assert.equal(result.status, 1);
  assert.match(result.output, /Sensor binary not found/);
  assert.match(result.output, /Download and verify/);
});

test('non-executable download gives chmod instructions', t => {
  const result = run(t, '#!/bin/sh\nexit 0\n', undefined, 0o644);
  assert.equal(result.status, 1);
  assert.match(result.output, /chmod \+x/);
});

const missingPcap = '#!/bin/sh\necho "libpcap.so.0.8: cannot open shared object file" >&2\nexit 127\n';
for (const args of [['--check-dependencies'], ['--key', 'test-key', '--ip', '192.0.2.1'], ['--interactive']]) {
  test(`missing libpcap stops the real entrypoint: ${args[0]}`, t => {
    const result = run(t, missingPcap, args);
    assert.equal(result.status, 1);
    assert.match(result.output, /libpcap.so.0.8: cannot open shared object file/);
    assert.match(result.output, /apt-get install libpcap0.8/);
    assert.match(result.output, /dnf install libpcap/);
    assert.doesNotMatch(result.output, /Enter registration key|Registration key is required|must be run as root|Creating service user|Registering sensor/);
  });
}

test('real missing-interpreter failure explains libpcap and loader compatibility', t => {
  const result = run(t, '#!/nonexistent-vista-test-loader\n');
  assert.equal(result.status, 1);
  assert.match(result.output, /requires the libpcap runtime/);
  assert.match(result.output, /architecture and libc/);
  assert.doesNotMatch(result.output, /runtime dependencies are available/);
});

test('help works without a sensor binary', t => {
  const result = run(t, null, ['--help']);
  assert.equal(result.status, 0);
  assert.match(result.output, /--check-dependencies/);
});

// The loose release asset is vista-sensor_<version>_linux_<arch>; the archive
// holds crypto-sensor. Either works without a rename.
const arch = { x64: 'amd64', arm64: 'arm64' }[process.arch];
function runWith(t, files, args = ['--check-dependencies']) {
  const cwd = mkdtempSync(join(tmpdir(), 'sensor-dependencies-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(cwd, name), body, { mode: 0o755 });
  const result = spawnSync('bash', [installer, ...args], { cwd, encoding: 'utf8', timeout: 5000, input: '' });
  assert.ifError(result.error);
  return { ...result, output: result.stdout + result.stderr };
}
const ok = (tag) => `#!/bin/sh\necho "Sensor v1 ${tag}" >&2\nexit 0\n`;
const bad = '#!/bin/sh\nexit 90\n';

test('the loose release file for this machine is accepted under its release name', { skip: !arch && 'unknown machine' }, t => {
  const result = runWith(t, {
    [`vista-sensor_5.4.0_linux_${arch}`]: ok('release'),
    [`vista-sensor_5.4.0_linux_${arch}.tar.gz`]: bad,
    [`vista-sensor_5.4.0_linux_${arch}.cdx.json`]: bad,
    [`vista-sensor_5.4.0_linux_${arch === 'amd64' ? 'arm64' : 'amd64'}`]: bad,
    [`vista-sensor_5.4.0_darwin_${arch}`]: bad,
  });
  assert.equal(result.status, 0, result.output);
});

test('the archive name wins over a release file beside it', { skip: !arch && 'unknown machine' }, t => {
  const result = runWith(t, { 'crypto-sensor': ok('archive'), [`vista-sensor_5.4.0_linux_${arch}`]: bad });
  assert.equal(result.status, 0, result.output);
});

test('two release files for this machine, or none, fail naming both accepted names', { skip: !arch && 'unknown machine' }, t => {
  let result = runWith(t, { [`vista-sensor_5.3.0_linux_${arch}`]: ok(''), [`vista-sensor_5.4.0_linux_${arch}`]: ok('') });
  assert.equal(result.status, 1);
  assert.match(result.output, /keep only the one/);
  result = runWith(t, {});
  assert.equal(result.status, 1);
  assert.match(result.output, /\.\/crypto-sensor/);
  assert.match(result.output, new RegExp(`vista-sensor_<version>_linux_${arch}`));
  assert.doesNotMatch(result.output, /go build/, 'a developer instruction for a missing download');
});

test('help names --ca-fingerprint and the installer introduces itself by the product name', t => {
  const result = runWith(t, {}, ['--help']);
  assert.match(result.output, /--ca-fingerprint SHA256/);
  assert.match(result.output, /^Vista Platform Sensor Installer$/m);
  assert.doesNotMatch(result.output, /Crypto Inventory/);
});
