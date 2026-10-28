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
