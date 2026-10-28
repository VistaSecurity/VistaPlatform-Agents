#!/usr/bin/env node
// scripts/install-device-agent.sh: the entry checks, run for real without
// installing anything, and the guards on how it enrolls.
//
// What the config it writes does once it reaches the agent is tested in Go:
// cmd/device-agent/installer_config_test.go.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const installer = fileURLToPath(new URL('./install-device-agent.sh', import.meta.url));

function run(t, binary, args, mode = 0o755) {
  const cwd = mkdtempSync(join(tmpdir(), 'device-agent-installer-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  if (binary !== null) writeFileSync(join(cwd, 'device-agent'), binary, { mode });
  const result = spawnSync('bash', [installer, ...args], { cwd, encoding: 'utf8', timeout: 5000, input: '' });
  assert.ifError(result.error);
  return { ...result, output: result.stdout + result.stderr };
}

const works = '#!/bin/sh\n[ "$1" = -version ] || exit 90\necho "Vista Platform Device Agent v9.9.9"\n';

test('check mode needs neither root nor a key and only asks for the version', t => {
  const result = run(t, works, ['--check-dependencies']);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /runs on this host/);
});

test('missing binary says where it should be', t => {
  const result = run(t, null, ['--check-dependencies']);
  assert.equal(result.status, 1);
  assert.match(result.output, /binary not found/);
});

test('non-executable download gives chmod instructions', t => {
  const result = run(t, works, ['--check-dependencies'], 0o644);
  assert.equal(result.status, 1);
  assert.match(result.output, /chmod \+x/);
});

test('a binary that cannot run stops before anything changes', t => {
  const result = run(t, '#!/nonexistent-vista-test-loader\n', ['--url', 'https://p.example', '--key', 'REG-x']);
  assert.equal(result.status, 1);
  assert.match(result.output, /cannot run on this host/);
  assert.doesNotMatch(result.output, /must be run as root|Creating service user/);
});

test('url and key are required', t => {
  const result = run(t, works, ['--key', 'REG-x']);
  assert.equal(result.status, 1);
  assert.match(result.output, /--url and --key are required/);
});

test('help works without a binary', t => {
  const result = run(t, null, ['--help']);
  assert.equal(result.status, 0);
  assert.match(result.output, /--ca-fingerprint/);
});

// Comments explain the history and may name what is forbidden; only code counts.
const code = readFileSync(installer, 'utf8').split('\n').filter(l => !l.trimStart().startsWith('#')).join('\n');

test('the installer leaves enrollment to the agent', () => {
  assert.doesNotMatch(code, /agents\/register/, 'installer calls the register endpoint itself');
  assert.doesNotMatch(code, /-register\b/, 'installer runs the agent with -register');
  assert.match(code, /\[0-9a-fA-F\]\{8\}-\[0-9a-fA-F\]\{4\}/, 'no UUID check on the enrolled agent_id');
});

test("the agent's data path is inside the install directory it owns", () => {
  assert.match(code, /data_path: \$\(yaml_quote "\$INSTALL_DIR\/data"\)/);
  assert.doesNotMatch(code, /\/var\/lib\/crypto-device-agent/,
    'the root-owned default is where an ordinary user spent the key on an enrollment it could not save');
  assert.match(code, /chown -R "\$SERVICE_USER:\$SERVICE_USER" "\$INSTALL_DIR"/);
});

test('the systemd unit does not restart on exit 78 (a rejected key needs a person)', () => {
  assert.match(code, /^RestartPreventExitStatus=78$/m);
});

test('every YAML value the installer writes is quoted, and the key is never echoed', () => {
  assert.match(code, /^platform_url: \$\(yaml_quote "\$CONTROL_PLANE_URL"\)$/m);
  assert.match(code, /^registration_key: \$\(yaml_quote "\$REGISTRATION_KEY"\)$/m);
  assert.match(code, /^data_path: \$\(yaml_quote /m);
  const unmasked = code.replace(/mask_key "\$REGISTRATION_KEY"/g, '');
  assert.doesNotMatch(unmasked, /echo[^\n]*\$REGISTRATION_KEY|print_\w+[^\n]*\$REGISTRATION_KEY/,
    'the registration key is printed in full');
});

test('the key is accepted from the environment and from stdin', () => {
  assert.match(code, /REGISTRATION_KEY="\$\{VISTA_REGISTRATION_KEY:-\}"/);
  assert.match(code, /--key-stdin\)/);
});

test('a key from the environment satisfies the key requirement', t => {
  const cwd = mkdtempSync(join(tmpdir(), 'device-agent-installer-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  writeFileSync(join(cwd, 'device-agent'), works, { mode: 0o755 });
  const result = spawnSync('bash', [installer, '--url', 'https://p.example'], {
    cwd, encoding: 'utf8', timeout: 5000, input: '',
    env: { ...process.env, VISTA_REGISTRATION_KEY: 'REG-from-env' },
  });
  assert.doesNotMatch(result.stdout + result.stderr, /--url and --key are required/);
});
