#!/usr/bin/env node
// The sensor installers must leave registration to the sensor.
//
// The sensor binary registers itself on first start: it generates its keypair
// locally, sends a CSR with its build-stamped version and capabilities, and
// records the UUID it was accepted under. Both installers once POSTed to the
// register endpoint themselves with a hardcoded "version": "1.0.0". That spent
// the single-use key, so the binary's own enrolment was rejected ("Registration
// key has already been used") and it never heartbeated, while the console
// showed a sensor stuck at v1.0.0 flagged as needing an upgrade. The
// control plane also generated — and sent back — the private key.
//
// What the installer's config does once it reaches the binary is tested in Go:
// cmd/sensor/installer_config_test.go.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
// Comments explain the history and may name what is forbidden; only code counts.
const code = (text, comment) =>
  text.split('\n').filter(line => !line.trimStart().startsWith(comment)).join('\n');

const installers = [
  ['install-sensor.sh', code(read('install-sensor.sh'), '#')],
  ['install-sensor.ps1', code(read('install-sensor.ps1').replace(/<#[\s\S]*?#>/g, ''), '#')],
];

for (const [name, text] of installers) {
  test(`${name} does not register on the sensor's behalf`, () => {
    assert.doesNotMatch(text, /sensors\/register/, 'installer calls the register endpoint itself');
    // (Deleting an old install's registration-response.json is allowed; reading
    // credentials out of a response is not.)
    assert.doesNotMatch(text, /client_key|client_cert/, 'installer handles a registration response');
  });

  test(`${name} does not invent a sensor version`, () => {
    // The platform shows the version the sensor reports; nothing in the
    // installer may stand in for it.
    assert.doesNotMatch(text, /["']?version["']?\s*[:=]\s*["']?\d+\.\d+\.\d+/i);
  });

  test(`${name} waits for the sensor to record its UUID before reporting success`, () => {
    assert.match(text, /\[0-9a-fA-F\]\{8\}-\[0-9a-fA-F\]\{4\}/, 'no UUID check on the registered sensorId');
  });
}

test('install-sensor.ps1 checks for Npcap before changing anything', () => {
  const [, ps1] = installers[1];
  const npcap = ps1.indexOf('wpcap.dll');
  assert.ok(npcap > 0, 'no Npcap check');
  for (const sideEffect of ['Stop-Service', 'New-Item', 'Copy-Item', 'New-Service', 'WriteAllText']) {
    const at = ps1.indexOf(sideEffect);
    assert.ok(at > npcap, `${sideEffect} runs before the Npcap check`);
  }
  assert.match(ps1, /npcap\.com/, 'Npcap failure gives no download location');
});

// The Windows sensor runs under the Service Control Manager
// (cmd/sensor/service_windows.go), where stderr goes nowhere: its log is a file
// under the data dir, and the installer is the only thing that tells an
// operator where.
test('install-sensor.ps1 points at the log the sensor writes as a service', () => {
  const [, ps1] = installers[1];
  const logfile = read('../cmd/sensor/logfile.go');
  const name = logfile.match(/sensorLogFileName = "([^"]+)"/)?.[1];
  assert.ok(name, 'cmd/sensor/logfile.go no longer declares sensorLogFileName');
  assert.match(logfile, /filepath\.Join\(dataPath, "logs", sensorLogFileName\)/, 'the sensor log moved out of <dataPath>/logs');
  assert.ok(ps1.includes(`Join-Path $DataDir "logs\\${name}"`), `installer does not point at <dataPath>\\logs\\${name}`);
  assert.match(ps1, /Get-Content -Tail \d+ -Wait '\$LogFile'/, 'closing hint does not show how to follow the log');
});

test('install-sensor.ps1 reads the log when the sensor fails to start', () => {
  const [, ps1] = installers[1];
  // A rejected key makes the sensor exit during startup, so Start-Service
  // throws. Under $ErrorActionPreference = "Stop" an uncaught throw ends the
  // install before it can say why or stop the restart loop.
  assert.match(ps1, /try \{\s*Start-Service -Name \$ServiceName\s*\} catch/, 'Start-Service is not guarded');
  assert.match(ps1, /Registration was REJECTED/, 'installer does not look for a rejected key in the log');
  assert.ok(ps1.indexOf('-StartupType Disabled') > 0, 'a rejected key leaves the service restarting');
});

test('install-sensor.ps1 lets the SCM restart a sensor that exits for a restart command', () => {
  const [, ps1] = installers[1];
  // The sensor honours the control plane's restart command by stopping with a
  // failure exit code (serviceExitRestart). The SCM runs failure actions for
  // that only with the non-crash failure flag set.
  assert.match(ps1, /sc\.exe failureflag \$ServiceName 1/);
  assert.match(read('../cmd/sensor/service.go'), /serviceExitRestart uint32 = [1-9]/, 'restart no longer exits non-zero');
});

test('install-sensor.ps1 is pure ASCII', () => {
  // Windows PowerShell 5.1 reads a BOM-less file as the ANSI code page, so a
  // UTF-8 em-dash's bytes decode as "â€" plus a curly quote (U+201D), which
  // the parser honours as a string delimiter. One em-dash inside a quoted
  // message unbalanced the quotes and failed the whole script with
  // "Missing closing '}'" before it ran a line. No BOM, no non-ASCII.
  const raw = read('install-sensor.ps1');
  assert.doesNotMatch(raw, /^﻿/, 'installer starts with a BOM');
  const offenders = raw.split('\n').map((line, i) => [i + 1, line]).filter(([, l]) => /[^\x00-\x7F]/.test(l));
  assert.deepEqual(offenders, [], 'installer contains non-ASCII characters');
});

// Restart storm, lethal reload and plaintext key (install-sensor.sh).
const shText = installers[0][1];

test('install-sensor.sh: exit 78 stops the restart loop', () => {
  assert.match(shText, /^RestartPreventExitStatus=78$/m);
});

test('install-sensor.sh: the unit has no ExecReload (the sensor does not handle SIGHUP)', () => {
  assert.doesNotMatch(shText, /^ExecReload=/m);
});

test('install-sensor.sh: the registration key is masked in output', () => {
  const unmasked = shText.replace(/mask_key "\$REGISTRATION_KEY"/g, '');
  assert.doesNotMatch(unmasked, /echo[^\n]*\$REGISTRATION_KEY|print_\w+[^\n]*\$REGISTRATION_KEY/,
    'the registration key is printed in full');
  assert.match(shText, /mask_key "\$REGISTRATION_KEY"/);
});

test('install-sensor.sh: the key can come from the environment or stdin', () => {
  assert.match(shText, /REGISTRATION_KEY="\$\{VISTA_REGISTRATION_KEY:-\}"/);
  assert.match(shText, /--key-stdin\)/);
});
