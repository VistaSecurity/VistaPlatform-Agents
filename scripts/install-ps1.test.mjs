// The Windows installers (install-*.ps1) and the binaries they drive.
//
// No Windows host runs in CI, so these read the scripts as text. What they pin
// is the contract between an installer and its binary: the log lines and
// files the installer waits for are the ones the binary writes. Named
// *.test.mjs so the PR gate's `node --test 'scripts/**/*.test.mjs'` runs it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const read = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
// Comments explain history and may name what is forbidden; only code counts.
const codeOf = text =>
  text.replace(/<#[\s\S]*?#>/g, '').split('\n').filter(line => !line.trimStart().startsWith('#')).join('\n');

const sensorPs1 = codeOf(read('install-sensor.ps1'));
const sensorMain = read('../cmd/sensor/main.go');

// A sensor that cannot capture stops before it registers (the key stays
// unused) and says so; the installer recognises that line and says the key
// was not spent instead of waiting out its timeout and blaming the network.
test('install-sensor.ps1 recognises the sensor stopping before registration because it cannot capture', () => {
  const marker = 'Not registering: the registration key is unused';
  assert.ok(sensorMain.includes(marker), 'cmd/sensor/main.go no longer prints the line the installer waits for');
  assert.ok(sensorPs1.includes(`'${marker}'`), 'install-sensor.ps1 does not look for the cannot-capture line');
  // The preflight comes before the first registration attempt.
  const preflight = sensorMain.indexOf('s.capturePreflight()');
  const register = sensorMain.indexOf('err := s.register()');
  assert.ok(preflight > 0 && register > preflight, 'the capture preflight does not run before registration');
  // The retry cannot help until the interfaces change.
  const branch = sensorPs1.slice(sensorPs1.indexOf('elseif ($cannotCapture)'));
  assert.match(branch, /-StartupType Disabled/, 'a sensor that cannot capture is left restarting');
  assert.match(branch, /NOT used/, 'the installer does not say the key is still good');
});

test('install-sensor.ps1 says which interface names it takes', () => {
  const raw = read('install-sensor.ps1');
  const help = raw.slice(raw.indexOf('param('), raw.indexOf('[string]$Interfaces'));
  for (const form of ['Ethernet 2', 'description', 'NPF_']) {
    assert.ok(help.includes(form), `-Interfaces help does not mention ${form}`);
  }
});

for (const name of ['install-sensor.ps1']) {
  test(`${name} is pure ASCII without a BOM`, () => {
    // Windows PowerShell 5.1 reads a BOM-less file in the ANSI code page; a
    // UTF-8 dash in a string unbalances its quotes.
    const raw = read(name);
    assert.doesNotMatch(raw, /^﻿/);
    const offenders = raw.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => /[^\x00-\x7F]/.test(l));
    assert.deepEqual(offenders, []);
  });
}

// install-sensor.ps1 as text, and pwsh for the tests that run its functions
// (on GitHub's Linux runners; they skip without it).
const raw = read('install-sensor.ps1');
const code = sensorPs1;
const pwsh = spawnSync('pwsh', ['-NoProfile', '-Command', 'exit 0']).status === 0 ? 'pwsh' : null;
const needsPwsh = { skip: !pwsh && 'pwsh not available' };

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
  assert.ok(lines.filter((l) => /^\s*(&\s*)?(sc|icacls)(\.exe)?\s/i.test(l)).length >= 2, 'the guard matches nothing');
});
