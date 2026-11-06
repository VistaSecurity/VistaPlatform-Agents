// The Windows installers (install-*.ps1) and the binaries they drive.
//
// No Windows host runs in CI, so these read the scripts as text. What they pin
// is the contract between an installer and its binary: the log lines and
// files the installer waits for are the ones the binary writes. Named
// *.test.mjs so the PR gate's `node --test 'scripts/**/*.test.mjs'` runs it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
// Comments explain history and may name what is forbidden; only code counts.
const code = text =>
  text.replace(/<#[\s\S]*?#>/g, '').split('\n').filter(line => !line.trimStart().startsWith('#')).join('\n');

const sensorPs1 = code(read('install-sensor.ps1'));
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
