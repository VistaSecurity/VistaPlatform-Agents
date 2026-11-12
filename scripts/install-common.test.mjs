// What all six installers, and the agents' own interactive setup, promise a
// customer: there is no hosted platform to default to, the help shows only
// what works, and the commands they print exist in the release archive.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (f) => readFileSync(new URL(f, import.meta.url), 'utf8');
const SH = ['install-sensor.sh', 'install-device-agent.sh', 'install-sensor-macos.sh', 'install-device-agent-macos.sh'];
const PS1 = ['install-sensor.ps1', 'install-device-agent.ps1'];
const INSTALLERS = [...SH, ...PS1].map((f) => [f, read(`./${f}`)]);
const PROMPTS = ['../cmd/sensor/main.go', '../cmd/device-agent/main.go'].map((f) => [f, read(f)]);

// Assembled from parts so this file does not hold the address it hunts for.
const DEAD_HOST = new RegExp(['app', 'vistasecurity', 'io'].join('\\.'));

test('no installer and no interactive setup defaults to a hosted platform that does not exist', () => {
  for (const [name, text] of [...INSTALLERS, ...PROMPTS]) {
    assert.doesNotMatch(text, DEAD_HOST, `${name} still names the dead default URL`);
  }
  // Each says what the URL is, and the examples use a placeholder.
  for (const [name, text] of INSTALLERS) {
    assert.match(text, /the address of your own Vista Platform console, as shown in your browser/, name);
    assert.match(text, /-Url https:\/\/vista\.example\.com|--url https:\/\/vista\.example\.com/, name);
  }
  for (const [name, text] of PROMPTS) {
    assert.match(text, /the address of your own Vista Platform console, as shown in your browser/, name);
  }
});

test('the dead-URL guard catches the URL (mutation)', () => {
  const [, text] = INSTALLERS[0];
  const host = ['app', 'vistasecurity', 'io'].join('.');
  assert.match(`${text}\nCONTROL_PLANE_URL="https://${host}"\n`, DEAD_HOST);
});

test('no installer tells a customer to run a path the release archive does not have', () => {
  for (const [name, text] of INSTALLERS) {
    assert.doesNotMatch(text, /(bash|\.\\|\.\/)\s*scripts[/\\]install-/, `${name} prints a scripts/ path`);
  }
  assert.match('echo "  Retry: bash scripts/install-sensor.sh --check-dependencies"', /(bash|\.\\|\.\/)\s*scripts[/\\]install-/, 'the guard matches nothing');
});

test('the sensor installers do not promise deployment profiles they ignore', () => {
  for (const name of ['install-sensor.sh', 'install-sensor-macos.sh', 'install-sensor.ps1']) {
    const text = read(`./${name}`);
    assert.doesNotMatch(text, /air[_-]gapped|Offline mode|export files/i, `${name} still advertises the air-gapped profile`);
    assert.match(text, /currently ignored/, `${name} does not say the profile is ignored`);
    // The flag itself stays: the console and the lab rehearsals pass it.
    assert.match(text, /-p\|--profile\)|\[string\]\$Profile\b/, `${name} no longer takes the profile`);
  }
});

test('every installer offers an uninstall and prints the real command', () => {
  for (const [name, text] of INSTALLERS) {
    assert.match(text, /--uninstall\)|\[switch\]\$Uninstall\b/, `${name} has no uninstall option`);
    assert.match(text, /Uninstall: +(sudo bash \$0 --uninstall|& '\$PSCommandPath' -Uninstall)/, `${name} does not print the uninstall command`);
    assert.doesNotMatch(text, /Uninstall: +systemctl stop|Uninstall: +Stop-Service/, `${name} prints a stop, not an uninstall`);
  }
});

test('the four shell installers check the CA fingerprint with one function', () => {
  const fn = (text) => {
    const m = /^normalize_ca_fingerprint\(\) \{[\s\S]*?^\}$/m.exec(text);
    assert.ok(m, 'normalize_ca_fingerprint not found');
    return m[0];
  };
  const first = fn(read(`./${SH[0]}`));
  for (const name of SH.slice(1)) assert.equal(fn(read(`./${name}`)), first, name);
  for (const name of SH) {
    assert.match(read(`./${name}`), /CA_FINGERPRINT=\$\(normalize_ca_fingerprint "\$CA_FINGERPRINT"\)/, `${name} does not use it`);
  }
  for (const name of PS1) {
    assert.match(read(`./${name}`), /\$normalized = ConvertTo-CaFingerprint \$CaFingerprint/, `${name} does not use it`);
  }
});

test('the install flags the console prints are all still accepted', () => {
  const flags = {
    'install-sensor.sh': ['--url', '--key', '--ip', '--name', '--ca-fingerprint', '--key-stdin', '--check-dependencies', '--profile'],
    'install-sensor-macos.sh': ['--url', '--key', '--ip', '--name', '--ca-fingerprint', '--key-stdin', '--check-dependencies', '--profile'],
    'install-device-agent.sh': ['--url', '--key', '--ca-fingerprint', '--key-stdin', '--check-dependencies'],
    'install-device-agent-macos.sh': ['--url', '--key', '--ca-fingerprint', '--key-stdin', '--check-dependencies'],
  };
  for (const [name, list] of Object.entries(flags)) {
    const text = read(`./${name}`);
    for (const f of list) assert.match(text, new RegExp(`(^\\s*|\\|)${f}\\)`, 'm'), `${name} no longer takes ${f}`);
  }
  const ps = {
    'install-sensor.ps1': ['Url', 'Key', 'IP', 'Name', 'CaFingerprint', 'KeyStdin', 'CheckDependencies', 'Profile'],
    'install-device-agent.ps1': ['Url', 'Key', 'CaFingerprint', 'KeyStdin', 'CheckDependencies'],
  };
  for (const [name, list] of Object.entries(ps)) {
    const text = read(`./${name}`);
    for (const p of list) assert.match(text, new RegExp(`\\[(string|switch)\\]\\$${p}\\b`), `${name} no longer takes -${p}`);
  }
});
