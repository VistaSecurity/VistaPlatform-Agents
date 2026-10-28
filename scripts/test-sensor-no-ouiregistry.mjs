#!/usr/bin/env node
// Guard: the sensor must never import shared/ouiregistry.
//
// Vendor resolution from the IEEE OUI registry happens on the platform, at
// ingestion, not in the passive sensor. A transitive import is as bad as a
// direct one, so this checks the full dependency closure (`go list -deps`) of
// every sensor package (cmd/sensor, internal/sensor), for each OS the sensor
// ships to.
//
// The guard mutation-tests itself before it checks the sensor: it builds a
// throwaway module that DOES import the package and requires a violation, and
// one that does not and requires a pass. A guard that cannot fail would print
// the same "OK" as a guard that works.
//
//   node scripts/test-sensor-no-ouiregistry.mjs   (make sensor-no-ouiregistry-test)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const MODULE = 'github.com/vistasecurity/vistaplatform-agents';
export const FORBIDDEN = `${MODULE}/shared/ouiregistry`;
const SENSOR_PACKAGES = ['./cmd/sensor/...', './internal/sensor/...'];
const TARGETS = ['linux', 'windows', 'darwin'];

function goToolchain() {
  const v = fs.readFileSync(path.join(ROOT, 'go.mod'), 'utf8').match(/^go (\d+\.\d+\.\d+)$/m)?.[1];
  if (!v) throw new Error('cannot read the go directive from go.mod');
  return `go${v}`;
}

/**
 * Returns the packages in dir's dependency closure that are, or live under,
 * the forbidden package, for every target OS. Throws if `go list` fails: a
 * guard that cannot list dependencies must not report a clean result.
 */
export function violations(dir, extraEnv = {}, patterns = ['./...']) {
  const found = new Set();
  for (const goos of TARGETS) {
    const out = execFileSync('go', ['list', '-deps', ...patterns], {
      cwd: dir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || goToolchain(), GOOS: goos, GOFLAGS: '', ...extraEnv },
    });
    const pkgs = out.split('\n').filter(Boolean);
    if (pkgs.length < 2) throw new Error(`go list -deps in ${dir} (GOOS=${goos}) returned ${pkgs.length} packages`);
    for (const p of pkgs) if (p === FORBIDDEN || p.startsWith(`${FORBIDDEN}/`)) found.add(`${p} (GOOS=${goos})`);
  }
  return [...found];
}

/** A throwaway module wired to this module, optionally importing the forbidden package. */
function probeModule(importIt) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sensor-ouiregistry-guard-'));
  fs.writeFileSync(
    path.join(dir, 'go.mod'),
    `module example.com/guardprobe\n\ngo ${goToolchain().slice(2)}\n\n` +
      `require ${MODULE} v0.0.0\n\n` +
      `replace ${MODULE} => ${ROOT}\n`,
  );
  fs.copyFileSync(path.join(ROOT, 'go.sum'), path.join(dir, 'go.sum'));
  const imp = importIt
    ? `import "${FORBIDDEN}"\n\nvar _ = ouiregistry.Count\n`
    : `import "${MODULE}/shared/atomicfile"\n\nvar _ = atomicfile.Write\n`;
  fs.writeFileSync(path.join(dir, 'probe.go'), `package guardprobe\n\n${imp}`);
  return dir;
}

function main() {
  let failures = 0;
  const check = (name, cond, detail = '') => {
    if (cond) console.log(`PASS ${name}`);
    else {
      console.error(`FAIL ${name}${detail ? `\n   ${detail}` : ''}`);
      failures++;
    }
  };
  // The probes are their own modules, so they resolve this one through a
  // replace directive.
  const probeEnv = { GOWORK: 'off', GOFLAGS: '-mod=mod' };

  const bad = probeModule(true);
  const good = probeModule(false);
  try {
    const v = violations(bad, probeEnv);
    check('self-test: a module importing ouiregistry is caught', v.length > 0, `got ${JSON.stringify(v)}`);
    const ok = violations(good, probeEnv);
    check('self-test: a module that does not import it passes', ok.length === 0, `got ${JSON.stringify(ok)}`);
  } finally {
    fs.rmSync(bad, { recursive: true, force: true });
    fs.rmSync(good, { recursive: true, force: true });
  }

  const sensor = violations(ROOT, { GOWORK: 'off' }, SENSOR_PACKAGES);
  check(
    'the sensor (cmd/sensor, internal/sensor) does not import shared/ouiregistry (directly or transitively)',
    sensor.length === 0,
    `found: ${sensor.join(', ')} — vendor resolution belongs on the platform, not in the sensor`,
  );

  if (failures) {
    console.error(`❌ ${failures} sensor/ouiregistry guard check(s) failed`);
    process.exit(1);
  }
  console.log('✅ sensor does not import shared/ouiregistry');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(`❌ sensor/ouiregistry guard could not run: ${err.stderr?.toString() || err.message}`);
    process.exit(1);
  }
}
