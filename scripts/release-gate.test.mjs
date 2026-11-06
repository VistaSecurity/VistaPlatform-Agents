// The final `gate` job of nightly.yml and release.yml: a run that did not do
// its job must end red. A job GitHub cancels (a runner label it no longer
// serves) leaves the run "cancelled" with every later job skipped, which
// nothing reported as a failure; the gate turns that into a failed run.
//
// Static: each workflow has the gate, it runs if: always(), needs every other
// job, holds no permissions, is in no environment and runs only shell.
// Behaviour: the gate's own run: text, read from the workflow, driven with job
// results through bash and jq.
//
//   node --test scripts/release-gate.test.mjs

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { HOSTED_LABELS, parseYaml } from './check-workflows.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflow = (name) => parseYaml(readFileSync(path.join(root, '.github', 'workflows', name), 'utf8'));

// How each workflow decides it was meant to publish: the nightly from the
// same prepare output its build and publish jobs read; a tagged release always.
const PUBLISH_EXPECTED = {
  'nightly.yml': "${{ needs.prepare.outputs.skip == 'false' }}",
  'release.yml': 'true',
};

for (const name of Object.keys(PUBLISH_EXPECTED)) {
  test(`${name}: the gate runs after everything, needs every other job, and holds nothing`, () => {
    const jobs = workflow(name).jobs;
    const gate = jobs.gate;
    assert.ok(gate, 'no gate job');
    assert.equal(gate.if, 'always()', 'the gate must run after a cancellation or failure');
    const needs = Array.isArray(gate.needs) ? gate.needs : [gate.needs];
    assert.deepEqual([...needs].sort(), Object.keys(jobs).filter((j) => j !== 'gate').sort(),
      'the gate does not need every other job (a new job must be added to it)');
    assert.deepEqual(gate.permissions, {}, 'the gate holds permissions');
    assert.equal(gate.environment, undefined, 'the gate runs in an environment');
    assert.equal(gate.uses, undefined);
    assert.ok(HOSTED_LABELS.has(gate['runs-on']), 'not a hosted runner label');
    assert.equal(gate.steps.length, 1);
    assert.equal(gate.steps[0].uses, undefined, 'the gate runs an action');
    assert.equal(gate.steps[0].env.NEEDS, '${{ toJSON(needs) }}');
    assert.equal(gate.steps[0].env.PUBLISH_EXPECTED, PUBLISH_EXPECTED[name]);
    // Nothing else depends on the gate, and it does not change what publish runs on.
    for (const [id, j] of Object.entries(jobs)) {
      if (id === 'gate') continue;
      const n = Array.isArray(j.needs) ? j.needs : [j.needs];
      assert.ok(!n.includes('gate'), `${id} needs the gate`);
    }
  });
}

test('nightly.yml: publish and the gate read the same skip decision', () => {
  const jobs = workflow('nightly.yml').jobs;
  assert.equal(jobs.publish.if, "needs.prepare.outputs.skip == 'false'");
  assert.equal(jobs.build.if, "needs.prepare.outputs.skip == 'false'");
});

// The gate's run: text, executed as the runner would (bash -e).
function gate(name, results, publishExpected) {
  const step = workflow(name).jobs.gate.steps[0];
  const needs = Object.fromEntries(Object.entries(results).map(([k, v]) => [k, { result: v, outputs: {} }]));
  const r = spawnSync('bash', ['-e', '-c', step.run], {
    encoding: 'utf8',
    env: { ...process.env, NEEDS: JSON.stringify(needs), PUBLISH_EXPECTED: publishExpected },
  });
  assert.ifError(r.error);
  return { status: r.status, output: r.stdout + r.stderr };
}

const ok = { prepare: 'success', build: 'success', publish: 'success' };
const cases = [
  ['every job succeeded', ok, 'true', 0],
  ['build cancelled (a runner label GitHub refuses), publish skipped', { ...ok, build: 'cancelled', publish: 'skipped' }, 'true', 1],
  ['build failed, publish skipped', { ...ok, build: 'failure', publish: 'skipped' }, 'true', 1],
  ['publish skipped although there was something to publish', { ...ok, publish: 'skipped' }, 'true', 1],
  ['publish failed', { ...ok, publish: 'failure' }, 'true', 1],
  ['publish cancelled', { ...ok, publish: 'cancelled' }, 'true', 1],
  // prepare's skip output is empty when prepare did not finish, so only the
  // cancelled result itself can turn this red.
  ['prepare cancelled, everything after it skipped', { prepare: 'cancelled', build: 'skipped', publish: 'skipped' }, 'false', 1],
  ['prepare failed, everything after it skipped', { prepare: 'failure', build: 'skipped', publish: 'skipped' }, 'false', 1],
  ['nothing new: prepare said skip, build and publish skipped', { prepare: 'success', build: 'skipped', publish: 'skipped' }, 'false', 0],
];

for (const name of Object.keys(PUBLISH_EXPECTED)) {
  for (const [what, results, expected, status] of cases) {
    // A tagged release is always meant to publish.
    if (name === 'release.yml' && expected === 'false' && status === 0) continue;
    test(`${name} gate: ${what} -> ${status === 0 ? 'green' : 'red'}`, () => {
      const r = gate(name, results, name === 'release.yml' ? 'true' : expected);
      assert.equal(r.status, status, r.output);
    });
  }
  test(`${name} gate: no job results at all is red`, () => {
    const step = workflow(name).jobs.gate.steps[0];
    const r = spawnSync('bash', ['-e', '-c', step.run], { encoding: 'utf8', env: { ...process.env, NEEDS: '{}', PUBLISH_EXPECTED: 'false' } });
    assert.equal(r.status, 1);
  });
}

test('release.yml gate: a skipped publish is red even when the other jobs succeeded', () => {
  assert.equal(gate('release.yml', { ...ok, publish: 'skipped' }, 'true').status, 1);
});
