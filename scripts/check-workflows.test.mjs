// Tests for check-workflows.mjs. Run: node --test scripts/check-workflows.test.mjs
//
// Each rule is tested in both polarities: a minimal workflow that keeps every
// rule passes, and each mutation of it that breaks one rule fails with that
// rule's name. The repository's own workflows must pass as they stand.

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkRepository, checkWorkflowText, parseYaml, YamlSubsetError } from './check-workflows.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, 'check-workflows.mjs');

const CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1';
const SETUP_GO = 'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e  # v7.0.0';

const GOOD_PR = `name: PR
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: ${CHECKOUT}
        with:
          persist-credentials: false
      - uses: ${SETUP_GO}
        with:
          go-version: '1.26.10'
          cache: false
      - run: go test ./...
`;

function rules(text) {
  return checkWorkflowText(text).violations.map((v) => v.rule);
}

function replaceOnce(text, from, to) {
  assert.ok(text.includes(from), `fixture does not contain ${JSON.stringify(from)}`);
  return text.replace(from, to);
}

test('a workflow that keeps every rule passes', () => {
  assert.deepEqual(rules(GOOD_PR), []);
});

test("this repository's own workflows pass", () => {
  const { files, violations, errors } = checkRepository(path.join(here, '..'));
  assert.ok(files >= 1, 'no workflows found');
  assert.deepEqual(errors, []);
  assert.deepEqual(violations, []);
});

// --- runner ---------------------------------------------------------------

const runnerMutations = {
  'runs-on: [self-hosted]': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'runs-on: [self-hosted]'),
  'runs-on: self-hosted list with linux': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'runs-on: [self-hosted, linux, x64]'),
  'runs-on block list': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'runs-on:\n      - self-hosted\n      - linux'),
  'unknown label': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'runs-on: build-box'),
  'runner group': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'runs-on:\n      group: private-pool'),
  'label from a variable': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'runs-on: ${{ vars.RUNNER }}'),
  'matrix value': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'strategy:\n      matrix:\n        os: [ubuntu-24.04, self-hosted]\n    runs-on: ${{ matrix.os }}'),
  'matrix include value': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'strategy:\n      matrix:\n        include:\n          - os: lab-runner\n    runs-on: ${{ matrix.os }}'),
  'matrix from JSON': (t) => replaceOnce(t, 'runs-on: ubuntu-24.04', 'strategy:\n      matrix: ${{ fromJSON(vars.M) }}\n    runs-on: ${{ matrix.os }}'),
};

for (const [name, mutate] of Object.entries(runnerMutations)) {
  test(`runner: ${name} fails`, () => {
    assert.ok(rules(mutate(GOOD_PR)).includes('runner'));
  });
}

test('runner: hosted matrix and hosted list pass', () => {
  const t = replaceOnce(GOOD_PR, 'runs-on: ubuntu-24.04', 'strategy:\n      matrix:\n        os: [ubuntu-24.04, macos-14, windows-latest]\n    runs-on: ${{ matrix.os }}');
  assert.deepEqual(rules(t), []);
  assert.deepEqual(rules(replaceOnce(GOOD_PR, 'runs-on: ubuntu-24.04', 'runs-on: [ubuntu-24.04-arm]')), []);
});

test('runner: the word in a comment is not a violation', () => {
  assert.deepEqual(rules(GOOD_PR + '# never self-hosted\n'), []);
});

// --- pin ------------------------------------------------------------------

const pinMutations = {
  'tag': (t) => replaceOnce(t, CHECKOUT, 'actions/checkout@v7'),
  'branch': (t) => replaceOnce(t, CHECKOUT, 'actions/checkout@main'),
  'short SHA': (t) => replaceOnce(t, CHECKOUT, 'actions/checkout@3d3c42e5  # v7.0.1'),
  'no version comment': (t) => replaceOnce(t, CHECKOUT, 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'),
  'docker by tag': (t) => replaceOnce(t, CHECKOUT, 'docker://alpine:3.22'),
  'quoted tag': (t) => replaceOnce(t, CHECKOUT, '"actions/checkout@v7"'),
  'reusable workflow by tag': (t) => t.replace(/jobs:\n/, 'jobs:\n  call:\n    uses: someone/workflows/.github/workflows/x.yml@v1\n'),
};

for (const [name, mutate] of Object.entries(pinMutations)) {
  test(`pin: ${name} fails`, () => {
    assert.ok(rules(mutate(GOOD_PR)).includes('pin'));
  });
}

test('pin: local actions and docker digests pass', () => {
  const t = GOOD_PR + '      - uses: ./.github/actions/local\n      - uses: docker://alpine@sha256:' + 'a'.repeat(64) + '\n';
  assert.deepEqual(rules(t), []);
});

// --- trigger --------------------------------------------------------------

test('trigger: pull_request_target fails', () => {
  assert.ok(rules(replaceOnce(GOOD_PR, '  pull_request:\n', '  pull_request_target:\n')).includes('trigger'));
});

test('trigger: workflow_run fails', () => {
  const t = replaceOnce(GOOD_PR, '  pull_request:\n    branches: [main]\n', '  workflow_run:\n    workflows: [PR]\n    types: [completed]\n');
  assert.ok(rules(t).includes('trigger'));
});

test('trigger: list form is read', () => {
  assert.ok(rules(replaceOnce(GOOD_PR, 'on:\n  pull_request:\n    branches: [main]\n', 'on: [push, pull_request_target]\n')).includes('trigger'));
});

// --- permissions ----------------------------------------------------------

const permissionMutations = {
  'top-level contents: write': (t) => replaceOnce(t, 'permissions:\n  contents: read\n', 'permissions:\n  contents: write\n'),
  'top-level write-all': (t) => replaceOnce(t, 'permissions:\n  contents: read\n', 'permissions: write-all\n'),
  'job-level id-token: write': (t) => replaceOnce(t, '    runs-on: ubuntu-24.04\n', '    runs-on: ubuntu-24.04\n    permissions:\n      id-token: write\n'),
  'job-level packages: write': (t) => replaceOnce(t, '    runs-on: ubuntu-24.04\n', '    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      packages: write\n'),
  'no top-level permissions': (t) => replaceOnce(t, 'permissions:\n  contents: read\n', ''),
};

for (const [name, mutate] of Object.entries(permissionMutations)) {
  test(`permissions: ${name} fails`, () => {
    assert.ok(rules(mutate(GOOD_PR)).includes('permissions'));
  });
}

test('permissions: write is allowed outside pull-request workflows (not over-strict)', () => {
  const t = replaceOnce(
    replaceOnce(GOOD_PR, '  pull_request:\n    branches: [main]\n', '  workflow_dispatch:\n'),
    'permissions:\n  contents: read\n',
    'permissions:\n  contents: write\n',
  );
  assert.deepEqual(rules(t), []);
});

test('permissions: empty block passes', () => {
  assert.deepEqual(rules(replaceOnce(GOOD_PR, 'permissions:\n  contents: read\n', 'permissions: {}\n')), []);
});

// --- secrets --------------------------------------------------------------

test('secrets: a named secret in a pull-request workflow fails', () => {
  assert.ok(rules(GOOD_PR + '      - run: echo "${{ secrets.SIGNING_KEY }}"\n').includes('secrets'));
  assert.ok(rules(GOOD_PR + "      - run: echo \"${{ secrets['SIGNING_KEY'] }}\"\n").includes('secrets'));
});

test('secrets: GITHUB_TOKEN is not a named secret', () => {
  assert.deepEqual(rules(GOOD_PR + '      - run: gh pr view\n        env:\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n'), []);
});

test('secrets: inherit fails in any workflow', () => {
  const t = replaceOnce(GOOD_PR, '  pull_request:\n    branches: [main]\n', '  workflow_dispatch:\n')
    .replace(/jobs:\n/, 'jobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n    secrets: inherit\n');
  assert.ok(rules(t).includes('secrets'));
});

// --- cache ----------------------------------------------------------------

test('cache: actions/cache fails', () => {
  assert.ok(rules(GOOD_PR + '      - uses: actions/cache@0400d5f644dc74513175e3cd8d07132dd4860809  # v4.2.4\n        with:\n          path: x\n          key: k\n').includes('cache'));
});

test('cache: setup-go without cache: false fails', () => {
  assert.ok(rules(replaceOnce(GOOD_PR, "          cache: false\n", '')).includes('cache'));
  assert.ok(rules(replaceOnce(GOOD_PR, "          cache: false\n", '          cache: true\n')).includes('cache'));
});

test('cache: setup-node needs package-manager-cache: false', () => {
  const node = '      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1  # v7.1.0\n        with:\n          node-version: 24\n';
  assert.ok(rules(GOOD_PR + node).includes('cache'));
  assert.deepEqual(rules(GOOD_PR + node + '          package-manager-cache: false\n'), []);
  assert.ok(rules(GOOD_PR + node + '          package-manager-cache: false\n          cache: npm\n').includes('cache'));
});

// --- checkout -------------------------------------------------------------

test('checkout: persisted credentials fail', () => {
  assert.ok(rules(replaceOnce(GOOD_PR, '          persist-credentials: false\n', '')).includes('checkout'));
});

// --- YAML subset ----------------------------------------------------------

test('parser: workflow shapes', () => {
  const doc = parseYaml(`on: [push]
a: 'it''s'
b: "tab\\tend"
c: |
  line 1
    line 2
d: >-
  folded
  text

  para
e: {x: 1, y: [a, "b, c"], z: \${{ matrix.v }}}
f:
- one
- k: v
  k2: v2
g: plain # comment
h: "quoted # not a comment"
i: echo don't # comment
`);
  assert.deepEqual(doc, {
    on: ['push'],
    a: "it's",
    b: 'tab\tend',
    c: 'line 1\n  line 2\n',
    d: 'folded text\npara',
    e: { x: '1', y: ['a', 'b, c'], z: '${{ matrix.v }}' },
    f: ['one', { k: 'v', k2: 'v2' }],
    g: 'plain',
    h: 'quoted # not a comment',
    i: "echo don't",
  });
});

test('parser: an apostrophe inside a plain scalar in a flow collection is text', () => {
  assert.deepEqual(parseYaml("p:\n- { name: a, description: Only this site's rows. }\n"), {
    p: [{ name: 'a', description: "Only this site's rows." }],
  });
});

for (const [name, text] of Object.entries({
  anchor: 'a: &x 1\nb: *x\n',
  'merge key': 'a:\n  <<: {b: 1}\n',
  tag: 'a: !secret x\n',
  'two documents': 'a: 1\n---\nb: 2\n',
  'duplicate key': 'a: 1\na: 2\n',
  'tab indentation': 'a:\n\tb: 1\n',
})) {
  test(`parser: ${name} is refused, not guessed`, () => {
    assert.throws(() => parseYaml(text), YamlSubsetError);
  });
}

// --- the command line -----------------------------------------------------

function cli(files) {
  const dir = mkdtempSync(path.join(tmpdir(), 'check-workflows-'));
  try {
    mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
    for (const [name, text] of Object.entries(files)) writeFileSync(path.join(dir, '.github', 'workflows', name), text);
    return spawnSync(process.execPath, [script, dir], { encoding: 'utf8' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('cli: exit 0 clean, 1 on a violation, 2 when a file cannot be read', () => {
  assert.equal(cli({ 'pr.yml': GOOD_PR }).status, 0);
  const bad = cli({ 'pr.yml': GOOD_PR, 'other.yml': replaceOnce(GOOD_PR, 'runs-on: ubuntu-24.04', 'runs-on: [self-hosted]') });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /other\.yml.*\[runner\]/);
  assert.equal(cli({ 'pr.yml': GOOD_PR, 'odd.yml': 'a: &x 1\n' }).status, 2);
  assert.equal(cli({}).status, 2, 'no workflows at all must not pass');
});
