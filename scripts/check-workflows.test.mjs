// Tests for check-workflows.mjs. Run: node --test scripts/check-workflows.test.mjs
//
// Each rule is tested in both polarities: a minimal workflow that keeps every
// rule passes, and each mutation of it that breaks one rule fails with that
// rule's name. The repository's own workflows must pass as they stand.

import assert from 'node:assert/strict';
import { accessSync, constants, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkRepository, checkWorkflowText, parseYaml, YamlSubsetError } from './check-workflows.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, 'check-workflows.mjs');

// Where this file's fixtures live: $VISTA_TEST_TMPDIR when set; otherwise
// `.scratch/` at the repository root (gitignored, created on demand);
// otherwise, only when the checkout is not writable, the operating system's
// temp directory, a fallback that says so in `source`. Same rule as
// scripts/release/fixture.mjs, repeated here because this file also ships,
// byte for byte, in a repository that has no release scripts.
export function scratchBase(env = process.env) {
  if (env.VISTA_TEST_TMPDIR) {
    const dir = path.resolve(env.VISTA_TEST_TMPDIR);
    mkdirSync(dir, { recursive: true });
    return { dir, source: 'VISTA_TEST_TMPDIR' };
  }
  const dir = path.join(here, '..', '.scratch');
  try {
    mkdirSync(dir, { recursive: true });
    accessSync(dir, constants.W_OK);
    return { dir, source: 'checkout' };
  } catch {
    return { dir: tmpdir(), source: 'os.tmpdir (fallback: the checkout is not writable)' };
  }
}

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
    '    runs-on: ubuntu-24.04\n',
    '    runs-on: ubuntu-24.04\n    environment: release\n    permissions:\n      contents: write\n',
  );
  assert.deepEqual(rules(t), []);
  // ... but not at the top level, where every job would inherit it.
  assert.ok(rules(replaceOnce(
    replaceOnce(GOOD_PR, '  pull_request:\n    branches: [main]\n', '  workflow_dispatch:\n'),
    'permissions:\n  contents: read\n',
    'permissions:\n  contents: write\n',
  )).includes('trusted'));
});

test('permissions: empty block passes', () => {
  assert.deepEqual(rules(replaceOnce(GOOD_PR, 'permissions:\n  contents: read\n', 'permissions: {}\n')), []);
});

// --- secrets --------------------------------------------------------------

test('secrets: a named secret in a pull-request workflow fails', () => {
  assert.ok(rules(GOOD_PR + '      - run: echo "${{ secrets.SIGNING_KEY }}"\n').includes('secrets'));
  assert.ok(rules(GOOD_PR + "      - run: echo \"${{ secrets['SIGNING_KEY'] }}\"\n").includes('secrets'));
});

test('secrets: the whole secrets context in a pull-request workflow fails', () => {
  assert.ok(rules(GOOD_PR + '      - run: echo "$S"\n        env:\n          S: ${{ toJSON(secrets) }}\n').includes('secrets'));
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

// --- artifact -------------------------------------------------------------

const DOWNLOAD = '      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333  # v8.0.2\n        with:\n          name: bin\n';

test('artifact: a same-run download passes', () => {
  assert.deepEqual(rules(GOOD_PR + DOWNLOAD), []);
});

for (const k of ['run-id', 'github-token', 'repository']) {
  test(`artifact: download-artifact with ${k} fails`, () => {
    assert.ok(rules(GOOD_PR + DOWNLOAD + `          ${k}: x\n`).includes('artifact'));
  });
}

// --- trusted (write-holding) workflows ------------------------------------

// The shape of release.yml: a tag push, nothing at the top level, a read-only
// build and a publishing job that holds its writes inside an environment.
const GOOD_TRUSTED = `name: Release
on:
  push:
    tags: ['v*.*.*']
  workflow_dispatch:
    inputs:
      tag:
        required: true
permissions: {}
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: ${CHECKOUT}
        with:
          persist-credentials: false
      - run: make
  publish:
    needs: [build]
    runs-on: ubuntu-24.04
    environment: release
    permissions:
      contents: write
      id-token: write
      attestations: write
    steps:
      - uses: ${CHECKOUT}
        with:
          persist-credentials: false
      - run: gh release create
        env:
          GH_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`;

function trustedRules(text) {
  return checkWorkflowText(text).violations.filter((v) => v.rule === 'trusted').map((v) => v.message);
}

test('trusted: the release shape passes', () => {
  assert.deepEqual(rules(GOOD_TRUSTED), []);
});

test('trusted: schedule, push to main and an environment given as a mapping pass', () => {
  const t = replaceOnce(
    replaceOnce(GOOD_TRUSTED, "  push:\n    tags: ['v*.*.*']\n", "  schedule:\n    - cron: '17 3 * * *'\n  push:\n    branches: [main]\n    paths: ['compatibility/records/*.json']\n"),
    '    environment: release\n',
    '    environment:\n      name: nightly\n',
  );
  assert.deepEqual(rules(t), []);
});

test('trusted: a read-only workflow with other triggers is not trusted (not over-strict)', () => {
  const t = replaceOnce(GOOD_PR, '  pull_request:\n    branches: [main]\n', '  pull_request:\n    branches: [main]\n  push:\n    branches: [main, develop]\n');
  assert.deepEqual(rules(t), []);
});

const trustedMutations = {
  'pull_request added': (t) => replaceOnce(t, 'on:\n', 'on:\n  pull_request:\n'),
  'workflow_call added': (t) => replaceOnce(t, 'on:\n', 'on:\n  workflow_call:\n'),
  'repository_dispatch added': (t) => replaceOnce(t, 'on:\n', 'on:\n  repository_dispatch:\n'),
  'push to every branch': (t) => replaceOnce(t, "  push:\n    tags: ['v*.*.*']\n", '  push:\n'),
  'push filtered by paths only (every branch)': (t) => replaceOnce(t, "    tags: ['v*.*.*']\n", "    paths: ['src/**']\n"),
  'push to an unprotected branch': (t) => replaceOnce(t, "    tags: ['v*.*.*']\n", "    tags: ['v*.*.*']\n    branches: [main, 'release/**']\n"),
  'push with branches-ignore': (t) => replaceOnce(t, "    tags: ['v*.*.*']\n", "    branches-ignore: [wip]\n"),
  'push to every tag': (t) => replaceOnce(t, "    tags: ['v*.*.*']\n", "    tags: ['*']\n"),
  'build job given contents: write': (t) => replaceOnce(t, '    permissions:\n      contents: read\n', '    permissions:\n      contents: write\n'),
  'build job given id-token: write': (t) => replaceOnce(t, '    permissions:\n      contents: read\n', '    permissions:\n      contents: read\n      id-token: write\n'),
  'publish job outside its environment': (t) => replaceOnce(t, '    environment: release\n', ''),
  'write permissions at the top level': (t) => replaceOnce(t, 'permissions: {}\n', 'permissions:\n  contents: write\n'),
  'write-all at the top level': (t) => replaceOnce(t, 'permissions: {}\n', 'permissions: write-all\n'),
  'a named secret': (t) => replaceOnce(t, 'secrets.GITHUB_TOKEN', 'secrets.RELEASE_APP_KEY'),
  'checkout of another ref': (t) => replaceOnce(t, '      - run: gh release create\n', '      - uses: ' + CHECKOUT + '\n        with:\n          persist-credentials: false\n          ref: \${{ inputs.tag }}\n      - run: gh release create\n'),
  'checkout of another repository': (t) => replaceOnce(t, '      - run: gh release create\n', '      - uses: ' + CHECKOUT + '\n        with:\n          persist-credentials: false\n          repository: someone/fork\n      - run: gh release create\n'),
  'write passed to a reusable workflow': (t) => t.replace(/jobs:\n/, 'jobs:\n  call:\n    uses: ./.github/workflows/build.yml\n    permissions:\n      contents: write\n'),
};

for (const [name, mutate] of Object.entries(trustedMutations)) {
  test(`trusted: ${name} fails`, () => {
    const mutated = mutate(GOOD_TRUSTED);
    assert.notEqual(mutated, GOOD_TRUSTED);
    assert.ok(trustedRules(mutated).length > 0, `no trusted violation: ${JSON.stringify(rules(mutated))}`);
  });
}

test('trusted: the reasons are specific (a reusable call with writes, every branch)', () => {
  assert.ok(trustedRules(trustedMutations['write passed to a reusable workflow'](GOOD_TRUSTED)).some((m) => m.includes('passes write permissions to a reusable workflow')));
  assert.ok(trustedRules(trustedMutations['push filtered by paths only (every branch)'](GOOD_TRUSTED)).some((m) => m.includes('runs on every branch')));
});

test('trusted: the whole secrets context fails', () => {
  assert.ok(trustedRules(replaceOnce(GOOD_TRUSTED, 'secrets.GITHUB_TOKEN', 'toJSON(secrets)')).length > 0);
});

// A reusable workflow holds no writes of its own, but runs inside callers
// that sign what it builds (release.yml and nightly.yml call build-agents.yml).
const GOOD_REUSABLE = `name: Build
on:
  workflow_call:
    inputs:
      version:
        required: true
        type: string
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: ${CHECKOUT}
        with:
          persist-credentials: false
      - run: make
        env:
          GH_TOKEN: \${{ github.token }}
`;

test('reusable: a read-only workflow_call workflow passes', () => {
  assert.deepEqual(rules(GOOD_REUSABLE), []);
});

const reusableMutations = {
  'checkout of another ref': (t) => replaceOnce(t, '          persist-credentials: false\n', '          persist-credentials: false\n          ref: refs/heads/other\n'),
  'checkout of another repository': (t) => replaceOnce(t, '          persist-credentials: false\n', '          persist-credentials: false\n          repository: someone/fork\n'),
  'a named secret': (t) => replaceOnce(t, '${{ github.token }}', '${{ secrets.RELEASE_APP_KEY }}'),
  'the whole secrets context': (t) => replaceOnce(t, '${{ github.token }}', '${{ toJSON(secrets) }}'),
};

for (const [name, mutate] of Object.entries(reusableMutations)) {
  test(`reusable: ${name} fails`, () => {
    const mutated = mutate(GOOD_REUSABLE);
    assert.notEqual(mutated, GOOD_REUSABLE);
    assert.ok(trustedRules(mutated).length > 0, `no trusted violation: ${JSON.stringify(rules(mutated))}`);
  });
}

// A workflow that declares workflow_call declares no other trigger.
const reusableTriggerMutations = {
  'push added': (t) => replaceOnce(t, 'on:\n', 'on:\n  push:\n    branches: [main]\n'),
  'pull_request added': (t) => replaceOnce(t, 'on:\n', 'on:\n  pull_request:\n'),
  'workflow_dispatch added': (t) => replaceOnce(t, 'on:\n', 'on:\n  workflow_dispatch:\n'),
  'schedule added': (t) => replaceOnce(t, 'on:\n', "on:\n  schedule:\n    - cron: '17 3 * * *'\n"),
  'the list form [workflow_call, push]': (t) => replaceOnce(t, /on:\n  workflow_call:\n(?:    .*\n|      .*\n|        .*\n)*?(?=permissions:)/.exec(t)[0], 'on: [workflow_call, push]\n'),
};

for (const [name, mutate] of Object.entries(reusableTriggerMutations)) {
  test(`reusable: workflow_call with ${name} fails (rule reusable)`, () => {
    const mutated = mutate(GOOD_REUSABLE);
    assert.notEqual(mutated, GOOD_REUSABLE);
    assert.ok(rules(mutated).includes('reusable'), JSON.stringify(rules(mutated)));
  });
}

test('reusable: workflow_call alone passes, and so does a workflow with other triggers and no workflow_call (not over-strict)', () => {
  assert.ok(!rules(GOOD_REUSABLE).includes('reusable'));
  assert.deepEqual(rules(GOOD_PR), []);
});

// The real reusable workflow with a push trigger added. It exists in the
// release repository only; the same test file also ships where it does not.
const REAL_BUILD = path.join(here, '..', '.github', 'workflows', 'build-agents.yml');
test('reusable: build-agents.yml with a push trigger added fails (the real file)', { skip: !existsSync(REAL_BUILD) && 'this repository has no build-agents.yml' }, () => {
  const real = readFileSync(REAL_BUILD, 'utf8');
  assert.ok(!rules(real).includes('reusable'), 'the real workflow keeps the rule');
  const mutated = replaceOnce(real, 'on:\n  workflow_call:', 'on:\n  push:\n    branches: [main]\n  workflow_call:');
  assert.ok(rules(mutated).includes('reusable'), JSON.stringify(rules(mutated)));
});

test('trusted: a cache restore in a trusted workflow fails (rule cache)', () => {
  const t = replaceOnce(GOOD_TRUSTED, '      - run: make\n', '      - uses: actions/cache/restore@0400d5f644dc74513175e3cd8d07132dd4860809  # v4.2.4\n        with:\n          path: x\n          key: k\n      - run: make\n');
  assert.ok(rules(t).includes('cache'));
});

test('trusted: an unpinned action in a trusted workflow fails (rule pin)', () => {
  assert.ok(rules(replaceOnce(GOOD_TRUSTED, CHECKOUT, 'actions/checkout@v7')).includes('pin'));
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
  const dir = mkdtempSync(path.join(scratchBase().dir, 'check-workflows-'));
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

// --- where fixtures live ------------------------------------------------------

test('fixtures: the default location is .scratch/ in the checkout, not the system temp directory', () => {
  const base = scratchBase({});
  assert.equal(base.dir, path.join(here, '..', '.scratch'));
  assert.equal(base.source, 'checkout');
  assert.ok(existsSync(base.dir), 'created on demand');
});

test('fixtures: .scratch/ is gitignored, and VISTA_TEST_TMPDIR wins', () => {
  assert.match(readFileSync(path.join(here, '..', '.gitignore'), 'utf8'), /^\.scratch\/$/m);
  const where = path.join(scratchBase().dir, 'override-check');
  try {
    assert.deepEqual(scratchBase({ VISTA_TEST_TMPDIR: where }), { dir: where, source: 'VISTA_TEST_TMPDIR' });
    assert.ok(existsSync(where));
  } finally {
    rmSync(where, { recursive: true, force: true });
  }
});

test('fixtures: the command-line tests leave nothing behind, on success or on failure', () => {
  const before = existsSync(scratchBase().dir) ? readdirSync(scratchBase().dir).filter((n) => n.startsWith('check-workflows-')) : [];
  cli({ 'pr.yml': GOOD_PR });
  cli({ 'pr.yml': replaceOnce(GOOD_PR, 'runs-on: ubuntu-24.04', 'runs-on: [self-hosted]') });
  cli({ 'odd.yml': 'a: &x 1\n' });
  const after = readdirSync(scratchBase().dir).filter((n) => n.startsWith('check-workflows-'));
  assert.deepEqual(after, before);
});
