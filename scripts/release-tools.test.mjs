// Tests for the release helpers: identifiers, the run resolver, the binary
// checks, the archives, the smoke run, nightly retention and the
// compatibility workflow's append-only rule. Run:
//   node --test scripts/release-tools.test.mjs

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { arch as hostArch, platform } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { tarGz, zip } from './release/archive.mjs';
import { checkBuildInfo, checkVersionStamp } from './release/buildinfo.mjs';
import { classifyChanges } from './release/compat-check.mjs';
import { MODULE, SHA, buildInfoFor, makeRelease, tempDir } from './release/fixture.mjs';
import { assetUrl, loadSurface, nightlyIdentifiers, parseTag } from './release/lib.mjs';
import { plan } from './release/prune-nightlies.mjs';
import { resolve } from './release/resolve.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

// --- identifiers ------------------------------------------------------------

test('tags: the three shapes and nothing else', () => {
  assert.deepEqual(parseTag('v5.3.0'), { tag: 'v5.3.0', channel: 'stable', version: '5.3.0', nightlyId: null });
  assert.equal(parseTag('v5.3.0-rc.2').channel, 'prerelease');
  assert.equal(parseTag('nightly-20261119-1a2b3c4d5e6f').version, '0.0.0-nightly.20261119.g1a2b3c4d5e6f');
  for (const bad of ['5.3.0', 'v5.3', 'v05.3.0', 'v5.3.0-beta.1', 'v5.3.0+build', 'latest', 'nightly-20261319-1a2b3c4d5e6f', 'nightly-20261119-1A2B3C4D5E6F', 'nightly-2026111-1a2b3c4d5e6f']) {
    assert.throws(() => parseTag(bad), Error, bad);
  }
});

test('nightly identifiers carry the date and the commit, and stay valid semver for an all-digit prefix', () => {
  assert.deepEqual(nightlyIdentifiers('20261119', SHA), { tag: 'nightly-20261119-1a2b3c4d5e6f', version: '0.0.0-nightly.20261119.g1a2b3c4d5e6f' });
  const digits = '012345678901' + 'a'.repeat(28);
  assert.match(nightlyIdentifiers('20261119', digits).version, /\.g012345678901$/);
  assert.throws(() => nightlyIdentifiers('2026-11-19', SHA));
  assert.throws(() => nightlyIdentifiers('20261119', 'abc'));
});

test('an asset URL never names a moving pointer', () => {
  assert.equal(assetUrl('o/r', 'v1.0.0', 'f'), 'https://github.com/o/r/releases/download/v1.0.0/f');
  assert.throws(() => assetUrl('o/r', 'latest', 'f'));
});

// --- the run resolver -------------------------------------------------------

const OTHER = 'b'.repeat(40);
function fakeGit({ tags = { 'v5.3.0': SHA }, onMain = [SHA] } = {}) {
  return (...args) => {
    if (args[0] === 'rev-parse') {
      const t = args[2].replace(/^refs\/tags\//, '').replace(/\^\{commit\}$/, '');
      if (!(t in tags)) throw new Error('unknown');
      return tags[t];
    }
    if (args[0] === 'merge-base') { if (!onMain.includes(args[2])) throw new Error('not ancestor'); return ''; }
    if (args[0] === 'show') return '2026-11-19T10:20:30Z';
    throw new Error(`unexpected git ${args.join(' ')}`);
  };
}
const tagPush = { GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/tags/v5.3.0', GITHUB_SHA: SHA };

test('resolve: a tag push and a dispatch on the tag', () => {
  assert.deepEqual(resolve('release', tagPush, fakeGit()), { tag: 'v5.3.0', version: '5.3.0', channel: 'stable', source_sha: SHA, source_time: '2026-11-19T10:20:30Z' });
  assert.equal(resolve('release', { ...tagPush, GITHUB_EVENT_NAME: 'workflow_dispatch', INPUT_TAG: 'v5.3.0' }, fakeGit()).tag, 'v5.3.0');
});

const refusals = {
  'a dispatch on main': ['release', { GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: SHA, INPUT_TAG: 'v5.3.0' }, fakeGit()],
  'a dispatch whose input names another tag': ['release', { ...tagPush, GITHUB_EVENT_NAME: 'workflow_dispatch', INPUT_TAG: 'v5.2.0' }, fakeGit()],
  'a tag on a commit that is not on main': ['release', tagPush, fakeGit({ onMain: [] })],
  'a tag pointing elsewhere than the built commit': ['release', tagPush, fakeGit({ tags: { 'v5.3.0': OTHER } })],
  'a nightly tag pushed to release.yml': ['release', { ...tagPush, GITHUB_REF: 'refs/tags/nightly-20261119-1a2b3c4d5e6f' }, fakeGit({ tags: { 'nightly-20261119-1a2b3c4d5e6f': SHA } })],
  'a tag that is not semver': ['release', { ...tagPush, GITHUB_REF: 'refs/tags/v5.3.0-beta' }, fakeGit({ tags: { 'v5.3.0-beta': SHA } })],
  'a pull request': ['release', { ...tagPush, GITHUB_EVENT_NAME: 'pull_request' }, fakeGit()],
  'a nightly from another branch': ['nightly', { GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: 'refs/heads/feature', GITHUB_SHA: SHA, NIGHTLY_DATE: '20261119' }, fakeGit()],
  'a nightly of a commit not on main': ['nightly', { GITHUB_EVENT_NAME: 'schedule', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: SHA, NIGHTLY_DATE: '20261119' }, fakeGit({ onMain: [] })],
  'a nightly on a push': ['nightly', { GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: SHA, NIGHTLY_DATE: '20261119' }, fakeGit()],
};
for (const [name, [kind, env, git]] of Object.entries(refusals)) {
  test(`resolve refuses ${name}`, () => assert.throws(() => resolve(kind, env, git)));
}

test('resolve: a scheduled nightly of main', () => {
  const r = resolve('nightly', { GITHUB_EVENT_NAME: 'schedule', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: SHA, NIGHTLY_DATE: '20261119' }, fakeGit());
  assert.equal(r.tag, 'nightly-20261119-1a2b3c4d5e6f');
  assert.equal(r.channel, 'nightly');
});

// --- binary checks ----------------------------------------------------------

const sensor = loadSurface().agents.find((a) => a.kind === 'sensor');
const linux = sensor.targets.find((t) => t.os === 'linux' && t.arch === 'amd64');
const expect = { modulePath: MODULE, command: 'cmd/sensor', goos: 'linux', goarch: 'amd64', cgo: true, version: '5.3.0', sourceSha: SHA, goVersion: 'go1.26.10' };
const setting = (info, key, value) => ({ ...info, Settings: info.Settings.map((s) => (s.Key === key ? { ...s, Value: value } : s)) });

test('buildinfo: a correct binary passes', () => {
  assert.deepEqual(checkBuildInfo(buildInfoFor(sensor, linux, '5.3.0'), expect), []);
});

const binMutations = {
  'ldflags recorded (no -trimpath)': (i) => ({ ...i, Settings: [...i.Settings, { Key: '-ldflags', Value: '-X main.Version=5.3.0' }] }),
  'modified working tree': (i) => setting(i, 'vcs.modified', 'true'),
  'another commit': (i) => setting(i, 'vcs.revision', 'c'.repeat(40)),
  'no -trimpath': (i) => setting(i, '-trimpath', 'false'),
  'another OS': (i) => setting(i, 'GOOS', 'darwin'),
  'CGO off for the Linux sensor': (i) => setting(i, 'CGO_ENABLED', '0'),
  'another toolchain': (i) => ({ ...i, GoVersion: 'go1.27.0' }),
  'another command': (i) => ({ ...i, Path: `${MODULE}/cmd/device-agent` }),
  'a replaced module': (i) => ({ ...i, Deps: [{ Path: 'x/y', Version: 'v1.0.0', Replace: { Path: '../y' } }] }),
  'build tags': (i) => ({ ...i, Settings: [...i.Settings, { Key: '-tags', Value: 'ee' }] }),
};
for (const [name, m] of Object.entries(binMutations)) {
  test(`buildinfo: ${name} fails`, () => assert.ok(checkBuildInfo(m(buildInfoFor(sensor, linux, '5.3.0')), expect).length > 0));
}

test('version stamp: the binary must carry the release version', () => {
  assert.deepEqual(checkVersionStamp(Buffer.from('xx 5.3.0 yy'), '5.3.0'), []);
  assert.equal(checkVersionStamp(Buffer.from('xx dev yy'), '5.3.0').length, 1);
  const r = makeRelease({ exeContent: (a, t) => (a.kind === 'sensor' && t.os === 'darwin' ? 'stamped dev\n' : `stamped 5.3.0 ${t.os}/${t.arch}\n`) });
  assert.ok(r.errors.some((e) => e.includes('sensor darwin/amd64') && e.includes('does not contain')), r.errors.join('\n'));
});

test('packaging refuses a binary that fails its check, and writes nothing', () => {
  const r = makeRelease({ infoOverride: (a, t) => (a.kind === 'device-agent' && t.os === 'windows' ? { GoVersion: 'go1.25.0' } : {}) });
  assert.ok(r.errors.some((e) => e.includes('device-agent windows/amd64') && e.includes('Go toolchain')), r.errors.join('\n'));
  assert.equal(r.assets, undefined);
});

// --- archives ---------------------------------------------------------------

test('archives read back with tar and unzip, keep modes, and allow long names', () => {
  const dir = tempDir('archive-');
  const long = 'vista-device-agent_0.0.0-nightly.20261119.g1a2b3c4d5e6f_windows_amd64';
  const entries = [
    { name: 'device-agent', data: Buffer.from('#!/bin/sh\necho hi\n'), mode: 0o755 },
    { name: 'THIRD_PARTY_LICENSES-with-a-rather-long-name-to-cross-one-hundred-bytes.txt', data: Buffer.from('x'.repeat(1000)), mode: 0o644 },
  ];
  writeFileSync(path.join(dir, 'a.tar.gz'), tarGz(long, entries, 1795000000));
  writeFileSync(path.join(dir, 'a.zip'), zip(long, entries, 1795000000));
  mkdirSync(path.join(dir, 't'));
  execFileSync('tar', ['-xzf', path.join(dir, 'a.tar.gz'), '-C', path.join(dir, 't')]);
  assert.equal(readFileSync(path.join(dir, 't', long, entries[1].name), 'utf8'), 'x'.repeat(1000));
  assert.equal(execFileSync('stat', ['-c', '%a', path.join(dir, 't', long, 'device-agent')], { encoding: 'utf8' }).trim(), '755');
  mkdirSync(path.join(dir, 'z'));
  execFileSync('unzip', ['-q', path.join(dir, 'a.zip'), '-d', path.join(dir, 'z')]);
  assert.equal(readFileSync(path.join(dir, 'z', long, 'device-agent'), 'utf8'), '#!/bin/sh\necho hi\n');
  assert.deepEqual(tarGz(long, entries, 1795000000), tarGz(long, entries, 1795000000));
  assert.deepEqual(zip(long, entries, 1795000000), zip(long, entries, 1795000000));
});

// --- smoke ------------------------------------------------------------------

const machine = { x64: 'amd64', arm64: 'arm64' }[hostArch()];
// A stand-in executable: carries the stamped version (as a real binary's data
// does) and prints a -version report, here with whatever version report()
// says.
const fakeExe = (report) => (agent, t, version) => (t.os === 'linux'
  ? `#!/bin/sh\n# stamped ${version}\necho "Vista Platform agent v${report(version)}"\necho "Platform: ${t.os}/${t.arch}"\n`
  : `fake, stamped ${version}\n`);

test('smoke: the packaged agents run here and are reported as executed', { skip: (platform() !== 'linux' || !machine) && 'smoke.sh runs on Linux amd64/arm64' }, () => {
  const r = makeRelease({ exeContent: fakeExe((v) => v) });
  assert.deepEqual(r.errors, []);
  const out = path.join(r.dir, 'smoke.json');
  const res = spawnSync('bash', [path.join(here, 'release', 'smoke.sh'), r.assets, '5.3.0', out], { encoding: 'utf8' });
  assert.equal(res.status, 0, res.stdout + res.stderr);
  const j = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(j.result, 'passed');
  assert.equal(j.arch, machine);
  assert.deepEqual(j.executed, [
    'install-device-agent.sh', 'install-sensor.sh',
    `vista-device-agent_5.3.0_linux_${machine}`, `vista-device-agent_5.3.0_linux_${machine}.tar.gz`,
    `vista-sensor_5.3.0_linux_${machine}`, `vista-sensor_5.3.0_linux_${machine}.tar.gz`,
  ]);
});

test('smoke: a binary that reports another version fails', { skip: (platform() !== 'linux' || !machine) && 'smoke.sh runs on Linux amd64/arm64' }, () => {
  const r = makeRelease({ exeContent: fakeExe(() => '5.2.0') });
  const res = spawnSync('bash', [path.join(here, 'release', 'smoke.sh'), r.assets, '5.3.0', path.join(r.dir, 's.json')], { encoding: 'utf8' });
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /does not report v5\.3\.0/);
});

test('smoke: a package whose binary differs from the published one fails', { skip: (platform() !== 'linux' || !machine) && 'smoke.sh runs on Linux amd64/arm64' }, () => {
  const r = makeRelease({ exeContent: fakeExe((v) => v) });
  writeFileSync(path.join(r.assets, `vista-sensor_5.3.0_linux_${machine}`), '#!/bin/sh\necho other\n');
  const res = spawnSync('bash', [path.join(here, 'release', 'smoke.sh'), r.assets, '5.3.0', path.join(r.dir, 's.json')], { encoding: 'utf8' });
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /differs from/);
});

// --- nightly retention (dry run) -------------------------------------------

test('retention keeps the newest, the referenced, the retained and the young; never touches stable', () => {
  const day = 86400e3;
  const now = Date.parse('2026-12-31T00:00:00Z');
  const n = (d, sha, extra = {}) => ({ tag_name: `nightly-202611${String(d).padStart(2, '0')}-${sha}`, draft: false, published_at: new Date(Date.parse(`2026-11-${String(d).padStart(2, '0')}T04:00:00Z`)).toISOString(), assets: [], ...extra });
  const releases = [
    n(1, 'aaaaaaaaaaaa'), n(2, 'bbbbbbbbbbbb'), n(3, 'cccccccccccc'), n(4, 'dddddddddddd', { assets: [{ name: 'compatibility-agents-nightly-20261104-dddddddddddd-c2.json' }] }),
    n(5, 'eeeeeeeeeeee', { draft: true }), n(29, 'ffffffffffff'),
    { tag_name: 'v5.3.0', draft: false, published_at: '2026-01-01T00:00:00Z' },
  ];
  const p = plan({ releases, recordTags: new Set(['nightly-20261102-bbbbbbbbbbbb']), retained: new Set(['nightly-20261103-cccccccccccc']), days: 30, keepLatest: 1, now });
  assert.deepEqual(p.remove.map((r) => r.tag), ['nightly-20261101-aaaaaaaaaaaa']);
  assert.deepEqual(p.quarantined, ['nightly-20261105-eeeeeeeeeeee']);
  const kept = Object.fromEntries(p.keep.map((k) => [k.tag, k.reasons.join('; ')]));
  assert.match(kept['nightly-20261102-bbbbbbbbbbbb'], /compatibility record/);
  assert.match(kept['nightly-20261103-cccccccccccc'], /retained-nightlies/);
  assert.match(kept['nightly-20261104-dddddddddddd'], /compatibility record/);
  assert.match(kept['nightly-20261129-ffffffffffff'], /newest 1/);
  assert.ok(!p.remove.some((r) => r.tag === 'v5.3.0') && !p.keep.some((r) => r.tag === 'v5.3.0'));
  void day;
});

test('retention script prints a dry run and deletes nothing (no gh call in it)', () => {
  const src = readFileSync(path.join(here, 'release', 'prune-nightlies.mjs'), 'utf8');
  assert.ok(!/execFile|spawn|child_process/.test(src), 'the dry run must not be able to run commands');
});

// --- compatibility records are append-only ----------------------------------

test('compat-check: an added record passes; a modified, deleted or renamed one fails', () => {
  assert.deepEqual(classifyChanges('A\tcompatibility/records/agents-5.3.0-c2.json\n'), { errors: [], added: ['compatibility/records/agents-5.3.0-c2.json'] });
  for (const s of ['M\tcompatibility/records/agents-5.3.0-c2.json', 'D\tcompatibility/records/agents-5.3.0-c2.json', 'T\tcompatibility/records/agents-5.3.0-c2.json']) {
    assert.ok(classifyChanges(s).errors.length > 0, s);
  }
  assert.ok(classifyChanges('A\tcompatibility/records/notes.txt').errors.length > 0);
  assert.deepEqual(classifyChanges('M\tREADME.md\nA\tcompatibility/records/README.md').errors, []);
});

// --- publishing: the rules that keep a release immutable --------------------
//
// scripts/release/github-release.sh against a stand-in `gh` on PATH that
// answers from environment variables and logs every call, so each rule is
// exercised without GitHub: a draft or a published release for the tag stops
// a run, a candidate or nightly never becomes latest, a published tag must
// resolve to the built commit, a nightly tag is never moved.

const GH_STUB = `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_LOG"
case "$*" in
  *"releases?per_page=100"*) printf '%s' "\${FAKE_RELEASES:-}"; [ -z "\${FAKE_RELEASES:-}" ] || echo ;;
  *"git/refs"*) exit "\${FAKE_POST_RC:-0}" ;;
  *"git/ref/tags/"*) echo "$FAKE_REF_SHA" ;;
  *"/commits/"*) echo "$FAKE_COMMIT" ;;
  "release view"*) echo "\${FAKE_ASSETS:-0}" ;;
  "release "*) ;;
  *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
`;

function ghRelease(args, env = {}) {
  const dir = tempDir('gh-stub-');
  const bin = path.join(dir, 'bin');
  mkdirSync(bin);
  writeFileSync(path.join(bin, 'gh'), GH_STUB, { mode: 0o755 });
  const log = path.join(dir, 'gh.log');
  writeFileSync(log, '');
  const r = spawnSync('bash', [path.join(here, 'release', 'github-release.sh'), ...args], {
    encoding: 'utf8',
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_LOG: log, ...env },
  });
  return { status: r.status, out: r.stdout + r.stderr, calls: readFileSync(log, 'utf8').split('\n').filter(Boolean) };
}

const REPO_SLUG = 'VistaSecurity/VistaPlatform-Agents';

test('publish: precheck passes with no release, and fails on a draft or a published one', () => {
  assert.equal(ghRelease(['precheck', REPO_SLUG, 'v5.3.0']).status, 0);
  const draft = ghRelease(['precheck', REPO_SLUG, 'v5.3.0'], { FAKE_RELEASES: '101 true' });
  assert.equal(draft.status, 1);
  assert.match(draft.out, /unpublished draft/);
  const published = ghRelease(['precheck', REPO_SLUG, 'v5.3.0'], { FAKE_RELEASES: '101 false' });
  assert.equal(published.status, 1);
  assert.match(published.out, /already published/);
});

test('publish: a draft is created against an existing tag, never as latest; only stable is not a prerelease', () => {
  const stable = ghRelease(['draft', REPO_SLUG, 'v5.3.0', 'stable', 'notes.md']);
  assert.equal(stable.status, 0);
  assert.match(stable.calls[0], /^release create v5\.3\.0 .*--verify-tag --draft .*--latest=false/);
  assert.doesNotMatch(stable.calls[0], /--prerelease/);
  for (const [tag, channel] of [['v5.3.0-rc.1', 'prerelease'], ['nightly-20261119-1a2b3c4d5e6f', 'nightly']]) {
    assert.match(ghRelease(['draft', REPO_SLUG, tag, channel, 'notes.md']).calls[0], /--draft .*--latest=false --prerelease/);
  }
});

test('publish: only stable becomes latest, and a published tag must resolve to the built commit', () => {
  const stable = ghRelease(['publish', REPO_SLUG, 'v5.3.0', 'stable', SHA], { FAKE_COMMIT: SHA });
  assert.equal(stable.status, 0);
  assert.match(stable.calls[0], /^release edit v5\.3\.0 .*--draft=false --latest$/);
  for (const [tag, channel] of [['v5.3.0-rc.1', 'prerelease'], ['nightly-20261119-1a2b3c4d5e6f', 'nightly']]) {
    const r = ghRelease(['publish', REPO_SLUG, tag, channel, SHA], { FAKE_COMMIT: SHA });
    assert.equal(r.status, 0);
    assert.match(r.calls[0], /--draft=false --prerelease --latest=false$/);
  }
  const moved = ghRelease(['publish', REPO_SLUG, 'v5.3.0', 'stable', SHA], { FAKE_COMMIT: 'f'.repeat(40) });
  assert.equal(moved.status, 1);
  assert.match(moved.out, /not the built commit/);
});

test('publish: upload never clobbers and fails when the draft holds another number of assets', () => {
  const dir = tempDir('upload-');
  for (const f of ['a', 'b']) writeFileSync(path.join(dir, f), f);
  const ok = ghRelease(['upload', REPO_SLUG, 'v5.3.0', dir], { FAKE_ASSETS: '2' });
  assert.equal(ok.status, 0);
  assert.ok(ok.calls.every((c) => !/--clobber/.test(c)));
  assert.equal(ghRelease(['upload', REPO_SLUG, 'v5.3.0', dir], { FAKE_ASSETS: '3' }).status, 1);
});

test('publish: a nightly tag must name the commit, is never moved, and must read back at the commit', () => {
  const tag = `nightly-20261119-${SHA.slice(0, 12)}`;
  assert.equal(ghRelease(['nightly-tag', REPO_SLUG, tag, SHA], { FAKE_REF_SHA: SHA }).status, 0);
  const wrongName = ghRelease(['nightly-tag', REPO_SLUG, 'nightly-20261119-ffffffffffff', SHA], { FAKE_REF_SHA: SHA });
  assert.equal(wrongName.status, 1);
  assert.deepEqual(wrongName.calls, [], 'no API call before the name is checked');
  assert.equal(ghRelease(['nightly-tag', REPO_SLUG, `v5.3.0-${SHA.slice(0, 12)}`, SHA], { FAKE_REF_SHA: SHA }).status, 1, 'only the nightly shape');
  const exists = ghRelease(['nightly-tag', REPO_SLUG, tag, SHA], { FAKE_POST_RC: '1', FAKE_REF_SHA: SHA });
  assert.equal(exists.status, 1);
  assert.match(exists.out, /never moved/);
  assert.equal(ghRelease(['nightly-tag', REPO_SLUG, tag, SHA], { FAKE_REF_SHA: 'f'.repeat(40) }).status, 1);
});
