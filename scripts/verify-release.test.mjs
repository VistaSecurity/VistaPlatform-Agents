// Tests for scripts/verify-release.sh against a synthetic release built by
// the real packaging and metadata scripts. Run:
//   node --test scripts/verify-release.test.mjs
//
// Signatures cannot be made here (keyless signing needs a CI identity), so
// these runs use --skip-signatures and test everything else: digests,
// coverage, metadata, packages, records. The signature path is exercised by
// the release workflows themselves, which run this script on their own
// signed assets before and after publishing.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFileSync, cpSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { tarGz } from './release/archive.mjs';
import { REPO, makeRelease, scratchEnv, tempDir } from './release/fixture.mjs';
import { compatibilityIdentity, identityRegexps, releaseIdentity, sha256File } from './release/lib.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const VERIFY = path.join(here, 'verify-release.sh');
const base = makeRelease();
assert.deepEqual(base.errors, []);

function verify(dir, { tag = 'v5.3.0', repo = REPO, skip = true } = {}) {
  const args = [VERIFY, '--repo', repo, '--tag', tag, '--dir', dir];
  if (skip) args.push('--skip-signatures');
  return spawnSync('bash', args, { encoding: 'utf8', env: scratchEnv() });
}

// A fresh copy of the good release for each mutation.
function mutated(fn) {
  const dir = path.join(tempDir('verify-'), 'assets');
  cpSync(base.assets, dir, { recursive: true });
  fn(dir);
  return verify(dir);
}

test('a consistent release passes, and the output says signatures were NOT verified', () => {
  const r = verify(base.assets);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /SIGNATURES AND PROVENANCE NOT VERIFIED/);
  assert.match(r.stdout, /--skip-signatures: cosign and provenance checks are NOT run/);
});

test('without --skip-signatures the script never reports success unless it can verify', () => {
  // With no cosign on PATH it must stop (exit 2), not pass silently.
  const r = spawnSync('bash', [VERIFY, '--repo', REPO, '--tag', 'v5.3.0', '--dir', base.assets], {
    encoding: 'utf8', env: scratchEnv({ PATH: '/usr/bin:/bin' }),
  });
  if (r.status === 2) assert.match(r.stderr, /cosign is required|gh is required/);
  else assert.notEqual(r.status, 0, 'placeholder bundles must not verify');
});

const failing = {
  'a tampered SHA256SUMS line': (d) => {
    const f = path.join(d, 'SHA256SUMS');
    const lines = readFileSync(f, 'utf8').split('\n');
    lines[3] = lines[3].replace(/^[0-9a-f]/, (c) => (c === '0' ? '1' : '0'));
    writeFileSync(f, lines.join('\n'));
  },
  'a renamed asset': (d) => renameSync(path.join(d, 'vista-sensor_5.3.0_linux_amd64'), path.join(d, 'vista-sensor_5.3.0_linux_amd64.bin')),
  'an asset added after signing': (d) => writeFileSync(path.join(d, 'extra-tool.sh'), 'echo hi\n'),
  'a missing asset': (d) => rmSync(path.join(d, 'install-sensor.sh')),
  'a tampered binary, SHA256SUMS regenerated to match': (d) => {
    appendFileSync(path.join(d, 'vista-sensor_5.3.0_linux_amd64'), 'x');
    rmSync(path.join(d, 'SHA256SUMS'));
    spawnSync('bash', [path.join(here, 'release', 'sums.sh'), d]);
  },
  'a malformed SHA256SUMS line': (d) => appendFileSync(path.join(d, 'SHA256SUMS'), 'not a checksum line\n'),
  'a duplicated SHA256SUMS line': (d) => {
    const f = path.join(d, 'SHA256SUMS');
    appendFileSync(f, readFileSync(f, 'utf8').split('\n')[0] + '\n');
  },
  'a signature bundle of no asset': (d) => writeFileSync(path.join(d, 'ghost.sigstore.json'), '{}\n'),
  'a missing signature bundle': (d) => rmSync(path.join(d, 'vista-sensor_5.3.0_linux_amd64.sigstore.json')),
  'metadata for another tag': (d) => {
    const f = path.join(d, 'agents-release.json');
    writeFileSync(f, readFileSync(f, 'utf8').replace(/"tag": "v5\.3\.0"/, '"tag": "v5.3.1"'));
  },
  'a missing compatibility record': (d) => {
    for (const f of ['compatibility-agents-5.3.0-c1.json', 'compatibility-agents-5.3.0-c1.json.sigstore.json']) rmSync(path.join(d, f));
    const s = path.join(d, 'SHA256SUMS');
    writeFileSync(s, readFileSync(s, 'utf8').split('\n').filter((l) => !l.includes('compatibility-')).join('\n'));
  },
  'a later record bound to other metadata': (d) => {
    const rec = JSON.parse(readFileSync(path.join(d, 'compatibility-agents-5.3.0-c1.json'), 'utf8'));
    rec.record_id = 'agents-5.3.0-c2';
    rec.agents_release.metadata.sha256 = 'f'.repeat(64);
    writeFileSync(path.join(d, 'compatibility-agents-5.3.0-c2.json'), JSON.stringify(rec));
    writeFileSync(path.join(d, 'compatibility-agents-5.3.0-c2.json.sigstore.json'), '{}');
  },
  'a later tested record signed by the release workflow': (d) => {
    const rec = JSON.parse(readFileSync(path.join(d, 'compatibility-agents-5.3.0-c1.json'), 'utf8'));
    rec.record_id = 'agents-5.3.0-c2';
    rec.platform_compatibility[0].status = 'tested';
    writeFileSync(path.join(d, 'compatibility-agents-5.3.0-c2.json'), JSON.stringify(rec));
    writeFileSync(path.join(d, 'compatibility-agents-5.3.0-c2.json.sigstore.json'), '{}');
  },
  'a package holding a different binary': (d) => {
    // Swap the amd64 and arm64 sensor packages (and their sums): each still
    // matches SHA256SUMS by name, but holds the other target's binary.
    const a = path.join(d, 'vista-sensor_5.3.0_linux_amd64.tar.gz');
    const b = path.join(d, 'vista-sensor_5.3.0_linux_arm64.tar.gz');
    const t = `${a}.tmp`;
    renameSync(a, t); renameSync(b, a); renameSync(t, b);
    rmSync(path.join(d, 'SHA256SUMS'));
    spawnSync('bash', [path.join(here, 'release', 'sums.sh'), d]);
  },
  'a stable release without provenance': (d) => rmSync(path.join(d, 'provenance.intoto.jsonl')),
};

for (const [name, fn] of Object.entries(failing)) {
  test(`fails: ${name}`, () => {
    const r = mutated(fn);
    assert.equal(r.status, 1, `${name}: exit ${r.status}\n${r.stdout.split('\n').filter((l) => /FAIL/.test(l)).join('\n')}`);
    assert.match(r.stdout, /FAIL/);
  });
}

// Rewrite agents-release.json, keep the record bound to it, and re-list
// SHA256SUMS: a release internally consistent except for the one fault.
function rebound(d, edit) {
  const metaPath = path.join(d, 'agents-release.json');
  const meta = JSON.parse(readFileSync(metaPath, 'utf8'));
  edit(meta);
  writeFileSync(metaPath, JSON.stringify(meta, null, 2) + '\n');
  const recPath = path.join(d, 'compatibility-agents-5.3.0-c1.json');
  const rec = JSON.parse(readFileSync(recPath, 'utf8'));
  rec.agents_release.metadata.sha256 = sha256File(metaPath);
  writeFileSync(recPath, JSON.stringify(rec, null, 2) + '\n');
  rmSync(path.join(d, 'SHA256SUMS'));
  spawnSync('bash', [path.join(here, 'release', 'sums.sh'), d]);
}

test('fails: a stable release whose metadata says provenance is unavailable (all else consistent)', () => {
  const r = mutated((d) => {
    rmSync(path.join(d, 'provenance.intoto.jsonl'));
    rebound(d, (m) => { m.provenance = { status: 'unavailable', reason: 'test' }; });
  });
  assert.equal(r.status, 1, r.stdout);
  assert.match(r.stdout, /a stable release must carry provenance/);
});

test('fails: a package that holds another target\'s binary although every digest agrees', () => {
  const bad = makeRelease({
    // A packager bug: the amd64 package, correctly named and laid out, built
    // around the arm64 binary.
    afterPackage: (a) => writeFileSync(path.join(a, 'vista-sensor_5.3.0_linux_amd64.tar.gz'), tarGz('vista-sensor_5.3.0_linux_amd64', [
      { name: 'crypto-sensor', data: readFileSync(path.join(a, 'vista-sensor_5.3.0_linux_arm64')), mode: 0o755 },
      { name: 'THIRD_PARTY_LICENSES', data: readFileSync(path.join(a, 'THIRD_PARTY_LICENSES')), mode: 0o644 },
    ], 1795000000)),
  });
  assert.deepEqual(bad.errors, []);
  const r = verify(bad.assets);
  assert.equal(r.status, 1, r.stdout);
  assert.match(r.stdout, /FAIL  vista-sensor_5\.3\.0_linux_amd64\.tar\.gz: does not hold vista-sensor_5\.3\.0_linux_amd64/);
});

test('a nightly verifies under its tag, and fails when the metadata names another commit', () => {
  const n = makeRelease({ tag: 'nightly-20261119-1a2b3c4d5e6f', provenance: 'unavailable', rootOpts: { license: false, notice: null } });
  assert.deepEqual(n.errors, []);
  const ok = verify(n.assets, { tag: 'nightly-20261119-1a2b3c4d5e6f' });
  assert.equal(ok.status, 0, ok.stdout);
  assert.match(ok.stdout, /provenance: not available for this nightly release/);
  const metaPath = path.join(n.assets, 'agents-release.json');
  writeFileSync(metaPath, readFileSync(metaPath, 'utf8').replace(/"source_sha": "1a2b3c4d5e6f/, '"source_sha": "ffffffffffff'));
  const r = verify(n.assets, { tag: 'nightly-20261119-1a2b3c4d5e6f' });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /is not the commit nightly-20261119-1a2b3c4d5e6f names/);
});

test('a later pending record attached after the release (not in SHA256SUMS) passes', () => {
  const r = mutated((d) => {
    const rec = JSON.parse(readFileSync(path.join(d, 'compatibility-agents-5.3.0-c1.json'), 'utf8'));
    rec.record_id = 'agents-5.3.0-c2';
    rec.supersedes = 'agents-5.3.0-c1';
    rec.signer.identity = compatibilityIdentity(REPO);
    writeFileSync(path.join(d, 'compatibility-agents-5.3.0-c2.json'), JSON.stringify(rec));
    writeFileSync(path.join(d, 'compatibility-agents-5.3.0-c2.json.sigstore.json'), '{}');
  });
  assert.equal(r.status, 0, r.stdout);
});

test('usage errors exit 2: a tag that is not a release tag, a bad repo', () => {
  assert.equal(verify(base.assets, { tag: 'latest' }).status, 2);
  assert.equal(verify(base.assets, { tag: 'v5.3' }).status, 2);
  assert.equal(verify(base.assets, { repo: 'not a repo' }).status, 2);
});

test('verifying under the wrong repository fails (identity and source_repo are bound)', () => {
  assert.equal(verify(base.assets, { repo: 'someone/fork' }).status, 1);
});

test('the identities in verify-release.sh are the ones lib.mjs builds', () => {
  const sh = readFileSync(VERIFY, 'utf8');
  const expand = (tmpl, tag) => tmpl.replace('${repo}', REPO).replace('${tag}', tag);
  const baseLine = /base="(https:\/\/github\.com\/\$\{repo\}\/\.github\/workflows)"/.exec(sh)[1];
  const rel = /release_identity="\$\{base\}(\/release\.yml@refs\/tags\/\$\{tag\})"/.exec(sh)[1];
  const nig = /release_identity="\$\{base\}(\/nightly\.yml@refs\/heads\/main)"/.exec(sh)[1];
  const com = /compat_identity="\$\{base\}(\/compatibility\.yml@refs\/heads\/main)"/.exec(sh)[1];
  assert.equal(expand(baseLine + rel, 'v5.3.0'), releaseIdentity(REPO, 'v5.3.0'));
  assert.equal(expand(baseLine + nig, ''), releaseIdentity(REPO, 'nightly-20261119-1a2b3c4d5e6f'));
  assert.equal(expand(baseLine + com, ''), compatibilityIdentity(REPO));
  const re = identityRegexps(REPO);
  assert.match(releaseIdentity(REPO, 'v5.3.0'), new RegExp(re.stable));
  assert.doesNotMatch(releaseIdentity(REPO, 'v5.3.0-rc.1'), new RegExp(re.stable));
  assert.match(releaseIdentity(REPO, 'v5.3.0-rc.1'), new RegExp(re.prerelease));
  assert.doesNotMatch(releaseIdentity(REPO, 'nightly-20261119-1a2b3c4d5e6f'), new RegExp(re.stable));
  assert.match(releaseIdentity(REPO, 'nightly-20261119-1a2b3c4d5e6f'), new RegExp(re.nightly));
  assert.doesNotMatch(compatibilityIdentity(REPO), new RegExp(re.nightly));
});

test('packaging is deterministic: two builds of the same inputs give the same bytes', () => {
  const again = makeRelease();
  for (const f of ['vista-sensor_5.3.0_linux_amd64.tar.gz', 'vista-sensor_5.3.0_windows_amd64.zip', 'vista-sensor_5.3.0_linux_amd64.cdx.json', 'THIRD_PARTY_LICENSES']) {
    assert.equal(sha256File(path.join(again.assets, f)), sha256File(path.join(base.assets, f)), f);
  }
});
