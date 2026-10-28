// Tests for the release metadata and compatibility record schemas, their
// validator and the rules the schemas cannot state. Run:
//   node --test scripts/release-metadata.test.mjs
//
// Every rule is shown in both polarities: a document the real pipeline
// produced validates, and each mutation of it that breaks one rule fails.

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

import { parseYaml } from './check-workflows.mjs';
import { makeRelease } from './release/fixture.mjs';
import { compile, deepEqual, SchemaError } from './release/jsonschema.mjs';
import { REPO_ROOT, loadSurface } from './release/lib.mjs';
import { releaseNotes } from './release/notes.mjs';
import { recordDescribes, validateDocument } from './release/validate.mjs';
import { sha256File } from './release/lib.mjs';

const rel = makeRelease();
assert.deepEqual(rel.errors, [], 'the fixture release must build');
const release = () => JSON.parse(readFileSync(path.join(rel.assets, 'agents-release.json'), 'utf8'));
const record = () => JSON.parse(readFileSync(path.join(rel.assets, 'compatibility-agents-5.3.0-c1.json'), 'utf8'));
const errs = (doc) => validateDocument(doc, rel.root);

function laterRecord() {
  const r = record();
  r.record_id = 'agents-5.3.0-c2';
  r.supersedes = 'agents-5.3.0-c1';
  r.platform_compatibility = [{ editions: ['core'], platform_versions: ['5.3.0'], status: 'tested', tested_at: '2026-11-20T14:02:11Z', qualification_ref: 'Q-2026-11-20-03' }];
  r.signer.identity = 'https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/compatibility.yml@refs/heads/main';
  return r;
}

test('the pipeline produces a valid release metadata document and record', () => {
  assert.deepEqual(errs(release()), []);
  assert.deepEqual(errs(record()), []);
  assert.deepEqual(recordDescribes(record(), release(), sha256File(path.join(rel.assets, 'agents-release.json'))), []);
  assert.deepEqual(errs(laterRecord()), []);
});

test('the first record of a tagged release is pending for its own version, every edition', () => {
  const r = record();
  assert.equal(r.record_id, 'agents-5.3.0-c1');
  assert.equal(r.supersedes, null);
  assert.deepEqual(r.platform_compatibility, [{ editions: ['core', 'enterprise', 'msp'], platform_versions: ['5.3.0'], status: 'pending', tested_at: null, qualification_ref: null }]);
  assert.ok(r.platform_compatibility.every((c) => c.status === 'pending'));
});

test('metadata.mjs refuses a stable release whose provenance is unavailable, by its own check', () => {
  const r = makeRelease({ tag: 'v5.3.0', provenance: 'unavailable' });
  assert.ok(r.errors.some((e) => /a stable release requires provenance/.test(e)), JSON.stringify(r.errors));
});

test('a nightly release validates, names no platform and records provenance as unavailable', () => {
  const n = makeRelease({ tag: 'nightly-20261119-1a2b3c4d5e6f', provenance: 'unavailable', rootOpts: { license: false, notice: null } });
  assert.deepEqual(n.errors, []);
  const m = JSON.parse(readFileSync(path.join(n.assets, 'agents-release.json'), 'utf8'));
  const c = JSON.parse(readFileSync(path.join(n.assets, 'compatibility-agents-nightly-20261119-1a2b3c4d5e6f-c1.json'), 'utf8'));
  assert.equal(m.release.version, '0.0.0-nightly.20261119.g1a2b3c4d5e6f');
  assert.equal(m.release.channel, 'nightly');
  assert.equal(m.provenance.status, 'unavailable');
  assert.deepEqual(c.platform_compatibility, []);
  assert.deepEqual(validateDocument(m, n.root), []);
  assert.deepEqual(validateDocument(c, n.root), []);
});

test('runtime_qualified is true exactly for what the smoke legs executed', () => {
  const q = release().agents.flatMap((a) => a.artifacts.filter((x) => x.runtime_qualified).map((x) => x.file)).sort();
  assert.deepEqual(q, [
    'install-device-agent.sh', 'install-sensor.sh',
    'vista-device-agent_5.3.0_linux_amd64', 'vista-device-agent_5.3.0_linux_amd64.tar.gz',
    'vista-device-agent_5.3.0_linux_arm64', 'vista-device-agent_5.3.0_linux_arm64.tar.gz',
    'vista-sensor_5.3.0_linux_amd64', 'vista-sensor_5.3.0_linux_amd64.tar.gz',
    'vista-sensor_5.3.0_linux_arm64', 'vista-sensor_5.3.0_linux_arm64.tar.gz',
  ]);
  assert.ok(release().agents.every((a) => a.artifacts.every((x) => x.native_signing === 'none')));
});

test('an artefact the smoke legs did not execute is not runtime_qualified; a missing smoke leg fails', () => {
  const partial = makeRelease({ smokeExecuted: (leg, ex) => (leg.arch === 'arm64' ? ex.filter((f) => !f.startsWith('vista-device-agent_')) : ex) });
  assert.deepEqual(partial.errors, []);
  const m = JSON.parse(readFileSync(path.join(partial.assets, 'agents-release.json'), 'utf8'));
  const q = (f) => m.agents.flatMap((a) => a.artifacts).find((x) => x.file === f).runtime_qualified;
  assert.equal(q('vista-device-agent_5.3.0_linux_arm64'), false);
  assert.equal(q('vista-device-agent_5.3.0_linux_amd64'), true);
  const missing = makeRelease({ smokeExecuted: (leg, ex) => (leg.arch === 'arm64' ? null : ex) });
  assert.ok(missing.errors.some((e) => e.includes('smoke result for linux/arm64 is missing')), missing.errors.join('\n'));
});

test('release notes say what the metadata says: executed or compile-only, the exact signer, no native signing', () => {
  const notes = releaseNotes(release());
  assert.match(notes, /\| sensor \| linux \| amd64 \| `vista-sensor_5\.3\.0_linux_amd64` \| yes \(runtime-qualified\) \| libpcap \|/);
  assert.match(notes, /\| sensor \| windows \| 386 \| `vista-sensor_5\.3\.0_windows_386\.exe` \| no: compile-only, not supported \| npcap \|/);
  assert.ok(notes.includes("--certificate-identity 'https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/v5.3.0'"));
  assert.match(notes, /not Authenticode-signed/);
  assert.match(notes, /Build provenance \(SLSA v1\)/);
  assert.ok(!/releases\/latest/.test(notes));
});

// --- the mutations the brief names, and more --------------------------------

const recordMutations = {
  'a required field dropped (issued_at)': (r) => { delete r.issued_at; },
  'a required field dropped (artifact sha256)': (r) => { delete r.agents[0].artifacts[0].sha256; },
  'status tested with no tested_at': (r) => { r.platform_compatibility[0].status = 'tested'; r.platform_compatibility[0].qualification_ref = 'Q-1'; },
  'status tested with no qualification_ref': (r) => { r.platform_compatibility[0].status = 'tested'; r.platform_compatibility[0].tested_at = '2026-11-20T14:02:11Z'; },
  'a latest URL in artifact.url': (r) => { r.agents[0].artifacts[0].url = 'https://github.com/VistaSecurity/VistaPlatform-Agents/releases/latest/download/' + r.agents[0].artifacts[0].file; },
  'a tag named latest in artifact.url': (r) => { r.agents[0].artifacts[0].url = r.agents[0].artifacts[0].url.replace('/download/v5.3.0/', '/download/latest/'); },
  'an artefact URL of another release': (r) => { r.agents[0].artifacts[0].url = r.agents[0].artifacts[0].url.replace('/download/v5.3.0/', '/download/v5.2.0/'); },
  'a non-hex sha256': (r) => { r.agents[0].artifacts[0].sha256 = 'Z'.repeat(64); },
  'a short sha256': (r) => { r.agents[0].artifacts[0].sha256 = 'a'.repeat(63); },
  'a platform version range': (r) => { r.platform_compatibility[0].platform_versions = ['>=5.3.0']; },
  'an unknown edition': (r) => { r.platform_compatibility[0].editions = ['core', 'premium']; },
  'an unknown property': (r) => { r.notes = 'x'; },
  'a pending claim with a tested_at': (r) => { r.platform_compatibility[0].tested_at = '2026-11-20T14:02:11Z'; },
  'native signing claimed without a value from the enum': (r) => { r.agents[0].artifacts[0].native_signing = 'signed'; },
  'an installer with an architecture': (r) => { r.agents[0].artifacts.find((a) => a.type === 'installer').arch = 'amd64'; },
  'a binary without its SBOM': (r) => { delete r.agents[0].artifacts.find((a) => a.type === 'binary').sbom; },
  'a channel that disagrees with the tag': (r) => { r.agents_release.channel = 'prerelease'; },
  'a version that disagrees with the tag': (r) => { r.agents_release.version = '5.3.1'; },
  'a first record that supersedes something': (r) => { r.supersedes = 'agents-5.3.0-c1'; },
  'a record id of another release': (r) => { r.record_id = 'agents-5.2.0-c1'; },
  'a stable record with an artefact lacking provenance': (r) => { r.agents[0].artifacts[0].provenance = null; },
  'a signer of another repository': (r) => { r.signer.identity = r.signer.identity.replace('VistaPlatform-Agents', 'Other'); },
};

for (const [name, mutate] of Object.entries(recordMutations)) {
  test(`record: ${name} fails`, () => {
    const r = record();
    mutate(r);
    assert.notDeepEqual(r, record());
    assert.ok(errs(r).length > 0, `no error for: ${name}`);
  });
}

test('the schemas alone (without the URL rule) refuse a moving pointer in any asset URL', () => {
  for (const f of ['schemas/compatibility/v1/record.schema.json', 'schemas/release/v1/release.schema.json']) {
    const schema = JSON.parse(readFileSync(path.join(REPO_ROOT, f), 'utf8'));
    const v = compile({ $defs: schema.$defs, $ref: '#/$defs/asset_url' });
    assert.deepEqual(v('https://github.com/o/r/releases/download/v5.3.0/f'), [], f);
    assert.ok(v('https://github.com/o/r/releases/latest/download/f').length > 0, f);
    assert.ok(v('https://github.com/o/r/releases/download/latest/f').length > 0, f);
  }
});

test('record: a tested claim signed by the release workflow fails; by compatibility.yml passes', () => {
  const r = laterRecord();
  assert.deepEqual(errs(r), []);
  r.signer.identity = 'https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/v5.3.0';
  assert.ok(errs(r).length > 0);
});

test('record: a later record must supersede an earlier one of the same release', () => {
  const r = laterRecord();
  r.supersedes = null;
  assert.ok(errs(r).length > 0);
  r.supersedes = 'agents-5.3.0-c3';
  assert.ok(errs(r).length > 0);
  r.supersedes = 'agents-5.2.0-c1';
  assert.ok(errs(r).length > 0);
});

const releaseMutations = {
  'a required field dropped (checksums)': (m) => { delete m.checksums; },
  'a required field dropped (release.source_sha)': (m) => { delete m.release.source_sha; },
  'a stable release without provenance': (m) => { m.provenance = { status: 'unavailable', reason: 'x' }; for (const a of m.agents) for (const x of a.artifacts) x.provenance = null; },
  'a stable release without LICENSE': (m) => { m.notices.license_file = false; },
  'one artefact missing the provenance the others have': (m) => { m.agents[1].artifacts[0].provenance = null; },
  'a latest URL for the checksums': (m) => { m.checksums.url = 'https://github.com/VistaSecurity/VistaPlatform-Agents/releases/latest/download/SHA256SUMS'; },
  'a non-hex sha256': (m) => { m.agents[0].artifacts[0].sha256 = m.agents[0].artifacts[0].sha256.toUpperCase(); },
  'a signing identity of the nightly workflow': (m) => { m.signing.identity = 'https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/nightly.yml@refs/heads/main'; },
  'a signing identity for another tag': (m) => { m.signing.identity = m.signing.identity.replace('v5.3.0', 'v5.3.1'); },
  'a go toolchain other than 1.26': (m) => { m.release.go_version = 'go1.27.0'; },
  'a file twice': (m) => { m.agents[0].artifacts[1] = { ...m.agents[0].artifacts[0] }; },
  'a file name that does not carry its target': (m) => { m.agents[0].artifacts[0].file = 'vista-sensor_5.3.0_linux_arm64'; },
  'a run of another repository': (m) => { m.release.workflow.run_url = 'https://github.com/other/repo/actions/runs/1'; },
  'native signing claimed': (m) => { m.signing.native_signing.windows = 'authenticode-maybe'; },
};

for (const [name, mutate] of Object.entries(releaseMutations)) {
  test(`release: ${name} fails`, () => {
    const m = release();
    mutate(m);
    assert.ok(errs(m).length > 0, `no error for: ${name}`);
  });
}

test('a record does not describe a release whose metadata bytes or artefacts differ', () => {
  const sha = sha256File(path.join(rel.assets, 'agents-release.json'));
  assert.ok(recordDescribes(record(), release(), 'f'.repeat(64)).length > 0);
  const r = record();
  r.agents[0].artifacts[0].sha256 = 'f'.repeat(64);
  assert.ok(recordDescribes(r, release(), sha).length > 0);
  const later = laterRecord();
  later.agents[0].artifacts = later.agents[0].artifacts.slice(0, 2); // a qualified subset: allowed
  assert.deepEqual(recordDescribes(later, release(), sha), []);
  later.agents[0].artifacts[0].size += 1;
  assert.ok(recordDescribes(later, release(), sha).length > 0);
});

// --- the validator ----------------------------------------------------------

test('jsonschema: refuses a keyword it does not enforce, and a remote $ref', () => {
  assert.throws(() => compile({ type: 'object', patternProperties: { x: {} } }), SchemaError);
  assert.throws(() => compile({ $ref: 'https://example.com/s.json' }), SchemaError);
  assert.throws(() => compile({ type: 'string', format: 'email' }), SchemaError);
  assert.throws(() => compile({ $ref: '#/$defs/missing' }), SchemaError);
});

test('jsonschema: each keyword in both polarities', () => {
  const v = compile({
    type: 'object', required: ['a'], additionalProperties: false,
    properties: {
      a: { type: 'string', pattern: '^x', minLength: 2, maxLength: 3 },
      b: { type: 'array', items: { type: 'integer', minimum: 1, maximum: 9 }, minItems: 1, maxItems: 2, uniqueItems: true, contains: { const: 5 } },
      c: { oneOf: [{ type: 'null' }, { type: 'string', format: 'date-time' }] },
      d: { anyOf: [{ const: 1 }, { const: 2 }] },
      e: { not: { const: 'no' } },
      f: { if: { const: 'y' }, then: { type: 'string' }, else: { type: 'integer' } },
      g: { enum: [true, null] },
    },
  });
  assert.deepEqual(v({ a: 'xy', b: [5], c: '2026-01-01T00:00:00Z', d: 2, e: 'yes', f: 3, g: null }), []);
  for (const bad of [
    {}, { a: 'yy' }, { a: 'x' }, { a: 'xyzw' }, { a: 'xy', z: 1 },
    { a: 'xy', b: [] }, { a: 'xy', b: [5, 5] }, { a: 'xy', b: [1, 2] }, { a: 'xy', b: [5, 10] }, { a: 'xy', b: [5, 1.5] },
    { a: 'xy', c: '2026-13-01T00:00:00Z' }, { a: 'xy', c: 5 }, { a: 'xy', d: 3 }, { a: 'xy', e: 'no' }, { a: 'xy', f: 'n' }, { a: 'xy', g: false },
  ]) assert.ok(v(bad).length > 0, JSON.stringify(bad));
});

test('the shared $defs of the two schemas are identical', () => {
  const a = JSON.parse(readFileSync(path.join(REPO_ROOT, 'schemas/compatibility/v1/record.schema.json'), 'utf8')).$defs;
  const b = JSON.parse(readFileSync(path.join(REPO_ROOT, 'schemas/release/v1/release.schema.json'), 'utf8')).$defs;
  const shared = Object.keys(b);
  assert.ok(shared.includes('artifact') && shared.includes('agents') && shared.includes('asset_url'));
  for (const k of shared) assert.ok(deepEqual(a[k], b[k]), `$defs.${k} differs between the schemas`);
});

// The Distribution repository validates compatibility records with ajv in
// strict mode, which refuses a schema whose object, string or array keywords
// appear without the matching "type", or whose "required" names a property
// the same subschema does not define. This walks both schemas for exactly that.
function strictShapeErrors(schema, where = '#', out = []) {
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) return out;
  const kinds = [['object', ['required', 'properties', 'additionalProperties']], ['string', ['pattern', 'minLength', 'maxLength', 'format']], ['array', ['items', 'contains', 'minItems', 'maxItems', 'uniqueItems']]];
  for (const [type, kws] of kinds) {
    if (kws.some((k) => k in schema) && !('$ref' in schema) && ![].concat(schema.type || []).includes(type)) out.push(`${where}: ${kws.filter((k) => k in schema).join(', ')} without type ${type}`);
  }
  for (const r of schema.required || []) if (!schema.properties || !(r in schema.properties)) out.push(`${where}: required "${r}" not in properties`);
  for (const k of ['properties', '$defs']) for (const [n, v] of Object.entries(schema[k] || {})) strictShapeErrors(v, `${where}/${k}/${n}`, out);
  for (const k of ['items', 'additionalProperties', 'contains', 'not', 'if', 'then', 'else']) if (k in schema) strictShapeErrors(schema[k], `${where}/${k}`, out);
  for (const k of ['allOf', 'anyOf', 'oneOf']) (schema[k] || []).forEach((v, i) => strictShapeErrors(v, `${where}/${k}/${i}`, out));
  return out;
}

test('both schemas have the shape ajv strict mode needs (Distribution validates records with it)', () => {
  for (const f of ['schemas/compatibility/v1/record.schema.json', 'schemas/release/v1/release.schema.json']) {
    assert.deepEqual(strictShapeErrors(JSON.parse(readFileSync(path.join(REPO_ROOT, f), 'utf8'))), [], f);
  }
  assert.equal(strictShapeErrors({ required: ['a'] }).length, 2);
  assert.equal(strictShapeErrors({ type: 'string', pattern: 'x' }).length, 0);
});

// --- the release surface and the workflows agree ----------------------------

const wf = (name) => parseYaml(readFileSync(path.join(REPO_ROOT, '.github', 'workflows', name), 'utf8'));

test('build-agents.yml builds exactly the targets in release/agents.json, on the runners it names', () => {
  const surface = loadSurface();
  const want = surface.agents.flatMap((a) => a.targets.map((t) => `${a.kind} ${t.os}/${t.arch} ${t.runner}`)).sort();
  const got = wf('build-agents.yml').jobs.build.strategy.matrix.include.map((m) => `${m.agent} ${m.os}/${m.arch} ${m.runner}`).sort();
  assert.deepEqual(got, want);
  const smokeWant = surface.smoke.map((s) => `${s.os}/${s.arch} ${s.runner}`).sort();
  const smokeGot = wf('build-agents.yml').jobs.smoke.strategy.matrix.include.map((m) => `${m.os}/${m.arch} ${m.runner}`).sort();
  assert.deepEqual(smokeGot, smokeWant);
});

test('the sensor is CGO exactly where it links libpcap; the device agent never is', () => {
  for (const a of loadSurface().agents) {
    for (const t of a.targets) {
      assert.equal(t.cgo, a.kind === 'sensor' && t.os !== 'windows', `${a.kind} ${t.os}/${t.arch}`);
      assert.deepEqual(t.requires, a.kind !== 'sensor' ? [] : t.os === 'windows' ? ['npcap'] : ['libpcap']);
    }
  }
});

test('the three trusted workflows sign in their own environments, from the refs their identities name', () => {
  const r = wf('release.yml');
  const n = wf('nightly.yml');
  const c = wf('compatibility.yml');
  assert.deepEqual(Object.keys(r.on).sort(), ['push', 'workflow_dispatch']);
  assert.deepEqual(r.on.push, { tags: ['v*.*.*'] });
  assert.deepEqual(Object.keys(n.on).sort(), ['schedule', 'workflow_dispatch']);
  assert.deepEqual(Object.keys(c.on), ['push']);
  assert.deepEqual(c.on.push.branches, ['main']);
  for (const [doc, env] of [[r, 'release'], [n, 'nightly'], [c, 'compatibility']]) {
    assert.deepEqual(doc.permissions, {});
    const writers = Object.entries(doc.jobs).filter(([, j]) => j.permissions && Object.values(j.permissions).includes('write'));
    assert.equal(writers.length, 1, `${env}: one job holds write permissions`);
    assert.equal(writers[0][1].environment, env);
  }
  assert.match(r.jobs.publish.env.IDENTITY, /\/release\.yml@\$\{\{ github\.ref \}\}$/);
  assert.match(n.jobs.publish.env.IDENTITY, /\/nightly\.yml@\$\{\{ github\.ref \}\}$/);
  assert.match(c.jobs.sign.env.IDENTITY, /\/compatibility\.yml@\$\{\{ github\.ref \}\}$/);
  assert.equal(r.jobs.build.with['require-notices'], 'true');
  assert.equal(n.jobs.build.with['require-notices'], 'false');
});

test('no workflow publishes with --clobber or moves latest for a prerelease', () => {
  const dir = path.join(REPO_ROOT, '.github', 'workflows');
  const code = (f) => readFileSync(f, 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  for (const f of readdirSync(dir)) assert.ok(!/--clobber/.test(code(path.join(dir, f))), f);
  const gr = code(path.join(REPO_ROOT, 'scripts', 'release', 'github-release.sh'));
  assert.ok(!/--clobber/.test(gr), 'github-release.sh uses --clobber');
  assert.match(gr, /--draft=false --prerelease --latest=false/);
  assert.match(gr, /--verify-tag --draft/);
});

// The capabilities the metadata declares are names the agents' code reports.
// In the bootstrap tree alone there is no Go source; the check runs in the
// assembled repository.
const goRoots = ['cmd', 'shared', 'internal'].map((d) => path.join(REPO_ROOT, d)).filter((d) => existsSync(d));
test('every declared capability is a string constant in the Go source', { skip: goRoots.length === 0 && 'no Go source here (bootstrap tree only)' }, () => {
  const text = [];
  const walk = (d) => {
    for (const n of readdirSync(d)) {
      const p = path.join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else if (n.endsWith('.go') && !n.endsWith('_test.go')) text.push(readFileSync(p, 'utf8'));
    }
  };
  goRoots.forEach(walk);
  const src = text.join('\n');
  for (const a of loadSurface().agents) {
    for (const c of a.capabilities) assert.ok(new RegExp(`=\\s*"${c}"`).test(src), `${a.kind} capability ${c} is not a Go string constant`);
  }
});
