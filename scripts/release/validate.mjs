#!/usr/bin/env node
// Validate release metadata and compatibility records: the JSON schema under
// schemas/, then the rules a schema cannot state (an asset URL names its own
// release and file, a tag agrees with its version and channel, a record's
// signer may make the claims it makes, provenance is all or nothing).
//
//   node scripts/release/validate.mjs FILE...                 # each by its `schema` field
//   node scripts/release/validate.mjs --release R --record C  # ...and C describes R's bytes
//
// Exit 0 valid, 1 invalid (every problem listed), 2 unreadable.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

import { compile, deepEqual } from './jsonschema.mjs';
import {
  REPO_ROOT, RECORD_SCHEMA_ID, RELEASE_SCHEMA_ID, assetUrl, bundleAsset, compatibilityIdentity, parseTag,
  recordFile, releaseIdentity, slugFromRepoUrl, sha256File,
} from './lib.mjs';

const SCHEMA_FILES = {
  [RELEASE_SCHEMA_ID]: 'schemas/release/v1/release.schema.json',
  [RECORD_SCHEMA_ID]: 'schemas/compatibility/v1/record.schema.json',
};
const compiled = new Map();

export function schemaFor(id, root = REPO_ROOT) {
  if (!SCHEMA_FILES[id]) return null;
  const key = `${root}:${id}`;
  if (!compiled.has(key)) compiled.set(key, compile(JSON.parse(readFileSync(path.join(root, SCHEMA_FILES[id]), 'utf8'))));
  return compiled.get(key);
}

function artifactRules(doc, slug, tag, errors) {
  const files = new Set();
  const provenance = [];
  (doc.agents || []).forEach((agent, i) => {
    (agent.artifacts || []).forEach((a, j) => {
      const at = `/agents/${i}/artifacts/${j}`;
      if (files.has(a.file)) errors.push(`${at}: file ${a.file} appears twice`);
      files.add(a.file);
      if (a.url !== assetUrl(slug, tag, a.file)) errors.push(`${at}/url: ${a.url} is not ${assetUrl(slug, tag, a.file)}`);
      if (a.signature && a.signature.bundle_url !== assetUrl(slug, tag, bundleAsset(a.file))) errors.push(`${at}/signature/bundle_url: must be the bundle asset of ${a.file}`);
      if (a.sbom && a.sbom.url !== assetUrl(slug, tag, `${a.file}.cdx.json`)) errors.push(`${at}/sbom/url: must be the SBOM asset of ${a.file}`);
      if (a.type !== 'installer' && !a.file.includes(`_${agent.version}_${a.os}_${a.arch}`)) errors.push(`${at}/file: ${a.file} does not carry ${agent.version}, ${a.os} and ${a.arch}`);
      provenance.push(a.provenance);
    });
  });
  return provenance;
}

function tagRules(r, errors, where) {
  let t;
  try { t = parseTag(r.tag); } catch (e) { errors.push(`${where}/tag: ${e.message}`); return null; }
  if (t.channel !== r.channel) errors.push(`${where}/channel: tag ${r.tag} is ${t.channel}, document says ${r.channel}`);
  if (t.version !== r.version) errors.push(`${where}/version: tag ${r.tag} means version ${t.version}, document says ${r.version}`);
  if (t.nightlyId !== r.nightly_id) errors.push(`${where}/nightly_id: must be ${JSON.stringify(t.nightlyId)}`);
  if (t.channel === 'nightly' && r.source_sha && t.sha12 !== r.source_sha.slice(0, 12)) errors.push(`${where}/source_sha: does not match the nightly tag`);
  return t;
}

export function semanticRelease(doc) {
  const errors = [];
  const r = doc.release || {};
  if (!tagRules(r, errors, '/release')) return errors;
  let slug;
  try { slug = slugFromRepoUrl(r.source_repo); } catch (e) { errors.push(`/release/source_repo: ${e.message}`); return errors; }
  const identity = releaseIdentity(slug, r.tag);
  if (r.workflow && r.workflow.identity !== identity) errors.push(`/release/workflow/identity: must be ${identity}`);
  if (doc.signing && doc.signing.identity !== identity) errors.push(`/signing/identity: must be ${identity}`);
  if (r.workflow && !r.workflow.run_url.startsWith(`https://github.com/${slug}/actions/runs/`)) errors.push('/release/workflow/run_url: not a run of the source repository');
  for (const a of doc.agents || []) if (a.version !== r.version) errors.push(`/agents/${a.kind}/version: ${a.version} is not the release version ${r.version}`);
  const prov = artifactRules(doc, slug, r.tag, errors);
  const p = doc.provenance || {};
  if (p.status === 'attested') {
    if (p.url !== assetUrl(slug, r.tag, 'provenance.intoto.jsonl')) errors.push('/provenance/url: must be the provenance.intoto.jsonl asset');
    const want = { url: p.url, sha256: p.sha256, predicate_type: p.predicate_type };
    if (!prov.every((x) => deepEqual(x, want))) errors.push('/agents/*/artifacts/*/provenance: every artefact must name the release provenance');
  } else if (!prov.every((x) => x === null)) {
    errors.push('/agents/*/artifacts/*/provenance: provenance is unavailable, so every artefact must say null');
  }
  if (doc.checksums) {
    if (doc.checksums.url !== assetUrl(slug, r.tag, 'SHA256SUMS')) errors.push('/checksums/url: must be the SHA256SUMS asset');
    if (doc.checksums.signature_url !== assetUrl(slug, r.tag, bundleAsset('SHA256SUMS'))) errors.push('/checksums/signature_url: must be the SHA256SUMS bundle asset');
  }
  if (doc.notices && doc.notices.third_party_notices && doc.notices.third_party_notices.url !== assetUrl(slug, r.tag, 'THIRD_PARTY_LICENSES')) errors.push('/notices/third_party_notices/url: must be the THIRD_PARTY_LICENSES asset');
  if (doc.initial_record) {
    const t = parseTag(r.tag);
    const id = `agents-${t.channel === 'nightly' ? t.nightlyId : t.version}-c1`;
    if (doc.initial_record.record_id !== id) errors.push(`/initial_record/record_id: must be ${id}`);
    if (doc.initial_record.file !== recordFile(id)) errors.push(`/initial_record/file: must be ${recordFile(id)}`);
    if (doc.initial_record.url !== assetUrl(slug, r.tag, recordFile(id))) errors.push('/initial_record/url: must be the record asset');
  }
  return errors;
}

export function semanticRecord(doc) {
  const errors = [];
  const r = doc.agents_release || {};
  const t = tagRules(r, errors, '/agents_release');
  if (!t) return errors;
  let slug;
  try { slug = slugFromRepoUrl(r.source_repo); } catch (e) { errors.push(`/agents_release/source_repo: ${e.message}`); return errors; }
  const stem = `agents-${t.channel === 'nightly' ? t.nightlyId : t.version}-c`;
  const n = doc.record_id && doc.record_id.startsWith(stem) ? Number(doc.record_id.slice(stem.length)) : NaN;
  if (!Number.isInteger(n) || n < 1) errors.push(`/record_id: must be ${stem}<n> for this release`);
  if (n === 1 && doc.supersedes !== null) errors.push('/supersedes: the first record supersedes nothing');
  if (n > 1) {
    const m = typeof doc.supersedes === 'string' && doc.supersedes.startsWith(stem) ? Number(doc.supersedes.slice(stem.length)) : NaN;
    if (!(Number.isInteger(m) && m >= 1 && m < n)) errors.push(`/supersedes: record ${n} must supersede an earlier record of the same release (${stem}<m>, m < ${n})`);
  }
  if (r.metadata && r.metadata.url !== assetUrl(slug, r.tag, 'agents-release.json')) errors.push('/agents_release/metadata/url: must be the agents-release.json asset of the release');
  for (const a of doc.agents || []) if (a.version !== r.version) errors.push(`/agents/${a.kind}/version: ${a.version} is not the release version ${r.version}`);
  artifactRules(doc, slug, r.tag, errors);
  const claims = doc.platform_compatibility || [];
  const onlyPending = claims.every((c) => c.status === 'pending');
  const allowed = onlyPending ? [releaseIdentity(slug, r.tag), compatibilityIdentity(slug)] : [compatibilityIdentity(slug)];
  if (doc.signer && !allowed.includes(doc.signer.identity)) errors.push(`/signer/identity: ${doc.signer.identity} may not sign this record (allowed: ${allowed.join(' or ')})`);
  if (doc.notices && doc.notices.third_party_notices_url !== assetUrl(slug, r.tag, 'THIRD_PARTY_LICENSES')) errors.push('/notices/third_party_notices_url: must be the THIRD_PARTY_LICENSES asset');
  return errors;
}

// A record describes a release when it names that release, the release
// metadata's exact bytes and exactly the artefacts the metadata lists.
export function recordDescribes(record, release, releaseSha256) {
  const errors = [];
  const ar = record.agents_release || {};
  const r = release.release || {};
  for (const k of ['version', 'tag', 'channel', 'nightly_id', 'source_repo', 'source_sha']) {
    if (ar[k] !== r[k]) errors.push(`/agents_release/${k}: record says ${JSON.stringify(ar[k])}, release says ${JSON.stringify(r[k])}`);
  }
  if (!ar.metadata || ar.metadata.sha256 !== releaseSha256) errors.push('/agents_release/metadata/sha256: does not match agents-release.json');
  if (/-c1$/.test(record.record_id || '')) {
    if (!deepEqual(record.agents, release.agents)) errors.push('/agents: the first record names exactly the artefacts of the release metadata');
  } else {
    // A later record may name a subset (the targets that were qualified),
    // each artefact exactly as the release metadata publishes it.
    const published = new Map();
    for (const a of release.agents || []) for (const x of a.artifacts || []) published.set(`${a.kind}:${x.file}`, x);
    for (const a of record.agents || []) {
      const rel = (release.agents || []).find((b) => b.kind === a.kind);
      if (!rel || rel.variant !== a.variant || rel.version !== a.version) { errors.push(`/agents/${a.kind}: not an agent of the release`); continue; }
      for (const x of a.artifacts || []) {
        if (!deepEqual(published.get(`${a.kind}:${x.file}`), x)) errors.push(`/agents/${a.kind}/${x.file}: not exactly as the release metadata publishes it`);
      }
    }
  }
  if (!deepEqual(record.protocol, release.protocol)) errors.push('/protocol: differs from the release metadata');
  if (!deepEqual(record.modes, release.modes)) errors.push('/modes: differs from the release metadata');
  if (record.notices && release.notices && record.notices.third_party_notices_sha256 !== release.notices.third_party_notices.sha256) errors.push('/notices/third_party_notices_sha256: differs from the release metadata');
  return errors;
}

export function validateDocument(doc, root = REPO_ROOT) {
  const validate = schemaFor(doc && doc.schema, root);
  if (!validate) return [`unknown document type ${JSON.stringify(doc && doc.schema)}`];
  const errors = validate(doc).map((e) => `${e.path}: ${e.message}`);
  if (errors.length) return errors; // semantic rules assume the shape
  return doc.schema === RELEASE_SCHEMA_ID ? semanticRelease(doc) : semanticRecord(doc);
}

function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: { release: { type: 'string' }, record: { type: 'string' } } });
  const files = [...positionals, ...(values.release ? [values.release] : []), ...(values.record ? [values.record] : [])];
  if (files.length === 0) { console.error('usage: validate.mjs FILE... | --release R --record C'); process.exit(2); }
  let bad = 0;
  const docs = new Map();
  for (const f of files) {
    let doc;
    try { doc = JSON.parse(readFileSync(f, 'utf8')); } catch (e) { console.error(`${f}: cannot read: ${e.message}`); process.exit(2); }
    docs.set(f, doc);
    const errors = validateDocument(doc);
    for (const e of errors) console.error(`::error file=${f}::${e}`);
    if (errors.length) bad++;
    else console.log(`${f}: valid ${doc.schema}`);
  }
  if (values.release && values.record) {
    const errors = recordDescribes(docs.get(values.record), docs.get(values.release), sha256File(values.release));
    for (const e of errors) console.error(`::error file=${values.record}::${e}`);
    if (errors.length) bad++;
    else console.log(`${values.record}: describes ${values.release}`);
  }
  process.exit(bad ? 1 : 0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
