#!/usr/bin/env node
// Write agents-release.json and the release's first compatibility record
// (c1, every claim pending) from the packaged, signed assets, and validate
// both before returning. Runs in the publishing job after every artefact has
// its signature bundle and (where GitHub can attest) the provenance exists.
//
//   node scripts/release/metadata.mjs --assets DIR --state DIR --repo OWNER/REPO \
//        --run-url URL --smoke DIR --provenance attested|unavailable \
//        [--provenance-reason TEXT] --issued-at RFC3339
//
// --smoke holds the smoke legs' results (smoke-<os>-<arch>.json). An
// artefact is runtime_qualified only if a smoke leg of this run executed it;
// a smoke leg the release surface names but whose result is missing fails
// the step. Nothing here infers qualification from a target's name.

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

import {
  OIDC_ISSUER, PROVENANCE_ASSET, RECORD_SCHEMA_ID, RELEASE_SCHEMA_ID, REPO_ROOT, SLSA_PREDICATE, assetUrl,
  bundleAsset, expectedArtifacts, loadSurface, parseTag, recordFile, recordId, releaseIdentity, repoUrl,
  sbomAsset, sha256File, sizeOf, stableJson,
} from './lib.mjs';
import { recordDescribes, validateDocument } from './validate.mjs';

export function readSmoke(dir, surface) {
  const errors = [];
  const qualified = new Set();
  for (const leg of surface.smoke) {
    const f = path.join(dir, `smoke-${leg.os}-${leg.arch}.json`);
    if (!existsSync(f)) { errors.push(`smoke result for ${leg.os}/${leg.arch} is missing (${f})`); continue; }
    const r = JSON.parse(readFileSync(f, 'utf8'));
    if (r.os !== leg.os || r.arch !== leg.arch || r.result !== 'passed') { errors.push(`smoke ${leg.os}/${leg.arch}: ${JSON.stringify({ os: r.os, arch: r.arch, result: r.result })}`); continue; }
    for (const file of r.executed || []) qualified.add(file);
  }
  return { errors, qualified };
}

export function buildMetadata(opts) {
  const root = opts.root || REPO_ROOT;
  const surface = loadSurface(root);
  const state = JSON.parse(readFileSync(path.join(opts.state, 'package.json'), 'utf8'));
  const tag = parseTag(state.tag);
  const slug = opts.repo;
  const url = (f) => assetUrl(slug, tag.tag, f);
  const errors = [];
  const at = (f) => path.join(opts.assets, f);
  const need = (f) => { if (!existsSync(at(f))) errors.push(`missing asset ${f}`); return existsSync(at(f)); };

  const smoke = readSmoke(opts.smoke, surface);
  errors.push(...smoke.errors);

  let provenance;
  if (opts.provenance === 'attested') {
    if (need(PROVENANCE_ASSET)) provenance = { url: url(PROVENANCE_ASSET), sha256: sha256File(at(PROVENANCE_ASSET)), predicate_type: SLSA_PREDICATE };
  } else if (opts.provenance === 'unavailable') {
    if (tag.channel === 'stable') errors.push('a stable release requires provenance');
    if (!opts.provenanceReason) errors.push('--provenance-reason is required when provenance is unavailable');
    if (existsSync(at(PROVENANCE_ASSET))) errors.push(`${PROVENANCE_ASSET} exists but provenance is declared unavailable`);
    provenance = null;
  } else {
    errors.push(`--provenance must be attested or unavailable, got ${JSON.stringify(opts.provenance)}`);
  }

  const artifacts = expectedArtifacts(surface, tag.version);
  const agents = surface.agents.map((agent) => ({
    kind: agent.kind,
    variant: agent.variant,
    version: tag.version,
    artifacts: artifacts.filter((a) => a.kind === agent.kind).map((a) => {
      if (!need(a.file) || !need(bundleAsset(a.file))) return null;
      const out = {
        os: a.os,
        arch: a.arch,
        type: a.type,
        file: a.file,
        url: url(a.file),
        sha256: sha256File(at(a.file)),
        size: sizeOf(at(a.file)),
        signature: { bundle_url: url(bundleAsset(a.file)), sha256: sha256File(at(bundleAsset(a.file))) },
        provenance: provenance === undefined ? null : provenance,
        runtime_qualified: smoke.qualified.has(a.file),
        native_signing: 'none',
        requires: a.requires,
      };
      if (a.type === 'binary' && need(sbomAsset(a.file))) {
        out.sbom = { url: url(sbomAsset(a.file)), sha256: sha256File(at(sbomAsset(a.file))), format: 'CycloneDX-1.6-json' };
      }
      return out;
    }),
  }));
  for (const f of ['THIRD_PARTY_LICENSES']) need(f);
  if (errors.length) return { errors };

  const identity = releaseIdentity(slug, tag.tag);
  const protocol = {
    managed_versions: surface.protocol.managed_versions,
    capabilities: Object.fromEntries(surface.agents.map((a) => [a.kind, [...a.capabilities].sort()])),
    output_versions: surface.protocol.output_versions,
  };
  const firstId = recordId(tag, 1);
  const release = {
    schema: RELEASE_SCHEMA_ID,
    release: {
      version: tag.version,
      tag: tag.tag,
      channel: tag.channel,
      nightly_id: tag.nightlyId,
      source_repo: repoUrl(slug),
      source_sha: state.source_sha,
      source_time: state.source_time,
      go_version: state.go_version,
      workflow: { identity, run_url: opts.runUrl },
    },
    agents,
    protocol,
    modes: surface.modes,
    checksums: { file: 'SHA256SUMS', url: url('SHA256SUMS'), signature_url: url(bundleAsset('SHA256SUMS')) },
    provenance: provenance
      ? { status: 'attested', ...provenance }
      : { status: 'unavailable', reason: opts.provenanceReason },
    signing: { method: 'sigstore-cosign-keyless-bundle', issuer: OIDC_ISSUER, identity, native_signing: surface.native_signing },
    notices: {
      license: surface.license,
      license_file: state.license_file,
      notice_file: state.notice_file,
      third_party_notices: { file: 'THIRD_PARTY_LICENSES', url: url('THIRD_PARTY_LICENSES'), sha256: sha256File(at('THIRD_PARTY_LICENSES')) },
    },
    initial_record: { record_id: firstId, file: recordFile(firstId), url: url(recordFile(firstId)) },
  };
  const releaseText = stableJson(release);
  return { errors: [], release, releaseText, firstId, identity, slug, tag, protocol, agents };
}

export function buildRecord(meta, releaseSha256, issuedAt) {
  const { tag, slug, release } = meta;
  return {
    schema: RECORD_SCHEMA_ID,
    record_id: meta.firstId,
    issued_at: issuedAt,
    supersedes: null,
    agents_release: {
      version: tag.version,
      tag: tag.tag,
      channel: tag.channel,
      nightly_id: tag.nightlyId,
      source_repo: repoUrl(slug),
      source_sha: release.release.source_sha,
      metadata: { url: assetUrl(slug, tag.tag, 'agents-release.json'), sha256: releaseSha256 },
    },
    agents: release.agents,
    protocol: release.protocol,
    modes: release.modes,
    // D04: a tagged release carries the platform number it is to be qualified
    // against; pending until WO-05's qualification publishes a tested record.
    // A nightly names no platform version, so it claims nothing.
    platform_compatibility: tag.channel === 'nightly' ? [] : [{
      editions: ['core', 'enterprise', 'msp'],
      platform_versions: [tag.version],
      status: 'pending',
      tested_at: null,
      qualification_ref: null,
    }],
    signer: { issuer: OIDC_ISSUER, identity: meta.identity },
    notices: {
      license: release.notices.license,
      third_party_notices_url: release.notices.third_party_notices.url,
      third_party_notices_sha256: release.notices.third_party_notices.sha256,
    },
  };
}

export function writeMetadata(opts) {
  const meta = buildMetadata(opts);
  if (meta.errors.length) return meta;
  const releasePath = path.join(opts.assets, 'agents-release.json');
  writeFileSync(releasePath, meta.releaseText);
  const record = buildRecord(meta, sha256File(releasePath), opts.issuedAt);
  const recordPath = path.join(opts.assets, recordFile(meta.firstId));
  writeFileSync(recordPath, stableJson(record));
  const errors = [
    ...validateDocument(meta.release, opts.root).map((e) => `agents-release.json${e}`),
    ...validateDocument(record, opts.root).map((e) => `${recordFile(meta.firstId)}${e}`),
    ...recordDescribes(record, meta.release, sha256File(releasePath)).map((e) => `${recordFile(meta.firstId)}${e}`),
  ];
  return { errors, files: ['agents-release.json', recordFile(meta.firstId)] };
}

function main() {
  const { values } = parseArgs({
    options: {
      assets: { type: 'string' }, state: { type: 'string' }, repo: { type: 'string' }, 'run-url': { type: 'string' },
      smoke: { type: 'string' }, provenance: { type: 'string' }, 'provenance-reason': { type: 'string' },
      'issued-at': { type: 'string' }, root: { type: 'string' },
    },
  });
  for (const k of ['assets', 'state', 'repo', 'run-url', 'smoke', 'provenance', 'issued-at']) {
    if (!values[k]) { console.error(`metadata.mjs: --${k} is required`); process.exit(2); }
  }
  let res;
  try {
    res = writeMetadata({
      assets: values.assets, state: values.state, repo: values.repo, runUrl: values['run-url'], smoke: values.smoke,
      provenance: values.provenance, provenanceReason: values['provenance-reason'], issuedAt: values['issued-at'],
      root: values.root || REPO_ROOT,
    });
  } catch (e) {
    console.error(`metadata.mjs: ${e.message}`);
    process.exit(1);
  }
  if (res.errors.length) {
    for (const e of res.errors) console.error(`::error::metadata: ${e}`);
    process.exit(1);
  }
  console.log(`metadata.mjs: wrote and validated ${res.files.join(', ')}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
