// Shared definitions of the release scripts: asset names, release
// identifiers, signer identities. Zero dependencies (Node >= 20).
//
// Every name and identity a customer's verifier depends on is built here and
// nowhere else in JavaScript; scripts/verify-release.sh carries the same
// identity strings in shell and scripts/verify-release.test.mjs checks that the
// two agree.

import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
export const SLSA_PREDICATE = 'https://slsa.dev/provenance/v1';
export const RELEASE_SCHEMA_ID = 'vista.agents-release/v1';
export const RECORD_SCHEMA_ID = 'vista.agent-compatibility/v1';

export const STABLE_TAG = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
export const RC_TAG = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-rc\.(0|[1-9]\d*)$/;
export const NIGHTLY_TAG = /^nightly-(\d{8})-([0-9a-f]{12})$/;
const SLUG = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function loadSurface(root = REPO_ROOT) {
  return JSON.parse(readFileSync(path.join(root, 'release', 'agents.json'), 'utf8'));
}

// A tag to its channel and agent version. Throws on anything else: the
// release workflows accept these three shapes and nothing more.
export function parseTag(tag) {
  if (STABLE_TAG.test(tag)) return { tag, channel: 'stable', version: tag.slice(1), nightlyId: null };
  if (RC_TAG.test(tag)) return { tag, channel: 'prerelease', version: tag.slice(1), nightlyId: null };
  const m = NIGHTLY_TAG.exec(tag);
  if (m) {
    checkDate(m[1]);
    return { tag, channel: 'nightly', version: nightlyVersion(m[1], m[2]), nightlyId: tag, date: m[1], sha12: m[2] };
  }
  throw new Error(`not a release tag: ${JSON.stringify(tag)} (want vX.Y.Z, vX.Y.Z-rc.N or nightly-YYYYMMDD-<12 hex>)`);
}

function checkDate(d) {
  const iso = `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}T00:00:00Z`;
  const t = Date.parse(iso);
  if (Number.isNaN(t) || new Date(t).toISOString().slice(0, 10) !== iso.slice(0, 10)) throw new Error(`not a calendar date: ${d}`);
}

// D19: the immutable nightly identifier carries the UTC date and the source
// commit. The agent version stamped into the binaries is a semver
// pre-release that sorts below every real release and claims no number of
// its own (D04 numbers belong to tagged releases); the "g" keeps the commit
// field alphanumeric, which semver needs when a 12-hex prefix is all digits.
export function nightlyIdentifiers(date, sourceSha) {
  if (!/^\d{8}$/.test(date)) throw new Error(`nightly date must be YYYYMMDD, got ${JSON.stringify(date)}`);
  checkDate(date);
  if (!/^[0-9a-f]{40}$/.test(sourceSha)) throw new Error(`source sha must be 40 hex, got ${JSON.stringify(sourceSha)}`);
  const sha12 = sourceSha.slice(0, 12);
  return { tag: `nightly-${date}-${sha12}`, version: nightlyVersion(date, sha12) };
}

export function nightlyVersion(date, sha12) {
  return `0.0.0-nightly.${date}.g${sha12}`;
}

export function repoUrl(slug) {
  if (!SLUG.test(slug)) throw new Error(`not an owner/repo slug: ${JSON.stringify(slug)}`);
  return `https://github.com/${slug}`;
}

export function slugFromRepoUrl(url) {
  const m = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)$/.exec(url);
  if (!m) throw new Error(`not a repository URL: ${url}`);
  return m[1];
}

export function assetUrl(slug, tag, file) {
  if (tag === 'latest') throw new Error('a release tag named latest is refused');
  return `${repoUrl(slug)}/releases/download/${tag}/${file}`;
}

// The certificate identity (Fulcio SAN) of each signer. Exact strings: a
// verifier that knows the tag it is checking uses these, not a regexp.
export function releaseIdentity(slug, tag) {
  const { channel } = parseTag(tag);
  return channel === 'nightly'
    ? `${repoUrl(slug)}/.github/workflows/nightly.yml@refs/heads/main`
    : `${repoUrl(slug)}/.github/workflows/release.yml@refs/tags/${tag}`;
}

export function compatibilityIdentity(slug) {
  return `${repoUrl(slug)}/.github/workflows/compatibility.yml@refs/heads/main`;
}

// The regular expressions published for verifiers that check a channel
// rather than one tag (docs/verify-release.md).
export function identityRegexps(slug) {
  const r = repoUrl(slug).replace(/[.]/g, '\\.');
  const w = `${r}/\\.github/workflows`;
  return {
    stable: `^${w}/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$`,
    prerelease: `^${w}/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+-rc\\.[0-9]+$`,
    nightly: `^${w}/nightly\\.yml@refs/heads/main$`,
    compatibility: `^${w}/compatibility\\.yml@refs/heads/main$`,
  };
}

export function exeSuffix(os) {
  return os === 'windows' ? '.exe' : '';
}

export function binaryAsset(agent, version, os, arch) {
  return `${agent.asset_prefix}_${version}_${os}_${arch}${exeSuffix(os)}`;
}

export function packageAsset(agent, version, os, arch) {
  return `${agent.asset_prefix}_${version}_${os}_${arch}${os === 'windows' ? '.zip' : '.tar.gz'}`;
}

export function packageRoot(agent, version, os, arch) {
  return `${agent.asset_prefix}_${version}_${os}_${arch}`;
}

export function sbomAsset(binaryFile) {
  return `${binaryFile}.cdx.json`;
}

export function bundleAsset(file) {
  return `${file}.sigstore.json`;
}

export function recordId(tagInfo, n = 1) {
  const stem = tagInfo.channel === 'nightly' ? tagInfo.nightlyId : tagInfo.version;
  return `agents-${stem}-c${n}`;
}

export function recordFile(id) {
  return `compatibility-${id}.json`;
}

export const PROVENANCE_ASSET = 'provenance.intoto.jsonl';
export const SUMS_ASSET = 'SHA256SUMS';
export const METADATA_ASSET = 'agents-release.json';
export const NOTICES_ASSET = 'THIRD_PARTY_LICENSES';

export function sha256File(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

export function sizeOf(file) {
  return statSync(file).size;
}

// Every artefact a release of this surface publishes (not the metadata,
// checksums, notices or signature bundles). Order is stable: agents as listed,
// targets as listed, binary then package, then installers.
export function expectedArtifacts(surface, version) {
  const out = [];
  for (const agent of surface.agents) {
    for (const t of agent.targets) {
      out.push({ kind: agent.kind, type: 'binary', os: t.os, arch: t.arch, requires: t.requires, file: binaryAsset(agent, version, t.os, t.arch) });
      out.push({ kind: agent.kind, type: 'package', os: t.os, arch: t.arch, requires: t.requires, file: packageAsset(agent, version, t.os, t.arch) });
    }
    for (const [os, file] of Object.entries(agent.installers || {})) {
      const req = [...new Set(agent.targets.filter((t) => t.os === os).flatMap((t) => t.requires))].sort();
      out.push({ kind: agent.kind, type: 'installer', os, arch: 'any', requires: req, file });
    }
  }
  return out;
}

// Stable JSON for every document the release writes: two-space indent, keys
// in the order the code builds them, trailing newline.
export function stableJson(v) {
  return JSON.stringify(v, null, 2) + '\n';
}
