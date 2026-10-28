#!/usr/bin/env node
// Decide what a release or nightly run builds, from the event that started
// it, and refuse every other case. Run first, read-only, in a checkout with
// full history (actions/checkout fetch-depth: 0).
//
//   node scripts/release/resolve.mjs release   # tag push or dispatch on a tag
//   node scripts/release/resolve.mjs nightly   # schedule or dispatch on main
//
// Reads GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_SHA, INPUT_TAG (dispatch input)
// and, for a nightly, NIGHTLY_DATE (YYYYMMDD; default today in UTC). Writes
// tag, version, channel, source_sha and source_time to GITHUB_OUTPUT (or
// stdout).
//
// Release: the ref is refs/tags/<tag>; a dispatch must be started ON that tag
// (`gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z`), so the signing
// identity is always release.yml@refs/tags/<tag>; the tag is vX.Y.Z or
// vX.Y.Z-rc.N, points at the commit being built, and that commit is on main.
// Nightly: the ref is refs/heads/main and the commit is on main.

import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { nightlyIdentifiers, parseTag } from './lib.mjs';

const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();

export function resolve(kind, env, gitFn = git) {
  const event = env.GITHUB_EVENT_NAME;
  const ref = env.GITHUB_REF || '';
  const sha = env.GITHUB_SHA || '';
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error(`GITHUB_SHA is not a commit: ${sha}`);
  let tag;
  if (kind === 'release') {
    if (event === 'push') {
      if (!ref.startsWith('refs/tags/')) throw new Error(`a release runs on a tag push, not ${ref}`);
      tag = ref.slice('refs/tags/'.length);
    } else if (event === 'workflow_dispatch') {
      tag = env.INPUT_TAG || '';
      if (ref !== `refs/tags/${tag}`) throw new Error(`dispatch release.yml on the tag itself: gh workflow run release.yml --ref ${tag || '<tag>'} -f tag=${tag || '<tag>'} (this run is on ${ref})`);
    } else {
      throw new Error(`release.yml does not run on ${event}`);
    }
    const t = parseTag(tag);
    if (t.channel === 'nightly') throw new Error('nightly tags are published by nightly.yml only');
    let tagged;
    try { tagged = gitFn('rev-parse', '--verify', `refs/tags/${tag}^{commit}`); } catch { throw new Error(`tag ${tag} does not exist in this checkout`); }
    if (tagged !== sha) throw new Error(`tag ${tag} points at ${tagged}, this run built ${sha}`);
  } else if (kind === 'nightly') {
    if (event !== 'schedule' && event !== 'workflow_dispatch') throw new Error(`nightly.yml does not run on ${event}`);
    if (ref !== 'refs/heads/main') throw new Error(`a nightly builds main only, not ${ref}`);
    const date = env.NIGHTLY_DATE || new Date().toISOString().slice(0, 10).replace(/-/g, '');
    tag = nightlyIdentifiers(date, sha).tag;
  } else {
    throw new Error(`usage: resolve.mjs release|nightly (got ${kind})`);
  }
  try { gitFn('merge-base', '--is-ancestor', sha, 'refs/remotes/origin/main'); } catch { throw new Error(`${sha} is not on main (refs/remotes/origin/main)`); }
  const t = parseTag(tag);
  const sourceTime = gitFn('show', '-s', '--date=format-local:%Y-%m-%dT%H:%M:%SZ', '--format=%cd', sha);
  return { tag: t.tag, version: t.version, channel: t.channel, source_sha: sha, source_time: sourceTime };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.env.TZ = 'UTC';
    const out = resolve(process.argv[2], process.env);
    const text = Object.entries(out).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, text);
    process.stdout.write(text);
  } catch (e) {
    console.error(`::error::${e.message}`);
    process.exit(1);
  }
}
