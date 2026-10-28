#!/usr/bin/env node
// Nightly retention: a DRY RUN. It prints which nightly releases the policy
// would remove and why every other one stays; it deletes nothing and has no
// option to. A maintainer runs the printed commands by hand (the nightly tag
// ruleset refuses tag deletion to everyone else).
//
//   gh api --paginate 'repos/OWNER/REPO/releases?per_page=100' > releases.json
//   node scripts/release/prune-nightlies.mjs --releases releases.json \
//        [--records compatibility/records] [--retained release/retained-nightlies.txt] \
//        [--days 30] [--keep-latest 7] [--now 2026-11-20T00:00:00Z]
//
// Policy (docs/releasing.md, "Nightly retention"):
//   - a published nightly older than --days is removable, EXCEPT
//   - the newest --keep-latest nightlies, whatever their age;
//   - any nightly a compatibility record names (compatibility/records/*.json
//     by agents_release.tag, or a compatibility-*.json asset on the nightly
//     itself beyond the first record): a platform build may have been tested
//     or shipped against it;
//   - any nightly listed in release/retained-nightlies.txt (one tag per line):
//     the private platform's release and recovery manifests name the nightlies
//     they pin here, so a recovery never finds its bytes gone;
//   - stable releases and release candidates are never candidates.
// Unpublished drafts are listed separately as quarantined: an earlier run
// failed and someone must look at them.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

import { NIGHTLY_TAG } from './lib.mjs';

export function plan({ releases, recordTags, retained, days, keepLatest, now }) {
  const cutoff = now - days * 86400e3;
  const nightlies = releases.filter((r) => NIGHTLY_TAG.test(r.tag_name));
  const published = nightlies.filter((r) => !r.draft)
    .sort((a, b) => Date.parse(b.published_at) - Date.parse(a.published_at) || (a.tag_name < b.tag_name ? 1 : -1));
  const latest = new Set(published.slice(0, keepLatest).map((r) => r.tag_name));
  const out = { remove: [], keep: [], quarantined: nightlies.filter((r) => r.draft).map((r) => r.tag_name).sort() };
  for (const r of published) {
    const tag = r.tag_name;
    const extraRecord = (r.assets || []).some((a) => /^compatibility-.*-c([2-9]|[1-9]\d+)\.json$/.test(a.name));
    const reasons = [];
    if (latest.has(tag)) reasons.push(`one of the newest ${keepLatest}`);
    if (recordTags.has(tag) || extraRecord) reasons.push('named by a compatibility record');
    if (retained.has(tag)) reasons.push('listed in release/retained-nightlies.txt');
    if (Date.parse(r.published_at) >= cutoff) reasons.push(`younger than ${days} days`);
    if (reasons.length) out.keep.push({ tag, reasons });
    else out.remove.push({ tag, published_at: r.published_at });
  }
  return out;
}

export function recordTagsFrom(dir) {
  const tags = new Set();
  if (!existsSync(dir)) return tags;
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.json'))) {
    const doc = JSON.parse(readFileSync(path.join(dir, f), 'utf8'));
    if (doc && doc.agents_release && doc.agents_release.tag) tags.add(doc.agents_release.tag);
  }
  return tags;
}

export function retainedFrom(file) {
  if (!existsSync(file)) return new Set();
  return new Set(readFileSync(file, 'utf8').split('\n').map((l) => l.replace(/#.*/, '').trim()).filter(Boolean));
}

function main() {
  const { values } = parseArgs({
    options: {
      releases: { type: 'string' }, records: { type: 'string', default: 'compatibility/records' },
      retained: { type: 'string', default: 'release/retained-nightlies.txt' },
      days: { type: 'string', default: '30' }, 'keep-latest': { type: 'string', default: '7' },
      now: { type: 'string' }, repo: { type: 'string', default: 'OWNER/REPO' },
    },
  });
  if (!values.releases) { console.error('usage: prune-nightlies.mjs --releases releases.json [...]'); process.exit(2); }
  const raw = JSON.parse(readFileSync(values.releases, 'utf8'));
  const releases = Array.isArray(raw[0]) ? raw.flat() : raw; // gh api --paginate --slurp gives pages
  const p = plan({
    releases,
    recordTags: recordTagsFrom(values.records),
    retained: retainedFrom(values.retained),
    days: Number(values.days),
    keepLatest: Number(values['keep-latest']),
    now: values.now ? Date.parse(values.now) : Date.now(),
  });
  console.log(`DRY RUN: nothing is deleted. ${p.remove.length} nightly release(s) are past retention; ${p.keep.length} kept; ${p.quarantined.length} quarantined draft(s).`);
  for (const k of p.keep) console.log(`keep    ${k.tag}  (${k.reasons.join('; ')})`);
  for (const q of p.quarantined) console.log(`DRAFT   ${q}  (an unpublished, quarantined run: inspect before anything else)`);
  for (const r of p.remove) console.log(`remove  ${r.tag}  (published ${r.published_at})`);
  if (p.remove.length) {
    console.log('\nA maintainer who agrees runs, one by one:');
    for (const r of p.remove) console.log(`  gh release delete ${r.tag} --repo ${values.repo} --cleanup-tag --yes`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
