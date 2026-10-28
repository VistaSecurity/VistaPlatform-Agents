#!/usr/bin/env node
// compatibility.yml's checks, run before anything is signed.
//
//   node scripts/release/compat-check.mjs added BEFORE AFTER
//     prints the record files a push added under compatibility/records/, and
//     fails if it modified, renamed or deleted one (records are append-only),
//     or added anything there that is not <record_id>.json or README.md.
//
//   node scripts/release/compat-check.mjs check RECORD ASSETS [RECORDS_DIR]
//     RECORD against the release whose assets (already verified by
//     scripts/verify-release.sh) are in ASSETS: schema and rules, bound to
//     that release's agents-release.json by digest, every artefact exactly as
//     published, a new record id, and a superseded record that exists.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { recordFile, sha256File } from './lib.mjs';
import { recordDescribes, validateDocument } from './validate.mjs';

const DIR = 'compatibility/records/';

export function classifyChanges(nameStatus) {
  const errors = [];
  const added = [];
  for (const line of nameStatus.split('\n').filter(Boolean)) {
    const [status, ...paths] = line.split('\t');
    const p = paths[paths.length - 1];
    if (!paths.some((x) => x.startsWith(DIR))) continue;
    if (status !== 'A') { errors.push(`${paths.join(' -> ')}: ${status} — records are append-only; add a new record that supersedes this one`); continue; }
    if (p === `${DIR}README.md`) continue;
    if (!/^compatibility\/records\/agents-[0-9A-Za-z.-]+-c[1-9][0-9]*\.json$/.test(p)) { errors.push(`${p}: not a record file name (<record_id>.json)`); continue; }
    added.push(p);
  }
  return { errors, added };
}

export function checkRecord(record, recordPath, assetsDir, recordsDir, now = Date.now()) {
  const errors = validateDocument(record);
  if (errors.length) return errors;
  if (path.basename(recordPath) !== `${record.record_id}.json`) errors.push(`file name must be ${record.record_id}.json`);
  if (/-c1$/.test(record.record_id)) errors.push('c1 is the release workflow\'s record; a committed record starts at c2');
  if (Date.parse(record.issued_at) > now + 5 * 60e3) errors.push(`issued_at ${record.issued_at} is in the future`);
  const metaPath = path.join(assetsDir, 'agents-release.json');
  if (!existsSync(metaPath)) return [...errors, `the release has no agents-release.json in ${assetsDir}`];
  const release = JSON.parse(readFileSync(metaPath, 'utf8'));
  errors.push(...recordDescribes(record, release, sha256File(metaPath)));
  if (existsSync(path.join(assetsDir, recordFile(record.record_id)))) errors.push(`${recordFile(record.record_id)} is already published: a record id is never reused`);
  if (record.supersedes) {
    const asAsset = existsSync(path.join(assetsDir, recordFile(record.supersedes)));
    const asFile = existsSync(path.join(recordsDir, `${record.supersedes}.json`));
    if (!asAsset && !asFile) errors.push(`supersedes ${record.supersedes}, which is neither published nor in ${recordsDir}`);
  }
  return errors;
}

function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (cmd === 'added') {
    const [before, after] = args;
    if (!/^[0-9a-f]{40}$/.test(before || '') || !/^[0-9a-f]{40}$/.test(after || '')) { console.error('usage: compat-check.mjs added BEFORE AFTER (40-hex commits)'); process.exit(2); }
    const out = execFileSync('git', ['diff', '--no-renames', '--name-status', before, after, '--', DIR], { encoding: 'utf8' });
    const { errors, added } = classifyChanges(out);
    for (const e of errors) console.error(`::error::${e}`);
    if (errors.length) process.exit(1);
    for (const a of added) console.log(a);
    return;
  }
  if (cmd === 'check') {
    const [recordPath, assetsDir, recordsDir = DIR] = args;
    if (!recordPath || !assetsDir) { console.error('usage: compat-check.mjs check RECORD ASSETS [RECORDS_DIR]'); process.exit(2); }
    const errors = checkRecord(JSON.parse(readFileSync(recordPath, 'utf8')), recordPath, assetsDir, recordsDir);
    for (const e of errors) console.error(`::error file=${recordPath}::${e}`);
    if (errors.length) process.exit(1);
    console.log(`${recordPath}: valid, and describes the published release`);
    return;
  }
  console.error('usage: compat-check.mjs added BEFORE AFTER | check RECORD ASSETS [RECORDS_DIR]');
  process.exit(2);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
