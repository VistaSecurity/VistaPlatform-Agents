// THIRD_PARTY_LICENSES: the licence text of every third-party module linked
// into the released binaries, read from the module list the binaries carry
// (`go version -m`), so the bundle covers exactly what ships: not the test
// graph, not modules of another OS.
//
// The build FAILS, it never skips, when:
//   - a module has no licence file at its root (LICENSE, LICENCE, COPYING,
//     UNLICENSE, with any suffix);
//   - a licence cannot be identified ("unknown blocks", LICENSE_POLICY 3);
//   - a licence is outside the agents' allowlist (GPL, AGPL, LGPL and every
//     non-redistributable term: removed, never excepted, for the public
//     agents);
//   - a "listed" licence (MPL-2.0) is missing from NOTICE, when a NOTICE is
//     given, or NOTICE is missing when one is required.
//
// Upstream NOTICE and PATENTS files are carried with the licence text
// (Apache-2.0 4(d)). The Go standard library's licence is included: it is
// linked into every binary.

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

export const ALLOWED = new Set(['MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD', 'Zlib', 'Apache-2.0', 'CC0-1.0', 'Unlicense', 'MPL-2.0']);
// Allowed only when NOTICE names the component (LICENSE_POLICY 3, "listed").
export const LISTED = new Set(['MPL-2.0']);

const LICENSE_FILE = /^(LICEN[CS]E|COPYING|UNLICENSE)([-._][A-Za-z0-9._-]*)?$/i;
const NOTICE_FILE = /^(NOTICE|PATENTS)([-._][A-Za-z0-9._-]*)?$/i;

// Identify the licences in one text. Every match is reported, so a file
// carrying two licences yields both. The GNU licences are recognised by their
// own title (upper case, as the texts print it) or by the "under the terms of
// the GNU ..." grant a header uses, not by any mention: MPL-2.0 section 1.12
// names the GPL, LGPL and AGPL as "Secondary Licenses", and reading that
// sentence as a GPL grant would refuse every MPL module.
export function identify(text) {
  const t = text.replace(/\s+/g, ' ');
  const found = new Set();
  const grant = (name) => new RegExp(`under the terms of the GNU ${name}`, 'i').test(t);
  if (/GNU AFFERO GENERAL PUBLIC LICENSE/.test(t) || grant('Affero General Public License')) found.add('AGPL-3.0');
  if (/GNU (LESSER|LIBRARY) GENERAL PUBLIC LICENSE/.test(t) || grant('(Lesser|Library) General Public License')) found.add('LGPL');
  if (/GNU GENERAL PUBLIC LICENSE/.test(t) || grant('General Public License')) found.add('GPL');
  if (/Server Side Public License|Business Source License|Elastic License|Commons Clause/i.test(t)) found.add('NON-FREE');
  if (/Mozilla Public License,? (Version|v\.?) ?2\.0/i.test(t)) found.add('MPL-2.0');
  if (/Apache License,? Version 2\.0/i.test(t) || /Apache License\s*Version 2\.0/i.test(t)) found.add('Apache-2.0');
  if (/Permission is hereby granted, free of charge, to any person obtaining a copy/i.test(t)) found.add('MIT');
  if (/Permission to use, copy, modify, and(\/or)? distribute this software for any purpose with or without fee is hereby granted/i.test(t)) {
    found.add(/THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES/i.test(t) && !/copyright notice and this permission notice appear in all copies/i.test(t) ? '0BSD' : 'ISC');
  }
  if (/Redistribution and use in source and binary forms, with or without modification, are permitted/i.test(t)) {
    found.add(/(Neither the name|names of its contributors may be used|name of the copyright holder nor)/i.test(t) ? 'BSD-3-Clause' : 'BSD-2-Clause');
  }
  if (/This software is provided 'as-is', without any express or implied warranty/i.test(t) && /Altered source versions must be plainly marked/i.test(t)) found.add('Zlib');
  if (/This is free and unencumbered software released into the public domain/i.test(t)) found.add('Unlicense');
  if (/CC0 1\.0 Universal/i.test(t)) found.add('CC0-1.0');
  return [...found].sort();
}

// The licence and notice files at a module's root.
export function moduleFiles(dir) {
  const names = existsSync(dir) ? readdirSync(dir).filter((n) => statSync(path.join(dir, n)).isFile()).sort() : [];
  return {
    licenses: names.filter((n) => LICENSE_FILE.test(n)).map((n) => path.join(dir, n)),
    notices: names.filter((n) => NOTICE_FILE.test(n)).map((n) => path.join(dir, n)),
  };
}

// The module cache directory of path@version (already downloaded by the
// build; `go mod download` verifies it against go.sum).
export function goModuleDir(root, modPath, version) {
  const out = execFileSync('go', ['mod', 'download', '-json', `${modPath}@${version}`], { cwd: root, encoding: 'utf8' });
  const info = JSON.parse(out);
  if (info.Error) throw new Error(`go mod download ${modPath}@${version}: ${info.Error}`);
  return info.Dir;
}

// modules: [{ path, version, usedBy: [names] }]; resolve(path, version) -> dir.
// stdlib: { version, dir } (GOROOT). notice: NOTICE text or null.
export function buildNotices({ modules, resolve, stdlib, notice, requireNotice }) {
  const errors = [];
  const sections = [];
  const licenses = new Map();
  if (notice === null && requireNotice) errors.push('NOTICE is required for this release and is missing');
  const one = (title, dir, key) => {
    const { licenses: lf, notices: nf } = moduleFiles(dir);
    if (lf.length === 0) { errors.push(`${title}: no licence file at the module root (${dir})`); return; }
    const ids = [...new Set(lf.flatMap((f) => identify(readFileSync(f, 'utf8'))))].sort();
    if (ids.length === 0) errors.push(`${title}: licence not identified (${lf.map((f) => path.basename(f)).join(', ')}); unknown licences block the release`);
    for (const id of ids) {
      if (!ALLOWED.has(id)) errors.push(`${title}: ${id} is not allowed in the public agents`);
      if (LISTED.has(id) && notice !== null && !notice.includes(key)) errors.push(`${title}: ${id} must be named in NOTICE (look for "${key}")`);
    }
    licenses.set(key, ids);
    let body = `${'='.repeat(78)}\n${title}\nLicence: ${ids.join(' AND ') || 'UNKNOWN'}\n${'='.repeat(78)}\n`;
    for (const f of [...lf, ...nf]) body += `\n--- ${path.basename(f)} ---\n\n${readFileSync(f, 'utf8').replace(/\r\n/g, '\n').trimEnd()}\n`;
    sections.push(body);
  };
  if (stdlib) one(`The Go standard library (${stdlib.version})`, stdlib.dir, 'stdlib');
  for (const m of [...modules].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    one(`${m.path} ${m.version}${m.usedBy && m.usedBy.length ? ` (linked into: ${m.usedBy.join(', ')})` : ''}`, resolve(m.path, m.version), m.path);
  }
  const head = [
    'THIRD-PARTY LICENSES',
    '',
    'The Vista Platform agents binaries in this release link the components',
    'below. Each remains under its own licence, reproduced in full. This file',
    'is generated from the module list compiled into the binaries',
    '(`go version -m`), so it lists exactly what ships. The capture libraries',
    'the sensor loads at run time (libpcap, Npcap) are not distributed; see',
    'NOTICE.',
    '',
  ].join('\n');
  return { errors, text: `${head}\n${sections.join('\n')}`, licenses };
}
