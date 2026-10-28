// Tests for THIRD_PARTY_LICENSES generation (scripts/release/licenses.mjs)
// and its use by the packaging step. Run:
//   node --test scripts/third-party-licenses.test.mjs
//
// The cases LICENSE_POLICY section 5.3 requires, in both polarities: only
// allowlisted licences pass; a GPL component fails; a component with no
// licence file fails (the build fails, it does not skip the module); an
// MPL-2.0 component absent from NOTICE fails.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

import { BSD3, GPL, MIT, MPL, fixtureModules, makeRelease, tempDir } from './release/fixture.mjs';
import { buildNotices, identify } from './release/licenses.mjs';

const APACHE = '                                 Apache License\n                           Version 2.0, January 2004\n';
const ISC = 'Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.';
const LGPL = '                   GNU LESSER GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n';
const AGPL = '                    GNU AFFERO GENERAL PUBLIC LICENSE\n';
const BSD2 = 'Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 1. ... 2. ...';

test('identify: the licences the agents link today, and the ones they must not', () => {
  assert.deepEqual(identify(MIT), ['MIT']);
  assert.deepEqual(identify(BSD3), ['BSD-3-Clause']);
  assert.deepEqual(identify(BSD2), ['BSD-2-Clause']);
  assert.deepEqual(identify(APACHE), ['Apache-2.0']);
  assert.deepEqual(identify(ISC), ['ISC']);
  assert.deepEqual(identify(MPL), ['MPL-2.0']);
  assert.deepEqual(identify(MIT + '\n' + APACHE), ['Apache-2.0', 'MIT']);
  assert.deepEqual(identify(GPL), ['GPL']);
  assert.deepEqual(identify(LGPL), ['LGPL']);
  assert.deepEqual(identify(AGPL), ['AGPL-3.0']);
  assert.deepEqual(identify('All rights reserved. Do what you like.'), []);
  // A GPL header grant, without the licence's title.
  assert.deepEqual(identify('This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by'), ['GPL']);
});

test('identify: MPL-2.0 naming the GNU licences as Secondary Licenses is MPL-2.0, not copyleft', () => {
  const mplSecondary = MPL + '1.12. "Secondary License"\n    means either the GNU General Public License, Version 2.0, the GNU Lesser\n    General Public License, Version 2.1, the GNU Affero General Public\n    License, Version 3.0, or any later versions of those licenses.\n';
  assert.deepEqual(identify(mplSecondary), ['MPL-2.0']);
});

function notices(mods, { notice = null, requireNotice = false } = {}) {
  const dir = tempDir('licenses-');
  const resolve = fixtureModules(dir, mods);
  const goroot = path.join(dir, 'modcache', 'goroot');
  fixtureModules(dir, { goroot: BSD3 });
  return buildNotices({
    modules: Object.keys(mods).map((p) => ({ path: p, version: 'v1.0.0', usedBy: ['sensor linux/amd64'] })),
    resolve,
    stdlib: { version: 'go1.26.10', dir: goroot },
    notice,
    requireNotice,
  });
}

test('only allowlisted licences: passes, with every text in the bundle', () => {
  const r = notices({ 'github.com/a/mit': MIT, 'github.com/b/apache': APACHE, 'github.com/c/bsd': BSD3 });
  assert.deepEqual(r.errors, []);
  for (const m of ['github.com/a/mit v1.0.0', 'github.com/b/apache v1.0.0', 'github.com/c/bsd v1.0.0', 'The Go standard library (go1.26.10)']) {
    assert.ok(r.text.includes(m), m);
  }
  assert.ok(r.text.includes('Permission is hereby granted'));
});

test('a GPL component fails', () => {
  const r = notices({ 'github.com/a/mit': MIT, 'github.com/x/gpl': GPL });
  assert.ok(r.errors.some((e) => e.includes('github.com/x/gpl') && e.includes('GPL is not allowed')), r.errors.join('\n'));
});

test('LGPL and AGPL components fail (no exception file can admit them to the agents)', () => {
  assert.ok(notices({ 'github.com/x/lgpl': LGPL }).errors.length > 0);
  assert.ok(notices({ 'github.com/x/agpl': AGPL }).errors.length > 0);
});

test('a module whose licence file is missing fails the build, it is not skipped', () => {
  const r = notices({ 'github.com/a/mit': MIT, 'github.com/x/nolicence': null });
  assert.ok(r.errors.some((e) => e.includes('github.com/x/nolicence') && e.includes('no licence file')), r.errors.join('\n'));
});

test('a licence that cannot be identified fails', () => {
  const r = notices({ 'github.com/x/odd': 'Custom terms. Ask us.' });
  assert.ok(r.errors.some((e) => e.includes('not identified')));
});

test('MPL-2.0 passes only when NOTICE names the component', () => {
  assert.ok(notices({ 'github.com/go-sql-driver/mysql': MPL }, { notice: 'NOTICE without it' }).errors.some((e) => e.includes('must be named in NOTICE')));
  assert.deepEqual(notices({ 'github.com/go-sql-driver/mysql': MPL }, { notice: 'github.com/go-sql-driver/mysql is MPL-2.0' }).errors, []);
});

test('a required NOTICE that is missing fails', () => {
  assert.ok(notices({ 'github.com/a/mit': MIT }, { requireNotice: true }).errors.some((e) => e.includes('NOTICE is required')));
});

test('packaging fails on a licence problem and writes nothing', () => {
  const r = makeRelease({ modules: { 'github.com/example/mit': null } });
  assert.ok(r.errors.some((e) => e.includes('no licence file')), r.errors.join('\n'));
  assert.equal(r.assets, undefined);
});

test('packaging a tagged release fails without LICENSE or NOTICE; a nightly may lack them', () => {
  assert.ok(makeRelease({ rootOpts: { license: false } }).errors.some((e) => e.includes('LICENSE is required')));
  assert.ok(makeRelease({ rootOpts: { notice: null } }).errors.some((e) => e.includes('NOTICE is required')));
  assert.deepEqual(makeRelease({ tag: 'nightly-20261119-1a2b3c4d5e6f', provenance: 'unavailable', rootOpts: { license: false, notice: null } }).errors, []);
});

test('the bundle in every package is the THIRD_PARTY_LICENSES asset', () => {
  const r = makeRelease();
  assert.deepEqual(r.errors, []);
  const text = readFileSync(path.join(r.assets, 'THIRD_PARTY_LICENSES'), 'utf8');
  assert.ok(text.includes('github.com/example/mit v1.2.3 (linked into: device-agent darwin/amd64'));
});
