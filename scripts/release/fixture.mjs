// Test fixtures: a complete synthetic release built by the real scripts
// (package.mjs, metadata.mjs, sums.sh) from fake binaries, with the build
// information and module licences injected. Signature bundles are
// placeholders, so a fixture release verifies only with --skip-signatures;
// everything else about it is what a release job would produce.

import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { REPO_ROOT, bundleAsset, expectedArtifacts, loadSurface, parseTag, stableJson } from './lib.mjs';
import { packageRelease } from './package.mjs';
import { writeMetadata } from './metadata.mjs';

export const MIT = 'Permission is hereby granted, free of charge, to any person obtaining a copy\nof this software ...\n';
export const BSD3 = 'Redistribution and use in source and binary forms, with or without modification, are permitted\nprovided ... Neither the name of Google Inc. nor the names of its contributors may be used ...\n';
export const GPL = '                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n';
export const MPL = 'Mozilla Public License Version 2.0\n==================================\n';
export const SHA = '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b';
export const SOURCE_TIME = '2026-11-19T10:20:30Z';
export const REPO = 'VistaSecurity/VistaPlatform-Agents';
export const MODULE = 'github.com/vistasecurity/vistaplatform-agents';

const made = [];
process.on('exit', () => { for (const d of made) rmSync(d, { recursive: true, force: true }); });

// A temporary directory removed when the test process exits.
export function tempDir(prefix = 'agents-release-') {
  const d = mkdtempSync(path.join(tmpdir(), prefix));
  made.push(d);
  return d;
}

// A repository root with the real release surface and schemas, and fake
// go.mod, installers and notices.
export function fixtureRoot(dir, { license = true, notice = 'NOTICE\nlists github.com/example/mpl under MPL-2.0\n' } = {}) {
  const root = path.join(dir, 'repo');
  mkdirSync(path.join(root, 'scripts'), { recursive: true });
  cpSync(path.join(REPO_ROOT, 'release'), path.join(root, 'release'), { recursive: true });
  cpSync(path.join(REPO_ROOT, 'schemas'), path.join(root, 'schemas'), { recursive: true });
  writeFileSync(path.join(root, 'go.mod'), `module ${MODULE}\n\ngo 1.26.10\n`);
  for (const f of ['install-sensor.sh', 'install-sensor.ps1', 'install-device-agent.sh']) {
    writeFileSync(path.join(root, 'scripts', f), `#!/bin/bash\n# fixture installer ${f}\n`);
  }
  if (license) writeFileSync(path.join(root, 'LICENSE'), 'Apache License\nVersion 2.0, January 2004\n');
  if (notice !== null) writeFileSync(path.join(root, 'NOTICE'), notice);
  return root;
}

// Module directories: name -> licence text (null: no licence file).
export function fixtureModules(dir, mods) {
  const base = path.join(dir, 'modcache');
  for (const [name, text] of Object.entries(mods)) {
    const d = path.join(base, name.replace(/\//g, '_'));
    mkdirSync(d, { recursive: true });
    if (text !== null) writeFileSync(path.join(d, 'LICENSE'), text);
    writeFileSync(path.join(d, 'go.mod'), `module ${name}\n`);
  }
  return (p) => path.join(base, p.replace(/\//g, '_'));
}

export function buildInfoFor(agent, target, version, { sha = SHA, deps = [{ Path: 'github.com/example/mit', Version: 'v1.2.3', Sum: 'h1:abc=' }] } = {}) {
  return {
    GoVersion: 'go1.26.10',
    Path: `${MODULE}/${agent.command}`,
    Main: { Path: MODULE, Version: '(devel)' },
    Deps: deps,
    Settings: [
      { Key: '-buildmode', Value: 'exe' },
      { Key: '-trimpath', Value: 'true' },
      { Key: 'CGO_ENABLED', Value: target.cgo ? '1' : '0' },
      { Key: 'GOARCH', Value: target.arch },
      { Key: 'GOOS', Value: target.os },
      { Key: 'vcs', Value: 'git' },
      { Key: 'vcs.revision', Value: sha },
      { Key: 'vcs.time', Value: SOURCE_TIME },
      { Key: 'vcs.modified', Value: 'false' },
    ],
  };
}

// Fake binaries in the build-leg layout; returns the builds dir and a map
// exe path -> build info.
export function fixtureBuilds(dir, root, version, infoOverride = () => ({}), exeContent = null) {
  const builds = path.join(dir, 'builds');
  const infos = new Map();
  const surface = loadSurface(root);
  for (const agent of surface.agents) {
    for (const t of agent.targets) {
      const d = path.join(builds, `build-${agent.kind}-${t.os}-${t.arch}`);
      mkdirSync(d, { recursive: true });
      const exe = path.join(d, agent.executable + (t.os === 'windows' ? '.exe' : ''));
      writeFileSync(exe, exeContent ? exeContent(agent, t, version) : `fake ${agent.kind} ${t.os}/${t.arch} ${version}\n`);
      infos.set(exe, { ...buildInfoFor(agent, t, version), ...infoOverride(agent, t) });
    }
  }
  return { builds, infos };
}

// The whole pipeline. Returns { root, assets, state, tag }.
export function makeRelease({ tag = 'v5.3.0', modules = { 'github.com/example/mit': MIT }, rootOpts, infoOverride, exeContent, provenance = 'attested', afterPackage, smokeExecuted } = {}) {
  const dir = tempDir();
  const root = fixtureRoot(dir, rootOpts);
  const t = parseTag(tag);
  const { builds, infos } = fixtureBuilds(dir, root, t.version, infoOverride, exeContent);
  const goroot = path.join(dir, 'goroot');
  mkdirSync(goroot);
  writeFileSync(path.join(goroot, 'LICENSE'), BSD3);
  const assets = path.join(dir, 'assets');
  const state = path.join(dir, 'state');
  const sha = t.channel === 'nightly' ? `${t.sha12}${SHA.slice(12)}` : SHA;
  if (t.channel === 'nightly') for (const [k, v] of infos) infos.set(k, { ...v, Settings: v.Settings.map((s) => (s.Key === 'vcs.revision' ? { ...s, Value: sha } : s)) });
  const res = packageRelease(
    { builds, tag, sourceSha: sha, sourceTime: SOURCE_TIME, out: assets, state, root, requireNotices: t.channel !== 'nightly' },
    { readBuildInfo: (f) => infos.get(f), moduleDir: fixtureModules(dir, modules), goroot },
  );
  if (res.errors.length) return { dir, root, errors: res.errors };
  if (afterPackage) afterPackage(assets);
  // Placeholder bundles (not signatures) for every artefact; provenance file.
  for (const a of expectedArtifacts(loadSurface(root), t.version)) writeFileSync(path.join(assets, bundleAsset(a.file)), `{"placeholder":"${a.file}"}\n`);
  if (provenance === 'attested') writeFileSync(path.join(assets, 'provenance.intoto.jsonl'), '{"placeholder":"provenance"}\n');
  const smoke = path.join(dir, 'smoke');
  mkdirSync(smoke);
  for (const leg of loadSurface(root).smoke) {
    const executed = [];
    for (const agent of loadSurface(root).agents) {
      if (!agent.targets.some((x) => x.os === leg.os && x.arch === leg.arch)) continue;
      const base = `${agent.asset_prefix}_${t.version}_${leg.os}_${leg.arch}`;
      executed.push(base, `${base}.tar.gz`, ...(agent.installers[leg.os] ? [agent.installers[leg.os]] : []));
    }
    const ran = smokeExecuted ? smokeExecuted(leg, executed) : executed;
    if (ran !== null) writeFileSync(path.join(smoke, `smoke-${leg.os}-${leg.arch}.json`), stableJson({ os: leg.os, arch: leg.arch, result: 'passed', executed: ran }));
  }
  const meta = writeMetadata({
    assets, state, repo: REPO, runUrl: `https://github.com/${REPO}/actions/runs/123/attempts/1`, smoke,
    provenance, provenanceReason: 'fixture: no attestation', issuedAt: '2026-11-19T11:00:00Z', root,
  });
  if (meta.errors.length) return { dir, root, errors: meta.errors };
  for (const f of ['agents-release.json', JSON.parse(readFileSync(path.join(assets, 'agents-release.json'), 'utf8')).initial_record.file]) {
    writeFileSync(path.join(assets, bundleAsset(f)), `{"placeholder":"${f}"}\n`);
  }
  execFileSync('bash', [path.join(REPO_ROOT, 'scripts', 'release', 'sums.sh'), assets], { stdio: 'pipe' });
  writeFileSync(path.join(assets, 'SHA256SUMS.sigstore.json'), '{"placeholder":"SHA256SUMS"}\n');
  return { dir, root, assets, state, tag, errors: [] };
}
