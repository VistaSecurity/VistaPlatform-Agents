#!/usr/bin/env node
// Build the agents' container images from this checkout, for a local cluster
// (the kind test, a developer's own). The same builder a release uses
// (scripts/release/image.mjs) and the same image settings
// (release/agents.json), from executables built with
// `scripts/build.sh <agent> linux-<arch> container`.
//
//   node scripts/dev-images.mjs --out DIR [--arch amd64] [--repository localhost/vista] [--version dev]
//
// Writes DIR/<image>.oci.tar for each agent and prints "<image> <reference>"
// per line. Nothing is pushed and nothing is signed: these are not release
// artefacts.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';

import { buildImage } from './release/image.mjs';
import { REPO_ROOT, loadSurface } from './release/lib.mjs';

const { values } = parseArgs({
  options: { out: { type: 'string' }, arch: { type: 'string' }, repository: { type: 'string', default: 'localhost/vista' }, version: { type: 'string', default: 'dev' } },
});
if (!values.out) { console.error('dev-images.mjs: --out is required'); process.exit(2); }
const arch = values.arch || execFileSync('go', ['env', 'GOARCH'], { encoding: 'utf8', cwd: REPO_ROOT }).trim();
mkdirSync(values.out, { recursive: true });
const docs = ['LICENSE', 'NOTICE'].filter((f) => existsSync(path.join(REPO_ROOT, f))).map((f) => ({ name: f, data: readFileSync(path.join(REPO_ROOT, f)) }));
for (const agent of loadSurface().agents.filter((a) => a.image)) {
  const exe = path.join(REPO_ROOT, 'dist', `${agent.kind}-container`, `linux-${arch}`, agent.executable);
  if (!existsSync(exe)) { console.error(`dev-images.mjs: no ${exe}; run scripts/build.sh ${agent.kind} linux-${arch} container`); process.exit(1); }
  const ref = `${values.repository}/${agent.image.name}:${values.version}`;
  const built = buildImage({
    name: agent.image.name, version: values.version, executable: agent.executable, args: agent.image.args, env: agent.image.env,
    platforms: [{ os: 'linux', arch, binary: readFileSync(exe) }], docs,
    labels: { 'org.opencontainers.image.title': agent.image.name, 'org.opencontainers.image.version': values.version },
    sourceTime: '2026-01-01T00:00:00Z', refName: ref,
  });
  writeFileSync(path.join(values.out, `${agent.image.name}.oci.tar`), built.archive);
  console.log(`${agent.image.name} ${ref} ${built.digest}`);
}
