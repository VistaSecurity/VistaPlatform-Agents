#!/usr/bin/env node
// Package one release from the binaries the build legs produced. Runs in an
// unprivileged job: it reads, checks and writes files, and signs nothing.
//
//   node scripts/release/package.mjs --builds DIR --tag TAG --source-sha SHA \
//        --source-time RFC3339 --out ASSETS --state STATE [--require-notices]
//        [--repo OWNER/REPO] [--image-repository REGISTRY/PATH]
//
// --image-repository (ghcr.io/owner) is where a tagged release pushes its
// images. It names each image inside its archive, so that containerd, kind
// and docker call it by the reference a manifest uses; it does not change the
// image's digest.
//
// DIR holds one directory per build leg, build-<kind>-<os>-<arch>/, with the
// executable scripts/build.sh produced. For every target in release/agents.json
// it checks the binary's build information (buildinfo.mjs), then writes into
// ASSETS:
//   <prefix>_<version>_<os>_<arch>[.exe]          the binary
//   <prefix>_<version>_<os>_<arch>.tar.gz|.zip    the package: binary, the
//                                                 OS's installer, LICENSE,
//                                                 NOTICE, THIRD_PARTY_LICENSES
//   <binary>.cdx.json                             CycloneDX SBOM of the binary
//   install-*.sh, install-*.ps1                   the installers
//   <image>_<version>_linux.oci.tar               the agent's container image,
//                                                 every platform in one OCI
//                                                 archive (image.mjs), from the
//                                                 container build legs
//   <image>_<version>_linux_<arch>.image.cdx.json CycloneDX SBOM of the
//                                                 executable in that image
//   THIRD_PARTY_LICENSES
// and into STATE: artifacts.sha256 (binaries, packages, installers and images:
// the provenance subjects) and package.json (what the metadata step needs).
// Exit 1 with every problem listed; nothing is written to ASSETS unless every
// check passed.

import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

import { tarGz, zip } from './archive.mjs';
import { checkBuildInfo, checkVersionStamp, modulesOf, readBuildInfo } from './buildinfo.mjs';
import { buildImage } from './image.mjs';
import { buildNotices, goModuleDir } from './licenses.mjs';
import {
  REPO_ROOT, NOTICES_ASSET, binaryAsset, containerBuildDir, exeSuffix, expectedArtifacts, expectedImages, imageAsset,
  imageSbomAsset, loadSurface, packageAsset, packageRoot, parseTag, repoUrl, sbomAsset, sha256File, stableJson,
} from './lib.mjs';
import { cyclonedx } from './sbom.mjs';

export function goModInfo(root) {
  const mod = readFileSync(path.join(root, 'go.mod'), 'utf8');
  const modulePath = (/^module\s+(\S+)$/m.exec(mod) || [])[1];
  const go = (/^go\s+(\d+\.\d+\.\d+)$/m.exec(mod) || [])[1];
  if (!modulePath || !go) throw new Error('go.mod has no module path or no exact go directive');
  return { modulePath, goVersion: `go${go}` };
}

// deps: injectable for tests ({ readBuildInfo, moduleDir, goroot }).
export function packageRelease(opts, deps = {}) {
  const root = opts.root || REPO_ROOT;
  const surface = loadSurface(root);
  const tag = parseTag(opts.tag);
  const { modulePath, goVersion } = goModInfo(root);
  const read = deps.readBuildInfo || readBuildInfo;
  const moduleDir = deps.moduleDir || ((p, v) => goModuleDir(root, p, v));
  const goroot = deps.goroot || execFileSync('go', ['env', 'GOROOT'], { encoding: 'utf8' }).trim();
  const epoch = Math.floor(Date.parse(opts.sourceTime) / 1000);
  if (!Number.isFinite(epoch) || !/Z$/.test(opts.sourceTime)) throw new Error(`--source-time must be an RFC 3339 UTC time, got ${opts.sourceTime}`);
  if (!/^[0-9a-f]{40}$/.test(opts.sourceSha)) throw new Error('--source-sha must be 40 hex');
  if (tag.channel === 'nightly' && tag.sha12 !== opts.sourceSha.slice(0, 12)) throw new Error(`nightly tag ${tag.tag} does not name source ${opts.sourceSha}`);

  const errors = [];
  const binaries = [];
  const modules = new Map();
  for (const agent of surface.agents) {
    for (const t of agent.targets) {
      const exe = path.join(opts.builds, `build-${agent.kind}-${t.os}-${t.arch}`, agent.executable + exeSuffix(t.os));
      if (!existsSync(exe)) { errors.push(`${agent.kind} ${t.os}/${t.arch}: no binary at ${exe}`); continue; }
      let info;
      try { info = read(exe); } catch (e) { errors.push(`${agent.kind} ${t.os}/${t.arch}: cannot read build information: ${e.message}`); continue; }
      for (const e of checkBuildInfo(info, {
        modulePath, command: agent.command, goos: t.os, goarch: t.arch, cgo: t.cgo,
        version: tag.version, sourceSha: opts.sourceSha, goVersion,
      })) errors.push(`${agent.kind} ${t.os}/${t.arch}: ${e}`);
      for (const e of checkVersionStamp(readFileSync(exe), tag.version)) errors.push(`${agent.kind} ${t.os}/${t.arch}: ${e}`);
      const file = binaryAsset(agent, tag.version, t.os, t.arch);
      for (const m of modulesOf(info)) {
        const key = `${m.path}@${m.version}`;
        if (!modules.has(key)) modules.set(key, { ...m, usedBy: new Set() });
        modules.get(key).usedBy.add(`${agent.kind} ${t.os}/${t.arch}`);
      }
      binaries.push({ agent, target: t, exe, file, info });
    }
  }
  // The container builds: one static executable per platform of each image.
  const containerBuilds = [];
  for (const agent of surface.agents.filter((a) => a.image)) {
    for (const arch of agent.image.arches) {
      const where = `${agent.kind} image linux/${arch}`;
      const exe = path.join(opts.builds, containerBuildDir(agent, arch), agent.executable);
      if (!existsSync(exe)) { errors.push(`${where}: no binary at ${exe}`); continue; }
      let info;
      try { info = read(exe); } catch (e) { errors.push(`${where}: cannot read build information: ${e.message}`); continue; }
      for (const e of checkBuildInfo(info, {
        modulePath, command: agent.command, goos: 'linux', goarch: arch, cgo: false, tags: agent.image.build_tags,
        version: tag.version, sourceSha: opts.sourceSha, goVersion,
      })) errors.push(`${where}: ${e}`);
      for (const e of checkVersionStamp(readFileSync(exe), tag.version)) errors.push(`${where}: ${e}`);
      for (const m of modulesOf(info)) {
        const key = `${m.path}@${m.version}`;
        if (!modules.has(key)) modules.set(key, { ...m, usedBy: new Set() });
        modules.get(key).usedBy.add(where);
      }
      containerBuilds.push({ agent, arch, exe, info });
    }
  }
  if (opts.imageRepository !== undefined && !/^[a-z0-9.-]+(:\d+)?(\/[a-z0-9._-]+)+$/.test(opts.imageRepository)) {
    errors.push(`--image-repository must be a lower-case registry path such as ghcr.io/owner, got ${JSON.stringify(opts.imageRepository)}`);
  }
  const licenseFile = existsSync(path.join(root, 'LICENSE'));
  const noticePath = path.join(root, 'NOTICE');
  const notice = existsSync(noticePath) ? readFileSync(noticePath, 'utf8') : null;
  if (opts.requireNotices && !licenseFile) errors.push('LICENSE is required for this release and is missing');
  const notices = buildNotices({
    modules: [...modules.values()].map((m) => ({ path: m.path, version: m.version, usedBy: [...m.usedBy].sort() })),
    resolve: moduleDir,
    stdlib: { version: goVersion, dir: goroot },
    notice,
    requireNotice: Boolean(opts.requireNotices),
  });
  errors.push(...notices.errors);
  if (errors.length) return { errors };

  mkdirSync(opts.out, { recursive: true });
  mkdirSync(opts.state, { recursive: true });
  if (readdirSync(opts.out).length) return { errors: [`${opts.out} is not empty`] };
  const write = (name, data, mode) => {
    const p = path.join(opts.out, name);
    writeFileSync(p, data);
    chmodSync(p, mode);
  };
  const thirdParty = Buffer.from(notices.text);
  write(NOTICES_ASSET, thirdParty, 0o644);
  const extras = [
    ...(licenseFile ? [{ name: 'LICENSE', data: readFileSync(path.join(root, 'LICENSE')), mode: 0o644 }] : []),
    ...(notice !== null ? [{ name: 'NOTICE', data: Buffer.from(notice), mode: 0o644 }] : []),
    { name: NOTICES_ASSET, data: thirdParty, mode: 0o644 },
  ];
  for (const b of binaries) {
    const data = readFileSync(b.exe);
    write(b.file, data, 0o755);
    const sha256 = sha256File(path.join(opts.out, b.file));
    const sbom = cyclonedx({
      info: b.info,
      binary: { file: b.file, sha256, kind: b.agent.kind, version: tag.version, requires: b.target.requires },
      licenses: notices.licenses,
      sourceTime: opts.sourceTime,
    });
    write(sbomAsset(b.file), stableJson(sbom), 0o644);
    const installer = (b.agent.installers || {})[b.target.os];
    const entries = [
      { name: b.agent.executable + exeSuffix(b.target.os), data, mode: 0o755 },
      ...(installer ? [{ name: installer, data: readFileSync(path.join(root, 'scripts', installer)), mode: 0o755 }] : []),
      ...extras,
    ];
    const rootDir = packageRoot(b.agent, tag.version, b.target.os, b.target.arch);
    const pkg = b.target.os === 'windows' ? zip(rootDir, entries, epoch) : tarGz(rootDir, entries, epoch);
    write(packageAsset(b.agent, tag.version, b.target.os, b.target.arch), pkg, 0o644);
  }
  for (const agent of surface.agents) {
    for (const file of Object.values(agent.installers || {})) write(file, readFileSync(path.join(root, 'scripts', file)), 0o755);
  }

  // One image per agent, every platform in it. The image holds the container
  // build of the executable and the same notices as a package.
  const images = [];
  for (const agent of surface.agents.filter((a) => a.image)) {
    const builds = containerBuilds.filter((b) => b.agent === agent);
    const file = imageAsset(agent, tag.version);
    const built = buildImage({
      name: agent.image.name,
      version: tag.version,
      executable: agent.executable,
      args: agent.image.args,
      env: agent.image.env,
      platforms: builds.map((b) => ({ os: 'linux', arch: b.arch, binary: readFileSync(b.exe) })),
      docs: extras.map((e) => ({ name: e.name, data: e.data })),
      labels: {
        'org.opencontainers.image.title': agent.image.name,
        'org.opencontainers.image.version': tag.version,
        'org.opencontainers.image.revision': opts.sourceSha,
        'org.opencontainers.image.created': opts.sourceTime,
        'org.opencontainers.image.licenses': surface.license,
        ...(opts.repo ? { 'org.opencontainers.image.source': repoUrl(opts.repo) } : {}),
      },
      sourceTime: opts.sourceTime,
      refName: opts.imageRepository ? `${opts.imageRepository}/${agent.image.name}:${tag.version}` : undefined,
    });
    write(file, built.archive, 0o644);
    const platforms = builds.map((b) => {
      const exeSha = sha256File(b.exe);
      const sbomFile = imageSbomAsset(agent, tag.version, b.arch);
      write(sbomFile, stableJson(cyclonedx({
        info: b.info,
        binary: { file: `${file}:/usr/local/bin/${agent.executable} (linux/${b.arch})`, sha256: exeSha, kind: agent.kind, version: tag.version, requires: [] },
        licenses: notices.licenses,
        sourceTime: opts.sourceTime,
      })), 0o644);
      return { os: 'linux', arch: b.arch, digest: built.platforms.find((x) => x.arch === b.arch).digest, executable_sha256: exeSha, sbom_file: sbomFile };
    });
    images.push({
      kind: agent.kind, name: agent.image.name, file, digest: built.digest, platforms,
      repository: opts.imageRepository ? `${opts.imageRepository}/${agent.image.name}` : null,
    });
  }

  const artifacts = [...expectedArtifacts(surface, tag.version), ...expectedImages(surface, tag.version)];
  const missing = artifacts.filter((a) => !existsSync(path.join(opts.out, a.file)));
  if (missing.length) return { errors: missing.map((a) => `not produced: ${a.file}`) };
  const sums = artifacts.map((a) => a.file).sort().map((f) => `${sha256File(path.join(opts.out, f))}  ${f}\n`).join('');
  writeFileSync(path.join(opts.state, 'artifacts.sha256'), sums);
  writeFileSync(path.join(opts.state, 'package.json'), stableJson({
    tag: tag.tag, channel: tag.channel, version: tag.version, nightly_id: tag.nightlyId,
    source_sha: opts.sourceSha, source_time: opts.sourceTime, go_version: goVersion, module_path: modulePath,
    license_file: licenseFile, notice_file: notice !== null,
    images,
  }));
  return { errors: [], artifacts, modules: modules.size };
}

function main() {
  const { values } = parseArgs({
    options: {
      builds: { type: 'string' }, tag: { type: 'string' }, 'source-sha': { type: 'string' },
      'source-time': { type: 'string' }, out: { type: 'string' }, state: { type: 'string' },
      root: { type: 'string' }, 'require-notices': { type: 'boolean', default: false },
      repo: { type: 'string' }, 'image-repository': { type: 'string' },
    },
  });
  for (const k of ['builds', 'tag', 'source-sha', 'source-time', 'out', 'state']) {
    if (!values[k]) { console.error(`package.mjs: --${k} is required`); process.exit(2); }
  }
  let res;
  try {
    res = packageRelease({
      builds: values.builds, tag: values.tag, sourceSha: values['source-sha'], sourceTime: values['source-time'],
      out: values.out, state: values.state, root: values.root, requireNotices: values['require-notices'],
      repo: values.repo, imageRepository: values['image-repository'],
    });
  } catch (e) {
    console.error(`package.mjs: ${e.message}`);
    process.exit(1);
  }
  if (res.errors.length) {
    for (const e of res.errors) console.error(`::error::package: ${e}`);
    process.exit(1);
  }
  console.log(`package.mjs: ${res.artifacts.length} artefact(s), ${res.modules} third-party module(s) -> ${values.out}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
