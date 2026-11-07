#!/usr/bin/env node
// The GitHub Release body, written from agents-release.json so the page says
// exactly what the metadata says. First what to download: one row per agent
// and system, the archive as a direct link, then which targets were executed
// in this run and which are compile-only, what the host must provide. Then the
// channel, native signing status, and how to verify.
//
// A release page lists every asset in one flat list (about 70 files) that
// cannot be grouped or reordered; this table is how a person finds the one
// file to install.
//
//   node scripts/release/notes.mjs agents-release.json > NOTES.md

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { identityRegexps, slugFromRepoUrl } from './lib.mjs';

const AGENT_ORDER = ['sensor', 'device-agent'];
const AGENT_NAMES = { sensor: 'Sensor', 'device-agent': 'Device agent' };
const OS_NAMES = { linux: 'Linux', darwin: 'macOS', windows: 'Windows' };
const OS_ORDER = ['linux', 'darwin', 'windows'];
const ARCH_ORDER = ['amd64', 'arm64', '386'];
const ARCH_NAMES = {
  linux: { amd64: 'x86-64', arm64: 'ARM64' },
  darwin: { amd64: 'Intel', arm64: 'Apple silicon' },
  windows: { amd64: 'x64', '386': 'x86 (32-bit)', arm64: 'ARM64' },
};

const link = (a) => `[\`${a.file}\`](${a.url})`;

// One row per agent and system: the package (binary, installer, licence
// files) first, then the loose binary and installer for those who want them.
export function downloadTable(meta) {
  const rank = (list, x) => (list.includes(x) ? list.indexOf(x) : list.length);
  const agents = [...meta.agents].sort((a, b) => rank(AGENT_ORDER, a.kind) - rank(AGENT_ORDER, b.kind));
  const lines = ['| Agent | System | Download | Loose binary | Installer | Executed in this release run | Host must provide |', '|---|---|---|---|---|---|---|'];
  for (const a of agents) {
    const pkgs = a.artifacts.filter((x) => x.type === 'package')
      .sort((x, y) => rank(OS_ORDER, x.os) - rank(OS_ORDER, y.os) || rank(ARCH_ORDER, x.arch) - rank(ARCH_ORDER, y.arch));
    for (const p of pkgs) {
      const bin = a.artifacts.find((x) => x.type === 'binary' && x.os === p.os && x.arch === p.arch);
      const inst = a.artifacts.find((x) => x.type === 'installer' && x.os === p.os);
      const system = `${OS_NAMES[p.os] || p.os} ${(ARCH_NAMES[p.os] || {})[p.arch] || p.arch}`;
      const art = bin || p;
      // smoke.sh fails when it finds Npcap, so an executed npcap build ran without it.
      const executed = !art.runtime_qualified ? 'no: compile-only, not supported'
        : art.requires.includes('npcap') ? 'yes (runtime-qualified), started without Npcap: capture library not loaded' : 'yes (runtime-qualified)';
      lines.push(`| ${AGENT_NAMES[a.kind] || a.kind} | ${system} | ${link(p)} | ${bin ? link(bin) : ''} | ${inst ? link(inst) : 'none'} | ${executed} | ${(bin || p).requires.join(', ') || 'nothing'} |`);
    }
  }
  return lines;
}

export function releaseNotes(meta) {
  const r = meta.release;
  const slug = slugFromRepoUrl(r.source_repo);
  const lines = ['## Download', ''];
  lines.push(...downloadTable(meta));
  lines.push('', 'Download the archive for your agent and system: it holds the binary, the installer for that system where there is one, `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES`. ' +
    'The installers accept the loose binary under its release name too. ' +
    'The other files of this release are for verification and tooling: `*.sigstore.json` signature bundles, `*.cdx.json` SBOMs, `SHA256SUMS`, `agents-release.json` (the release metadata) and the compatibility records.');
  lines.push('', '## About this release', '');
  if (r.channel === 'nightly') {
    lines.push(`**Nightly build ${r.tag}** of \`${r.source_sha}\`. A prerelease: not supported, not offered by any platform release, and pruned after the retention period unless a compatibility record names it.`);
  } else if (r.channel === 'prerelease') {
    lines.push(`**Release candidate ${r.tag}** of \`${r.source_sha}\`. A prerelease: it does not advance the stable channel.`);
  } else {
    lines.push(`**Vista Platform agents ${r.version}** from \`${r.source_sha}\`.`);
  }
  lines.push('', 'Platform compatibility: this release ships with compatibility record ' +
    `\`${meta.initial_record.record_id}\`, in which every platform claim is **pending**. ` +
    'A platform release offers these agents only after a later, separately signed record says **tested** for its exact version and edition.');
  lines.push('', 'Each binary has a CycloneDX SBOM (`<binary>.cdx.json`). "Executed" means this release\'s workflow ran that build on a GitHub-hosted runner of its system; a compile-only build is published but not supported.');
  lines.push('', '**Windows in this run:** the Windows leg is a hosted Windows Server x64 runner with no Npcap. ' +
    'The device agent ran `-version` and `install-device-agent.ps1 -CheckDependencies`. ' +
    'The x64 sensor started and reported its version without loading Npcap, and `install-sensor.ps1` stopped at its Npcap check as it should on such a host; nothing on that runner loaded Npcap or captured a packet. ' +
    'The x86 sensor was started on the same runner under WoW64 as an extra check; that is not a machine of its architecture, so it stays compile-only.');
  lines.push('', '**Native code signing:** Windows binaries are not Authenticode-signed and macOS binaries are not notarized. The Sigstore signatures below prove origin; they do not satisfy Windows SmartScreen or macOS Gatekeeper.');
  lines.push('', '**Packet capture:** the sensor uses the host\'s libpcap on Linux and macOS. On Windows it needs Npcap, which you install yourself from https://npcap.com under its own licence (the free licence covers up to five systems); it is never bundled.');
  const re = identityRegexps(slug);
  const kind = { stable: 'release', prerelease: 'release candidate', nightly: 'nightly build' }[r.channel];
  lines.push('', '**Verify** (see `docs/verify-release.md`):', '', '```sh',
    `gh release download ${r.tag} --repo ${slug} --dir ${r.tag}`,
    `cosign verify-blob --bundle ${r.tag}/SHA256SUMS.sigstore.json \\`,
    `  --certificate-identity '${meta.signing.identity}' \\`,
    `  --certificate-oidc-issuer ${meta.signing.issuer} ${r.tag}/SHA256SUMS`,
    `(cd ${r.tag} && sha256sum -c SHA256SUMS)`,
    '```', '',
    `Signer of every ${kind} of this repository, as a regular expression: \`${re[r.channel]}\`.`);
  if (meta.provenance.status === 'attested') {
    lines.push('', `Build provenance (SLSA v1): \`gh attestation verify <file> --repo ${slug} --cert-identity '${meta.signing.identity}'\`.`);
  } else {
    lines.push('', `Build provenance: not available for this ${kind} (${meta.provenance.reason}).`);
  }
  lines.push('', `Built by ${r.workflow.run_url}.`);
  return lines.join('\n') + '\n';
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!process.argv[2]) { console.error('usage: notes.mjs agents-release.json'); process.exit(2); }
  process.stdout.write(releaseNotes(JSON.parse(readFileSync(process.argv[2], 'utf8'))));
}
