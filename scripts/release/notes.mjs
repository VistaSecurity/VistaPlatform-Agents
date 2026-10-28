#!/usr/bin/env node
// The GitHub Release body, written from agents-release.json so the page says
// exactly what the metadata says: channel, which targets were executed in
// this run and which are compile-only, what the host must provide, native
// signing status, and how to verify.
//
//   node scripts/release/notes.mjs agents-release.json > NOTES.md

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { identityRegexps, slugFromRepoUrl } from './lib.mjs';

export function releaseNotes(meta) {
  const r = meta.release;
  const slug = slugFromRepoUrl(r.source_repo);
  const lines = [];
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
  lines.push('', '| Agent | OS | Arch | File | Executed in this release run | Host must provide |', '|---|---|---|---|---|---|');
  for (const a of meta.agents) {
    for (const x of a.artifacts.filter((y) => y.type === 'binary')) {
      lines.push(`| ${a.kind} | ${x.os} | ${x.arch} | \`${x.file}\` | ${x.runtime_qualified ? 'yes (runtime-qualified)' : 'no: compile-only, not supported'} | ${x.requires.join(', ') || 'nothing'} |`);
    }
  }
  lines.push('', 'Each binary also ships as a package (`.tar.gz`, or `.zip` for Windows) with its installer where there is one, `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES`, and has a CycloneDX SBOM (`<binary>.cdx.json`).');
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
