// A CycloneDX 1.6 SBOM for one released binary, generated from the build
// information the binary itself carries (`go version -m -json`): the main
// module at the source commit, every linked module with its go.sum hash, the
// Go standard library, and the licences THIRD_PARTY_LICENSES identified.
// Deterministic: the serial number derives from the binary's digest and the
// timestamp is the source commit's time.

import { createHash } from 'node:crypto';
import { settingsOf } from './buildinfo.mjs';

function uuidFrom(hex) {
  const h = hex.slice(0, 32).split('');
  h[12] = '5'; // version nibble: name-based
  h[16] = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16); // variant
  const s = h.join('');
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

function purl(modPath, version) {
  return `pkg:golang/${modPath}@${version}`;
}

// info: build info; binary: { file, sha256, kind, version, requires };
// licenses: Map module path (or 'stdlib') -> [SPDX ids]; sourceTime: RFC 3339.
export function cyclonedx({ info, binary, licenses, sourceTime }) {
  const s = settingsOf(info);
  const lic = (key) => (licenses.get(key) || []).map((id) => ({ license: { id } }));
  const mainRef = purl(info.Main.Path, `v${binary.version}`);
  const stdRef = purl('stdlib', info.GoVersion);
  const deps = (info.Deps || []).map((d) => ({
    type: 'library',
    'bom-ref': purl(d.Path, d.Version),
    name: d.Path,
    version: d.Version,
    purl: purl(d.Path, d.Version),
    licenses: lic(d.Path),
    properties: d.Sum ? [{ name: 'go:module:sum', value: d.Sum }] : [],
  }));
  const props = [
    ['go:GOOS', s.get('GOOS')],
    ['go:GOARCH', s.get('GOARCH')],
    ['go:CGO_ENABLED', s.get('CGO_ENABLED')],
    ['go:-trimpath', s.get('-trimpath')],
    ['vcs:revision', s.get('vcs.revision')],
    ['vcs:time', s.get('vcs.time')],
    ...binary.requires.map((r) => ['vista:runtime-requires', `${r} (provided by the host, not bundled)`]),
  ].filter(([, v]) => v !== undefined).map(([name, value]) => ({ name, value }));
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${uuidFrom(createHash('sha256').update(`sbom:${binary.sha256}`).digest('hex'))}`,
    version: 1,
    metadata: {
      timestamp: sourceTime,
      tools: { components: [{ type: 'application', name: 'scripts/release/sbom.mjs', version: '1' }] },
      component: {
        type: 'application',
        'bom-ref': mainRef,
        name: binary.file,
        version: binary.version,
        purl: mainRef,
        hashes: [{ alg: 'SHA-256', content: binary.sha256 }],
        licenses: [{ license: { id: 'Apache-2.0' } }],
        properties: props,
      },
    },
    components: [
      { type: 'library', 'bom-ref': stdRef, name: 'stdlib', version: info.GoVersion, purl: stdRef, licenses: lic('stdlib'), properties: [] },
      ...deps,
    ],
    dependencies: [{ ref: mainRef, dependsOn: [stdRef, ...deps.map((d) => d['bom-ref'])] }],
  };
}
