// Container images of the agents, built without a container engine.
//
// An image here is one static executable and a handful of files: there is no
// base image, no package manager and no shell, so there is nothing to patch
// but the agent itself. It is written directly as an OCI image layout in a tar
// archive, a pure function of its inputs and the source commit's time, so two
// builds of one commit produce the same bytes and the same image digest, and
// the digest a registry reports after a push is the one computed here.
//
// One archive holds one multi-platform image: an image index naming one
// manifest per platform. Each platform's image is a single layer:
//
//   /usr/local/bin/<executable>      0755 root
//   /etc/passwd, /etc/group          the unprivileged user the image runs as
//   /var/lib/vista/                  0700, owned by that user: the data directory
//   /tmp/                            1777
//   /usr/share/doc/<name>/...        LICENSE, NOTICE, THIRD_PARTY_LICENSES
//
// It runs as user 65532, never as root, and writes only under /var/lib/vista
// and /tmp, so it runs with a read-only root filesystem when those two are
// volumes. Zero dependencies (Node >= 20).

import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';

export const IMAGE_UID = 65532;
export const IMAGE_GID = 65532;
export const DATA_DIR = '/var/lib/vista';

export const MEDIA = {
  index: 'application/vnd.oci.image.index.v1+json',
  manifest: 'application/vnd.oci.image.manifest.v1+json',
  config: 'application/vnd.oci.image.config.v1+json',
  layer: 'application/vnd.oci.image.layer.v1.tar+gzip',
};

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const digestOf = (buf) => `sha256:${sha256(buf)}`;
const json = (v) => Buffer.from(JSON.stringify(v));

function octal(n, width) {
  const s = n.toString(8);
  if (s.length > width - 1) throw new Error(`value ${n} does not fit a ${width}-byte tar field`);
  return s.padStart(width - 1, '0') + '\0';
}

// One ustar header. name is at most 100 bytes: every path this file writes is
// short, and a longer one is a mistake to fail on.
function tarHeader({ name, size = 0, mode, uid = 0, gid = 0, mtime, type }) {
  if (Buffer.byteLength(name) > 100) throw new Error(`path too long for an image layer: ${name}`);
  const b = Buffer.alloc(512);
  b.write(name, 0, 100, 'utf8');
  b.write(octal(mode, 8), 100, 8, 'ascii');
  b.write(octal(uid, 8), 108, 8, 'ascii');
  b.write(octal(gid, 8), 116, 8, 'ascii');
  b.write(octal(size, 12), 124, 12, 'ascii');
  b.write(octal(mtime, 12), 136, 12, 'ascii');
  b.fill(' ', 148, 156);
  b.write(type, 156, 1, 'ascii');
  b.write('ustar\0', 257, 6, 'ascii');
  b.write('00', 263, 2, 'ascii');
  let sum = 0;
  for (const x of b) sum += x;
  b.write(octal(sum, 7) + ' ', 148, 8, 'ascii');
  return b;
}

// entries: [{ name, dir?: true, data?: Buffer, mode, uid?, gid? }], in the
// order given. Directory names end with "/".
export function tar(entries, mtime) {
  const blocks = [];
  for (const e of entries) {
    if (e.dir) {
      blocks.push(tarHeader({ name: e.name, mode: e.mode, uid: e.uid, gid: e.gid, mtime, type: '5' }));
      continue;
    }
    blocks.push(tarHeader({ name: e.name, size: e.data.length, mode: e.mode, uid: e.uid, gid: e.gid, mtime, type: '0' }));
    blocks.push(e.data);
    const pad = (512 - (e.data.length % 512)) % 512;
    if (pad) blocks.push(Buffer.alloc(pad));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

// The files of one platform's image, as tar entries.
export function rootfs({ name, executable, binary, docs }) {
  // The account database of the image: two accounts, neither of which can log
  // in. There is no secret in it.
  const accounts = `root:x:0:0:root:/:/sbin/nologin\nvista:x:${IMAGE_UID}:${IMAGE_GID}:Vista agent:${DATA_DIR}:/sbin/nologin\n`;
  const groups = `root:x:0:\nvista:x:${IMAGE_GID}:\n`;
  const own = { uid: IMAGE_UID, gid: IMAGE_GID };
  const doc = `usr/share/doc/${name}/`;
  return [
    { name: 'etc/', dir: true, mode: 0o755 },
    { name: 'etc/group', data: Buffer.from(groups), mode: 0o644 },
    { name: 'etc/passwd', data: Buffer.from(accounts), mode: 0o644 },
    { name: 'tmp/', dir: true, mode: 0o1777 },
    { name: 'usr/', dir: true, mode: 0o755 },
    { name: 'usr/local/', dir: true, mode: 0o755 },
    { name: 'usr/local/bin/', dir: true, mode: 0o755 },
    { name: `usr/local/bin/${executable}`, data: binary, mode: 0o755 },
    { name: 'usr/share/', dir: true, mode: 0o755 },
    { name: 'usr/share/doc/', dir: true, mode: 0o755 },
    { name: doc, dir: true, mode: 0o755 },
    ...docs.map((d) => ({ name: doc + d.name, data: d.data, mode: 0o644 })),
    { name: 'var/', dir: true, mode: 0o755 },
    { name: 'var/lib/', dir: true, mode: 0o755 },
    { name: `${DATA_DIR.slice(1)}/`, dir: true, mode: 0o700, ...own },
  ];
}

// spec: {
//   name          image name without a registry ("vista-device-agent")
//   version       the agent version
//   executable    file name of the executable
//   args          default arguments (the image's Cmd)
//   env           { KEY: value } set in the image, beside PATH
//   platforms     [{ os, arch, binary: Buffer }]
//   docs          [{ name, data: Buffer }] placed under /usr/share/doc/<name>/
//   labels        { key: value } OCI annotations and config labels
//   sourceTime    RFC 3339 UTC time of the source commit
//   refName       optional full reference written to index.json so that
//                 containerd, kind and docker name the image on import
//                 ("ghcr.io/owner/vista-device-agent:1.2.3"); it is outside
//                 the digest
// }
// Returns { archive: Buffer, digest, platforms: [{ os, arch, digest }], size }.
export function buildImage(spec) {
  const epoch = Math.floor(Date.parse(spec.sourceTime) / 1000);
  if (!Number.isFinite(epoch) || !/Z$/.test(spec.sourceTime)) throw new Error(`sourceTime must be an RFC 3339 UTC time, got ${spec.sourceTime}`);
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(spec.name)) throw new Error(`not an image name: ${spec.name}`);
  if (!spec.platforms || spec.platforms.length === 0) throw new Error(`image ${spec.name} has no platform`);
  const blobs = new Map();
  const put = (buf) => { const d = digestOf(buf); blobs.set(d, buf); return d; };
  const env = ['PATH=/usr/local/bin', ...Object.entries(spec.env || {}).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}=${v}`)];
  const labels = Object.fromEntries(Object.entries(spec.labels || {}).sort(([a], [b]) => (a < b ? -1 : 1)));

  const manifests = [];
  for (const p of [...spec.platforms].sort((a, b) => (`${a.os}/${a.arch}` < `${b.os}/${b.arch}` ? -1 : 1))) {
    const layerTar = tar(rootfs({ name: spec.name, executable: spec.executable, binary: p.binary, docs: spec.docs || [] }), epoch);
    const layer = gzipSync(layerTar, { level: 9 });
    const layerDigest = put(layer);
    const config = json({
      architecture: p.arch,
      os: p.os,
      created: spec.sourceTime,
      config: {
        User: `${IMAGE_UID}:${IMAGE_GID}`,
        Env: env,
        Entrypoint: [`/usr/local/bin/${spec.executable}`],
        Cmd: spec.args || [],
        WorkingDir: DATA_DIR,
        Labels: labels,
      },
      rootfs: { type: 'layers', diff_ids: [digestOf(layerTar)] },
      history: [{ created: spec.sourceTime, created_by: 'scripts/release/image.mjs' }],
    });
    const configDigest = put(config);
    const manifest = json({
      schemaVersion: 2,
      mediaType: MEDIA.manifest,
      config: { mediaType: MEDIA.config, digest: configDigest, size: config.length },
      layers: [{ mediaType: MEDIA.layer, digest: layerDigest, size: layer.length }],
      annotations: labels,
    });
    manifests.push({ mediaType: MEDIA.manifest, digest: put(manifest), size: manifest.length, platform: { architecture: p.arch, os: p.os } });
  }
  const index = json({ schemaVersion: 2, mediaType: MEDIA.index, manifests, annotations: labels });
  const digest = put(index);

  const top = { mediaType: MEDIA.index, digest, size: index.length, annotations: { 'org.opencontainers.image.ref.name': spec.version } };
  if (spec.refName) top.annotations['io.containerd.image.name'] = spec.refName;
  const entries = [
    { name: 'blobs/', dir: true, mode: 0o755 },
    { name: 'blobs/sha256/', dir: true, mode: 0o755 },
    ...[...blobs.keys()].sort().map((d) => ({ name: `blobs/sha256/${d.slice(7)}`, data: blobs.get(d), mode: 0o644 })),
    { name: 'index.json', data: json({ schemaVersion: 2, manifests: [top] }), mode: 0o644 },
    { name: 'oci-layout', data: json({ imageLayoutVersion: '1.0.0' }), mode: 0o644 },
  ];
  const archive = tar(entries, epoch);
  return {
    archive,
    digest,
    size: archive.length,
    platforms: manifests.map((m) => ({ os: m.platform.os, arch: m.platform.architecture, digest: m.digest })),
  };
}

// Read an image archive back: every blob by digest, and the image's digest
// (the one descriptor of index.json). It checks every blob against its name,
// so an archive that was altered does not read.
export function readImage(archive) {
  const files = new Map();
  for (let off = 0; off + 512 <= archive.length;) {
    const h = archive.subarray(off, off + 512);
    if (h.every((x) => x === 0)) break;
    const name = h.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const size = parseInt(h.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim() || '0', 8);
    const type = String.fromCharCode(h[156]);
    off += 512;
    if (type === '0' || type === '\0') files.set(name, archive.subarray(off, off + size));
    off += Math.ceil(size / 512) * 512;
  }
  const need = (name) => { if (!files.has(name)) throw new Error(`not an OCI image layout: no ${name}`); return files.get(name); };
  if (JSON.parse(need('oci-layout')).imageLayoutVersion !== '1.0.0') throw new Error('unknown OCI image layout version');
  const top = JSON.parse(need('index.json')).manifests;
  if (!Array.isArray(top) || top.length !== 1) throw new Error('index.json must name exactly one image');
  const blobs = new Map();
  for (const [name, data] of files) {
    const m = /^blobs\/sha256\/([0-9a-f]{64})$/.exec(name);
    if (!m) continue;
    if (sha256(data) !== m[1]) throw new Error(`blob ${m[1]} does not match its digest`);
    blobs.set(`sha256:${m[1]}`, data);
  }
  const blob = (d) => { if (!blobs.has(d)) throw new Error(`blob ${d} is missing`); return blobs.get(d); };
  const index = JSON.parse(blob(top[0].digest));
  const platforms = (index.manifests || []).map((m) => {
    const manifest = JSON.parse(blob(m.digest));
    return {
      os: m.platform.os, arch: m.platform.architecture, digest: m.digest, mediaType: m.mediaType,
      manifest, config: JSON.parse(blob(manifest.config.digest)),
    };
  });
  // Everything the index reaches is present, and nothing else is in the
  // archive.
  const reached = new Set([top[0].digest]);
  for (const p of platforms) {
    reached.add(p.digest);
    reached.add(p.manifest.config.digest);
    for (const l of p.manifest.layers) { blob(l.digest); reached.add(l.digest); }
  }
  for (const d of blobs.keys()) if (!reached.has(d)) throw new Error(`blob ${d} is not part of the image`);
  return { digest: top[0].digest, mediaType: top[0].mediaType, refName: (top[0].annotations || {})['io.containerd.image.name'] || null, index, platforms, blobs };
}
