// Tests for the container images of a release: the image builder, what the
// packaging step records about an image, and what the metadata, the validator,
// the release notes and verify-release.sh do with it. Run:
//   node --test scripts/release-images.test.mjs

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { gunzipSync } from 'node:zlib';

import { checkBuildInfo } from './release/buildinfo.mjs';
import { MODULE, REPO, SHA, buildInfoFor, makeRelease, scratchEnv, tempDir } from './release/fixture.mjs';
import { DATA_DIR, IMAGE_UID, MEDIA, buildImage, readImage } from './release/image.mjs';
import { REPO_ROOT, expectedImages, loadSurface } from './release/lib.mjs';
import { releaseNotes } from './release/notes.mjs';
import { validateDocument } from './release/validate.mjs';
import { parseYaml } from './check-workflows.mjs';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const spec = (over = {}) => ({
  name: 'vista-device-agent', version: '5.3.0', executable: 'device-agent', args: ['-interactive=false'],
  env: { DATA_PATH: DATA_DIR, HOST_INVENTORY_ENABLED: 'false' },
  platforms: [{ os: 'linux', arch: 'arm64', binary: Buffer.from('arm64 binary') }, { os: 'linux', arch: 'amd64', binary: Buffer.from('amd64 binary') }],
  docs: [{ name: 'LICENSE', data: Buffer.from('Apache') }],
  labels: { 'org.opencontainers.image.version': '5.3.0' },
  sourceTime: '2026-11-19T10:20:30Z',
  ...over,
});

// The entries of a tar: name -> { mode, uid, gid, type, data }.
function untar(buf) {
  const out = new Map();
  for (let off = 0; off + 512 <= buf.length;) {
    const h = buf.subarray(off, off + 512);
    if (h.every((x) => x === 0)) break;
    const field = (a, b) => h.subarray(a, b).toString('ascii').replace(/\0.*$/, '').trim();
    const size = parseInt(field(124, 136) || '0', 8);
    out.set(h.subarray(0, 100).toString('utf8').replace(/\0.*$/, ''), {
      mode: parseInt(field(100, 108), 8), uid: parseInt(field(108, 116), 8), gid: parseInt(field(116, 124), 8),
      mtime: parseInt(field(136, 148), 8), type: String.fromCharCode(h[156]), data: buf.subarray(off + 512, off + 512 + size),
    });
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

test('an image is a pure function of its inputs: same bytes, same digest', () => {
  const a = buildImage(spec());
  const b = buildImage(spec({ platforms: [...spec().platforms].reverse() }));
  assert.ok(a.archive.equals(b.archive), 'the order the platforms were given in changed the image');
  assert.match(a.digest, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(buildImage(spec({ version: '5.3.1', labels: { 'org.opencontainers.image.version': '5.3.1' } })).digest, a.digest);
  assert.notEqual(buildImage(spec({ sourceTime: '2026-11-19T10:20:31Z' })).digest, a.digest);
});

test('the name an image is imported under is outside its digest', () => {
  const plain = buildImage(spec());
  const named = buildImage(spec({ refName: 'ghcr.io/example/vista-device-agent:5.3.0' }));
  assert.equal(named.digest, plain.digest);
  assert.equal(readImage(named.archive).refName, 'ghcr.io/example/vista-device-agent:5.3.0');
  assert.equal(readImage(plain.archive).refName, null);
});

test('the image is an OCI layout holding one index with one manifest per platform', () => {
  const built = buildImage(spec());
  const img = readImage(built.archive);
  assert.equal(img.digest, built.digest);
  assert.equal(img.mediaType, MEDIA.index);
  assert.deepEqual(img.platforms.map((p) => `${p.os}/${p.arch}`), ['linux/amd64', 'linux/arm64']);
  assert.deepEqual(built.platforms, img.platforms.map((p) => ({ os: p.os, arch: p.arch, digest: p.digest })));
  for (const p of img.platforms) {
    assert.equal(p.mediaType, MEDIA.manifest);
    assert.equal(p.manifest.layers.length, 1, 'one layer');
    assert.equal(p.config.architecture, p.arch);
    const layer = gunzipSync(img.blobs.get(p.manifest.layers[0].digest));
    assert.equal(`sha256:${sha256(layer)}`, p.config.rootfs.diff_ids[0], 'diff_id is the uncompressed layer');
  }
});

test('the image runs as an unprivileged user, with the agent as its entrypoint and nothing else in it', () => {
  const img = readImage(buildImage(spec()).archive);
  const p = img.platforms.find((x) => x.arch === 'amd64');
  const c = p.config.config;
  assert.equal(c.User, `${IMAGE_UID}:${IMAGE_UID}`);
  assert.notEqual(IMAGE_UID, 0);
  assert.deepEqual(c.Entrypoint, ['/usr/local/bin/device-agent']);
  assert.deepEqual(c.Cmd, ['-interactive=false']);
  assert.deepEqual(c.Env, ['PATH=/usr/local/bin', `DATA_PATH=${DATA_DIR}`, 'HOST_INVENTORY_ENABLED=false']);
  assert.equal(c.WorkingDir, DATA_DIR);
  const files = untar(gunzipSync(img.blobs.get(p.manifest.layers[0].digest)));
  assert.deepEqual([...files.keys()], [
    'etc/', 'etc/group', 'etc/passwd', 'tmp/', 'usr/', 'usr/local/', 'usr/local/bin/', 'usr/local/bin/device-agent',
    'usr/share/', 'usr/share/doc/', 'usr/share/doc/vista-device-agent/', 'usr/share/doc/vista-device-agent/LICENSE',
    'var/', 'var/lib/', 'var/lib/vista/',
  ]);
  const exe = files.get('usr/local/bin/device-agent');
  assert.equal(exe.data.toString(), 'amd64 binary');
  assert.deepEqual([exe.mode, exe.uid, exe.gid], [0o755, 0, 0], 'the executable is root-owned and not writable by the user it runs as');
  const data = files.get('var/lib/vista/');
  assert.deepEqual([data.type, data.mode, data.uid, data.gid], ['5', 0o700, IMAGE_UID, IMAGE_UID], 'the data directory belongs to the agent alone');
  assert.equal(files.get('tmp/').mode, 0o1777);
  // Only the data directory is the agent's to write.
  for (const [name, e] of files) if (name !== 'var/lib/vista/') assert.equal(e.uid, 0, `${name} is owned by ${e.uid}`);
  assert.ok(files.get('etc/passwd').data.toString().includes(`vista:x:${IMAGE_UID}:${IMAGE_UID}:`));
  for (const e of files.values()) assert.equal(e.mtime, Date.parse('2026-11-19T10:20:30Z') / 1000);
});

test('an image archive that was altered does not read', () => {
  const built = buildImage(spec());
  const at = built.archive.indexOf(Buffer.from('"architecture"'));
  assert.ok(at > 0);
  const bad = Buffer.from(built.archive);
  bad[at + 1] ^= 1;
  assert.throws(() => readImage(bad), /does not match its digest/);
  assert.throws(() => readImage(Buffer.alloc(2048)), /not an OCI image layout/);
});

test('buildImage refuses what it cannot build honestly', () => {
  assert.throws(() => buildImage(spec({ platforms: [] })), /no platform/);
  assert.throws(() => buildImage(spec({ name: 'Bad Name' })), /not an image name/);
  assert.throws(() => buildImage(spec({ sourceTime: '2026-11-19 10:20:30' })), /RFC 3339/);
});

// --- the release ------------------------------------------------------------

const rel = makeRelease({ imageRepository: 'ghcr.io/vistasecurity', imagesPushed: true });
assert.deepEqual(rel.errors, [], 'the fixture release must build');
const meta = () => JSON.parse(readFileSync(path.join(rel.assets, 'agents-release.json'), 'utf8'));

test('a release publishes one image per agent, described by the metadata and matching its archive', () => {
  const m = meta();
  assert.deepEqual(validateDocument(m, rel.root), []);
  assert.deepEqual(m.images.map((i) => `${i.kind} ${i.name} ${i.file}`), [
    'sensor vista-sensor vista-sensor_5.3.0_linux.oci.tar',
    'device-agent vista-device-agent vista-device-agent_5.3.0_linux.oci.tar',
  ]);
  for (const i of m.images) {
    const img = readImage(readFileSync(path.join(rel.assets, i.file)));
    assert.equal(img.digest, i.digest);
    assert.equal(img.refName, `ghcr.io/vistasecurity/${i.name}:5.3.0`);
    assert.deepEqual(i.platforms.map((p) => `${p.os}/${p.arch} ${p.digest}`), img.platforms.map((p) => `${p.os}/${p.arch} ${p.digest}`));
    assert.deepEqual(i.registry, { repository: `ghcr.io/vistasecurity/${i.name}`, tag: '5.3.0', reference: `ghcr.io/vistasecurity/${i.name}@${i.digest}` });
    assert.equal(i.runtime_qualified, false, 'the release run starts no container, so it does not claim to have');
    assert.equal(i.sha256, sha256(readFileSync(path.join(rel.assets, i.file))));
    for (const p of img.platforms) {
      const labels = p.config.config.Labels;
      assert.equal(labels['org.opencontainers.image.version'], '5.3.0');
      assert.equal(labels['org.opencontainers.image.revision'], SHA);
      assert.equal(labels['org.opencontainers.image.source'], `https://github.com/${REPO}`);
      assert.equal(labels['org.opencontainers.image.licenses'], 'Apache-2.0');
      const files = untar(gunzipSync(img.blobs.get(p.manifest.layers[0].digest)));
      const doc = `usr/share/doc/${i.name}/`;
      for (const f of ['LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES']) assert.ok(files.has(doc + f), `${i.name} has no ${f}`);
      assert.ok(files.get(doc + 'THIRD_PARTY_LICENSES').data.equals(readFileSync(path.join(rel.assets, 'THIRD_PARTY_LICENSES'))));
      const want = i.platforms.find((x) => x.arch === p.arch);
      assert.equal(sha256(files.get(`usr/local/bin/${p.config.config.Entrypoint[0].split('/').pop()}`).data), want.executable_sha256);
      assert.equal(want.sbom.sha256, sha256(readFileSync(path.join(rel.assets, `${i.name}_5.3.0_linux_${p.arch}.image.cdx.json`))));
    }
  }
  const sensor = readImage(readFileSync(path.join(rel.assets, 'vista-sensor_5.3.0_linux.oci.tar'))).platforms[0].config.config;
  assert.ok(sensor.Env.includes('CAPTURE_DISABLED=true'), 'the sensor image runs scans only');
  assert.deepEqual(sensor.Entrypoint, ['/usr/local/bin/crypto-sensor']);
});

test('the images are provenance subjects and are listed in SHA256SUMS', () => {
  const subjects = readFileSync(path.join(rel.state, 'artifacts.sha256'), 'utf8');
  const sums = readFileSync(path.join(rel.assets, 'SHA256SUMS'), 'utf8');
  for (const i of meta().images) {
    assert.ok(subjects.includes(`${i.sha256}  ${i.file}\n`), `${i.file} is not a provenance subject`);
    assert.ok(sums.includes(`${i.sha256}  ${i.file}\n`), `${i.file} is not in SHA256SUMS`);
    assert.deepEqual(i.provenance, meta().provenance.status === 'attested' ? { url: meta().provenance.url, sha256: meta().provenance.sha256, predicate_type: meta().provenance.predicate_type } : null);
  }
});

test('a release that did not push its images names no registry', () => {
  const nightly = makeRelease({ tag: 'nightly-20261119-1a2b3c4d5e6f', provenance: 'unavailable', rootOpts: { license: false, notice: null } });
  assert.deepEqual(nightly.errors, []);
  const m = JSON.parse(readFileSync(path.join(nightly.assets, 'agents-release.json'), 'utf8'));
  assert.deepEqual(validateDocument(m, nightly.root), []);
  assert.equal(m.images.length, 2);
  for (const i of m.images) {
    assert.equal(i.registry, undefined);
    assert.equal(readImage(readFileSync(path.join(nightly.assets, i.file))).refName, null);
  }
  assert.match(releaseNotes(m), /not pushed to a registry by this release/);
  const claimed = makeRelease({ imagesPushed: true });
  assert.ok(claimed.errors.some((e) => /--images-pushed, but the package step was given no --image-repository/.test(e)), claimed.errors.join('\n'));
});

const mutations = {
  'an image file that is not named for its image and version': (m) => { m.images[0].file = 'vista-sensor_9.9.9_linux.oci.tar'; },
  'an image of another version': (m) => { m.images[0].version = '5.3.1'; },
  'a registry reference that is not this image by digest': (m) => { m.images[0].registry.reference = `${m.images[0].registry.repository}@sha256:${'0'.repeat(64)}`; },
  'a registry reference by tag': (m) => { m.images[0].registry.reference = `${m.images[0].registry.repository}:5.3.0`; },
  'a registry tag that is not the version': (m) => { m.images[0].registry.tag = 'latest'; },
  'a registry repository of another image': (m) => { m.images[0].registry.repository = 'ghcr.io/vistasecurity/other'; m.images[0].registry.reference = `ghcr.io/vistasecurity/other@${m.images[0].digest}`; },
  'an image without provenance in an attested release': (m) => { m.images[0].provenance = null; },
  'an image digest that is not a sha256': (m) => { m.images[0].digest = 'latest'; },
  'an image claimed for a system it is not built for': (m) => { m.images[0].platforms[0].os = 'windows'; },
  'a platform listed twice': (m) => { m.images[0].platforms.push(m.images[0].platforms[0]); },
  'an image URL outside the release': (m) => { m.images[0].url = 'https://example.test/vista-sensor_5.3.0_linux.oci.tar'; },
  'an unknown member on an image': (m) => { m.images[0].pull_secret = 'x'; },
};
for (const [name, mutate] of Object.entries(mutations)) {
  test(`release: ${name} fails`, () => {
    const m = meta();
    mutate(m);
    assert.ok(validateDocument(m, rel.root).length > 0);
  });
}

test('the release notes say what to pull, by digest, and that the images were not started', () => {
  const notes = releaseNotes(meta());
  for (const i of meta().images) {
    assert.ok(notes.includes(`\`${i.registry.reference}\``), `${i.name}: no pull reference`);
    assert.ok(notes.includes(`[\`${i.file}\`](${i.url})`), `${i.name}: no archive link`);
  }
  assert.match(notes, /built and checked by this run but not started in it/);
  assert.ok(notes.indexOf('## Download') < notes.indexOf('## Container images') && notes.indexOf('## Container images') < notes.indexOf('## About this release'));
});

// --- verify-release.sh ------------------------------------------------------

function verify(dir) {
  return spawnSync('bash', [path.join(REPO_ROOT, 'scripts', 'verify-release.sh'), '--repo', REPO, '--tag', 'v5.3.0', '--dir', dir, '--skip-signatures'],
    { encoding: 'utf8', env: scratchEnv() });
}

function copyOfRelease() {
  const dir = path.join(tempDir('agents-verify-image-'), 'assets');
  cpSync(rel.assets, dir, { recursive: true });
  return dir;
}

test('verify-release.sh checks each image archive against the digest the metadata names', () => {
  const good = verify(rel.assets);
  assert.equal(good.status, 0, good.stdout + good.stderr);
  for (const i of meta().images) assert.ok(good.stdout.includes(`${i.file}: image ${i.digest}`), good.stdout);
});

test('verify-release.sh refuses an image that is not the one the metadata names', () => {
  // The metadata names another digest; everything else (SHA256SUMS included)
  // still agrees with the files.
  const dir = copyOfRelease();
  const m = JSON.parse(readFileSync(path.join(dir, 'agents-release.json'), 'utf8'));
  m.images[0].digest = `sha256:${'1'.repeat(64)}`;
  delete m.images[0].registry;
  writeFileSync(path.join(dir, 'agents-release.json'), JSON.stringify(m, null, 2) + '\n');
  const sums = readFileSync(path.join(dir, 'SHA256SUMS'), 'utf8').split('\n')
    .map((l) => (l.endsWith('  agents-release.json') ? `${sha256(readFileSync(path.join(dir, 'agents-release.json')))}  agents-release.json` : l)).join('\n');
  writeFileSync(path.join(dir, 'SHA256SUMS'), sums);
  const res = verify(dir);
  assert.notEqual(res.status, 0);
  assert.match(res.stdout + res.stderr, /vista-sensor_5\.3\.0_linux\.oci\.tar: is not image sha256:1{64}/);
});

test('verify-release.sh refuses an image archive whose bytes changed', () => {
  const dir = copyOfRelease();
  const file = path.join(dir, 'vista-device-agent_5.3.0_linux.oci.tar');
  const bytes = readFileSync(file);
  bytes[bytes.indexOf(Buffer.from('"architecture"')) + 1] ^= 1;
  writeFileSync(file, bytes);
  const res = verify(dir);
  assert.notEqual(res.status, 0);
  assert.match(res.stdout + res.stderr, /vista-device-agent_5\.3\.0_linux\.oci\.tar: sha256 differs/);
});

// --- the build legs ---------------------------------------------------------

test('a container build carries exactly the tags its image declares, and no other build carries any', () => {
  const surface = loadSurface();
  for (const agent of surface.agents.filter((a) => a.image)) {
    const info = buildInfoFor(agent, { os: 'linux', arch: 'amd64', cgo: false }, '5.3.0');
    const expect = { modulePath: MODULE, command: agent.command, goos: 'linux', goarch: 'amd64', cgo: false, version: '5.3.0', sourceSha: SHA, goVersion: 'go1.26.11' };
    assert.ok(checkBuildInfo(info, { ...expect, tags: agent.image.build_tags }).some((e) => e.startsWith('build tags')), 'a build without the tags passed as a container build');
    info.Settings.push({ Key: '-tags', Value: agent.image.build_tags });
    assert.deepEqual(checkBuildInfo(info, { ...expect, tags: agent.image.build_tags }), []);
    assert.ok(checkBuildInfo(info, expect).some((e) => e.startsWith('build tags')), 'a tagged build passed as an ordinary one');
  }
  const sensor = surface.agents.find((a) => a.kind === 'sensor');
  assert.ok(sensor.image.build_tags.split(',').includes('nocapture'), 'the sensor image is built without packet capture');
  for (const a of surface.agents.filter((x) => x.image)) assert.ok(a.image.build_tags.split(',').includes('container'));
});

test('build-agents.yml has one container build leg per platform of each image, and scripts/build.sh builds it', () => {
  const surface = loadSurface();
  const wf = parseYaml(readFileSync(path.join(REPO_ROOT, '.github', 'workflows', 'build-agents.yml'), 'utf8'));
  const want = surface.agents.filter((a) => a.image).flatMap((a) => a.image.arches.map((arch) => `${a.kind} linux/${arch}`)).sort();
  const got = wf.jobs['build-container'].strategy.matrix.include.map((m) => `${m.agent} ${m.os}/${m.arch}`).sort();
  assert.deepEqual(got, want);
  assert.deepEqual(expectedImages(surface, '5.3.0').map((i) => i.file), ['vista-sensor_5.3.0_linux.oci.tar', 'vista-device-agent_5.3.0_linux.oci.tar']);
  const build = readFileSync(path.join(REPO_ROOT, 'scripts', 'build.sh'), 'utf8');
  for (const a of surface.agents.filter((x) => x.image)) {
    assert.ok(build.includes(`${a.kind}) tags=${a.image.build_tags}`), `scripts/build.sh does not build the ${a.kind} image with tags ${a.image.build_tags}`);
  }
});

// --- pushing to a registry ---------------------------------------------------

import { createServer } from 'node:http';
import { pushImage, pushRelease, registryClient, splitRepository } from './release/push-images.mjs';

// A registry that speaks enough of the OCI distribution API to be pushed to,
// with the bearer-token flow a real one uses. It stores what it is sent and
// refuses a manifest that names a blob it does not hold.
async function fakeRegistry(t, { user = 'robot', password = 'synthetic-password' } = {}) {
  const blobs = new Map();
  const manifests = new Map(); // "name:reference" -> { digest, type, data }
  const uploads = new Set();
  const seen = [];
  let tokens = 0;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const url = new URL(req.url, `http://${req.headers.host}`);
      seen.push(`${req.method} ${url.pathname}`);
      const send = (status, headers = {}, data = '') => { res.writeHead(status, headers); res.end(data); };
      if (url.pathname === '/token') {
        const want = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
        if (req.headers.authorization !== want) return send(401);
        if (url.searchParams.get('scope') !== 'repository:example/vista-device-agent:pull,push') return send(403);
        tokens++;
        return send(200, { 'Content-Type': 'application/json' }, JSON.stringify({ token: 'synthetic-token' }));
      }
      if (req.headers.authorization !== 'Bearer synthetic-token') {
        return send(401, { 'WWW-Authenticate': `Bearer realm="http://${req.headers.host}/token",service="fake"` });
      }
      let m;
      if ((m = /^\/v2\/(.+)\/blobs\/uploads\/$/.exec(url.pathname)) && req.method === 'POST') {
        const id = `u${uploads.size + 1}`;
        uploads.add(id);
        return send(202, { Location: `/v2/${m[1]}/blobs/uploads/${id}?state=x` });
      }
      if ((m = /^\/v2\/(.+)\/blobs\/uploads\/(u\d+)$/.exec(url.pathname)) && req.method === 'PUT') {
        const digest = url.searchParams.get('digest');
        if (!uploads.has(m[2]) || `sha256:${sha256(body)}` !== digest) return send(400);
        blobs.set(digest, body);
        return send(201, { 'Docker-Content-Digest': digest });
      }
      if ((m = /^\/v2\/(.+)\/blobs\/(sha256:[0-9a-f]{64})$/.exec(url.pathname)) && req.method === 'HEAD') {
        return send(blobs.has(m[2]) ? 200 : 404);
      }
      if ((m = /^\/v2\/(.+)\/manifests\/(.+)$/.exec(url.pathname))) {
        const key = `${m[1]}:${m[2]}`;
        if (req.method === 'HEAD') {
          const have = manifests.get(key);
          return have ? send(200, { 'Docker-Content-Digest': have.digest }) : send(404);
        }
        if (req.method === 'PUT') {
          const doc = JSON.parse(body);
          const refs = doc.manifests ? doc.manifests.map((x) => `m:${x.digest}`) : [doc.config, ...doc.layers].map((x) => `b:${x.digest}`);
          for (const r of refs) {
            const d = r.slice(2);
            if (r.startsWith('b:') ? !blobs.has(d) : !manifests.has(`${m[1]}:${d}`)) return send(400, {}, `unknown ${d}`);
          }
          const digest = `sha256:${sha256(body)}`;
          const entry = { digest, type: req.headers['content-type'], data: body };
          manifests.set(key, entry);
          manifests.set(`${m[1]}:${digest}`, entry);
          return send(201, { 'Docker-Content-Digest': digest });
        }
      }
      return send(404);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const host = `127.0.0.1:${server.address().port}`;
  return { host, blobs, manifests, seen, tokens: () => tokens, client: (repo, creds = { username: user, password }) => registryClient(repo, { scheme: 'http', ...creds }) };
}

test('an image is pushed byte for byte: the registry holds the digest the release recorded', async (t) => {
  const reg = await fakeRegistry(t);
  const built = buildImage(spec());
  const repository = `${reg.host}/example/vista-device-agent`;
  const first = await pushImage({ archive: built.archive, repository, tag: '5.3.0', digest: built.digest, client: reg.client(repository) });
  assert.deepEqual(first, { repository, tag: '5.3.0', digest: built.digest, pushed: true, blobs: 4 });
  const img = readImage(built.archive);
  const stored = reg.manifests.get('example/vista-device-agent:5.3.0');
  assert.equal(stored.digest, built.digest);
  assert.equal(stored.type, MEDIA.index);
  assert.ok(stored.data.equals(img.blobs.get(built.digest)), 'the index was re-encoded');
  for (const p of img.platforms) {
    assert.ok(reg.manifests.get(`example/vista-device-agent:${p.digest}`).data.equals(img.blobs.get(p.digest)));
    for (const l of p.manifest.layers) assert.ok(reg.blobs.get(l.digest).equals(img.blobs.get(l.digest)));
  }
  assert.equal(reg.tokens(), 1, 'one token for the whole push');

  // A re-run finds the same image and uploads nothing.
  const before = reg.seen.length;
  const again = await pushImage({ archive: built.archive, repository, tag: '5.3.0', digest: built.digest, client: reg.client(repository) });
  assert.equal(again.pushed, false);
  assert.ok(reg.seen.slice(before).every((l) => l.startsWith('HEAD ') || l === 'GET /token'), reg.seen.slice(before).join('\n'));
});

test('a version is never pushed again with other bytes', async (t) => {
  const reg = await fakeRegistry(t);
  const repository = `${reg.host}/example/vista-device-agent`;
  const a = buildImage(spec());
  await pushImage({ archive: a.archive, repository, tag: '5.3.0', digest: a.digest, client: reg.client(repository) });
  const b = buildImage(spec({ sourceTime: '2026-11-20T00:00:00Z' }));
  await assert.rejects(pushImage({ archive: b.archive, repository, tag: '5.3.0', digest: b.digest, client: reg.client(repository) }), /already exists as sha256:[0-9a-f]{64}; a version is never pushed again/);
  assert.equal(reg.manifests.get('example/vista-device-agent:5.3.0').digest, a.digest);
});

test('a push stops on an archive that is not the recorded image, on bad credentials, and on a redirect elsewhere', async (t) => {
  const reg = await fakeRegistry(t);
  const repository = `${reg.host}/example/vista-device-agent`;
  const built = buildImage(spec());
  await assert.rejects(pushImage({ archive: built.archive, repository, tag: '5.3.0', digest: `sha256:${'2'.repeat(64)}`, client: reg.client(repository) }), /the archive holds sha256:[0-9a-f]{64}, the release recorded sha256:2{64}/);
  await assert.rejects(pushImage({ archive: built.archive, repository, tag: '5.3.0', digest: built.digest, client: reg.client(repository, { username: 'robot', password: 'wrong' }) }), /token service answered 401/);
  assert.equal(reg.blobs.size, 0, 'something was uploaded');
  // The registry names a token service on another scheme or host: no
  // credentials go there.
  const elsewhere = registryClient(repository, {
    scheme: 'http', username: 'robot', password: 'synthetic-password',
    fetch: async () => new Response('', { status: 401, headers: { 'WWW-Authenticate': 'Bearer realm="https://tokens.example.test/token",service="x"' } }),
  });
  await assert.rejects(elsewhere.resolve('5.3.0'), /token service is https:\/\/, refused/);
  assert.deepEqual(splitRepository('ghcr.io/vistasecurity/vista-sensor'), { registry: 'ghcr.io', name: 'vistasecurity/vista-sensor' });
  assert.throws(() => splitRepository('vista-sensor'));
});

test('pushRelease pushes every image the package step recorded, under the release version', async (t) => {
  const reg = await fakeRegistry(t);
  const r = makeRelease({ imageRepository: `${reg.host}/example`.replace('127.0.0.1', 'localhost') });
  // The fixture's repository must be lower-case host/path; the fake registry
  // is reached through a client built for it here.
  assert.deepEqual(r.errors, []);
  const calls = [];
  const out = await pushRelease({ assets: r.assets, state: r.state }, {
    client: (repository) => { calls.push(repository); return { resolve: async () => null, putBlob: async () => true, putManifest: async () => {}, hasBlob: async () => false }; },
  }).catch((e) => e);
  // The stub never stores, so the final check must refuse the push.
  assert.match(String(out), /resolves to null after the push/);
  assert.deepEqual(calls, [`localhost:${reg.host.split(':')[1]}/example/vista-sensor`]);
  const none = makeRelease();
  await assert.rejects(pushRelease({ assets: none.assets, state: none.state }), /packaged without --image-repository/);
});

// --- the manifest renderer ---------------------------------------------------

import { MANIFEST, imagesOfRelease, render } from './render-kubernetes-manifest.mjs';

test('the manifest is rendered with the images a release pushed, by digest', () => {
  const text = readFileSync(MANIFEST, 'utf8');
  const images = imagesOfRelease(meta());
  const out = render(text, images, 'https://vista.example.test');
  for (const i of meta().images) {
    assert.ok(out.includes(`image: ${i.registry.reference}\n`), `${i.name} is not pinned by digest`);
    assert.match(i.registry.reference, /@sha256:[0-9a-f]{64}$/);
  }
  assert.ok(!out.includes('REPLACE-WITH-VERSION'));
  assert.ok(out.includes('platform-url: "https://vista.example.test"'));
  assert.ok(out.includes('REPLACE-WITH-THE-DEVICE-AGENT-REGISTRATION-KEY'), 'the registration keys are not the renderer\'s to fill');
  // Everything else is the file as committed.
  assert.equal(out.split('\n').length, text.split('\n').length);
});

test('the renderer refuses a release without pushed images, a tag named latest, and anything that is not a reference', () => {
  const text = readFileSync(MANIFEST, 'utf8');
  const nightly = meta();
  for (const i of nightly.images) delete i.registry;
  assert.throws(() => imagesOfRelease(nightly), /did not push vista-sensor to a registry/);
  const ok = { 'vista-device-agent': 'registry.example.test/vista/vista-device-agent:6.2.0', 'vista-sensor': 'registry.example.test/vista/vista-sensor:6.2.0' };
  assert.ok(render(text, ok).includes('image: registry.example.test/vista/vista-sensor:6.2.0'));
  assert.throws(() => render(text, { ...ok, 'vista-sensor': 'registry.example.test/vista/vista-sensor:latest' }), /never names :latest/);
  assert.throws(() => render(text, { ...ok, 'vista-sensor': 'vista-sensor; rm -rf /' }), /not an image reference/);
  assert.throws(() => render(text, { 'vista-device-agent': ok['vista-device-agent'] }), /not an image reference for vista-sensor/);
  assert.throws(() => render(text, ok, 'http://vista.example.test'), /https/);
  assert.throws(() => render(text, ok, 'https://user:pw@vista.example.test'), /without credentials/);
  assert.throws(() => render(render(text, ok), ok), /names the vista-device-agent image 0 times/);
});
