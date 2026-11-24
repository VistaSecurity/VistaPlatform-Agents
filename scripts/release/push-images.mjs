#!/usr/bin/env node
// Push a release's container images to a registry, byte for byte.
//
//   node scripts/release/push-images.mjs --assets DIR --state DIR
//
// For every image the packaging step recorded with a repository
// (STATE/package.json), this reads the image's archive from ASSETS, checks it
// (readImage: every blob against its digest, the image against the digest
// recorded for it), and uploads its blobs and manifests over the OCI
// distribution API. Nothing is rebuilt or re-encoded, so the digest the
// registry reports is the digest in the signed release metadata; the push
// fails if it is not.
//
// A version is never reused with other bytes: if the tag already exists in
// the registry and names another digest, the push stops. If it names this
// digest (a re-run), there is nothing to do.
//
// Credentials come from REGISTRY_USERNAME and REGISTRY_PASSWORD and are sent
// only to the registry and to the token service it names over HTTPS. There is
// no dependency and no container engine involved (Node >= 20).

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

import { MEDIA, readImage } from './image.mjs';

// repository: "ghcr.io/owner/name" -> { registry: "ghcr.io", name: "owner/name" }
export function splitRepository(repository) {
  const i = repository.indexOf('/');
  if (i <= 0 || i === repository.length - 1) throw new Error(`not a repository: ${repository}`);
  return { registry: repository.slice(0, i), name: repository.slice(i + 1) };
}

function parseChallenge(header) {
  const m = /^Bearer\s+(.*)$/i.exec(header || '');
  if (!m) return null;
  const out = {};
  for (const part of m[1].match(/[a-z_]+="[^"]*"/gi) || []) {
    const eq = part.indexOf('=');
    out[part.slice(0, eq).toLowerCase()] = part.slice(eq + 2, -1);
  }
  return out.realm ? out : null;
}

// A client for one repository. opts: { scheme, username, password, fetch }.
// scheme is https unless a test says otherwise.
export function registryClient(repository, opts = {}) {
  const { registry, name } = splitRepository(repository);
  const scheme = opts.scheme || 'https';
  const doFetch = opts.fetch || fetch;
  const base = `${scheme}://${registry}`;
  const basic = opts.username ? `Basic ${Buffer.from(`${opts.username}:${opts.password || ''}`).toString('base64')}` : null;
  let bearer = null;

  async function token(challenge) {
    const realm = new URL(challenge.realm);
    // The token service is named by the registry's own answer; it gets the
    // credentials only over HTTPS (or over the test's scheme).
    if (realm.protocol !== `${scheme}:`) throw new Error(`the registry's token service is ${realm.protocol}//, refused`);
    if (challenge.service) realm.searchParams.set('service', challenge.service);
    realm.searchParams.set('scope', `repository:${name}:pull,push`);
    const res = await doFetch(realm, { headers: basic ? { Authorization: basic } : {} });
    if (!res.ok) throw new Error(`the registry's token service answered ${res.status} for ${name}`);
    const body = await res.json();
    const t = body.token || body.access_token;
    if (!t) throw new Error('the registry\'s token service returned no token');
    return t;
  }

  async function call(method, urlOrPath, { headers = {}, body, expect } = {}) {
    const url = urlOrPath.startsWith('http') ? urlOrPath : base + urlOrPath;
    if (new URL(url).host !== registry) throw new Error(`the registry sent this client to ${new URL(url).host}, refused`);
    const send = () => doFetch(url, {
      method, body, redirect: 'manual',
      headers: { ...headers, ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) },
    });
    let res = await send();
    if (res.status === 401) {
      const challenge = parseChallenge(res.headers.get('www-authenticate'));
      if (!challenge) throw new Error(`${method} ${url}: 401 with no bearer challenge`);
      bearer = await token(challenge);
      res = await send();
    }
    if (expect && !expect.includes(res.status)) {
      const text = (await res.text()).slice(0, 300);
      throw new Error(`${method} ${new URL(url).pathname}: the registry answered ${res.status}${text ? `: ${text}` : ''}`);
    }
    return res;
  }

  return {
    registry, name,
    // The digest a tag or digest reference resolves to, or null.
    async resolve(reference) {
      const res = await call('HEAD', `/v2/${name}/manifests/${reference}`, {
        headers: { Accept: `${MEDIA.index}, ${MEDIA.manifest}` }, expect: [200, 404],
      });
      return res.status === 200 ? res.headers.get('docker-content-digest') : null;
    },
    async hasBlob(digest) {
      return (await call('HEAD', `/v2/${name}/blobs/${digest}`, { expect: [200, 404] })).status === 200;
    },
    async putBlob(digest, data) {
      if (await this.hasBlob(digest)) return false;
      const start = await call('POST', `/v2/${name}/blobs/uploads/`, { expect: [202] });
      const location = new URL(start.headers.get('location'), base);
      location.searchParams.set('digest', digest);
      await call('PUT', location.toString(), {
        headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(data.length) }, body: data, expect: [201],
      });
      return true;
    },
    async putManifest(reference, mediaType, data, digest) {
      const res = await call('PUT', `/v2/${name}/manifests/${reference}`, {
        headers: { 'Content-Type': mediaType, 'Content-Length': String(data.length) }, body: data, expect: [201],
      });
      const got = res.headers.get('docker-content-digest');
      if (got && got !== digest) throw new Error(`${reference}: the registry stored ${got}, not ${digest}`);
    },
  };
}

// Push one image archive as repository:tag. Returns what happened.
export async function pushImage({ archive, repository, tag, digest, client }) {
  const img = readImage(archive);
  if (img.digest !== digest) throw new Error(`${repository}: the archive holds ${img.digest}, the release recorded ${digest}`);
  const existing = await client.resolve(tag);
  if (existing === digest) return { repository, tag, digest, pushed: false };
  if (existing) throw new Error(`${repository}:${tag} already exists as ${existing}; a version is never pushed again with other bytes`);
  let blobs = 0;
  for (const p of img.platforms) {
    for (const d of [p.manifest.config.digest, ...p.manifest.layers.map((l) => l.digest)]) {
      if (await client.putBlob(d, img.blobs.get(d))) blobs++;
    }
    await client.putManifest(p.digest, MEDIA.manifest, img.blobs.get(p.digest), p.digest);
  }
  await client.putManifest(tag, MEDIA.index, img.blobs.get(digest), digest);
  const now = await client.resolve(tag);
  if (now !== digest) throw new Error(`${repository}:${tag} resolves to ${now} after the push, not ${digest}`);
  return { repository, tag, digest, pushed: true, blobs };
}

// Push every image of a packaged release. deps.client is injectable for tests.
export async function pushRelease({ assets, state }, deps = {}) {
  const pkg = JSON.parse(readFileSync(path.join(state, 'package.json'), 'utf8'));
  const images = pkg.images || [];
  if (images.length === 0) throw new Error('this release has no container image to push');
  const out = [];
  for (const img of images) {
    if (!img.repository) throw new Error(`image ${img.name} was packaged without --image-repository, so there is nowhere to push it`);
    const client = (deps.client || ((r) => registryClient(r, { username: process.env.REGISTRY_USERNAME, password: process.env.REGISTRY_PASSWORD })))(img.repository);
    out.push(await pushImage({ archive: readFileSync(path.join(assets, img.file)), repository: img.repository, tag: pkg.version, digest: img.digest, client }));
  }
  return out;
}

async function main() {
  const { values } = parseArgs({ options: { assets: { type: 'string' }, state: { type: 'string' } } });
  for (const k of ['assets', 'state']) if (!values[k]) { console.error(`push-images.mjs: --${k} is required`); process.exit(2); }
  try {
    for (const r of await pushRelease(values)) {
      console.log(`${r.pushed ? 'pushed' : 'already there'}: ${r.repository}:${r.tag} ${r.repository}@${r.digest}`);
    }
  } catch (e) {
    console.error(`::error::push-images: ${e.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
