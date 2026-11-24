#!/usr/bin/env node
// Fill in deploy/kubernetes/vista-agents.yaml: the two image references and,
// optionally, the platform URL. Writes the manifest to standard output.
//
//   node scripts/render-kubernetes-manifest.mjs --release agents-release.json [--platform-url URL]
//   node scripts/render-kubernetes-manifest.mjs --device-agent-image REF --sensor-image REF [--platform-url URL]
//
// With --release, the images are the ones that release pushed, by digest
// (images[].registry.reference): verify agents-release.json first
// (docs/verify-release.md), and the manifest then names exactly the bytes that
// release signed. It refuses a release that pushed no images (a nightly).
//
// The registration keys are not arguments, so they do not land in shell
// history or the process list: edit the Secret at the end of the output, or
// create it yourself and delete it from the output.

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const MANIFEST = path.join(ROOT, 'deploy', 'kubernetes', 'vista-agents.yaml');
const PLACEHOLDER = {
  'vista-device-agent': 'ghcr.io/vistasecurity/vista-device-agent:REPLACE-WITH-VERSION',
  'vista-sensor': 'ghcr.io/vistasecurity/vista-sensor:REPLACE-WITH-VERSION',
};
const PLATFORM_PLACEHOLDER = 'https://REPLACE-WITH-YOUR-PLATFORM';
const IMAGE_REF = /^[a-z0-9.-]+(:\d+)?(\/[a-z0-9._-]+)+(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(@sha256:[0-9a-f]{64})?$/;

export function imagesOfRelease(meta) {
  const out = {};
  for (const img of meta.images || []) {
    if (!img.registry) throw new Error(`release ${meta.release.tag} did not push ${img.name} to a registry; load the image archive into your own registry and name it with --device-agent-image and --sensor-image`);
    out[img.name] = img.registry.reference;
  }
  for (const name of Object.keys(PLACEHOLDER)) if (!out[name]) throw new Error(`release ${meta.release && meta.release.tag} has no ${name} image`);
  return out;
}

// images: { 'vista-device-agent': ref, 'vista-sensor': ref }
export function render(text, images, platformUrl) {
  let out = text;
  const replaceOnce = (from, to, what) => {
    const parts = out.split(from);
    if (parts.length !== 2) throw new Error(`the manifest names ${what} ${parts.length - 1} times, expected once`);
    out = parts.join(to);
  };
  for (const [name, placeholder] of Object.entries(PLACEHOLDER)) {
    const ref = images[name];
    if (!ref || !IMAGE_REF.test(ref)) throw new Error(`not an image reference for ${name}: ${JSON.stringify(ref)}`);
    if (/:latest(@|$)/.test(ref)) throw new Error(`${name}: a manifest never names :latest`);
    replaceOnce(`image: ${placeholder}`, `image: ${ref}`, `the ${name} image`);
  }
  if (platformUrl !== undefined) {
    let u;
    try { u = new URL(platformUrl); } catch { throw new Error(`not a URL: ${platformUrl}`); }
    if (u.protocol !== 'https:' || u.username || u.password) throw new Error('--platform-url must be an https:// URL without credentials');
    replaceOnce(`platform-url: "${PLATFORM_PLACEHOLDER}"`, `platform-url: ${JSON.stringify(platformUrl)}`, 'the platform URL');
  }
  return out;
}

function main() {
  const { values } = parseArgs({
    options: {
      release: { type: 'string' }, 'device-agent-image': { type: 'string' }, 'sensor-image': { type: 'string' },
      'platform-url': { type: 'string' }, manifest: { type: 'string' },
    },
  });
  try {
    let images;
    if (values.release) {
      if (values['device-agent-image'] || values['sensor-image']) throw new Error('give --release, or the two images, not both');
      images = imagesOfRelease(JSON.parse(readFileSync(values.release, 'utf8')));
    } else {
      images = { 'vista-device-agent': values['device-agent-image'], 'vista-sensor': values['sensor-image'] };
    }
    process.stdout.write(render(readFileSync(values.manifest || MANIFEST, 'utf8'), images, values['platform-url']));
  } catch (e) {
    console.error(`render-kubernetes-manifest: ${e.message}`);
    process.exit(1);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
