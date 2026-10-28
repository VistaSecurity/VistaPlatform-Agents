// What a built binary says about itself (`go version -m -json`), checked
// against what the release expects before anything is packaged or signed:
// the right command, OS, architecture and CGO setting, -trimpath, the
// version stamp, the toolchain go.mod pins, and the exact source commit with
// no local modification. A binary that fails here never reaches a signature.

import { execFileSync } from 'node:child_process';

export function readBuildInfo(file) {
  const out = execFileSync('go', ['version', '-m', '-json', file], { encoding: 'utf8', maxBuffer: 64 << 20 });
  return JSON.parse(out);
}

export function settingsOf(info) {
  const m = new Map();
  for (const s of info.Settings || []) m.set(s.Key, s.Value);
  return m;
}

// The modules linked into the binary, excluding the main module.
export function modulesOf(info) {
  return (info.Deps || []).map((d) => {
    const r = d.Replace || null;
    if (r) throw new Error(`module ${d.Path} is replaced by ${r.Path}@${r.Version}: a release never builds with replace directives`);
    return { path: d.Path, version: d.Version, sum: d.Sum || '' };
  });
}

// expect: { modulePath, command, goos, goarch, cgo, version, sourceSha, goVersion }
export function checkBuildInfo(info, expect) {
  const errors = [];
  const s = settingsOf(info);
  const want = (label, got, exp) => { if (got !== exp) errors.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(exp)}`); };
  want('main package', info.Path, `${expect.modulePath}/${expect.command}`);
  want('main module', info.Main && info.Main.Path, expect.modulePath);
  want('Go toolchain', info.GoVersion, expect.goVersion);
  want('GOOS', s.get('GOOS'), expect.goos);
  want('GOARCH', s.get('GOARCH'), expect.goarch);
  want('CGO_ENABLED', s.get('CGO_ENABLED'), expect.cgo ? '1' : '0');
  want('-trimpath', s.get('-trimpath'), 'true');
  want('vcs', s.get('vcs'), 'git');
  want('vcs.revision', s.get('vcs.revision'), expect.sourceSha);
  want('vcs.modified', s.get('vcs.modified'), 'false');
  // Under -trimpath the toolchain does not record -ldflags in the build
  // information (go.dev/issue/52372), so the version stamp is checked in the
  // binary itself (checkVersionStamp) and, on the smoked targets, by running it.
  if (s.has('-ldflags')) errors.push('-ldflags is recorded, so this binary was not built with -trimpath as scripts/build.sh builds');
  if (s.has('-tags') && s.get('-tags') !== '') errors.push(`build tags ${JSON.stringify(s.get('-tags'))}: release builds use none`);
  for (const d of info.Deps || []) {
    if (d.Replace) errors.push(`module ${d.Path} is replaced (${d.Replace.Path})`);
    if (!/^v\d/.test(d.Version || '')) errors.push(`module ${d.Path} has no released version (${JSON.stringify(d.Version)})`);
  }
  return errors;
}

// The version scripts/build.sh stamps into main.Version is a string in the
// binary's data. Its presence is necessary, not sufficient (the same bytes
// could occur elsewhere); the smoke legs run the binaries they can and compare
// what -version reports.
export function checkVersionStamp(bytes, version) {
  return bytes.includes(Buffer.from(version)) ? [] : [`version stamp: the binary does not contain ${JSON.stringify(version)}`];
}
