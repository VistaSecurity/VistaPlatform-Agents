#!/usr/bin/env node
// scripts/install-sensor-macos.sh and scripts/install-device-agent-macos.sh,
// tested where macOS is not available.
//
//   1. Static guards: both parse, they share one block of functions byte for
//      byte, and no line of code uses what macOS lacks: bash 4 features (macOS
//      ships bash 3.2) or Linux-only tools.
//   2. Their parts, run by sourcing the script: the launchd job description
//      (parsed as a real property list by Python's plistlib), the wrapper
//      launchd runs (exit status 78 must stop restarts, a signal must reach
//      the agent, the log must stay bounded) and how the binary is found.
//   3. The whole install, run against stand-ins for the macOS commands
//      (uname, launchctl, dscl, plutil, ifconfig, route, xattr, ...) and a fake
//      agent that rewrites its config the way the real one does on enrolment.
//
// Every test that runs bash also runs under bash 3.2 when BASH32 names one
// (for example a bash-3.2.57 built from source), which is the shell macOS
// runs these with. Without it they run under the system bash only, and the
// static guard is what stands for bash 3.2.
//
// What the installers' config does once it reaches the real agents is tested
// in Go: cmd/sensor/installer_config_test.go, cmd/device-agent/installer_config_test.go.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const here = (f) => fileURLToPath(new URL(`./${f}`, import.meta.url));
const SENSOR = here('install-sensor-macos.sh');
const DEVICE = here('install-device-agent-macos.sh');
const INSTALLERS = [['install-sensor-macos.sh', SENSOR], ['install-device-agent-macos.sh', DEVICE]];
const BASHES = ['bash', ...(process.env.BASH32 ? [process.env.BASH32] : [])];
const PYTHON = spawnSync('python3', ['-c', 'import plistlib'], { encoding: 'utf8' }).status === 0 ? 'python3' : null;
const UUID = '3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59';

const source = (f) => readFileSync(f, 'utf8');
// Comments explain history and may name what is forbidden; only code counts.
const codeOf = (text) => text.split('\n').filter((l) => !l.trimStart().startsWith('#')).join('\n');
const sharedBlock = (text) => {
  const m = /^# --- shared macOS installer functions \(begin\) ---$[\s\S]*?^# --- shared macOS installer functions \(end\) ---$/m.exec(text);
  assert.ok(m, 'shared block markers not found');
  return m[0];
};

function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), 'macos-installer-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// --- 1. static ----------------------------------------------------------------

for (const [name, file] of INSTALLERS) {
  for (const sh of BASHES) {
    test(`${name} parses (${sh})`, () => {
      const r = spawnSync(sh, ['-n', file], { encoding: 'utf8' });
      assert.equal(r.status, 0, r.stderr);
    });
  }
}

test('both macOS installers carry the same shared functions', () => {
  assert.equal(sharedBlock(source(DEVICE)), sharedBlock(source(SENSOR)));
});

// What macOS does not have. bash 3.2: associative arrays, case conversion,
// mapfile, namerefs, negative subscripts, ;& and ;;& in case, |&, &>>, coproc,
// ${v@Q}, [[ -v ]], wait -n, printf %(...)T, read -N/-i, globstar. macOS
// userland: no GNU sed -i, no ip/ss, useradd, systemctl, journalctl,
// sha256sum-only hashing, readlink -f, stat -c, date -d, grep -P, timeout.
const MACOS_FORBIDDEN = [
  [/\b(declare|local|typeset)\s+-[a-zA-Z]*A/, 'associative array'],
  [/\$\{[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?(,,?|\^\^?)\}/, 'case conversion ${v,,} / ${v^^}'],
  [/\b(mapfile|readarray|coproc)\b/, 'bash 4 builtin'],
  [/\b(declare|local|typeset)\s+-[a-zA-Z]*n\b/, 'nameref'],
  [/\$\{[A-Za-z_][A-Za-z0-9_]*\[-\d+\]\}/, 'negative array subscript'],
  [/;;&|;&\s*$/m, 'case fall-through'],
  [/\|&/, '|& (pipe stderr)'],
  [/&>>/, '&>> (append both)'],
  [/\$\{[A-Za-z_][A-Za-z0-9_]*@[QEPAa]\}/, '${v@op}'],
  [/\[\[\s+-v\s/, '[[ -v ]]'],
  [/\bwait\s+-n\b/, 'wait -n'],
  [/%\([^)]*\)T/, 'printf %(...)T'],
  [/\bread\b[^\n|]*\s-[a-zA-Z]*[Ni]\b/, 'read -N / read -i'],
  [/\bshopt\s+-s\s+globstar\b/, 'globstar'],
  [/\$EPOCHSECONDS|\$EPOCHREALTIME|\$BASHPID/, 'bash 4/5 variable'],
  [/\bsed\s+(-[a-zA-Z]*\s+)*-i\b/, 'GNU sed -i'],
  [/(^|[\s;|&(])(ip|ss|useradd|groupadd|systemctl|journalctl|timeout|tac)\s/m, 'Linux-only command'],
  [/\breadlink\s+-f\b|\bstat\s+-c\b|\bdate\s+-d\b|\bgrep\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*P/, 'GNU-only option'],
];

function macosViolations(text) {
  const code = codeOf(text);
  return MACOS_FORBIDDEN.filter(([re]) => re.test(code)).map(([, what]) => what);
}

for (const [name, file] of INSTALLERS) {
  test(`${name} uses nothing macOS lacks (bash 3.2, BSD userland)`, () => {
    assert.deepEqual(macosViolations(source(file)), []);
  });
}

test('the macOS guard catches what it is for (mutations)', () => {
  const base = source(SENSOR);
  const mutations = [
    'declare -A seen=()', 'local -A seen', 'x=${name,,}', 'x=${name^^}', 'mapfile -t lines < f',
    'local -n ref=x', 'echo ${a[-1]}', 'cmd |& tee f', 'cmd &>> f', 'echo ${v@Q}', 'if [[ -v FOO ]]; then :; fi',
    'wait -n', "printf '%(%s)T' -1", 'read -N 1 c', 'shopt -s globstar', 'echo $EPOCHSECONDS',
    'sed -i "s/a/b/" f', 'ip -o link show', 'useradd -r x', 'systemctl restart x', 'journalctl -u x',
    'readlink -f x', 'stat -c %s f', 'date -d @1', 'grep -P x f', 'timeout 5 x',
  ];
  for (const m of mutations) {
    assert.notDeepEqual(macosViolations(`${base}\n${m}\n`), [], `not caught: ${m}`);
  }
  // ...and a comment naming them is not code.
  assert.deepEqual(macosViolations(`${base}\n# systemctl and ${'$'}{v,,} do not exist here\n`), []);
});

for (const [name, file] of INSTALLERS) {
  const code = codeOf(source(file));
  test(`${name} leaves enrolment to the agent`, () => {
    assert.doesNotMatch(code, /(sensors|agents)\/register/, 'installer calls the register endpoint itself');
    assert.doesNotMatch(code, /\s-register\b/, 'installer runs the agent with -register');
    assert.match(code, /\[0-9a-fA-F\]\{8\}-\[0-9a-fA-F\]\{4\}/, 'no UUID check on the enrolled id');
  });
  test(`${name} never prints the registration key and takes it from stdin or the environment`, () => {
    const unmasked = code.replace(/mask_key "\$REGISTRATION_KEY"/g, '');
    assert.doesNotMatch(unmasked, /echo[^\n]*\$REGISTRATION_KEY|print_\w+[^\n]*\$REGISTRATION_KEY/);
    assert.match(code, /REGISTRATION_KEY="\$\{VISTA_REGISTRATION_KEY:-\}"/);
    assert.match(code, /--key-stdin\) read_key_from_stdin/);
  });
}

// --- 2. parts -----------------------------------------------------------------

// Runs bash code with the installer sourced (its main does not run).
function sourced(sh, file, code, opts = {}) {
  const r = spawnSync(sh, ['-c', `source "$1"; shift; ${code}`, 'test', file, ...(opts.args || [])], {
    encoding: 'utf8', timeout: 20000, cwd: opts.cwd, env: { ...process.env, ...(opts.env || {}) },
  });
  assert.ifError(r.error);
  return { ...r, output: r.stdout + r.stderr };
}

function plist(path) {
  const r = spawnSync(PYTHON, ['-I', '-c', 'import plistlib,json,sys; print(json.dumps(plistlib.load(open(sys.argv[1],"rb"))))', path], { encoding: 'utf8' });
  assert.equal(r.status, 0, `not a property list: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

for (const sh of BASHES) {
  test(`the launchd job description is a valid plist that restarts on failure only (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    const dir = scratch(t);
    const out = join(dir, 'job.plist');
    const r = sourced(sh, SENSOR, 'PLIST_ENV=("SENSOR_IP_ADDRESS=192.0.2.10" "ODD=a&b<c>"); write_launchd_plist "$@"', {
      args: [out, 'io.vistasecurity.sensor', '', '/usr/local/vista-sensor', '/var/log/x.log',
        '/usr/local/vista-sensor/service.sh', '/l/sensor.log', '/usr/local/vista-sensor/vista-sensor', '-config', '/p/a b&c.yaml'],
    });
    assert.equal(r.status, 0, r.output);
    const p = plist(out);
    assert.equal(p.Label, 'io.vistasecurity.sensor');
    assert.deepEqual(p.ProgramArguments, ['/usr/local/vista-sensor/service.sh', '/l/sensor.log',
      '/usr/local/vista-sensor/vista-sensor', '-config', '/p/a b&c.yaml']);
    assert.equal(p.RunAtLoad, true);
    assert.deepEqual(p.KeepAlive, { SuccessfulExit: false }, 'restart only when the wrapper reports failure');
    assert.equal(p.ThrottleInterval, 10);
    assert.equal(p.WorkingDirectory, '/usr/local/vista-sensor');
    assert.deepEqual(p.EnvironmentVariables, { SENSOR_IP_ADDRESS: '192.0.2.10', ODD: 'a&b<c>' });
    assert.ok(!('UserName' in p), 'an empty user means root: no UserName key');
  });

  test(`a job with a user runs as that user and group (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    const dir = scratch(t);
    const out = join(dir, 'job.plist');
    const r = sourced(sh, DEVICE, 'PLIST_ENV=(); write_launchd_plist "$@"', {
      args: [out, 'io.vistasecurity.device-agent', '_vistadeviceagent', '/w', '/l', '/w/service.sh', '/l/a.log', '/w/vista-device-agent'],
    });
    assert.equal(r.status, 0, r.output);
    const p = plist(out);
    assert.equal(p.UserName, '_vistadeviceagent');
    assert.equal(p.GroupName, '_vistadeviceagent');
    assert.ok(!('EnvironmentVariables' in p));
  });
}

// The wrapper, run for real with a stand-in agent.
function wrapper(t, sh) {
  const dir = scratch(t);
  const w = join(dir, 'service.sh');
  const r = sourced(sh, SENSOR, 'write_service_wrapper "$1"', { args: [w] });
  assert.equal(r.status, 0, r.output);
  assert.equal(statSync(w).mode & 0o777, 0o755);
  return { dir, w, log: join(dir, 'agent.log') };
}

function runWrapper(sh, w, log, agent, env = {}) {
  return spawnSync(sh, [w, log, 'sh', '-c', agent], { encoding: 'utf8', timeout: 20000, env: { ...process.env, ...env } });
}

for (const sh of BASHES) {
  test(`wrapper: exit 78 stops launchd restarting the agent (${sh})`, (t) => {
    const { w, log } = wrapper(t, sh);
    const r = runWrapper(sh, w, log, 'echo "⛔ Registration was REJECTED"; exit 78');
    assert.equal(r.status, 0, 'KeepAlive SuccessfulExit=false restarts anything but 0');
    const text = readFileSync(log, 'utf8');
    assert.match(text, /⛔ Registration was REJECTED/);
    assert.match(text, /exited with status 78: it needs a person/);
    assert.ok(!existsSync(`${log}.pipe`), 'the pipe is left behind');
  });

  test(`wrapper: a clean exit (a restart the platform asked for) and a crash are both restarted (${sh})`, (t) => {
    const { w, log } = wrapper(t, sh);
    assert.equal(runWrapper(sh, w, log, 'exit 0').status, 75);
    assert.equal(runWrapper(sh, w, log, 'exit 3').status, 3);
    assert.match(readFileSync(log, 'utf8'), /exited normally[\s\S]*exited with status 3/);
  });

  test(`wrapper: launchd's SIGTERM reaches the agent, which shuts down cleanly (${sh})`, async (t) => {
    const { dir, w, log } = wrapper(t, sh);
    const marker = join(dir, 'got-term');
    const { spawn } = await import('node:child_process');
    const p = spawn(sh, [w, log, 'sh', '-c', `trap 'echo term > ${marker}; exit 0' TERM; echo started; while :; do sleep 0.1; done`],
      { stdio: 'ignore', detached: true });
    // If the signal never reaches the agent it runs on: end the whole group.
    t.after(() => { try { process.kill(-p.pid, 'SIGKILL'); } catch { /* gone */ } });
    const exited = new Promise((res) => p.on('exit', (code) => res(code)));
    for (let i = 0; i < 100 && !(existsSync(log) && readFileSync(log, 'utf8').includes('started')); i++) await new Promise((r) => setTimeout(r, 50));
    p.kill('SIGTERM');
    const code = await exited;
    assert.equal(readFileSync(marker, 'utf8').trim(), 'term', 'the agent never saw the signal');
    assert.equal(code, 75);
  });

  test(`wrapper: the log moves aside at the size limit, so it stays bounded (${sh})`, (t) => {
    const { w, log } = wrapper(t, sh);
    const r = runWrapper(sh, w, log, 'i=0; while [ $i -lt 400 ]; do echo "line $i of the agent log"; i=$((i+1)); done', { VISTA_LOG_MAX_BYTES: '2000' });
    assert.equal(r.status, 75, r.stderr);
    assert.ok(existsSync(`${log}.1`), 'never rotated');
    assert.ok(statSync(log).size <= 2100 && statSync(`${log}.1`).size <= 2100, 'a log file passed the limit');
    assert.match(readFileSync(log, 'utf8'), /exited normally/, 'last lines lost');
  });
}

// find_agent_binary, against a directory of downloads.
function find(t, sh, file, names, arch = 'arm64') {
  const dir = scratch(t);
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  writeFileSync(join(bin, 'sysctl'), `#!/bin/sh\n[ "${arch}" = arm64 ] && echo 1 || echo 0\n`, { mode: 0o755 });
  writeFileSync(join(bin, 'uname'), `#!/bin/sh\ncase "$1" in -m) [ "${arch}" = arm64 ] && echo arm64 || echo x86_64 ;; *) echo Darwin ;; esac\n`, { mode: 0o755 });
  for (const n of names) writeFileSync(join(dir, n), '#!/bin/sh\n', { mode: 0o755 });
  return sourced(sh, file, 'find_agent_binary', { cwd: dir, env: { PATH: `${bin}:${process.env.PATH}` } });
}

for (const sh of BASHES) {
  test(`the binary is found under its archive name or its release name (${sh})`, (t) => {
    let r = find(t, sh, SENSOR, ['crypto-sensor', 'vista-sensor_5.4.0_darwin_arm64']);
    assert.equal(r.stdout.trim(), './crypto-sensor');
    r = find(t, sh, SENSOR, ['vista-sensor_5.4.0_darwin_arm64', 'vista-sensor_5.4.0_darwin_arm64.tar.gz',
      'vista-sensor_5.4.0_darwin_arm64.cdx.json', 'vista-sensor_5.4.0_darwin_amd64', 'vista-sensor_5.4.0_linux_arm64']);
    assert.equal(r.status, 0, r.output);
    assert.equal(r.stdout.trim(), './vista-sensor_5.4.0_darwin_arm64');
    r = find(t, sh, DEVICE, ['vista-device-agent_5.4.0_darwin_amd64'], 'amd64');
    assert.equal(r.stdout.trim(), './vista-device-agent_5.4.0_darwin_amd64');
  });

  test(`no binary, or two candidates, fails naming both accepted names (${sh})`, (t) => {
    let r = find(t, sh, DEVICE, ['vista-device-agent_5.4.0_darwin_amd64']);
    assert.equal(r.status, 1);
    assert.match(r.output, /\.\/device-agent/);
    assert.match(r.output, /vista-device-agent_<version>_darwin_arm64/);
    r = find(t, sh, SENSOR, ['vista-sensor_5.3.0_darwin_arm64', 'vista-sensor_5.4.0_darwin_arm64']);
    assert.equal(r.status, 1);
    assert.match(r.output, /keep only the one/);
  });
}

// --- 3. the whole install, against stand-ins -----------------------------------

const LAUNCHCTL = String.raw`#!/usr/bin/env python3
# Stand-in for launchctl: bootstrap starts ProgramArguments the way launchd
# would (environment, working directory, StandardOutPath); bootout sends
# SIGTERM and waits; print reports running or not. Calls go to calls.log.
import json, os, plistlib, signal, subprocess, sys, time
state = os.environ['FAKE_LAUNCHD']
os.makedirs(state, exist_ok=True)
with open(os.path.join(state, 'calls.log'), 'a') as f: f.write(' '.join(sys.argv[1:]) + '\n')
cmd = sys.argv[1]
def label_of(t): return t.split('/', 1)[1]
def pidfile(l): return os.path.join(state, l + '.pid')
def alive(l):
    try:
        pid = int(open(pidfile(l)).read())
        os.kill(pid, 0)
        return subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()[:1] not in ('Z', '')
    except Exception:
        return False
if cmd == 'print':
    l = label_of(sys.argv[2])
    if not os.path.exists(os.path.join(state, l + '.loaded')): sys.exit(113)
    print('state = running' if alive(l) else 'state = not running')
elif cmd == 'bootstrap':
    p = plistlib.load(open(sys.argv[3], 'rb'))
    l = p['Label']
    if os.path.exists(os.path.join(state, l + '.loaded')): sys.exit(5)
    if os.path.exists(os.path.join(state, l + '.disabled')): sys.exit(119)
    env = dict(os.environ); env.update(p.get('EnvironmentVariables', {}))
    out = open(p['StandardOutPath'], 'a')
    proc = subprocess.Popen(p['ProgramArguments'], cwd=p['WorkingDirectory'], env=env, stdout=out, stderr=out, stdin=subprocess.DEVNULL, start_new_session=True)
    open(pidfile(l), 'w').write(str(proc.pid))
    json.dump(p, open(os.path.join(state, l + '.loaded'), 'w'))
elif cmd == 'bootout':
    l = label_of(sys.argv[2])
    if not os.path.exists(os.path.join(state, l + '.loaded')): sys.exit(3)
    try:
        pid = int(open(pidfile(l)).read())
        os.kill(pid, signal.SIGTERM)
        for _ in range(100):
            if not alive(l): break
            time.sleep(0.05)
    except Exception: pass
    os.remove(os.path.join(state, l + '.loaded'))
elif cmd == 'disable':
    open(os.path.join(state, label_of(sys.argv[2]) + '.disabled'), 'w').close()
elif cmd == 'enable':
    try: os.remove(os.path.join(state, label_of(sys.argv[2]) + '.disabled'))
    except FileNotFoundError: pass
else:
    sys.exit(64)
`;

// A stand-in agent: answers -version, then behaves like the real one on
// first start. Key REG-bad: rejected, exit 78. Otherwise it records how it
// was started and, if not enrolled yet, writes the id into its config.
const fakeAgent = (idKey, keyKey) => `#!/bin/sh
case "$1" in -version|--version) echo "Vista Platform agent v9.9.9"; echo "Platform: darwin/arm64"; exit 0 ;; esac
cfg=""; for a in "$@"; do [ "$prev" = -config ] && cfg=$a; prev=$a; done
echo "$*" > "$FAKE_LAUNCHD/agent-args"
echo "SENSOR_IP_ADDRESS=$SENSOR_IP_ADDRESS" > "$FAKE_LAUNCHD/agent-env"
cp "$cfg" "$FAKE_LAUNCHD/config-at-start"
stat -c %a "$cfg" > "$FAKE_LAUNCHD/config-mode"
key=$(sed -n 's/^${keyKey}: "\\(.*\\)"$/\\1/p' "$cfg")
if [ "$key" = REG-bad ]; then echo "⛔ Registration was REJECTED: key already used"; exit 78; fi
if ! grep -q '^${idKey}: "${UUID}"' "$cfg"; then
  sleep 0.3
  sed -e 's/^${idKey}: .*$/${idKey}: "${UUID}"/' "$cfg" > "$cfg.new"
  grep -q '^${idKey}:' "$cfg.new" || echo '${idKey}: "${UUID}"' >> "$cfg.new"
  mv "$cfg.new" "$cfg"
  echo "✅ enrolled"
fi
trap 'exit 0' TERM
while :; do sleep 0.1; done
`;

const DSCL = String.raw`#!/bin/sh
# Stand-in for dscl: one file per record under $FAKE_LAUNCHD/ds.
db="$FAKE_LAUNCHD/ds"; mkdir -p "$db/Users" "$db/Groups"
echo "dscl $*" >> "$FAKE_LAUNCHD/calls.log"
shift
op=$1; rec=$2; key=$3; val=$4
case "$op" in
  -read) [ -f "$db$rec" ] || exit 56; [ -z "$key" ] || grep "^$key: " "$db$rec" || exit 181 ;;
  -create) touch "$db$rec"; [ -z "$key" ] || echo "$key: $val" >> "$db$rec" ;;
  -delete) rm -f "$db$rec" ;;
  -list) for f in "$db$rec"/*; do [ -f "$f" ] || continue; v=$(sed -n "s/^$key: //p" "$f"); [ -n "$v" ] && echo "$(basename "$f") $v"; done; true ;;
esac
`;

function macHost(t, kind) {
  const dir = mkdtempSync(join(tmpdir(), 'macos-installer-'));
  const bin = join(dir, 'bin');
  const state = join(dir, 'launchd');
  const work = join(dir, 'download');
  for (const d of [bin, state, work, join(dir, 'tmp')]) mkdirSync(d, { recursive: true });
  const stub = (name, text) => writeFileSync(join(bin, name), text, { mode: 0o755 });
  stub('uname', '#!/bin/sh\ncase "$1" in -m) echo arm64 ;; *) echo Darwin ;; esac\n');
  stub('sysctl', '#!/bin/sh\necho 1\n');
  stub('id', `#!/bin/sh\n[ "$1" = -u ] && { echo "\${FAKE_UID:-0}"; exit 0; }\nexec /usr/bin/id "$@"\n`);
  stub('xattr', '#!/bin/sh\nexit 0\n');
  stub('chown', '#!/bin/sh\necho "chown $*" >> "$FAKE_LAUNCHD/calls.log"\n');
  stub('plutil', `#!/bin/sh\n[ "$1" = -lint ] && exec ${PYTHON || 'python3'} -I -c 'import plistlib,sys; plistlib.load(open(sys.argv[1],"rb"))' "$2"\nexit 64\n`);
  stub('route', '#!/bin/sh\necho "   route to: default"\necho "  interface: en0"\n');
  stub('ifconfig', '#!/bin/sh\ncase "$1" in\n  -a) printf "lo0: flags\\n\\tinet 127.0.0.1 netmask 0xff000000\\nen0: flags\\n\\tinet6 fe80::1%%en0 prefixlen 64\\n\\tinet 192.0.2.10 netmask 0xffffff00\\n" ;;\n  -l) echo "lo0 en0 en1" ;;\n  en0|en1|lo0) echo "$1: flags" ;;\n  *) echo "ifconfig: interface $1 does not exist" >&2; exit 1 ;;\nesac\n');
  stub('hostname', '#!/bin/sh\necho testmac\n');
  stub('launchctl', LAUNCHCTL);
  stub('dscl', DSCL);
  const sensor = kind === 'sensor';
  writeFileSync(join(work, sensor ? 'crypto-sensor' : 'device-agent'),
    sensor ? fakeAgent('sensorId', 'registrationKey') : fakeAgent('agent_id', 'registration_key'), { mode: 0o755 });
  const root = {
    install: join(dir, 'install'), launchd: join(dir, 'LaunchDaemons'), logs: join(dir, 'Logs'),
  };
  mkdirSync(root.launchd);
  t.after(() => {
    // Stop whatever the stand-in launchd started (each job is its own process
    // group), then remove the host.
    for (const l of ['io.vistasecurity.sensor', 'io.vistasecurity.device-agent']) {
      try { process.kill(-Number(readFileSync(join(state, `${l}.pid`), 'utf8')), 'SIGKILL'); } catch { /* not running */ }
    }
    rmSync(dir, { recursive: true, force: true });
  });
  const install = (sh, args, env = {}) => {
    const r = spawnSync(sh, ['-c', 'source "$1"; shift; LAUNCHD_DIR=$1; LOG_DIR=$2; shift 2; main "$@"', 'test',
      sensor ? SENSOR : DEVICE, root.launchd, root.logs, '--dir', root.install, ...args], {
      cwd: work, encoding: 'utf8', timeout: 60000, input: env.INPUT || '',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_LAUNCHD: state, TMPDIR: join(dir, 'tmp'), REGISTRATION_TIMEOUT: '15', ...env },
    });
    assert.ifError(r.error);
    return { ...r, output: r.stdout + r.stderr };
  };
  const calls = () => (existsSync(join(state, 'calls.log')) ? readFileSync(join(state, 'calls.log'), 'utf8') : '');
  return { dir, root, state, work, install, calls };
}

const KEY = 'REG-0123456789abcdef-secret';

for (const sh of BASHES) {
  test(`sensor: a fresh install starts the job and reports the UUID the sensor recorded (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    const h = macHost(t, 'sensor');
    const r = h.install(sh, ['--url', 'https://p.example', '--key-stdin', '--ip', '192.0.2.10', '--ca-fingerprint', 'AB:CD'], { INPUT: `${KEY}\n` });
    assert.equal(r.status, 0, r.output);
    assert.match(r.output, new RegExp(`Sensor ID: ${UUID}`));
    assert.ok(!r.output.includes(KEY), 'the key was printed');
    assert.equal(readFileSync(join(h.state, 'config-mode'), 'utf8').trim(), '600', 'the config holding the key is readable by others');
    assert.ok(existsSync(join(h.root.install, 'vista-sensor')), 'binary not installed under the product name');
    const started = readFileSync(join(h.state, 'config-at-start'), 'utf8');
    assert.match(started, /^sensorId: "sensor-testmac-\d{8}"$/m);
    assert.match(started, /^registrationKey: "REG-0123456789abcdef-secret"$/m);
    assert.match(started, /^ {2}interfaces: \["en0"\]$/m, 'default-route interface not used');
    const args = readFileSync(join(h.state, 'agent-args'), 'utf8');
    assert.match(args, /--verbose -config \S+sensor-config\.yaml -interactive=false -ca-fingerprint AB:CD/);
    assert.equal(readFileSync(join(h.state, 'agent-env'), 'utf8').trim(), 'SENSOR_IP_ADDRESS=192.0.2.10');
    const p = plist(join(h.root.launchd, 'io.vistasecurity.sensor.plist'));
    assert.ok(!('UserName' in p), 'the sensor needs root for /dev/bpf*');
    assert.match(h.calls(), /^bootstrap system /m);
  });

  test(`sensor: re-running with the same key keeps the identity; another key enrols afresh (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    const h = macHost(t, 'sensor');
    const base = ['--url', 'https://p.example', '--ip', '192.0.2.10', '--name', 'mac-1'];
    assert.equal(h.install(sh, [...base, '--key', KEY]).status, 0);
    const again = h.install(sh, [...base, '--key', KEY]);
    assert.equal(again.status, 0, again.output);
    assert.match(again.output, /already enrolled with this key/);
    assert.match(readFileSync(join(h.state, 'config-at-start'), 'utf8'), new RegExp(`^sensorId: "${UUID}"`, 'm'), 'identity discarded');
    assert.match(h.calls(), /^bootout system\/io\.vistasecurity\.sensor$/m, 'the running job was not stopped first');
    const other = h.install(sh, [...base, '--key', 'REG-another-key-0000']);
    assert.equal(other.status, 0, other.output);
    assert.doesNotMatch(other.output, /already enrolled/);
    assert.match(readFileSync(join(h.state, 'config-at-start'), 'utf8'), /^sensorId: "mac-1"$/m, 'a new key did not get a fresh enrolment');
  });

  test(`sensor: a rejected key stops and disables the job and shows the log (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    const h = macHost(t, 'sensor');
    const r = h.install(sh, ['--url', 'https://p.example', '--ip', '192.0.2.10'], { VISTA_REGISTRATION_KEY: 'REG-bad' });
    assert.equal(r.status, 1, r.output);
    assert.match(r.output, /Registration was REJECTED/);
    assert.match(r.output, /stopped and disabled/);
    assert.match(h.calls(), /^disable system\/io\.vistasecurity\.sensor$/m);
    // The next install enables it again.
    h.install(sh, ['--url', 'https://p.example', '--ip', '192.0.2.10', '--key', KEY]);
    assert.match(h.calls(), /^enable system\/io\.vistasecurity\.sensor$/m);
  });

  test(`sensor: wrong address, unknown interface or missing key fail before anything changes (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    const h = macHost(t, 'sensor');
    for (const [args, msg] of [
      [['--key', KEY, '--ip', '192.0.2.99'], /192\.0\.2\.99 not found/],
      [['--key', KEY, '--ip', '192.0.2.10', '--interfaces', 'en9'], /Interface en9 does not exist/],
      [['--ip', '192.0.2.10'], /Registration key is required/],
      [['--key', KEY], /Expected IP address is required/],
      [['--key', KEY, '--ip', '192.0.2.10', '--ca-fingerprint', 'not hex'], /hexadecimal/],
    ]) {
      const r = h.install(sh, args);
      assert.equal(r.status, 1, r.output);
      assert.match(r.output, msg);
    }
    assert.ok(!existsSync(h.root.install), 'something was installed');
    assert.doesNotMatch(h.calls(), /bootstrap/);
  });

  test(`device agent: installs as a hidden service account, not root, and enrolls (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    const h = macHost(t, 'device-agent');
    const r = h.install(sh, ['--url', 'https://p.example', '--key-stdin'], { INPUT: `${KEY}\n` });
    assert.equal(r.status, 0, r.output);
    assert.match(r.output, new RegExp(`Agent ID: ${UUID}`));
    assert.ok(!r.output.includes(KEY), 'the key was printed');
    const p = plist(join(h.root.launchd, 'io.vistasecurity.device-agent.plist'));
    assert.equal(p.UserName, '_vistadeviceagent');
    const user = readFileSync(join(h.state, 'ds', 'Users', '_vistadeviceagent'), 'utf8');
    assert.match(user, /^UniqueID: 499$/m);
    assert.match(user, /^UserShell: \/usr\/bin\/false$/m);
    assert.match(user, /^IsHidden: 1$/m);
    const calls = h.calls();
    assert.match(calls, /^chown -R root:wheel \S+\/install \S+\.plist$/m, 'the program files are not root\'s');
    assert.match(calls, /^chown -R _vistadeviceagent:_vistadeviceagent \S+\/etc \S+\/data \S+\/Logs$/m);
    const started = readFileSync(join(h.state, 'config-at-start'), 'utf8');
    assert.match(started, /^data_path: ".*\/install\/data"$/m);
    assert.match(readFileSync(join(h.state, 'agent-args'), 'utf8').trim(), /-config \S+\/etc\/device-agent\.yaml -interactive=false$/);
    assert.equal(readFileSync(join(h.state, 'config-mode'), 'utf8').trim(), '600');
    // A second install reuses the account.
    assert.equal(h.install(sh, ['--url', 'https://p.example', '--key', KEY]).status, 0);
    assert.equal((calls.match(/dscl \. -create \/Users\/_vistadeviceagent$/gm) || []).length, 1);
  });

  test(`device agent: a rejected key stops and disables the job (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    const h = macHost(t, 'device-agent');
    const r = h.install(sh, ['--url', 'https://p.example', '--key', 'REG-bad']);
    assert.equal(r.status, 1, r.output);
    assert.match(r.output, /could not enroll/);
    assert.match(r.output, /⛔ Registration was REJECTED/);
    assert.match(h.calls(), /^disable system\/io\.vistasecurity\.device-agent$/m);
  });

  test(`check mode needs neither root nor a key; uninstall removes everything (${sh})`, { skip: !PYTHON && 'needs python3' }, (t) => {
    for (const kind of ['sensor', 'device-agent']) {
      const h = macHost(t, kind);
      const c = h.install(sh, ['--check-dependencies'], { FAKE_UID: '501' });
      assert.equal(c.status, 0, c.output);
      assert.match(c.output, /runs on this Mac/);
      const args = kind === 'sensor' ? ['--ip', '192.0.2.10', '--key', KEY] : ['--url', 'https://p.example', '--key', KEY];
      assert.equal(h.install(sh, args).status, 0);
      const u = h.install(sh, ['--uninstall']);
      assert.equal(u.status, 0, u.output);
      assert.ok(!existsSync(h.root.install));
      assert.ok(!existsSync(join(h.root.launchd, `io.vistasecurity.${kind}.plist`)));
      if (kind === 'device-agent') assert.ok(!existsSync(join(h.state, 'ds', 'Users', '_vistadeviceagent')));
    }
  });
}

for (const [name, file] of INSTALLERS) {
  test(`${name} refuses to run anywhere but macOS, naming the right installer`, () => {
    const r = spawnSync('bash', [file, '--check-dependencies'], { encoding: 'utf8', input: '' });
    if (process.platform === 'darwin') return;
    assert.equal(r.status, 1);
    assert.match(r.stdout + r.stderr, /This installer is for macOS\. On Linux use install-[a-z-]+\.sh; on Windows use install-[a-z-]+\.ps1\./);
  });
}


// One shape for "which binary" across the Unix installers: the archive name
// first, else exactly one release-named file for this machine, and the same
// two messages when that fails.
test('the macOS and Linux installers find the binary the same way and say so in the same words', () => {
  const lookup = (text, fn) => {
    const m = new RegExp(`^${fn}\\(\\) \\{[\\s\\S]*?^\\}`, 'm').exec(text);
    assert.ok(m, `${fn} not found`);
    return m[0];
  };
  const shapes = (body) => [
    /Several .*_<version>_(linux|darwin)_\$\{arch\} files are in the current directory; keep only the one to install\./.test(body),
    /binary not found in the current directory\./.test(body),
    /Download and verify the (Linux|macOS) build for this (host|Mac)'s architecture \(\$arch\), and place it here either as \.\/\$\S+ \(its name in the \.tar\.gz archive\) or under its release name \$\{\w+\}_<version>_(linux|darwin)_\$\{arch\}\./.test(body),
  ];
  for (const f of [SENSOR, DEVICE]) assert.deepEqual(shapes(lookup(source(f), 'find_agent_binary')), [true, true, true], f);
  for (const f of ['install-sensor.sh', 'install-device-agent.sh']) assert.deepEqual(shapes(lookup(source(here(f)), 'resolve_binary')), [true, true, true], f);
});

// scripts/build.sh promises the target's installer beside the binary in dist/:
// it must be the installer release/agents.json names for that agent and system.
test('build.sh copies the installer release/agents.json names for each agent and system', () => {
  const build = source(here('build.sh'));
  const surface = JSON.parse(source(fileURLToPath(new URL('../release/agents.json', import.meta.url))));
  for (const agent of surface.agents) {
    for (const [os, file] of Object.entries(agent.installers || {})) {
      const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const line = new RegExp(`^\\s*${esc(agent.kind)}:${esc(os)}\\) cp scripts/${esc(file)} `, 'm');
      assert.match(build, line, `build.sh does not copy ${file} for ${agent.kind} on ${os}`);
    }
  }
  assert.doesNotMatch(build, /sensor:\*\)/, 'a catch-all gives every other system the Linux installer');
});
