#!/usr/bin/env node
// scripts/install-sensor.sh and scripts/install-device-agent.sh: the Vista names
// on a fresh host, and the move of a host installed under the crypto-* names.
//
// Each test runs the real installer whole against a throwaway root. Stand-ins
// replace what needs root or a booted systemd (systemctl, journalctl, useradd,
// userdel, groupdel, chown, id, getent, pgrep, ip); everything that moves or
// rewrites files is the real tool. The installer's absolute locations and its
// root check are rewritten on the way in, and that rewrite asserts it
// matched, so a renamed line fails here rather than touching the real /opt.
//
// The last section breaks each guard in the installer's text and confirms a
// scenario goes red, so the scenarios are known to be able to fail.
//
// Not covered: a real systemd, real users, or a real second filesystem (the
// cross-filesystem path is forced by a stand-in for stat).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const here = (f) => fileURLToPath(new URL(`./${f}`, import.meta.url));
const skip = process.platform !== 'linux' && 'the Linux installers need GNU tools';
const UUID = '3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59';
const NEW_UUID = '11111111-2222-4333-8444-555555555555';
const KEY = 'REG-0123456789abcdef-secret';
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

const KINDS = {
  sensor: {
    script: 'install-sensor.sh', service: 'vista-sensor', legacy: 'crypto-sensor', config: 'sensor-config.yaml',
    download: 'crypto-sensor', oldBinary: 'crypto-sensor', idKey: 'sensorId', keyKey: 'registrationKey',
    args: ['--ip', '192.0.2.10'], firstArgs: ['--url', 'https://p.example', '--ip', '192.0.2.10'],
    configText: (dir) => `sensorId: "${UUID}"
controlPlaneUrl: https://p.example
registrationKeySha256: "${sha256(KEY)}"
reportingIntervalSeconds: 30
storage:
  dataPath: "${dir}/data"
  archivePath: "${dir}-backup/data"
security:
  clientCertPath: "${dir}/data/certs/client.crt"
  clientKeyPath: "${dir}/data/certs/client.key"
  serverCACertPath: "${dir}/data/certs/ca.crt"
  agentSecretPath: "${dir}/data/certs/agent.secret"
  useTLS: true
`,
    pending: (dir) => `sensorId: "sensor-1"\nregistrationKey: "${KEY}"\nstorage:\n  dataPath: "${dir}/data"\n`,
  },
  device: {
    script: 'install-device-agent.sh', service: 'vista-device-agent', legacy: 'crypto-device-agent', config: 'device-agent.yaml',
    download: 'device-agent', oldBinary: 'device-agent', idKey: 'agent_id', keyKey: 'registration_key',
    args: [], firstArgs: ['--url', 'https://p.example'],
    configText: (dir) => `agent_id: "${UUID}"
platform_url: "https://p.example"
registration_key_sha256: "${sha256(KEY)}"
poll_interval: 30s
data_path: "${dir}/data"
archive_path: "${dir}-backup/data"
security:
  client_cert_path: "${dir}/data/certs/client.crt"
  client_key_path: "${dir}/data/certs/client.key"
  server_ca_cert_path: "${dir}/data/certs/ca.crt"
  agent_secret_path: "${dir}/data/certs/agent.secret"
  use_tls: true
`,
    pending: (dir) => `platform_url: "https://p.example"\nregistration_key: "${KEY}"\ndata_path: "${dir}/data"\n`,
  },
};

const STUBS = {
  systemctl: `#!/bin/bash
S=$FAKE_STATE
echo "systemctl $*" >> "$S/calls.log"
case "$1" in
  stop)
    [ "$FAKE_STOP_IGNORED" = 1 ] && exit 1
    rm -f "$S/active-$2" ;;
  is-active) [ -f "$S/active-$3" ]; exit $? ;;
  restart)
    [ -n "$FAKE_RESTART_FAILS" ] && exit 1
    # The service: its binary must be there, and it enrols if it has not.
    unit="$FAKE_UNIT_DIR/$2"
    exec_start=$(sed -n 's/^ExecStart=//p' "$unit")
    [ -x "\${exec_start%% *}" ] || { echo "no binary at \${exec_start%% *}" >&2; exit 1; }
    config=$(sed -n 's/.* -config \\([^ ]*\\).*/\\1/p' <<<"$exec_start")
    if ! grep -qE "^(sensorId|agent_id): \\"?[0-9a-f]{8}-" "$config"; then
      echo "ENROLLED" >> "$S/calls.log"
      sed -i -E '/^(sensorId|agent_id):/d' "$config"
      echo "$FAKE_ID_KEY: \\"${NEW_UUID}\\"" >> "$config"
    fi
    : > "$S/active-$2" ;;
esac
exit 0
`,
  journalctl: '#!/bin/sh\nexit 0\n',
  useradd: '#!/bin/bash\nfor n; do :; done\necho "useradd $n" >> "$FAKE_STATE/calls.log"\n: > "$FAKE_STATE/users/$n"\n',
  userdel: '#!/bin/bash\necho "userdel $*" >> "$FAKE_STATE/calls.log"\nrm -f "$FAKE_STATE/users/$1"\n',
  groupdel: '#!/bin/bash\necho "groupdel $*" >> "$FAKE_STATE/calls.log"\n',
  getent: '#!/bin/bash\n[ -f "$FAKE_STATE/users/$2" ]\n',
  id: '#!/bin/bash\n[ -f "$FAKE_STATE/users/$1" ]\n',
  chown: '#!/bin/bash\n[ -n "$FAKE_CHOWN_FAILS" ] && exit 1\necho "chown $*" >> "$FAKE_STATE/calls.log"\n',
  pgrep: '#!/bin/bash\n[ -n "$FAKE_PROCESSES" ] && exit 0\nexit 1\n',
  ip: '#!/bin/sh\necho "    inet 192.0.2.10/24 scope global eth0"\n',
  // The cross-filesystem path, forced: two different paths, two devices.
  stat: '#!/bin/bash\nif [ -n "$FAKE_CROSS_FS" ]; then echo "$3"; exit 0; fi\nexec "$REAL_STAT" "$@"\n',
  cp: '#!/bin/bash\nif [ "$1" = -a ] && [ -n "$FAKE_CP_FAILS" ]; then mkdir -p "$3/partial"; exit 1; fi\nexec "$REAL_CP" "$@"\n',
};

function realTool(name) {
  const r = spawnSync('bash', ['-c', `command -v ${name}`], { encoding: 'utf8' });
  assert.equal(r.status, 0, `${name} not found`);
  return r.stdout.trim();
}

// The installer, pointed at the throwaway root. mutate() breaks it on purpose.
function prepared(kind, root, mutate = (s) => s) {
  const k = KINDS[kind];
  const once = (text, from, to) => {
    assert.equal(text.split(from).length - 1, 1, `installer no longer has exactly one ${from}`);
    return text.replace(from, () => to);
  };
  let text = readFileSync(here(k.script), 'utf8');
  text = once(text, `INSTALL_DIR="/opt/${k.service}"`, `INSTALL_DIR="${root}/opt/${k.service}"`);
  text = once(text, `LEGACY_DEFAULT_DIR="/opt/${k.legacy}"`, `LEGACY_DEFAULT_DIR="${root}/opt/${k.legacy}"`);
  text = once(text, 'UNIT_DIR="/etc/systemd/system"', `UNIT_DIR="${root}/etc/systemd/system"`);
  text = once(text, 'if [[ $EUID -ne 0 ]]; then', 'if false; then');
  return mutate(text);
}

function host(t, kind, { mutate } = {}) {
  const k = KINDS[kind];
  const dir = mkdtempSync(join(tmpdir(), 'linux-migration-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const root = join(dir, 'root');
  const units = join(root, 'etc/systemd/system');
  const state = join(dir, 'state');
  const bin = join(dir, 'bin');
  const work = join(dir, 'download');
  for (const d of [units, join(root, 'opt'), join(state, 'users'), bin, work]) mkdirSync(d, { recursive: true });
  for (const [name, text] of Object.entries(STUBS)) writeFileSync(join(bin, name), text, { mode: 0o755 });
  const script = join(dir, k.script);
  writeFileSync(script, prepared(kind, root, mutate));
  writeFileSync(join(work, k.download), '#!/bin/sh\necho "Vista v9.9.9"\n', { mode: 0o755 });

  const legacyDir = join(root, 'opt', k.legacy);
  const newDir = join(root, 'opt', k.service);
  const h = {
    k, root, units, state, work, legacyDir, newDir,
    legacyUnit: join(units, `${k.legacy}.service`),
    newUnit: join(units, `${k.service}.service`),
    run(args, env = {}, input = '') {
      const r = spawnSync('bash', [script, ...args], {
        cwd: work, encoding: 'utf8', timeout: 30000, input,
        env: {
          ...process.env, VISTA_REGISTRATION_KEY: '', PATH: `${bin}:${process.env.PATH}`,
          FAKE_STATE: state, FAKE_UNIT_DIR: units, FAKE_ID_KEY: k.idKey, REGISTRATION_TIMEOUT: '3',
          REAL_STAT: realTool('stat'), REAL_CP: realTool('cp'), ...env,
        },
      });
      assert.ifError(r.error);
      return { ...r, output: r.stdout + r.stderr };
    },
    calls: () => (existsSync(join(state, 'calls.log')) ? readFileSync(join(state, 'calls.log'), 'utf8') : ''),
    clearCalls: () => writeFileSync(join(state, 'calls.log'), ''),
    user: (name) => existsSync(join(state, 'users', name)),
    legacy({ dir: at = legacyDir, config = k.configText(at), unit = true, running = true } = {}) {
      mkdirSync(join(at, 'data/certs'), { recursive: true });
      mkdirSync(join(at, 'data/queue'), { recursive: true });
      writeFileSync(join(at, 'data/certs/client.crt'), 'THE CERTIFICATE\n');
      writeFileSync(join(at, 'data/certs/client.key'), 'THE KEY\n', { mode: 0o600 });
      writeFileSync(join(at, 'data/queue/pending.json'), '{"held":"data"}\n');
      writeFileSync(join(at, k.oldBinary), '#!/bin/sh\n', { mode: 0o755 });
      writeFileSync(join(at, k.config), config, { mode: 0o600 });
      writeFileSync(join(state, 'users', k.legacy), '');
      if (unit) {
        writeFileSync(h.legacyUnit, `[Service]\nUser=${k.legacy}\nWorkingDirectory=${at}\nEnvironment=SENSOR_IP_ADDRESS=192.0.2.10\nExecStart=${at}/${k.oldBinary}\n`);
        if (running) writeFileSync(join(state, `active-${k.legacy}.service`), '');
      }
    },
    assertMoved(dir, r) {
      assert.equal(r.status, 0, r.output);
      assert.ok(!existsSync(h.legacyUnit), 'the legacy unit is still there');
      assert.equal(readFileSync(join(dir, 'data/certs/client.crt'), 'utf8'), 'THE CERTIFICATE\n', 'the certificate did not survive');
      assert.equal(readFileSync(join(dir, 'data/queue/pending.json'), 'utf8'), '{"held":"data"}\n', 'the data did not survive');
      assert.doesNotMatch(h.calls(), /ENROLLED/, 'the host enrolled again');
      const config = readFileSync(join(dir, k.config), 'utf8');
      assert.match(config, new RegExp(`^${k.idKey}: "${UUID}"$`, 'm'), 'the identity was lost');
      assert.ok(existsSync(join(dir, k.service)), 'the new binary is not installed');
      assert.ok(!existsSync(join(dir, k.oldBinary)), 'the old binary is left behind');
      assert.ok(existsSync(h.newUnit), 'no new unit');
      assert.equal(statSync(join(dir, k.config)).mode & 0o777, 0o600, 'the config is readable by others');
      assert.match(readFileSync(h.newUnit, 'utf8'), new RegExp(`^ExecStart=${dir}/${k.service} `, 'm'));
      assert.ok(existsSync(join(state, `active-${k.service}.service`)), 'the new service is not running');
    },
  };
  return h;
}

const tree = (dir) => (existsSync(dir)
  ? readdirSync(dir, { recursive: true }).map(String).sort() : []);

function assertUntouched(h) {
  assert.ok(existsSync(h.legacyUnit), 'the legacy unit went');
  assert.ok(existsSync(join(h.legacyDir, h.k.config)), 'the legacy directory went');
  assert.ok(existsSync(join(h.state, `active-${h.k.legacy}.service`)), 'the running service was stopped');
  assert.ok(h.user(h.k.legacy), 'the legacy user went');
  assert.ok(!existsSync(h.newDir), 'the new directory was created');
}

// The same scenario, whichever way it is broken: `mutations` below reuses these.
const scenarios = {
  'moves an enrolled host to the new names with no key': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    const r = h.run(h.k.args);
    h.assertMoved(h.newDir, r);
    assert.ok(!existsSync(h.legacyDir), 'the legacy directory is still there');
    assert.match(r.output, /already enrolled/);
    const config = readFileSync(join(h.newDir, h.k.config), 'utf8');
    assert.ok(!config.includes(`${h.legacyDir}/`) && !config.includes(`${h.legacyDir}"`), `config still names the old directory:\n${config}`);
    for (const f of ['data/certs/client.crt', 'data/certs/client.key', 'data/certs/ca.crt', 'data/certs/agent.secret']) {
      assert.ok(config.includes(`"${h.newDir}/${f}"`), `config does not name ${f} in the new directory`);
    }
    assert.ok(config.includes(`"${h.newDir}/data"`), 'the data path was not rewritten');
    assert.ok(config.includes(`"${h.legacyDir}-backup/data"`), 'a directory that merely starts the same was rewritten');
    // The order the move depends on.
    const calls = h.calls();
    const at = (s) => { const i = calls.indexOf(s); assert.ok(i >= 0, `no ${s} in:\n${calls}`); return i; };
    assert.ok(at(`systemctl stop ${h.k.legacy}.service`) < at(`systemctl disable ${h.k.legacy}.service`));
    assert.ok(at(`useradd ${h.k.service}`) < at(`chown -R ${h.k.service}:${h.k.service} ${h.newDir}`));
    assert.ok(at(`chown -R ${h.k.service}:${h.k.service} ${h.newDir}`) < at(`userdel ${h.k.legacy}`), 'the old user went before the files changed hands');
    assert.ok(at('systemctl daemon-reload') < at(`userdel ${h.k.legacy}`));
    assert.ok(at(`userdel ${h.k.legacy}`) < at(`systemctl restart ${h.k.service}.service`));
    assert.ok(!h.user(h.k.legacy), 'the legacy user is still there');
    assert.ok(h.user(h.k.service), 'the new user was not created');
    assert.match(calls, new RegExp(`^userdel ${h.k.legacy}$`, 'm'), 'userdel -r would take the install directory with it');
  },

  'a second run changes nothing and needs no key': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    h.assertMoved(h.newDir, h.run(h.k.args));
    const before = tree(h.root);
    const config = readFileSync(join(h.newDir, h.k.config), 'utf8');
    h.clearCalls();
    const again = h.run([]);
    assert.equal(again.status, 0, again.output);
    assert.deepEqual(tree(h.root), before);
    assert.equal(readFileSync(join(h.newDir, h.k.config), 'utf8'), config, 'the second run changed the config');
    assert.doesNotMatch(h.calls(), /userdel|useradd|ENROLLED|crypto-/, 'the second run did migration work');
    assert.doesNotMatch(again.output, /Moving this host/);
  },

  'the same key keeps the enrolment; another key enrols afresh in the new place': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    h.assertMoved(h.newDir, h.run([...h.k.args, '--key', KEY]));
    const other = h.run(['--url', 'https://p.example', '--key', 'REG-another-key'], { REGISTRATION_TIMEOUT: '3' });
    assert.equal(other.status, 0, other.output);
    assert.match(h.calls(), /ENROLLED/);
    assert.ok(!existsSync(join(h.newDir, 'data/certs/client.crt')), 'a fresh enrolment inherited the certificate');
  },

  'a failed start says what to do, and running again finishes with no key': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    const failed = h.run(h.k.args, { FAKE_RESTART_FAILS: '1' });
    assert.equal(failed.status, 1, failed.output);
    assert.match(failed.output, /stopped while installing/);
    assert.match(failed.output, new RegExp(`are in ${h.newDir}\\.`));
    assert.match(failed.output, /run this installer again with the same options/);
    assert.ok(existsSync(join(h.newDir, 'data/certs/client.crt')), 'the certificate was lost');
    h.assertMoved(h.newDir, h.run([]));
  },

  'a failure part-way keeps the legacy unit, and running again finishes it': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    const failed = h.run(h.k.args, { FAKE_CHOWN_FAILS: '1' });
    assert.equal(failed.status, 1, failed.output);
    assert.match(failed.output, /stopped while handing/);
    assert.ok(existsSync(h.legacyUnit), 'nothing left to say where this install came from');
    assert.ok(h.user(h.k.legacy), 'the old user went before the files changed hands');
    h.assertMoved(h.newDir, h.run(h.k.args));
    assert.ok(!h.user(h.k.legacy));
  },

  'a path the rewrite cannot reach stops the install': (t, kind, opts) => {
    const h = host(t, kind, opts);
    const dir = h.legacyDir;
    h.legacy({ config: `${h.k.configText(dir)}extra: ${dir} ${dir}\n` });
    const r = h.run(h.k.args);
    assert.equal(r.status, 1, r.output);
    assert.match(r.output, /Could not rewrite/);
    assert.match(r.output, /run this installer again/);
    assert.doesNotMatch(h.calls(), /systemctl restart/, 'started on a config naming a directory that has gone');
    assert.ok(existsSync(h.legacyUnit));
  },

  'an install with a process still running as the old user keeps that user': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    const r = h.run(h.k.args, { FAKE_PROCESSES: '1' });
    h.assertMoved(h.newDir, r);
    assert.ok(h.user(h.k.legacy), 'the user was removed under a running process');
    assert.match(r.output, /Left user/);
    assert.doesNotMatch(h.calls(), /userdel/);
    const again = h.run([]);
    assert.equal(again.status, 0, again.output);
    assert.ok(!h.user(h.k.legacy), 'a later run did not finish the job');
  },

  'no key and no enrolment stops before anything changes': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy({ config: h.k.pending(h.legacyDir) });
    const r = h.run(h.k.args);
    assert.equal(r.status, 1, r.output);
    assert.match(r.output, /does not record an enrolled/);
    assertUntouched(h);
  },

  'a service that will not stop stops the move': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    const r = h.run(h.k.args, { FAKE_STOP_IGNORED: '1' });
    assert.equal(r.status, 1, r.output);
    assert.match(r.output, /did not stop/);
    assertUntouched(h);
  },

  'a directory in the way stops the move': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    const dir = join(h.root, 'srv/elsewhere');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'theirs'), 'x');
    const r = h.run([...h.k.args, '--dir', dir]);
    assert.equal(r.status, 1, r.output);
    assert.match(r.output, /not empty/);
    assertUntouched(h);
    assert.deepEqual(readdirSync(dir), ['theirs']);
  },

  'across filesystems the original goes only after a whole copy': (t, kind, opts) => {
    const h = host(t, kind, opts);
    h.legacy();
    const failed = h.run(h.k.args, { FAKE_CROSS_FS: '1', FAKE_CP_FAILS: '1' });
    assert.equal(failed.status, 1, failed.output);
    assert.ok(existsSync(join(h.legacyDir, 'data/certs/client.crt')), 'a failed copy cost the original');
    assert.ok(!existsSync(h.newDir), 'a partial copy appeared under the final name');
    h.assertMoved(h.newDir, h.run(h.k.args, { FAKE_CROSS_FS: '1' }));
    assert.ok(!existsSync(h.legacyDir), 'the original was left behind');
    assert.ok(!existsSync(`${h.newDir}.migrating`), 'the staging directory was left behind');
  },
};

for (const kind of Object.keys(KINDS)) {
  for (const [name, scenario] of Object.entries(scenarios)) {
    test(`${kind}: ${name}`, { skip }, (t) => scenario(t, kind));
  }

  test(`${kind}: a fresh host gets the Vista names and nothing of the old ones`, { skip }, (t) => {
    const h = host(t, kind);
    const r = h.run([...h.k.firstArgs, '--key', KEY]);
    assert.equal(r.status, 0, r.output);
    const unit = readFileSync(h.newUnit, 'utf8');
    assert.match(unit, new RegExp(`^User=${h.k.service}$`, 'm'));
    assert.match(unit, new RegExp(`^Group=${h.k.service}$`, 'm'));
    assert.match(unit, new RegExp(`^WorkingDirectory=${h.newDir}$`, 'm'));
    assert.match(unit, new RegExp(`^ExecStart=${h.newDir}/${h.k.service} `, 'm'));
    assert.match(unit, new RegExp(`^SyslogIdentifier=${h.k.service}$`, 'm'));
    assert.match(unit, /^Description=Vista Platform /m);
    assert.doesNotMatch(unit, /crypto|Crypto/);
    assert.ok(h.user(h.k.service));
    assert.match(h.calls(), /ENROLLED/);
    assert.doesNotMatch(h.calls(), /crypto-|userdel/);
    assert.doesNotMatch(r.output, /Moving this host/);
    assert.deepEqual(readdirSync(join(h.root, 'opt')), [h.k.service]);
    assert.match(r.output, new RegExp(`systemctl status ${h.k.service}`));
    assert.doesNotMatch(r.output, /crypto-/);
  });

  test(`${kind}: a fresh host still needs a key`, { skip }, (t) => {
    const h = host(t, kind);
    const r = h.run(h.k.firstArgs);
    assert.equal(r.status, 1, r.output);
    assert.match(r.output, /key.*required|required.*key/i);
    assert.ok(!existsSync(h.newUnit));
  });

  test(`${kind}: --dir chooses where a legacy install moves to`, { skip }, (t) => {
    const h = host(t, kind);
    h.legacy();
    const dir = join(h.root, 'srv/agents/vista');
    const r = h.run([...h.k.args, '--dir', dir]);
    h.assertMoved(dir, r);
    assert.ok(!existsSync(h.legacyDir));
    assert.ok(!existsSync(h.newDir), 'the default directory was used anyway');
    assert.ok(readFileSync(join(dir, h.k.config), 'utf8').includes(`"${dir}/data/certs/client.crt"`));
    // A later run finds it through the unit, with no --dir.
    const again = h.run([]);
    assert.equal(again.status, 0, again.output);
    assert.ok(!existsSync(h.newDir), 'a re-run without --dir made a second install');
  });

  test(`${kind}: a custom directory of a legacy install stays where the operator put it`, { skip }, (t) => {
    const h = host(t, kind);
    const dir = join(h.root, 'srv/custom');
    h.legacy({ dir });
    const before = readFileSync(join(dir, h.k.config), 'utf8');
    const r = h.run(h.k.args);
    h.assertMoved(dir, r);
    assert.ok(!existsSync(h.newDir), 'the install moved out of the directory the operator chose');
    assert.equal(readFileSync(join(dir, h.k.config), 'utf8'), before, 'the config changed with no directory change');
    assert.ok(!h.user(h.k.legacy));
  });

  test(`${kind}: --dir naming the directory it is already in works, with a trailing slash`, { skip }, (t) => {
    const h = host(t, kind);
    const dir = join(h.root, 'srv/custom');
    h.legacy({ dir });
    h.assertMoved(dir, h.run([...h.k.args, '--dir', `${dir}/`]));
    assert.ok(readFileSync(h.newUnit, 'utf8').includes(`WorkingDirectory=${dir}\n`));
  });

  test(`${kind}: a directory with no unit is moved too`, { skip }, (t) => {
    const h = host(t, kind);
    h.legacy({ unit: false });
    h.assertMoved(h.newDir, h.run(h.k.args));
    assert.ok(!existsSync(h.legacyDir));
  });

  test(`${kind}: a run that stopped just after the move still gets its paths rewritten`, { skip }, (t) => {
    const h = host(t, kind);
    mkdirSync(join(h.newDir, 'data/certs'), { recursive: true });
    writeFileSync(join(h.newDir, 'data/certs/client.crt'), 'THE CERTIFICATE\n');
    writeFileSync(join(h.newDir, h.k.config), h.k.configText(h.legacyDir), { mode: 0o600 });
    const r = h.run(h.k.args);
    assert.equal(r.status, 0, r.output);
    assert.ok(readFileSync(join(h.newDir, h.k.config), 'utf8').includes(`"${h.newDir}/data/certs/client.crt"`));
    assert.doesNotMatch(h.calls(), /ENROLLED/);
  });

  test(`${kind}: an install already at the new names leaves a legacy directory alone and says so`, { skip }, (t) => {
    const h = host(t, kind);
    h.legacy();
    mkdirSync(h.newDir);
    writeFileSync(join(h.newDir, h.k.config), h.k.configText(h.newDir), { mode: 0o600 });
    const r = h.run(h.k.args);
    assert.equal(r.status, 0, r.output);
    assert.match(r.output, /was not moved/);
    assert.ok(existsSync(join(h.legacyDir, 'data/certs/client.crt')), 'the legacy directory was touched');
    assert.ok(!existsSync(h.legacyUnit), 'two services would run');
    assert.ok(h.user(h.k.legacy), 'its files would be left with no owner');
  });

  test(`${kind}: local overrides of the legacy unit carry over`, { skip }, (t) => {
    const h = host(t, kind);
    h.legacy();
    mkdirSync(`${h.legacyUnit}.d`);
    writeFileSync(join(`${h.legacyUnit}.d`, 'override.conf'), '[Service]\nNice=5\n');
    const r = h.run(h.k.args);
    h.assertMoved(h.newDir, r);
    assert.equal(readFileSync(join(`${h.newUnit}.d`, 'override.conf'), 'utf8'), '[Service]\nNice=5\n');
    assert.ok(!existsSync(`${h.legacyUnit}.d`));
    assert.match(r.output, /check them for the old names/);
  });
}

test('sensor: the address comes from the unit of an existing install, and an unknown one still fails', { skip }, (t) => {
  const h = host(t, 'sensor');
  h.legacy();
  h.assertMoved(h.newDir, h.run([]));
  assert.match(readFileSync(h.newUnit, 'utf8'), /^Environment=SENSOR_IP_ADDRESS=192\.0\.2\.10$/m);
  const none = host(t, 'sensor');
  none.legacy({ unit: false });
  const r = none.run([]);
  assert.equal(r.status, 1, r.output);
  assert.match(r.output, /Expected IP address is required/);
});

test('sensor: --interactive does not insist on a key for an enrolled host', { skip }, (t) => {
  const h = host(t, 'sensor');
  h.legacy();
  // key, name, url, profile, interfaces, directory, confirm.
  h.assertMoved(h.newDir, h.run(['--interactive'], {}, '\n\n\n\n\n\ny\n'));
});

test('sensor: an enrolled install shows the platform in its config, not the default', { skip }, (t) => {
  const h = host(t, 'sensor');
  h.legacy();
  const r = h.run([]);
  assert.match(r.output, /^Control Plane: https:\/\/p\.example$/m);
});

test('device agent: the platform comes from the config of an enrolled install', { skip }, (t) => {
  const h = host(t, 'device');
  h.legacy();
  const r = h.run([]);
  h.assertMoved(h.newDir, r);
  assert.match(r.output, /Platform: https:\/\/p\.example/);
});

test('the two installers carry the same migration block', () => {
  const block = (f) => {
    const m = /^# --- shared Linux migration functions \(begin\) ---$[\s\S]*?^# --- shared Linux migration functions \(end\) ---$/m
      .exec(readFileSync(here(f), 'utf8'));
    assert.ok(m, 'block markers not found');
    return m[0];
  };
  assert.equal(block('install-sensor.sh'), block('install-device-agent.sh'));
});

test('neither installer can delete the install directory with the user', () => {
  for (const k of Object.values(KINDS)) {
    assert.doesNotMatch(readFileSync(here(k.script), 'utf8'), /^\s*userdel\s+.*-r\b/m);
  }
});

// --- each guard, broken -------------------------------------------------------

const replacing = (from, to) => (text) => {
  assert.ok(text.includes(from), `mutation does not apply: ${from}`);
  return text.replaceAll(from, to);
};

const mutations = [
  ['the sed that rewrites the paths is gone',
    'moves an enrolled host to the new names with no key',
    (s) => s.replace(/^\s*sed -i -E "s#\$pattern#.*$/m, '    :')],
  ['the rewrite is not asserted',
    'a path the rewrite cannot reach stops the install',
    replacing('if [[ "$after" -ne 0 ]] || ! grep -qF "$new" "$config"; then', 'if false; then')],
  ['the rewrite ignores path boundaries',
    'moves an enrolled host to the new names with no key',
    replacing('pattern="(^|[^[:alnum:]_./-])$escaped(/|[^[:alnum:]_./-]|\\$)"', 'pattern="()$escaped()"')],
  ['the legacy user goes with processes still running',
    'an install with a process still running as the old user keeps that user',
    replacing('if [[ "$found" -ne 1 ]]; then', 'if false; then')],
  ['the legacy user goes before the files change hands',
    'a failure part-way keeps the legacy unit, and running again finishes it',
    replacing('    MIGRATION_STEP="handing $INSTALL_DIR to user $SERVICE_USER"\n', '    remove_legacy_user\n    MIGRATION_STEP="handing $INSTALL_DIR to user $SERVICE_USER"\n')],
  ['no recovery message',
    'a failed start says what to do, and running again finishes with no key',
    replacing('trap migration_exit EXIT', ':')],
  ['the enrolled check before the move is gone',
    'no key and no enrolment stops before anything changes',
    (s) => s.replace(/if \[\[ -z "\$REGISTRATION_KEY" \]\] \\\n\s+&& ! \[\[ "\$\(read_config_value (sensorId|agent_id) "\$EXISTING_CONFIG"\)" =~ \$UUID_RE \]\]; then/, 'if false; then')],
  ['a stuck service is not noticed',
    'a service that will not stop stops the move',
    replacing('if systemctl is-active --quiet "$LEGACY_NAME.service"; then', 'if false; then')],
  ['a directory in the way is not noticed',
    'a directory in the way stops the move',
    replacing('elif [[ -e "$INSTALL_DIR" && ( ! -d "$INSTALL_DIR" || -n "$(ls -A "$INSTALL_DIR")" ) ]]; then', 'elif false; then')],
  ['a re-run with no key re-registers',
    'a second run changes nothing and needs no key',
    (s) => s.replace(/&& \{ \[\[ -z "\$REGISTRATION_KEY" \]\] \|\| enrolled_with_key "\$CONFIG_FILE" "\$REGISTRATION_KEY"; \}; then/, '&& false; then')],
  ['the cross-filesystem path copies under the final name',
    'across filesystems the original goes only after a whole copy',
    replacing('cp -a "$LEGACY_DIR" "$staging"', 'cp -a "$LEGACY_DIR" "$INSTALL_DIR"')],
];

for (const kind of Object.keys(KINDS)) {
  for (const [what, scenario, mutate] of mutations) {
    test(`${kind}: red when ${what}`, { skip }, (t) => {
      const before = readFileSync(here(KINDS[kind].script), 'utf8');
      assert.notEqual(mutate(before), before, 'the mutation changed nothing');
      assert.throws(() => scenarios[scenario](t, kind, { mutate }), (e) => !(e instanceof TypeError));
    });
  }
}
