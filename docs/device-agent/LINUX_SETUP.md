# Installing the device agent on Linux

`install-device-agent.sh` installs the Vista Platform device agent as a systemd
service: it starts at boot, restarts when it stops, and enrolls itself with
your Vista Platform on first start. It runs on x86-64 (`amd64`) and ARM64
(`arm64`) Linux hosts with systemd.

## What you need

- **The commands from your console.** In your Vista Platform console, open
  Discovery → Sensors & Agents and choose **Register sensor or agent**, then
  the device agent. The dialog creates the registration key and prints the
  install commands for this system, with your platform's URL and, where needed,
  its CA fingerprint already filled in (see "The platform URL and CA
  fingerprint" below).
- **The device agent for this host** from the release page of the agents
  release your console names: the archive
  `vista-device-agent_<version>_linux_amd64.tar.gz` (x86-64) or
  `vista-device-agent_<version>_linux_arm64.tar.gz` (ARM64). The archive holds
  the binary (`device-agent`), `install-device-agent.sh`, `LICENSE`, `NOTICE`
  and `THIRD_PARTY_LICENSES`. The loose binary
  `vista-device-agent_<version>_linux_<arch>` and the loose
  `install-device-agent.sh` also work, side by side in one directory: the
  installer accepts either name and needs no rename.
- **root** (the installer runs with `sudo`) and **systemd**.
- Nothing else: the device agent is built without cgo and needs no extra
  package.

Verify what you downloaded before you run it: [verify-release.md](../verify-release.md).
Use the installer from the release, never a copy from this repository's source
tree.

## The platform URL and CA fingerprint

There is no hosted platform and no default URL: `--url` is the address of your
own Vista Platform console, the URL the registration dialog was opened at. The
commands the dialog prints already carry it.

If your platform's certificate is signed by a private CA that this host does not
trust, the dialog shows a **Platform CA fingerprint** panel with a copy button,
and its commands carry `--ca-fingerprint`. The value is the CA's SHA-256
fingerprint, 64 hexadecimal digits (colons and a `sha256:` prefix are accepted).
The agent pins that CA on first start only if it has this fingerprint. Without
the option, the host must already trust the platform's certificate.

## Install

From the directory holding the downloaded files:

```sh
tar -xzf vista-device-agent_<version>_linux_amd64.tar.gz
cd vista-device-agent_<version>_linux_amd64
bash install-device-agent.sh --check-dependencies      # no root, changes nothing
printf '%s\n' "$KEY" | sudo bash install-device-agent.sh \
    --url https://vista.example.com --key-stdin
```

The key is never printed. Pass it on standard input (`--key-stdin`) or in the
`VISTA_REGISTRATION_KEY` environment variable; `--key KEY` works too but shows
the key to other users in the process list. A registration key works once.

| Option | |
|---|---|
| `--url URL` | Your platform's URL (required on a first install) |
| `--key-stdin`, `--key KEY` | Registration key (or `VISTA_REGISTRATION_KEY`) |
| `--ca-fingerprint SHA256` | Pin a private platform CA (see above) |
| `--dir DIRECTORY` | Installation directory (default `/opt/vista-device-agent`) |
| `--check-dependencies` | Check the binary runs here, then exit |
| `--uninstall` | Remove the agent (see "Uninstall") |

## What gets installed

| | |
|---|---|
| Program | `/opt/vista-device-agent/vista-device-agent` |
| Configuration | `/opt/vista-device-agent/device-agent.yaml`, mode 0600 (it holds the registration key until the agent redeems it) |
| Data and certificates | `/opt/vista-device-agent/data/` (the certificate the platform issued is under `data/certs/`) |
| Service | `vista-device-agent.service` (`/etc/systemd/system/vista-device-agent.service`), enabled at boot |
| Account | system user and group `vista-device-agent`, no login shell, owning `/opt/vista-device-agent` |

The service runs `vista-device-agent -config /opt/vista-device-agent/device-agent.yaml -interactive=false`
as `vista-device-agent`, with no added capabilities, and may write only under
`/opt/vista-device-agent`. The agent reaches devices over ordinary network
connections and does not need root.

The installer does not enroll the agent. It starts the service and waits up to
90 seconds until the agent itself has enrolled and written the agent ID the
platform accepted into its configuration. If the platform rejects the key
(invalid, expired or already used), the installer prints the agent's own lines,
stops and disables the service, and asks for a new key. If the agent has not
enrolled in time for any other reason, it keeps running and retrying, and the
installer says where to look.

## Running it

| | |
|---|---|
| Status | `systemctl status vista-device-agent` |
| Log | `journalctl -u vista-device-agent -f` |
| Restart | `sudo systemctl restart vista-device-agent` |
| Stop | `sudo systemctl stop vista-device-agent` |

systemd restarts the agent 10 seconds after it stops, except when it exits with
status 78: a rejected registration key or an unusable configuration needs a
person, and restarting would only repeat it.

## Upgrade

Download and verify the new release, then run its installer again from the
directory holding the new files, with **no key**:

```sh
sudo bash install-device-agent.sh
```

It keeps the agent's identity, configuration and certificate and replaces only
the binary. `--url` is not needed either. A host installed under the old
`crypto-device-agent` names moves to the `vista-device-agent` names on the way
(see "Linux host names" in the [repository README](../../README.md)).

A registration key cannot be used twice. Running the installer with a **new**
key enrolls this host as a **second, new agent**: the old certificate is
discarded and the old agent stays in the console until you remove it. Do that
only to replace the agent's identity on purpose, for example after its
certificate was lost.

## Uninstall

```sh
sudo bash install-device-agent.sh --uninstall
```

It stops and removes the service and the installation. The agent stays listed
in the console until you remove it there.

## Linux on ARM64

The `linux_arm64` build is a separate download and is run on a GitHub-hosted
ARM64 runner in every release. Install it the same way: on an ARM64 host the
installer looks for the loose `vista-device-agent_<version>_linux_arm64` file,
and `--check-dependencies` fails for a binary of the wrong architecture.

## Troubleshooting

See [CERTIFICATE_MANAGEMENT.md](CERTIFICATE_MANAGEMENT.md) for enrollment and
certificate problems.
