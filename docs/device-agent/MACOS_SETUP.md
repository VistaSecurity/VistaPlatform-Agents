# Installing the device agent on macOS

`install-device-agent-macos.sh` installs the device agent as a launchd daemon:
it starts at boot, restarts when it stops, and enrolls itself with the platform
on first start. It runs on macOS 12 Monterey or later, on Apple silicon and
Intel Macs, with the bash macOS ships. The minimum is the Go release the agents
are built with: Go 1.26 runs on macOS 12 and later, and is the last Go release
that does ([Go 1.26 release notes](https://go.dev/doc/go1.26)).

## What you need

- The macOS device agent for your Mac from the release page: the archive
  `vista-device-agent_<version>_darwin_arm64.tar.gz` (Apple silicon) or
  `vista-device-agent_<version>_darwin_amd64.tar.gz` (Intel). The archive holds
  the binary (`device-agent`), the installer, `LICENSE`, `NOTICE` and
  `THIRD_PARTY_LICENSES`. The loose binary
  `vista-device-agent_<version>_darwin_<arch>` and the loose
  `install-device-agent-macos.sh` also work, side by side in one directory.
- An administrator account (the installer runs with `sudo`).
- The commands from your console: in your Vista Platform console, open
  Discovery → Sensors & Agents and choose **Register sensor or agent**, then
  the device agent. The dialog creates a single-use registration key and
  prints the install commands for macOS, with your platform's URL and, where
  needed, its CA fingerprint (see "The platform URL and CA fingerprint"
  below).

Verify what you downloaded before you run it
([verify-release.md](../verify-release.md)). Use the installer from the
release, never a copy from this repository's source tree.

## The platform URL and CA fingerprint

There is no hosted platform and no default URL: `--url` is the address of your
own Vista Platform console, the URL the registration dialog was opened at. The
commands the dialog prints already carry it.

If your platform's certificate is signed by a private CA that this Mac does not
trust, the dialog shows a **Platform CA fingerprint** panel with a copy button,
and its commands carry `--ca-fingerprint`. The value is the CA's SHA-256
fingerprint, 64 hexadecimal digits (colons and a `sha256:` prefix are accepted).

## Install

```sh
tar -xzf vista-device-agent_<version>_darwin_arm64.tar.gz
cd vista-device-agent_<version>_darwin_arm64
bash install-device-agent-macos.sh --check-dependencies      # no root, changes nothing
printf '%s\n' "$KEY" | sudo bash install-device-agent-macos.sh \
    --url https://vista.example.com --key-stdin
```

The installer:

1. checks that the binary runs on this Mac (from a private copy without the
   download quarantine flag), before anything changes;
2. creates the hidden system account `_vistadeviceagent` (no password, no
   shell, not shown at the login window) unless it exists;
3. copies the binary to `/usr/local/vista-device-agent/vista-device-agent` and
   removes its quarantine flag;
4. writes `/usr/local/vista-device-agent/etc/device-agent.yaml` (readable by the
   account only: it holds the key until the agent redeems it);
5. creates the launchd job `io.vistasecurity.device-agent`
   (`/Library/LaunchDaemons/io.vistasecurity.device-agent.plist`), running as
   `_vistadeviceagent`, and starts it;
6. waits until the agent has written the ID the platform accepted into its
   config. The installer never enrolls on the agent's behalf.

It never prints the key. Pass it on standard input (`--key-stdin`) or in
`VISTA_REGISTRATION_KEY`; `--key KEY` works too but shows the key to other
users in the process list. A registration key works once.

For a platform whose certificate this Mac does not trust, pass
`--ca-fingerprint <SHA-256 of the platform CA>`: macOS does not let a script
change certificate trust without someone at the screen, so this is the
unattended way.

## What runs as whom

The agent reaches devices over ordinary network connections and does not run as
root. The program files (`/usr/local/vista-device-agent/vista-device-agent` and
the launchd wrapper `service.sh` beside it) are root's, so the account cannot
change what it runs. What the agent writes is the account's: `etc/` (its
config), `data/` (its certificate and the platform CA) and
`/Library/Logs/Vista/device-agent/`.

### What that account can see

The host inventory reads this Mac's sockets with `netstat`, which macOS answers
in full for any account: every listening and bound socket and every connection,
with the process that owns it, including root's. The process name is cut to 16
characters.

If `netstat` does not answer, the agent falls back to `lsof`, which shows a
non-root account only that account's own processes. It then reports the
`listeners` and `bound_udp_sockets` sections as `partial`, with the reason in
the report's `errors`, and `connections` as `failed`. Sockets in a partial
report are real; ones missing from it mean nothing, and the platform does not
treat them as closed.

## Running it

| | |
|---|---|
| Status | `sudo launchctl print system/io.vistasecurity.device-agent` |
| Log | `sudo tail -f /Library/Logs/Vista/device-agent/device-agent.log` (moves to `.1` at 10 MiB) |
| Restart | `sudo launchctl kickstart -k system/io.vistasecurity.device-agent` |
| Stop until the next boot | `sudo launchctl bootout system/io.vistasecurity.device-agent` |
| Uninstall | `sudo bash install-device-agent-macos.sh --uninstall` (also removes the account) |

launchd starts the agent again whenever it stops, at most every 10 seconds,
including after a restart requested from the console. It does not restart it
after exit status 78: a rejected registration key or an unusable configuration
needs a person. The job then stays stopped until the next boot or the next
install; after a rejected key during an install the installer also disables it,
and running the installer again with a new key enables it.

## Upgrade

Download and verify the new release, then run its installer again from the
directory holding the new files, with **no key**:

```sh
sudo bash install-device-agent-macos.sh
```

It keeps the agent's identity, configuration and certificate and replaces only
the binary. `--url` is not needed either.

A registration key cannot be used twice. Running the installer with a **new**
key enrolls this Mac as a **second, new agent**: the old certificate is
discarded and the old agent stays in the console until you remove it there.
Do that only to replace the agent's identity on purpose.

## Uninstall

```sh
sudo bash install-device-agent-macos.sh --uninstall
```

It stops the agent and removes the job, the installation, the logs and the
`_vistadeviceagent` account. The agent stays listed in the console until you
remove it there.

## Not notarized

The macOS binaries are not notarized. The installer removes the quarantine flag
from the copy it installs; Sigstore signatures (`docs/verify-release.md`) are how
to check where a binary came from.
