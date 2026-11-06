# Installing the device agent on macOS

`install-device-agent-macos.sh` installs the device agent as a launchd daemon:
it starts at boot, restarts when it stops, and enrolls itself with the platform
on first start. It runs on macOS 13 or later, on Apple silicon and Intel Macs,
with the bash macOS ships.

## What you need

- The macOS device agent for your Mac from the release page: the archive
  `vista-device-agent_<version>_darwin_arm64.tar.gz` (Apple silicon) or
  `vista-device-agent_<version>_darwin_amd64.tar.gz` (Intel). The archive holds
  the binary (`device-agent`), the installer, `LICENSE`, `NOTICE` and
  `THIRD_PARTY_LICENSES`. The loose binary
  `vista-device-agent_<version>_darwin_<arch>` and the loose
  `install-device-agent-macos.sh` also work, side by side in one directory.
- An administrator account (the installer runs with `sudo`).
- A registration key from the console (Discovery → Sensors & Agents →
  Register → Device agent).

Verify what you downloaded before you run it (`docs/verify-release.md`).

## Install

```sh
tar -xzf vista-device-agent_<version>_darwin_arm64.tar.gz
cd vista-device-agent_<version>_darwin_arm64
bash install-device-agent-macos.sh --check-dependencies      # no root, changes nothing
printf '%s\n' "$KEY" | sudo bash install-device-agent-macos.sh \
    --url https://platform.example.com --key-stdin
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
users in the process list.

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
| Upgrade | run the installer again with the new binary and the same key |
| Uninstall | `sudo bash install-device-agent-macos.sh --uninstall` (also removes the account) |

launchd starts the agent again whenever it stops, at most every 10 seconds,
including after a restart requested from the console. It does not restart it
after exit status 78: a rejected registration key or an unusable configuration
needs a person. The job then stays stopped until the next boot or the next
install; after a rejected key during an install the installer also disables it,
and running the installer again with a new key enables it.

Re-running the installer with the same key keeps the agent's identity and
replaces only the binary. A different key is a fresh enrollment.

## Not covered

The macOS binaries are not notarized. The installer removes the quarantine flag
from the copy it installs; Sigstore signatures (`docs/verify-release.md`) are how
to check where a binary came from.
