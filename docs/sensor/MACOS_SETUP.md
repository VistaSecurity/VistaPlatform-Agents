# Installing the sensor on macOS

`install-sensor-macos.sh` installs the sensor as a launchd daemon: it starts at
boot, restarts when it stops, and registers itself with the platform on first
start. It runs on macOS 12 Monterey or later, on Apple silicon and Intel Macs,
with the bash macOS ships. The minimum is the Go release the agents are built
with: Go 1.26 runs on macOS 12 and later, and is the last Go release that does
([Go 1.26 release notes](https://go.dev/doc/go1.26)).

## What you need

- The macOS sensor for your Mac from the release page: the archive
  `vista-sensor_<version>_darwin_arm64.tar.gz` (Apple silicon) or
  `vista-sensor_<version>_darwin_amd64.tar.gz` (Intel). The archive holds the
  binary (`crypto-sensor`), the installer, `LICENSE`, `NOTICE` and
  `THIRD_PARTY_LICENSES`. The loose binary `vista-sensor_<version>_darwin_<arch>`
  and the loose `install-sensor-macos.sh` also work, side by side in one
  directory: the installer accepts either name and needs no rename.
- An administrator account (the installer runs with `sudo`).
- The commands from your console: in your Vista Platform console, open
  Discovery → Sensors & Agents and choose **Register sensor or agent**. The
  dialog creates a single-use registration key and prints the install commands
  for macOS, with your platform's URL and, where needed, its CA fingerprint
  (see "The platform URL and CA fingerprint" below). You also need the address
  of this Mac the key was created for (`--ip`).
- Nothing else: the sensor uses the libpcap that is part of macOS.

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
tar -xzf vista-sensor_<version>_darwin_arm64.tar.gz
cd vista-sensor_<version>_darwin_arm64
bash install-sensor-macos.sh --check-dependencies      # no root, changes nothing
printf '%s\n' "$KEY" | sudo bash install-sensor-macos.sh \
    --url https://vista.example.com --key-stdin --ip 192.0.2.10
```

The installer:

1. checks that the binary runs on this Mac (from a private copy without the
   download quarantine flag, so Gatekeeper does not stop it), before anything
   changes;
2. checks that `--ip` is an address of this Mac and that every interface it
   will capture on exists (default: the interface of the default route, for
   example `en0`; name others with `--interfaces en0,en1`);
3. copies the binary to `/usr/local/vista-sensor/vista-sensor` and removes its
   quarantine flag;
4. writes `/usr/local/vista-sensor/etc/sensor-config.yaml` (readable by root
   only: it holds the key until the sensor redeems it);
5. creates the launchd job `io.vistasecurity.sensor`
   (`/Library/LaunchDaemons/io.vistasecurity.sensor.plist`) and starts it;
6. waits until the sensor has written the UUID the platform accepted into its
   config. The installer never registers on the sensor's behalf.

It never prints the key. Pass it on standard input (`--key-stdin`) or in
`VISTA_REGISTRATION_KEY`; `--key KEY` works too but shows the key to other
users in the process list. A registration key works once.

### A platform with a private CA

macOS does not let a script change certificate trust without someone at the
screen, so an unattended install against a platform whose certificate this Mac
does not trust passes the CA's SHA-256 fingerprint:

```sh
... --ca-fingerprint <SHA-256 of the platform CA: 64 hex digits>
```

The sensor pins that CA on first start only if it hashes to the fingerprint.

## Why the sensor runs as root

On macOS only root can open the packet-capture devices (`/dev/bpf*`) and send
the raw packets an active scan uses. The sensor therefore runs as root. Its
files are root's: `/usr/local/vista-sensor` (program, `etc/`, `data/`) and
`/Library/Logs/Vista/sensor/`.

## Running it

| | |
|---|---|
| Status | `sudo launchctl print system/io.vistasecurity.sensor` |
| Log | `tail -f /Library/Logs/Vista/sensor/sensor.log` (moves to `sensor.log.1` at 10 MiB) |
| Restart | `sudo launchctl kickstart -k system/io.vistasecurity.sensor` |
| Stop until the next boot | `sudo launchctl bootout system/io.vistasecurity.sensor` |
| Uninstall | `sudo bash install-sensor-macos.sh --uninstall` |

launchd starts the sensor again whenever it stops, at most every 10 seconds,
except when it exits with status 78: that means a person has to act (the
registration key was rejected, or the configuration cannot be used), and
restarting would only repeat it. The job then stays stopped until the next boot
or the next install. If the key is rejected during an install, the installer
also disables the job; running the installer again with a new key enables it.

## Upgrade

Download and verify the new release, then run its installer again from the
directory holding the new files, with **no key**:

```sh
sudo bash install-sensor-macos.sh
```

It keeps the sensor's identity, configuration and certificate and replaces only
the binary. `--url` and `--ip` are not needed either.

A registration key cannot be used twice. Running the installer with a **new**
key registers this Mac as a **second, new sensor**: the old certificate is
discarded and the old sensor stays in the console until you remove it there.
Do that only to replace the sensor's identity on purpose.

## Uninstall

```sh
sudo bash install-sensor-macos.sh --uninstall
```

It stops the sensor and removes the job, the installation and the logs. The
sensor stays listed in the console until you remove it there.

## Options

| Option | |
|---|---|
| `--url URL` | Your platform's URL, as the console shows it (required on a first install) |
| `--key-stdin`, `--key KEY` | Registration key (or `VISTA_REGISTRATION_KEY`) |
| `--ip ADDRESS` | The address the key was created for (required on a first install) |
| `--name NAME` | Sensor name (default `sensor-<host name>-<date>`) |
| `--interfaces LIST` | Interfaces to capture on, comma-separated |
| `--ca-fingerprint SHA256` | Pin a private platform CA (see above) |
| `--dir DIRECTORY` | Installation directory (default `/usr/local/vista-sensor`) |
| `--check-dependencies` | Check the binary runs here, then exit |
| `--uninstall` | Remove the job, the installation and the logs |

`--profile` is accepted for parity with `install-sensor.sh` and is not applied
yet. There is no interactive mode on macOS.

## Not notarized

The macOS binaries are not notarized. The installer removes the quarantine flag
from the copy it installs; Sigstore signatures (`docs/verify-release.md`) are how
to check where a binary came from.
