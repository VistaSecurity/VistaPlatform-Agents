# Installing the sensor on Linux

`install-sensor.sh` installs the Vista Platform sensor as a systemd service: it
starts at boot, restarts when it stops, and registers itself with your Vista
Platform on first start. It runs on x86-64 (`amd64`) and ARM64 (`arm64`) Linux
hosts with systemd.

## What you need

- **The commands from your console.** In your Vista Platform console, open
  Discovery → Sensors & Agents and choose **Register sensor or agent**. The
  dialog creates the registration key and prints the install commands for
  this system, with your platform's URL and, where needed, its CA fingerprint
  already filled in (see "The platform URL and CA fingerprint" below).
- **The sensor for this host** from the release page of the agents release
  your console names: the archive `vista-sensor_<version>_linux_amd64.tar.gz`
  (x86-64) or `vista-sensor_<version>_linux_arm64.tar.gz` (ARM64). The archive
  holds the binary (`crypto-sensor`), `install-sensor.sh`, `LICENSE`, `NOTICE`
  and `THIRD_PARTY_LICENSES`. The loose binary `vista-sensor_<version>_linux_<arch>`
  and the loose `install-sensor.sh` also work, side by side in one directory:
  the installer accepts either name and needs no rename.
- **libpcap**, the packet-capture library, from your distribution:

  | Distribution | Command |
  |---|---|
  | Debian, Ubuntu | `sudo apt-get update && sudo apt-get install libpcap0.8` (apt installs `libpcap0.8t64` on Ubuntu 24.04+ and Debian 13+) |
  | RHEL, Fedora, Rocky, Alma | `sudo dnf install libpcap` |
  | Amazon Linux 2, CentOS 7 | `sudo yum install libpcap` |
  | SUSE, openSUSE | `sudo zypper install libpcap1` |

  An offline host needs the distribution's libpcap package and its
  dependencies from an approved local repository. The installer never installs
  packages itself.
- **root** (the installer runs with `sudo`) and **systemd**.
- The **address** of this host that the registration key was created for
  (`--ip`): the installer checks that it is on one of this host's interfaces.

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
The sensor pins that CA on first start only if it has this fingerprint. Without
the option, the host must already trust the platform's certificate.

## Install

From the directory holding the downloaded files:

```sh
tar -xzf vista-sensor_<version>_linux_amd64.tar.gz
cd vista-sensor_<version>_linux_amd64
bash install-sensor.sh --check-dependencies      # no root, changes nothing
printf '%s\n' "$KEY" | sudo bash install-sensor.sh \
    --url https://vista.example.com --key-stdin --ip 192.0.2.10
```

`--check-dependencies` runs the binary's `--version` to prove it loads on this
host (libpcap present, right architecture and libc), then exits. If it fails it
prints the libpcap package for your distribution.

The key is never printed. Pass it on standard input (`--key-stdin`) or in the
`VISTA_REGISTRATION_KEY` environment variable; `--key KEY` works too but shows
the key to other users in the process list. A registration key works once.

Other options:

| Option | |
|---|---|
| `--url URL` | Your platform's URL (required on a first install) |
| `--key-stdin`, `--key KEY` | Registration key (or `VISTA_REGISTRATION_KEY`) |
| `--ip ADDRESS` | The address the key was created for (required on a first install) |
| `--name NAME` | Sensor name (default `sensor-<host name>-<date>`) |
| `--interfaces LIST` | Interfaces to capture on, comma-separated, for example `eth0,eth1` (default: up to five interfaces named `eth*`, `ens*`, `enp*` or `wl*`) |
| `--ca-fingerprint SHA256` | Pin a private platform CA (see above) |
| `--dir DIRECTORY` | Installation directory (default `/opt/vista-sensor`) |
| `--check-dependencies` | Check the binary loads here, then exit |
| `--uninstall` | Remove the sensor (see "Uninstall") |

`--profile` is accepted and not applied yet: the sensor registers with the
`datacenter_host` profile.

## What gets installed

| | |
|---|---|
| Program | `/opt/vista-sensor/vista-sensor` |
| Configuration | `/opt/vista-sensor/sensor-config.yaml`, mode 0600 (it holds the registration key until the sensor redeems it) |
| Data and certificates | `/opt/vista-sensor/data/` (the certificate the platform issued is under `data/certs/`) |
| Service | `vista-sensor.service` (`/etc/systemd/system/vista-sensor.service`), enabled at boot |
| Account | system user and group `vista-sensor`, no login shell, owning `/opt/vista-sensor` |

The service runs `vista-sensor --verbose -config /opt/vista-sensor/sensor-config.yaml`
as `vista-sensor` with only the `CAP_NET_RAW` capability, which packet capture
needs, and may write only under `/opt/vista-sensor`. It sets
`SENSOR_IP_ADDRESS` to the `--ip` address, so registration reports that address
even on a host with several.

The installer does not register the sensor. It starts the service and waits up
to 90 seconds until the sensor itself has registered and written the UUID the
platform accepted into its configuration. If the platform rejects the key
(invalid, expired or already used), the installer prints the sensor's own lines,
stops and disables the service, and asks for a new key. If the sensor has not
registered in time for any other reason, it keeps running and retrying, and the
installer says where to look.

## Running it

| | |
|---|---|
| Status | `systemctl status vista-sensor` |
| Log | `journalctl -u vista-sensor -f` |
| Restart | `sudo systemctl restart vista-sensor` |
| Stop | `sudo systemctl stop vista-sensor` |

systemd restarts the sensor 10 seconds after it stops, except when it exits with
status 78: that means a person has to act (the registration key was rejected, or
the configuration cannot be used), and restarting would only repeat it.

## Upgrade

Download and verify the new release, then run its installer again from the
directory holding the new files, with **no key**:

```sh
sudo bash install-sensor.sh
```

It keeps the sensor's identity, configuration and certificate and replaces only
the binary. `--url` and `--ip` are not needed either. A host installed under the
old `crypto-sensor` names moves to the `vista-sensor` names on the way (see
"Linux host names" in the [repository README](../../README.md)).

A registration key cannot be used twice. Running the installer with a **new**
key registers this host as a **second, new sensor**: the old certificate is
discarded and the old sensor stays in the console until you remove it. Do that
only to replace the sensor's identity on purpose, for example after its
certificate was lost.

## Uninstall

```sh
sudo bash install-sensor.sh --uninstall
```

It stops and removes the service and the installation. The sensor stays listed
in the console until you remove it there.

## Linux on ARM64

The `linux_arm64` build is a separate download and is run on a GitHub-hosted
ARM64 runner in every release. Install it the same way: on an ARM64 host the
installer looks for the loose `vista-sensor_<version>_linux_arm64` file, and
`--check-dependencies` fails for a binary of the wrong architecture.

## Troubleshooting

See [USAGE_GUIDE.md](USAGE_GUIDE.md) for running the sensor by hand while
diagnosing a problem, and [CERTIFICATE_MANAGEMENT.md](CERTIFICATE_MANAGEMENT.md)
for certificate problems.
