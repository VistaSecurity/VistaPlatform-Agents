# Vista Platform sensor

The passive network sensor of Vista Platform: it captures traffic on the
interfaces you choose, reports the cryptography it observes to your Vista
Platform, and runs the active scans the platform hands it.

## Installing

Install the sensor from a verified release with its installer, which sets it up
as a service and lets it register itself with your platform:

1. In your Vista Platform console, open Discovery → Sensors & Agents and choose
   **Register sensor or agent**. The dialog creates a single-use registration
   key and prints the install commands for your system, with your platform's
   URL and, for a platform with a private CA, its CA fingerprint.
2. Download the sensor for your system from the release your console names.
3. Verify the download: [verify-release.md](../verify-release.md).
4. Run the installer from the directory holding the downloaded files, as the
   console's commands show.

| System | Guide |
|---|---|
| Linux (systemd) | [LINUX_SETUP.md](LINUX_SETUP.md) |
| macOS (launchd) | [MACOS_SETUP.md](MACOS_SETUP.md) |
| Windows (service) | [WINDOWS_SETUP.md](WINDOWS_SETUP.md) |

Use the installer published with the release, never a copy from this
repository's source tree, and no rename is needed: each installer finds the
binary beside it under its archive name (`crypto-sensor`, `crypto-sensor.exe`)
or its release name (`vista-sensor_<version>_<os>_<arch>[.exe]`).

On a host installed under the old `crypto-sensor` names, running the new Linux
installer moves it to the `vista-sensor` names and keeps its enrolment; see
"Linux host names" in the [repository README](../../README.md).

## Runtime dependencies

- **Linux:** libpcap from the distribution, for example `libpcap0.8` on
  Debian and Ubuntu or `libpcap` on RHEL and Fedora
  ([LINUX_SETUP.md](LINUX_SETUP.md) lists the packages).
  `bash install-sensor.sh --check-dependencies` checks, without root and
  without changing anything, that the binary loads on the host.
- **macOS:** nothing; macOS includes libpcap.
- **Windows:** [Npcap](https://npcap.com/#download), installed with
  "API-compatible Mode" checked.

## Configuration

The installers write a YAML configuration file and start the sensor with
`-config <file>`:

| System | Configuration file |
|---|---|
| Linux | `/opt/vista-sensor/sensor-config.yaml` |
| macOS | `/usr/local/vista-sensor/etc/sensor-config.yaml` |
| Windows | `%ProgramFiles%\VistaSensor\sensor-config.yaml` |

The keys the sensor reads are listed, with their defaults, in
[`examples/sensor/config.example.yaml`](../../examples/sensor/config.example.yaml);
where the sensor keeps its files, in
[CONFIGURATION_AND_LOGS.md](CONFIGURATION_AND_LOGS.md). Settings the console
manages (for example the additional TLS ports) are delivered by the platform and
written back into the file.

A few capture settings worth knowing:

- `capture.dedupTTLMinutes`: minimum minutes before the same passive
  observation (same destination address, port and protocol) is reported again.
  Default 60. Also set by the `DEDUP_TTL_MINUTES` environment variable, and by
  the platform, whose value applies at the next heartbeat without a restart. The
  window is shared by the passive connection cache and the TLS enricher's
  debounce.
- `capture.thirdPartyTLSEnrichment` (`THIRD_PARTY_TLS_ENRICHMENT`): default
  false. Lets the TLS enricher connect to third-party TLS services the network
  talks to, to read their certificates. Without it the enricher connects only to
  private addresses, `capture.ownedNetworks` or platform-declared networks, and
  elevated connections. It is a local value: it applies only while the platform
  has never delivered its own setting. The platform's value wins from its first
  delivery and is recorded in `<dataPath>/platform-probe-consent.json`, so it
  keeps winning after a restart; delete that file to hand control back to the
  local value.
- `capture.ownedNetworks` (`OWNED_NETWORKS`, comma-separated): public CIDRs this
  sensor may treat as the tenant's own, for an air-gapped sensor with no
  platform-declared networks. IPv4 must be /8 or narrower, IPv6 /16 or narrower;
  wider entries are ignored. Same precedence as `thirdPartyTLSEnrichment`.

## Running and troubleshooting

[USAGE_GUIDE.md](USAGE_GUIDE.md) covers the installed service, its logs, and
running the binary by hand in the foreground to diagnose a problem.
[CERTIFICATE_MANAGEMENT.md](CERTIFICATE_MANAGEMENT.md) covers registration and
the sensor's certificate.

## Building from source

```sh
make sensor                # builds bin/crypto-sensor for this machine (CGO, libpcap-dev)
make sensor-all            # builds every released target into dist/sensor/<os>-<arch>/
```

Release archives, checksums and signatures are produced by the repository's
release workflow, not by a local make target ([releasing.md](../releasing.md)).
A binary you build yourself is not a release and carries no signature.
