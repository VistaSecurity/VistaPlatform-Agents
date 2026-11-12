# Vista Platform agents

The public home of the two customer-deployed agents of Vista Platform: the
passive network sensor and the device interrogation agent. Source, builds,
signed releases, installers and compatibility records are published here.
Bugs and requests go to this repository's issues (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)).

## What lives here

- `cmd/sensor`, `cmd/device-agent`: the two executables, built and released
  separately, used by Vista Platform in managed mode.
- `internal/`, `shared/`: the code they are built from, maintained here.
- `scripts/`: the installers, the build script and the release tooling.
- Nightly and tagged builds, installers and compatibility metadata, published
  as this repository's releases. Every artefact carries a Sigstore signature.

## Releases

`release.yml` publishes a release for each protected `vX.Y.Z` tag (release
candidates `vX.Y.Z-rc.N` as prereleases) and `nightly.yml` a prerelease of the
head of `main` on every push to `main` and daily (skipped when that commit
already has one), under `nightly-YYYYMMDD-<commit>`. Both build every
target on GitHub-hosted runners, run the Linux builds on linux/amd64 and
linux/arm64, and publish each binary, package and installer with a Sigstore
signature, an SBOM, `SHA256SUMS`, the release metadata `agents-release.json`
and a compatibility record. Signatures are present on every release. Where
GitHub can attest, a release carries SLSA build provenance
(`provenance.intoto.jsonl`); a release built while the repository was private
says in `agents-release.json` that provenance is unavailable
(`provenance.status: "unavailable"`, with the reason), and a stable release is not published without provenance. `compatibility.yml` signs
later records, which say which platform versions were tested with those bytes.
How to verify a download: `docs/verify-release.md`. How releases are made and
what protects them: `docs/releasing.md`.

## Installing

The agents report to your own Vista Platform; there is no hosted platform and
no default URL. To install one:

1. In your Vista Platform console, open Discovery → Sensors & Agents and choose
   **Register sensor or agent**. The dialog creates a single-use registration
   key and prints the install commands for your system, with your platform's
   URL (`--url`, `-Url`) and, for a platform with a private CA, its CA
   fingerprint (`--ca-fingerprint`, `-CaFingerprint`).
2. Download the agent for your system from the release the console names
   (see "Which file do I need" below) and verify it
   ([`docs/verify-release.md`](docs/verify-release.md)).
3. Run the installer from the directory holding the downloaded files. It
   installs the agent as a service, which registers itself with your platform.

Each agent has one installer per supported system; each release archive
carries the installer for its system.

| | Linux (systemd) | macOS (launchd) | Windows (service) |
|---|---|---|---|
| Sensor | `install-sensor.sh` ([guide](docs/sensor/LINUX_SETUP.md)) | `install-sensor-macos.sh` ([guide](docs/sensor/MACOS_SETUP.md)) | `install-sensor.ps1` ([guide](docs/sensor/WINDOWS_SETUP.md)) |
| Device agent | `install-device-agent.sh` ([guide](docs/device-agent/LINUX_SETUP.md)) | `install-device-agent-macos.sh` ([guide](docs/device-agent/MACOS_SETUP.md)) | `install-device-agent.ps1` ([guide](docs/device-agent/WINDOWS.md)) |

To upgrade, run the new release's installer with no key: it keeps the agent's
identity. A registration key works once; a new key registers the host as a new
agent. Each installer removes its agent with `--uninstall` (`-Uninstall` on
Windows).

### Linux host names

The Linux installers use `vista-sensor.service`, user and group `vista-sensor`,
and `/opt/vista-sensor`, and likewise `vista-device-agent` for the device agent.

**Upgrading from the `crypto-sensor` and `crypto-device-agent` names:** run the
installer of the new release. It stops the old service, moves the install
directory with its configuration, certificates and data, updates the paths in the
configuration, and starts the service under the new names. An enrolled host keeps
its identity and needs no registration key, `--url` or `--ip`:

```bash
sudo bash install-sensor.sh
sudo bash install-device-agent.sh
```

A custom directory stays where it is unless `--dir` names another. If the run
stops part-way the installer says where the files are; fix the cause and run it
again with the same options. Anything that named the old service, such as a
monitoring check, needs the new name.

## Which file do I need

Each release lists about 70 files; a person installing an agent needs one. The
release notes open with a table linking it for every agent and system. In
short, download the archive for your agent and system:

| Agent | System | Download |
|---|---|---|
| Sensor | Linux x86-64 / ARM64 | `vista-sensor_<version>_linux_amd64.tar.gz` / `..._linux_arm64.tar.gz` |
| Sensor | macOS Intel / Apple silicon | `vista-sensor_<version>_darwin_amd64.tar.gz` / `..._darwin_arm64.tar.gz` |
| Sensor | Windows x64 | `vista-sensor_<version>_windows_amd64.zip` |
| Device agent | Linux x86-64 / ARM64 | `vista-device-agent_<version>_linux_amd64.tar.gz` / `..._linux_arm64.tar.gz` |
| Device agent | macOS Intel / Apple silicon | `vista-device-agent_<version>_darwin_amd64.tar.gz` / `..._darwin_arm64.tar.gz` |
| Device agent | Windows x64 | `vista-device-agent_<version>_windows_amd64.zip` |

Releases also contain a Windows x86 sensor (`..._windows_386.zip`). It is
compile-only: built, checked and signed, but never run on its architecture in
the release run (`runtime_qualified: false` in `agents-release.json`), and not
supported.

Each archive holds the binary, the installer for its system where there is
one, `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES`; run the installer from the
unpacked directory. The loose binaries (`vista-<agent>_<version>_<os>_<arch>`)
and installers are published too, for those who want them. Everything else
(`*.sigstore.json`, `*.cdx.json`, `SHA256SUMS`, `agents-release.json`,
`compatibility-*.json`, `provenance.intoto.jsonl`) is for verification and
tooling: see [`docs/verify-release.md`](docs/verify-release.md).

## Pull-request checks

Every pull request runs `.github/workflows/pr.yml` on GitHub-hosted runners
with a read-only token and no secrets: build, vet and test with CGO on
linux/amd64, CGO-free cross-builds for Linux, macOS and Windows, gofmt,
golangci-lint, govulncheck, and `scripts/check-workflows.mjs`, which fails if
any workflow asks for a runner GitHub does not host, uses an action that is not
pinned to a commit SHA, asks for write permissions on a pull request, or (in
the release workflows) holds a write permission outside the publishing job and
its environment, restores a cache or names a secret. The
same commands run locally with `GOWORK=off`, Go 1.26.11 and, for the sensor,
`libpcap-dev`.

## License

The Vista Platform agents are **open source under the
Apache License 2.0 ([`LICENSE`](LICENSE))**. You may use, modify and redistribute them,
commercially or not, under that licence's terms, including its patent grant and
its notice requirements. See [`NOTICE`](NOTICE) for the third-party components
and their licences.

The licensor is **Lakeshore Labs LLC**, which does business as **Vista
Security**.

Two things the Apache licence here does not cover:

- **Vista Platform itself.** The platform that manages these agents (its
  services, user interfaces, Helm chart and container images) is proprietary
  software under its own licence, published separately. Using these agents does
  not require it, and the Apache licence here grants no rights in it.
- **Third-party software you install alongside.** On Windows the sensor needs
  Npcap, which you install from its publisher under its own licence; its free
  licence covers up to five systems. On Linux and macOS the sensor uses the
  operating system's libpcap.

"Vista", "Vista Security" and "Vista Platform" are trademarks of Lakeshore Labs
LLC; the licence does not grant the right to use them beyond describing where
the software comes from.

Contributions: see [`CONTRIBUTING.md`](CONTRIBUTING.md). Security reports: see
[`SECURITY.md`](SECURITY.md).
