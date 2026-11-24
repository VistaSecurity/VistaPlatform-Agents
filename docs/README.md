# Documentation

## Running the agents on their own (standalone mode)

No platform, no account, nothing uploaded: name what to look at and the agent
writes what it observed to a file.

- [`standalone.md`](standalone.md): how to run `capture`, `scan`, `collect`
  and `host-inventory`, the flags, and what to do when something goes wrong.
- [`standalone-output.md`](standalone-output.md): the output format record by
  record, the CSV columns, what is stable, and `jq` recipes.

## Running the agents with Vista Platform (managed mode)

- Sensor: [`sensor/README.md`](sensor/README.md), then the setup guide for
  [Linux](sensor/LINUX_SETUP.md), [macOS](sensor/MACOS_SETUP.md) or
  [Windows](sensor/WINDOWS_SETUP.md); running it:
  [`sensor/USAGE_GUIDE.md`](sensor/USAGE_GUIDE.md),
  [`sensor/WINDOWS_USAGE.md`](sensor/WINDOWS_USAGE.md); its files and logs:
  [`sensor/CONFIGURATION_AND_LOGS.md`](sensor/CONFIGURATION_AND_LOGS.md); its
  certificate: [`sensor/CERTIFICATE_MANAGEMENT.md`](sensor/CERTIFICATE_MANAGEMENT.md).
- Device agent: the setup guide for [Linux](device-agent/LINUX_SETUP.md),
  [macOS](device-agent/MACOS_SETUP.md) or [Windows](device-agent/WINDOWS.md);
  its certificate:
  [`device-agent/CERTIFICATE_MANAGEMENT.md`](device-agent/CERTIFICATE_MANAGEMENT.md).
- How an agent and a platform talk: [`managed-protocol.md`](managed-protocol.md).

## Releases

- [`verify-release.md`](verify-release.md): checking a download's signature
  and checksum.
- [`releasing.md`](releasing.md): how releases are made and what protects them.

## Design and development

- [`design/standalone-mode.md`](design/standalone-mode.md): the standalone
  mode design and the rules it keeps.
- [`design/kubernetes-inventory.md`](design/kubernetes-inventory.md): the
  Kubernetes inventory job, what it reads and the record it returns.
- [`development/standalone.md`](development/standalone.md): where the
  standalone code is, how a run goes, and the tests that hold each rule.
