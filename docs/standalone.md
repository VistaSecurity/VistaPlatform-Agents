# Running the agents on their own

Both agents can run without a Vista Platform. You name what to look at, the
agent collects, and it writes what it observed to a file. There is no
registration, no account and no upload, and nothing is installed: you run the
binary, it does its work and exits.

Standalone mode collects data. It does not assess it: there are no risk
scores, no weak/strong verdicts and no compliance results. The output is a
documented format meant for your own scripts, spreadsheets and tools. Vista
Platform assesses the same observations, keeps their history and maps them;
see [vistasecurity.io](https://vistasecurity.io) if you want that.

The design and the exact rules are in
[`design/standalone-mode.md`](design/standalone-mode.md).

## Get the binary

Download the archive for your system from the
[latest release](https://github.com/VistaSecurity/VistaPlatform-Agents/releases/latest)
and verify it ([`verify-release.md`](verify-release.md)). The sensor is
`crypto-sensor` (it needs libpcap on Linux and macOS, Npcap on Windows); the
device agent is `device-agent`. You do not need to run an installer for
standalone use.

## Read a capture file

```bash
crypto-sensor capture --pcap traffic.pcap --out traffic.jsonl
```

Decodes TLS, SSH, STARTTLS, QUIC, IKE, WireGuard, OpenVPN, SMB, Kerberos, the
industrial protocols, and the host traffic (ARP, DHCP, mDNS, NetBIOS, LLDP,
CDP) in a pcap or pcapng file. It sends no packets and needs no privileges.
TLS is recognised on the usual TLS and STARTTLS ports; for a TLS service on an
unusual port, use `scan`.

## Capture live for a while

```bash
sudo crypto-sensor capture --interface eth0 --duration 15m --out eth0.jsonl
```

`--duration` is required, so a run always ends; Ctrl-C ends it early and still
writes what was seen. Live capture needs root or the capture capabilities on
Linux and macOS, and Npcap on Windows. Capture is passive: the sensor never
connects to what it sees.

## Scan addresses you name

```bash
crypto-sensor scan --target 10.20.0.0/24 --target app.internal.example --out scan.jsonl
crypto-sensor scan --targets-file targets.txt --depth quick --pace normal --format csv --out scan.csv
```

- Only the targets you name are touched, and never loopback, link-local,
  multicast or broadcast addresses.
- Public addresses are refused unless you add `--allow-public`, which says you
  own them or are authorised to scan them.
- `--depth quick|standard|thorough` picks how many ports are tried (default
  `standard`); `--pace polite|normal|fast` sets concurrency and timeouts
  (default `polite`).
- A host name is resolved once at the start; the addresses it resolved to are
  in the output's `run` record.
- Public targets are scanned at `standard` depth at most, and an OCSP responder
  is asked only if it is itself one of your targets.
- `--verbose` prints the scan engine's log on standard error.

## Interrogate a device

```bash
chmod 600 fw-creds.yaml
device-agent collect --type fortigate --target 192.0.2.10 --credentials fw-creds.yaml --out fw.jsonl
```

`fw-creds.yaml`:

```yaml
username: readonly
password: "…"
```

- `device-agent collect --help` lists the supported `--type` values.
- Credentials come from a file (YAML or JSON) that only you can read, or from
  `VISTA_DEVICE_USERNAME`, `VISTA_DEVICE_PASSWORD`, `VISTA_DEVICE_API_KEY` and
  `VISTA_DEVICE_TOKEN`. No flag takes a secret. Use a read-only account.
- The output carries posture (protocols, ciphers, certificates, interfaces,
  neighbours), never keys, pre-shared keys or configuration dumps.
- The first SSH contact accepts the device's host key and prints its
  fingerprint; pass it back with `--ssh-host-key SHA256:…` on later runs, and a
  different key stops the run before any credential is sent.
- `--insecure-skip-verify` accepts a self-signed management certificate.

## Inventory this machine

```bash
device-agent host-inventory --out host.json --format json
```

## The output

`--out` names the file (default: standard output). A file is readable only by
you and appears when the run ends. `--format` is one of:

- `jsonl` (default): one record per line;
- `json`: one document with `run`, `records` and `summary`;
- `csv`: one row per host, port and protocol seen, with the TLS and certificate
  columns. Interfaces, neighbours and host inventory are not in the CSV; use
  `json` or `jsonl` for those.

Every record has the envelope below; `data` uses the same field names the
agents use with a platform.

```json
{"schema":"vista.agent-output/v1","kind":"scan_host","agent":"crypto-sensor",
 "agent_version":"…","run_id":"…","observed_at":"…","data":{…}}
```

The kinds are `run` (first), `passive_observation`, `scan_host`,
`device_interrogation`, `host_inventory`, `error` and `summary` (last). The
envelope's JSON Schema is
[`schemas/output/v1/record.schema.json`](../schemas/output/v1/record.schema.json).

For example, every TLS endpoint a scan saw, with its version:

```bash
jq -r 'select(.kind=="scan_host") | .data.tcp[]?
       | select(.result.tls_versions)
       | "\(.addr):\(.port) \(.result.tls_versions | join(","))"' scan.jsonl
```

A summary goes to standard error (`--quiet` turns it off).

## Exit status

`0` the run finished and nothing failed; `1` it could not do its work; `2` the
result is partial (some hosts or sections failed; the `error` records say
which). An empty result means the agent saw nothing of that kind, not that
nothing is wrong.
