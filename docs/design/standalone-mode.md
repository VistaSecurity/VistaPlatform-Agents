# Standalone mode

Status: built (#41, #42, #43; tracking issue #40).

## What it is

Standalone mode runs the sensor and the device agent **without a Vista
Platform**: no registration key, no control plane, no account, no upload. The
operator names what to look at on the command line, the agent collects, and it
writes what it observed to a file in a documented format. Nothing else.

It is **data collection only**. The agents record what they saw: protocol
versions, cipher suites, key exchange groups, certificates, interfaces,
neighbours, host inventory. They do not judge it. There are no risk scores, no
weak/strong verdicts, no post-quantum readiness, no compliance results and no
history in standalone mode; that assessment is what Vista Platform does with
the same observations. People who want meaning without the platform parse the
output with their own scripts, which is why the output format is published and
versioned.

Managed mode (installed as a service, enrolled with a platform) is unchanged.
The standalone commands are subcommands of the same two binaries; running a
binary with no subcommand behaves exactly as it does today.

## Commands

```
crypto-sensor capture  --pcap FILE                 [output flags]
crypto-sensor capture  --interface IF --duration D [output flags]
crypto-sensor scan     --target T [--target T ...] | --targets-file FILE
                       [--depth quick|standard|thorough] [--pace polite|normal|fast]
                       [--allow-public] [output flags]

device-agent  collect  --type TYPE --target HOST [--port N]
                       [--credentials FILE] [--ssh-host-key SHA256:...]
                       [--insecure-skip-verify] [--timeout D] [output flags]
device-agent  host-inventory [output flags]

output flags: [--out PATH|-] [--format jsonl|json|csv] [--quiet]
sensor only:  [--verbose]   (decoder and engine logs on standard error)
```

Every subcommand prints `--help` with its flags, exits when its work is done,
and never starts a service, enrolls, reads the managed configuration file or
opens a connection to a control plane.

### `crypto-sensor capture`

Passive only. It decodes the same protocols the managed sensor decodes (TLS,
SSH, STARTTLS, QUIC, IKE, WireGuard, OpenVPN, SMB, Kerberos, the OT protocols)
and the same host-observation traffic (ARP, DHCP, mDNS, NetBIOS, LLDP, CDP).

- `--pcap FILE` reads a capture file (pcap or pcapng, whatever libpcap opens)
  to the end, then flushes every reassembly buffer and exits. Packets are never
  dropped for speed: reading a file blocks on the decoder instead.
- `--interface IF --duration D` captures live for `D` (required, so a run
  always ends), then flushes and exits. Ctrl-C ends it early and still writes
  what was seen. Live capture needs the same privileges the managed sensor
  needs (root or the capture capabilities on Linux, Npcap on Windows).
- The managed sensor's active TLS enrichment (connecting back to a server it
  saw passively) is **off**: `capture` sends no packets.
- TLS is decoded on the sensor's known TLS and STARTTLS ports, as in managed
  mode; a TLS service on another port is not recognised passively (`scan`
  finds it).

### `crypto-sensor scan`

Active scanning of targets the operator names, on the same scan engine the
managed sensor runs for a platform job.

- Targets: an address, a CIDR range, an `a-b` range, or a hostname. A hostname
  is resolved once at start and the addresses it resolved to are pinned for
  the run (printed in the run record); the name is offered as SNI.
- **Only the named targets are touched.** The run builds its allow rule from
  the targets themselves; nothing outside them is probed, liveness included.
- Reserved addresses are always refused: unspecified, loopback, link-local
  (cloud metadata lives there), multicast and broadcast.
- **Public addresses are refused unless `--allow-public` is given.** The flag
  states that the operator owns or is authorised to scan them. Without it a
  public target is a usage error before any packet is sent, never a silent
  skip. Private address space needs no flag.
- Fetches a scanned server's own data asks for (the OCSP responder its
  certificate names) are held to the same rule, so an OCSP status is reported
  only when the responder is itself a named target.
- A public target is scanned at `standard` depth at most, the engine's rule
  for addresses outside the operator's own networks; the run record says when
  a depth was lowered.
- Size limits are the engine's: a target or a run above the engine's address
  limits is refused before any packet (`discovery.CheckTargetSizes`).
- `--depth` picks the port preset (default `standard`), `--pace` the
  concurrency and timeouts (default `polite`, the gentlest, because a
  standalone run has no operator-tuned limits behind it).
- OT protocol probes are not offered in this version: they stay platform jobs
  with their own opt-in.

### `device-agent collect`

One interrogation of one device through the same collectors and the same
registry as a managed job, so the same projection and redaction apply: the
output carries posture, never key material, pre-shared keys or command
transcripts.

- `--type` is a registry device type (`fortigate`, `cisco`, `palo_alto`,
  `f5_bigip`, `unifi`, `generic_snmp`, `postgresql`, `mysql`, `generic_http`,
  …); `--help` lists them.
- Credentials come from `--credentials FILE` (YAML or JSON: `username`,
  `password`, `api_key`, `token`, plus vendor-specific keys) or from the
  environment (`VISTA_DEVICE_USERNAME`, `VISTA_DEVICE_PASSWORD`,
  `VISTA_DEVICE_API_KEY`, `VISTA_DEVICE_TOKEN`). There is no flag that takes a
  secret on the command line, where it would land in shell history and the
  process list. On Linux and macOS a credentials file readable by group or
  others is refused.
- SSH host keys: `--ssh-host-key` pins the expected key; a different key
  aborts before any credential is sent. Without it the first key seen is
  accepted and its fingerprint is written to the output, so the next run can
  pin it.
- `--insecure-skip-verify` disables TLS verification of the management
  endpoint (self-signed appliance certificates); it is recorded in the run
  record.
- `--timeout` bounds the whole interrogation (default 5 minutes).

### `device-agent host-inventory`

The existing `--host-inventory-once` collection of the machine the agent runs
on, with the output flags. `--host-inventory-once` keeps working.

## Output

`--out` names the file (default `-`, standard output). A file is created with
mode 0600 and written through a temporary file that is renamed into place, so
a reader never sees half a document. A human summary always goes to standard
error (record counts by kind, warnings, errors, where the output went) unless
`--quiet`.

### Records

Every record has the same envelope:

```json
{"schema":"vista.agent-output/v1","kind":"tls_endpoint","agent":"crypto-sensor",
 "agent_version":"6.1.0","run_id":"…","observed_at":"2026-11-23T14:02:11Z","data":{…}}
```

| kind | written by | `data` is |
|---|---|---|
| `run` | every command, first | the command, its non-secret flags, targets as resolved, host name, start time |
| `passive_observation` | `capture` | one decoded observation, the managed sensor's discovery record |
| `scan_host` | `scan` | one host's scan result: liveness, and every TCP and UDP observation |
| `device_interrogation` | `collect` | the collector's result: crypto assets, device identity, interfaces, facts, relationships, warnings |
| `host_inventory` | `host-inventory` | the host report and its observations |
| `error` | any | something that failed (a host that could not be scanned, a device that refused the login), with a reason |
| `summary` | every command, last | counts by kind, errors, duration, whether the result is partial |

`data` uses the same field names as the managed protocol, so a script written
against standalone output also reads what the managed agents report. The
envelope is held by `schemas/output/v1/record.schema.json`.

### Formats

- `jsonl` (default): one record per line, in the order above. On standard
  output it streams, so a long scan can be read while it runs; a file appears
  under its name when the run ends.
- `json`: one document `{"run": …, "records": […], "summary": …}`, for reading
  and diffing.
- `csv`: one row per **endpoint** (host, port, protocol) the run observed, with
  the columns a spreadsheet wants: `kind, host, address, port, transport,
  protocol, protocol_version, cipher_suite, key_exchange, certificate_subject,
  certificate_issuer, certificate_not_after, certificate_key_algorithm,
  certificate_key_size, certificate_signature_algorithm,
  certificate_fingerprint_sha256, source`. A row may leave columns empty.
  Interfaces, neighbours and host inventory have no endpoint and are not in
  the CSV; use `json` or `jsonl` for those. The summary still goes to standard
  error.

### Versioning

`schema` changes its version only for a breaking change to the envelope or to
a `kind`'s meaning; new fields and new kinds are additive within `v1`.

## Exit status

- `0`: the run finished and nothing failed.
- `1`: the run could not do its work (bad flags, a refused target, a capture
  file that will not open, every host failed). A bad invocation is reported on
  standard error and writes no output at all: `error` records are for failures
  after the run started.
- `2`: a partial result: some hosts, sections or collectors failed; the output
  is written and says which.

Empty output is not proof of anything: a run that saw no TLS saw no TLS, it did
not find the network safe. The summary says how much was looked at.

## What standalone mode will not do

- Upload, phone home, check for updates or send telemetry.
- Assess, score or rate anything.
- Run as a service, schedule, or remember anything between runs.
- Probe anything the operator did not name; scan public addresses without
  `--allow-public`; run OT probes.
- Take a secret on the command line or write one to its output or logs.

## Later, not in this version

- A devices file: several `collect` targets in one run.
- CycloneDX output (needs a mapping of observed algorithms to CycloneDX
  cryptographic-asset properties).
- Importing a standalone result into a Vista Platform (the air-gapped case).
- Other output targets (NetBox Diode and the like).
