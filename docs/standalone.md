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

| You want to | Run |
|---|---|
| Read a capture file | `crypto-sensor capture --pcap FILE` |
| Watch an interface for a while | `crypto-sensor capture --interface IF --duration D` |
| Scan addresses you own | `crypto-sensor scan --target T` |
| Ask one device about its own cryptography | `device-agent collect --type TYPE --target HOST` |
| Inventory the machine you are on | `device-agent host-inventory` |
| Describe the certificates, keys and crypto policy of this machine, or one over SSH | `device-agent host-crypto [--remote USER@HOST]` |

Every field of the output: [`standalone-output.md`](standalone-output.md). The
design and the exact rules: [`design/standalone-mode.md`](design/standalone-mode.md).

## Get the binary

1. Open the [releases page](https://github.com/VistaSecurity/VistaPlatform-Agents/releases)
   and pick `v6.1.0-rc.1` or a later release (see below). Download the
   archive for your agent and system (the README's
   ["Which file do I need"](../README.md#which-file-do-i-need) table names it)
   and `SHA256SUMS`.
2. Verify the archive **before you unpack it**
   ([`verify-release.md`](verify-release.md)). `SHA256SUMS` also lists the
   loose binaries, whose names are the same as the directories the archives
   unpack to, so checking it after unpacking reports those as `FAILED`.

   ```bash
   sha256sum --ignore-missing -c SHA256SUMS        # Linux
   shasum -a 256 --ignore-missing -c SHA256SUMS    # macOS
   ```

3. Unpack it. You do not need to run the installer for standalone use.

- The sensor is `crypto-sensor` (`crypto-sensor.exe` on Windows). It needs
  libpcap on Linux and macOS, which the system usually has, and
  [Npcap](https://npcap.com/#download) on Windows.
- The device agent is `device-agent` (`device-agent.exe`). It needs nothing
  else.

The first release with standalone mode is
[`v6.1.0-rc.1`](https://github.com/VistaSecurity/VistaPlatform-Agents/releases/tag/v6.1.0-rc.1),
a release candidate, and every release after it has it too; so do the nightly
builds from 2026-11-23 on. GitHub's "Latest" label stays on the newest stable
release, which until v6.1.0 ships is v6.0.0, and **v6.0.0 has no standalone
mode**: an older binary has no subcommands and would start as a managed agent
instead. A binary that has it lists the standalone commands at the top of
`--help`.

### macOS: before the first run

The macOS binaries are not notarized, so Gatekeeper refuses to open one that a
browser downloaded ("cannot be opened because Apple cannot check it"). Remove
the download's quarantine flag from the unpacked directory **before you run
anything in it**:

```bash
xattr -dr com.apple.quarantine vista-sensor_<version>_darwin_arm64
```

If you ran it first and macOS refused, removing the flag afterwards is not
enough: macOS remembers that file. Approve it in **System Settings → Privacy &
Security → Open Anyway**, or unpack the archive again into a new directory and
remove the flag there first. (The installers remove the flag themselves; this
step is only for running the binary directly.)

### Windows

Run the `.exe` from PowerShell or a command prompt; these are command-line
tools, and double-clicking one opens and closes a window. Windows binaries are
not Authenticode-signed: SmartScreen may warn about a file Explorer unpacked
from a downloaded archive. Verify the archive first, as above.

## Read a capture file

```bash
crypto-sensor capture --pcap traffic.pcap --out traffic.jsonl
```

Decodes TLS, SSH, STARTTLS, QUIC, IKE, WireGuard, OpenVPN, SMB, Kerberos, the
industrial protocols, and the host traffic (ARP, DHCP, mDNS, NetBIOS, LLDP,
CDP) in a pcap or pcapng file, to its end. It sends no packets, needs no
privileges, and drops nothing however large the file is.

TLS is recognised on the usual TLS and STARTTLS ports. A TLS service on an
unusual port is not decoded passively; `scan` it instead. TLS 1.3 encrypts the
server's certificate, so a passive capture sees certificates only for TLS 1.2
and earlier.

## Capture live for a while

```bash
sudo crypto-sensor capture --interface eth0 --duration 15m --out eth0.jsonl
```

`--duration` is required, so a run always ends; Ctrl-C ends it early and still
writes what was seen. Capture is passive: the sensor never connects to what it
sees. Run with `sudo`, the output file still belongs to you.

- Linux: run as root, or give the binary the capture capability once:
  `sudo setcap cap_net_raw=eip ./crypto-sensor` (the installed service runs
  with that capability alone).
- macOS: run with `sudo`. Interface names are like `en0`.
- Windows: run from an elevated prompt with Npcap installed. Name the
  interface by its adapter name (`Ethernet`, `Wi-Fi`); a name that does not
  match is refused with the list of capture devices.

If the decoders cannot keep up with the interface, the summary says how many
packets were dropped and the result is marked partial (exit 2).

## Scan addresses you name

```bash
crypto-sensor scan --target 10.20.0.0/24 --target app.internal.example --out scan.jsonl
crypto-sensor scan --targets-file targets.txt --depth quick --pace normal --format csv --out scan.csv
```

A target is an address (`10.20.0.5`), a CIDR range (`10.20.0.0/24`), a range
(`10.20.0.10-10.20.0.40`) or a host name. A targets file holds one per line;
`#` starts a comment.

- **Only the targets you name are touched.** That includes liveness checks and
  anything a certificate points to: an OCSP responder is asked only if it is
  one of your targets.
- Loopback, link-local (where cloud metadata services live), multicast and
  broadcast addresses are always refused, even when named.
- Private address space (RFC 1918, 100.64.0.0/10, fc00::/7) needs nothing
  more. **Public addresses are refused** unless you add `--allow-public`, which
  states that you own them or are authorised to scan them; they are then
  scanned at `standard` depth at most, and the `run` record says so.
- A host name is resolved once at the start, and only the addresses it
  resolved to are scanned; the name is offered as the TLS server name. A name
  that does not resolve is an `error` record, and the rest of the run goes on.
- `--depth quick|standard|thorough` picks how many ports are tried (default
  `standard`).
- `--pace polite|normal|fast` sets concurrency and timeouts (default `polite`,
  the gentlest).
- **How long it takes.** The defaults are gentle and thorough, so they are
  slow: on a lab network one host took about a minute and a half at
  `standard` depth and `polite` pace, about a second with `--depth quick`, and
  about 13 seconds at `standard` with `--pace normal`. Start with
  `--depth quick` to see what is there, then scan what matters at `standard`.
  A long scan prints how many addresses it has done every 15 seconds.
- The scan identifies cryptographic protocols (TLS, SSH, SMB, …). An open port
  that speaks something else, plain HTTP for example, is listed as open with
  no protocol.
- `--timeout 30m` stops the whole scan after that long and writes what
  finished; the rest is reported as not scanned, and the result is partial.
- `--verbose` prints the scan engine's log on standard error.
- OT protocol probes (Modbus, DNP3 and the like) are not offered: probing
  industrial devices is left to a platform job with its own opt-in.

## Interrogate a device

```bash
chmod 600 fw-creds.yaml
device-agent collect --type fortinet --target 192.0.2.10 --credentials fw-creds.yaml --out fw.jsonl
```

`fw-creds.yaml`:

```yaml
username: readonly
password: "…"
```

- `--type` is one of the device types `device-agent collect --help` lists:
  Fortinet (`fortinet`, `fortigate`), Cisco (`cisco`, `cisco_asa`,
  `cisco_router`, `cisco_switch`), Palo Alto (`paloalto`, `palo_alto`,
  `panos`), F5 BIG-IP (`f5`, `f5_bigip`, `bigip`), UniFi (`unifi`,
  `unifi_controller`, `ubiquiti`, `udm_pro`), databases (`postgresql`,
  `mysql`), and generic HTTPS or SNMP endpoints (`generic_http`,
  `generic_snmp`).
- **Credentials** come from a file (YAML or JSON: `username`, `password`,
  `api_key`, `token`, and `community` for SNMP) or from
  `VISTA_DEVICE_USERNAME`, `VISTA_DEVICE_PASSWORD`, `VISTA_DEVICE_API_KEY` and
  `VISTA_DEVICE_TOKEN`. No flag takes a secret, so none lands in your shell
  history or the process list. On Linux and macOS a credentials file that group
  or others can read is refused. Use a read-only account.
- The output carries posture (protocols, ciphers, certificates, interfaces,
  neighbours, device identity), never keys, pre-shared keys, passwords or
  command transcripts.
- **SSH host keys:** the first SSH contact accepts the device's host key and
  the summary prints its fingerprint. Pass it back with `--ssh-host-key
  SHA256:…` on later runs; a different key then stops the run before any
  credential is sent.
- `--insecure-skip-verify` accepts a self-signed management certificate; the
  `run` record says it was used.
- `--port` sets the management or SSH port when it is not the default;
  `--management-url` gives collectors that use one their URL; `--site` names
  the UniFi site.
- `--timeout` bounds the whole interrogation (default 5 minutes).

Parts of a device the account may not read are reported as warnings, and the
result is marked partial (exit 2); the rest is still written.

## Inventory this machine

```bash
device-agent host-inventory --out host.json --format json
```

Collects the machine's identity, hardware, interfaces, listening ports,
installed packages and the certificates in its system stores. It contacts
nothing on the network. Run it as an administrator for the fullest result; as
an ordinary user some sections may not complete, and the summary says which.

## Describe a host's cryptography

```bash
device-agent host-crypto --out crypto.jsonl
device-agent host-crypto --remote admin@db1.example.test --identity-file ~/.ssh/id_ed25519 \
    --ssh-host-key SHA256:… --out db1.jsonl
```

Describes the certificates, private keys (what they are and who can read
them, never their contents), keystores, SSH material, TLS and SSH policy,
crypto libraries and platform protection of this machine, or with `--remote`
of one host over SSH. Run it as root (or an elevated Administrator) for the
fullest result; on macOS give the terminal Full Disk Access too.

- `--remote USER@HOST` and `--port`: the host to collect, over SSH. The
  credential comes from `--identity-file` (a private key only you can read;
  its passphrase from `VISTA_DEVICE_KEY_PASSPHRASE`), a `--credentials` file
  (`username`, `password`, `private_key`, `passphrase`) or
  `VISTA_DEVICE_PASSWORD`. `--ssh-host-key` pins the host key; without it the
  key is checked against `known_hosts`, or accepted on first contact, and the
  summary names the pin to use next time.
- `--home-directories` and `--default-keystore-passwords`: the two opt-ins.
- `--exclude PATH` (repeatable): never entered. `--root PATH` (repeatable):
  swept for key material by content (by name and size with `--remote`); no
  sweep without one.
- `--max-duration` bounds the run (default 15 minutes, 1 minute to 1 hour).

A section the account could not read completely is a warning in the summary;
a section that failed, or a bound that cut one short, makes the result partial
(exit 2). What it collects, what it never does and its limits:
[`host-crypto.md`](host-crypto.md).

## The output

Every command takes the same output flags:

- `--out PATH` names the file (default `-`, standard output). A file is
  readable only by you and appears under its name only when the run ends, so a
  file that exists is complete. A path that is not a regular file, such as
  `/dev/null` or a named pipe, is written to directly.
- `--format jsonl|json|csv`:
  - `jsonl` (default): one record per line; on standard output it streams;
  - `json`: one document with `run`, `records` and `summary`;
  - `csv`: one row per host, port and protocol seen, with the TLS and
    certificate columns. Interfaces, neighbours, host inventory and host
    crypto are not in the CSV; use `json` or `jsonl` for those.
- `--quiet` turns off the summary (and a scan's progress lines) on standard
  error.

Every record has the same envelope:

```json
{"schema":"vista.agent-output/v1","kind":"scan_host","agent":"crypto-sensor",
 "agent_version":"…","run_id":"…","observed_at":"…","data":{…}}
```

The kinds are `run` (first), `passive_observation`, `scan_host`,
`device_interrogation`, `host_inventory`, `host_crypto`, `error` and `summary`
(last).
[`standalone-output.md`](standalone-output.md) describes every field, the CSV
columns, what stays stable between releases, and has `jq` recipes. For example,
every TLS endpoint a scan saw, with its versions:

```bash
jq -r 'select(.kind=="scan_host") | .data.tcp[]?
       | select(.result.tls_versions)
       | "\(.addr):\(.port) \(.result.tls_versions | join(","))"' scan.jsonl
```

## Exit status

| Status | Meaning |
|---|---|
| `0` | The run finished and nothing failed. |
| `1` | It could not do its work: a bad flag or target (nothing was contacted and no output written), a capture file that will not open, every host or the device failed. |
| `2` | A partial result: some hosts, sections or collectors failed, packets were dropped, or the run was interrupted. The output is written, and its `error` records and summary say what is missing. |

An empty result means the agent saw nothing of that kind, not that nothing is
wrong. The summary's `scope` says how much was looked at.

## When something goes wrong

| What you see | What to do |
|---|---|
| `outside private address space; nothing was sent` | The target is public. Add `--allow-public` if you own it or are authorised to scan it. |
| An `error` record `… is a reserved address` | Loopback, link-local, multicast and broadcast addresses are never scanned. To scan this machine, use its network address, not `127.0.0.1`. |
| Every port `filtered`, liveness `no_answer` | Nothing answered: the host is down, or a firewall drops the probes. Standalone scans do not use ICMP. |
| `permission denied` or `Operation not permitted` on `capture --interface` | Run as root (`sudo`), give the binary the capture capabilities, or on Windows use an elevated prompt. |
| Windows: `couldn't load wpcap.dll` | Install [Npcap](https://npcap.com/#download) with "API-compatible Mode" checked. |
| A capture of TLS traffic shows nothing | The service is on a port the passive decoder does not treat as TLS; use `scan` against it. |
| `the credentials file … is accessible by group or others` | `chmod 600` the file, as the message says. |
| An `error` record about the SSH host key after `--ssh-host-key` | The device presented a different key from the one you pinned, and no credential was sent. Find out why before you change the pin. |
| `unknown device type` | The message lists the types this binary knows. |
| A capture or scan is slow | Use `--pace normal` or `fast` for a scan on a network that can take it; a capture file is read as fast as it can be decoded. |

To see what the decoders and the scan engine are doing, add `--verbose`
(`crypto-sensor` only).
