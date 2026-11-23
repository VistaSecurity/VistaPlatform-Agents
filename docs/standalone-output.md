# Standalone output reference

What the standalone commands write, record by record, for people writing
scripts against it. How to run the commands: [`standalone.md`](standalone.md).
Why it is shaped this way: [`design/standalone-mode.md`](design/standalone-mode.md).

The examples below use documentation addresses (`192.0.2.0/24`,
`198.51.100.0/24`) and shortened values; real records carry more fields.

## The envelope

Every record, in every format, has the same envelope:

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `vista.agent-output/v1` for this version of the format. |
| `kind` | string | What `data` is: one of the kinds below. |
| `agent` | string | `crypto-sensor` or `device-agent`. |
| `agent_version` | string | The binary's version (`crypto-sensor -version`). |
| `run_id` | string | A UUID shared by every record of one run. |
| `observed_at` | string | RFC 3339 time, UTC, when the record was written. |
| `data` | object | The record's content, described per kind below. |

The envelope is held by the JSON Schema
[`schemas/output/v1/record.schema.json`](../schemas/output/v1/record.schema.json);
the repository's tests validate every kind against it.

```json
{"schema":"vista.agent-output/v1","kind":"scan_host","agent":"crypto-sensor",
 "agent_version":"6.1.0","run_id":"5f0c…","observed_at":"2026-11-23T14:51:23Z",
 "data":{"target":"192.0.2.10","address":"192.0.2.10","host":{…},"tcp":[…]}}
```

## Order and formats

A run writes one `run` record first and one `summary` record last. In between
come the observations and any `error` records, in the order they happened.

| `--format` | What you get |
|---|---|
| `jsonl` (default) | One record per line. On standard output it streams, so you can read it while the run goes on. |
| `json` | One document: `{"run": {…}, "records": [ … ], "summary": {…}}`. `records` is `[]` when nothing was seen. |
| `csv` | One row per endpoint (below). No envelope, no `run` or `summary` row; the summary still goes to standard error. |

With `--out FILE` the file is created readable only by you (mode 0600 on Linux
and macOS) and appears under its name only when the run ends, so a file that
exists is complete. A run interrupted with Ctrl-C still writes what it saw.

## Kinds

### `run`

What was asked for. Always first.

| Field | Meaning |
|---|---|
| `command` | `capture`, `scan`, `collect` or `host-inventory`. |
| `flags` | The flags given on the command line, by name, as text. Never a secret: no flag takes one. |
| `targets` | What the run was pointed at: the file or interface, the scan targets, the device. |
| `resolved` | `scan` only: each host name and the addresses it resolved to at the start. Only those addresses were scanned. |
| `hostname` | The machine the agent ran on. |
| `started_at` | When the run started. |
| `notes` | Facts about how the run was set up, when there are any: that TLS verification was turned off with `--insecure-skip-verify`, or that a public target was scanned at a lower depth than asked for. |

### `passive_observation` (`crypto-sensor capture`)

One thing the passive decoders saw. `data` is the managed sensor's discovery
record.

| Field | Meaning |
|---|---|
| `protocol` | `TLS`, `SSH`, `QUIC`, `IKE`, `WireGuard`, `OpenVPN`, `SMB`, `Kerberos`, an OT protocol (`Modbus`, `DNP3`, `MMS`, `OPC_UA`, `ENIP`, `HART_IP`, …), or `HOST` for a host observation. |
| `source_ip`, `dest_ip`, `port` | The flow. `port` is the server's port. |
| `version` | The protocol version negotiated (`TLS 1.3`, `SSH-2.0`, …), or empty when the decoder did not see it. |
| `cipher_suite` | The suite the server chose, when seen. |
| `key_size` | A key size in bits when the decoder saw one; `0` means not seen, not zero bits. |
| `discovery_method` | `passive` for a crypto observation, `passive_host_observation` for a host. |
| `discovery_type` | `host_observation` on host records, absent on crypto records. |
| `session_id` | Set when the observation came from a reassembled TCP session. |
| `timestamp`, `created_at` | When the packet was seen and when the record was made. For a capture file, `timestamp` is the packet's own time. |
| `raw_metadata` | What the decoder extracted, by protocol (below). |
| `id`, `sensor_id`, `confidence` | Identifiers and the decoder's confidence that it parsed the protocol, carried from the managed record. |

Common `raw_metadata` keys for TLS: `sni`, `sni_server_name`, `alpn_protocols`,
`supported_ciphers` (what the client offered), `client_max_offered_version`,
`handshake_types`, `key_exchange_algorithm`, `key_exchange_group_raw`,
`key_exchange_key_size`, `ja3_hash`, `ja4_fingerprint`, and `certificates`
when the server's certificate crossed the wire in clear text (TLS 1.2 and
earlier; TLS 1.3 encrypts it). SSH adds the algorithms each side offered and
chose. A host observation carries its payload under
`raw_metadata.host_observation` (addresses, MAC, names, and the LLDP/CDP
neighbour fields).

### `scan_host` (`crypto-sensor scan`)

One address's scan result. A host name target produces one record per address
it resolved to.

| Field | Meaning |
|---|---|
| `target` | The target as you gave it (address, range or name). |
| `address` | The address scanned. |
| `host.liveness` | `up` (something answered), `no_answer` (every probe timed out: not the same as down, since a firewall that drops everything looks the same), or `assumed_up`. |
| `host.liveness_evidence` | What decided it, such as `tcp-open:443` or `assumed`. |
| `host.ports_requested`, `open`, `open_count`, `closed`, `filtered`, `not_probed`, `local_errors` | The port counts. `open` lists the open ports. |
| `tcp`, `udp` | One entry per port that answered (below). |
| `deadline_hit` | `true` when this host's time budget ran out before its scan finished. |
| `error` | A note when set, such as the budget that was hit. |

Each `tcp` / `udp` entry:

| Field | Meaning |
|---|---|
| `addr`, `port`, `transport` | The endpoint. |
| `state` | `open`, `closed`, `filtered`, or for UDP `open_or_filtered`. |
| `protocol` | What answered (`TLS`, `SSH`, `SMB`, …), empty when it could not be named. |
| `service_hint` | A label from a banner (`ssh`, `smtp`, `mysql`, …), set even when no protocol prober ran. |
| `identified` | `true` only when a prober positively identified the service. |
| `result` | The prober's output, by protocol (below). |

TLS `result`: `tls_versions` (the version the server negotiated first, then
the other versions it accepted, newest first),
`selected_cipher`, `alpn`, `certificates` (the chain the server sent, leaf
first; each with `subject_dn`, `issuer_dn`, `not_before`, `not_after`,
`key_algorithm`, `key_size`, `signature_alg`, `fingerprint_sha256`,
`subject_alternative_names`, `serial_number`, `certificate_pem`,
`chain_order`), `cert_validation_status` and `cert_validation_error` (whether
the chain verified against this machine's trust store, and why not), and
`metadata`, which includes `tls_supports_pqc_hybrid_kex` and
`tls_pqc_hybrid_kex_group` when the server accepted a hybrid post-quantum key
exchange such as `X25519MLKEM768`.

SSH `result`: `ssh_banner`, `ssh_software_version`, `ssh_kex_algorithm`,
`ssh_host_key_algorithm`, `ssh_host_key_fingerprint`, the chosen ciphers and
MACs in each direction, and every algorithm the server offered
(`ssh_server_kex_algorithms`, `ssh_server_host_key_algorithms`, …).

```json
{"kind":"scan_host","data":{"target":"192.0.2.10","address":"192.0.2.10",
 "host":{"liveness":"up","liveness_evidence":"tcp-open:22","ports_requested":41,
         "open":[22,443],"open_count":2,"closed":39,"filtered":0},
 "tcp":[{"addr":"192.0.2.10","port":443,"transport":"tcp","state":"open",
         "protocol":"TLS","identified":true,
         "result":{"tls_versions":["TLS 1.2","TLS 1.3"],
                   "selected_cipher":"TLS_AES_128_GCM_SHA256",
                   "metadata":{"tls_supports_pqc_hybrid_kex":true,
                               "tls_pqc_hybrid_kex_group":"X25519MLKEM768"},
                   "certificates":[{"subject_dn":"CN=app.example.internal",
                                    "key_algorithm":"ECDSA","key_size":256,
                                    "not_after":"2027-02-01T00:00:00Z"}]}}]}}
```

### `device_interrogation` (`device-agent collect`)

The collector's result for the one device. Fields are absent when the
collector measured nothing for them.

| Field | Meaning |
|---|---|
| `assets` | The cryptographic endpoints the device runs: each with `hostname`, `ip_address`, `port`, `protocol`, `asset_type`, and as measured `protocol_version`, `tls_versions`, `cipher_suite`, `supported_ciphers`, `key_exchange_algorithm`, `hash_algorithm`, `key_size`, `certificates` (as above), `ssh_info`, `metadata`. |
| `device_info` | What the device says about itself: vendor, model, software version, serial, as the collector reads them. |
| `device_identity` | The same identity in a fixed shape, when the collector builds one. |
| `network` | The device's interfaces, addresses, VLANs and ARP cache. |
| `facts` | Measured operational facts: neighbours, uptime, hardware identity. Each names its key and value. |
| `relationships` | Edges the device reported: an LLDP or CDP neighbour, an uplink, an adoption. |
| `warnings` | Parts of the collection that did not work (an endpoint the account may not read, a command this version lacks). The rest of the result is still there. |

It never carries keys, pre-shared keys, passwords or command transcripts: the
collectors project each vendor response onto the fields above, and the
registry's redaction runs over the result. With no `--ssh-host-key`, the host
key fingerprint the agent accepted is in the summary's `warnings`, so the next
run can pin it.

### `host_inventory` (`device-agent host-inventory`)

| Field | Meaning |
|---|---|
| `report` | The machine's inventory, by section: `host`, `platform`, `hardware`, `interfaces`, `listeners` (listening TCP ports and their processes), `bound_udp_sockets`, `packages`, `cert_stores` (certificates in the system stores), and `sections`, which says which sections completed. |
| `observations` | The same inventory as the observation records the managed agent would report. |

### `error`

Something that did not work. The run goes on where it can.

| Field | Meaning |
|---|---|
| `target` | What failed: an address, a device, a file, or empty for the run as a whole. |
| `stage` | Where it failed: `resolve`, `scan`, `capture`, `interrogate`, `host_inventory`. |
| `reason` | Why, in words. Secrets are scrubbed from it. |

### `summary`

Always last.

| Field | Meaning |
|---|---|
| `records` | How many records of each kind were written. |
| `endpoints` | How many distinct endpoints the CSV has (or would have). |
| `errors` | How many `error` records were written. |
| `warnings` | The warnings, as text, when there are any: packets dropped, an interrupted run, a collector section that did not complete, the SSH host key accepted without a pin. |
| `partial` | `true` when some part failed; the exit status is then 2. |
| `scope` | How much was looked at, in words: "3 addresses in 1 target, depth standard, pace polite", or the packet count of a capture. |
| `duration_seconds`, `finished_at` | How long the run took and when it ended. |

## The CSV

One row per distinct endpoint (host, port, protocol, and what was observed on
it). A scan adds a row for each port that was open or identified. A passive capture sees the same handshake many times; the CSV lists it
once. A cell is empty when that value was not observed; it is never `0` for
"unknown".

| Column | From |
|---|---|
| `kind` | `passive_observation`, `scan_host` or `device_interrogation`. |
| `host` | A host name when there is one: the SNI for passive TLS, the target for a scan given a host name, the device's host name for `collect`. |
| `address`, `port`, `transport`, `protocol` | The endpoint. |
| `protocol_version`, `cipher_suite`, `key_exchange` | What was negotiated. For a scan that is the TLS version the server negotiated (the first of `tls_versions`), or for SSH the protocol version, key exchange and server-to-client cipher. |
| `certificate_subject`, `certificate_issuer`, `certificate_not_after` | The leaf certificate. |
| `certificate_key_algorithm`, `certificate_key_size`, `certificate_signature_algorithm`, `certificate_fingerprint_sha256` | The leaf certificate's key and signature. |
| `source` | Where the row came from: `passive`, `scan`, or the device type. |

Interfaces, neighbours and host inventory have no endpoint and are not in the
CSV; use `json` or `jsonl` for them.

## No verdicts

Standalone output holds observations only. The decoders and collectors are
shared with managed mode, where a few of them label what they saw for the
platform: a compliance result against IEC 62351, a "weak" signature or key, a
risk score. Standalone output removes those labels from every record (the keys
`iec62351_*`, `cert_weak_signature`, `cert_weak_public_key`, `risk_score`,
`risk_level`, `risk_factors`, `highest_risk` and `compliance_status`; an OT
`security` value of `weak` is written as `present`). The facts they were
derived from stay: the version, the suite, the signature algorithm, the key
size, the OPC UA policy, the DNP3 MAC. Deciding what is weak is yours.

What does stay are checks that are measurements, not opinions:
`cert_validation_status` (did the chain verify against this machine's trust
store) and `tls_supports_pqc_hybrid_kex` (did the server accept a hybrid
post-quantum group).

## Stability

Within `vista.agent-output/v1`:

- the envelope fields, the kinds and the CSV columns keep their names and
  meaning;
- new fields, new kinds and new CSV columns may be added at the end; a script
  should ignore what it does not know;
- the fields inside `data` follow the agents' own records and may gain fields
  between releases.

A change that breaks any of that changes the schema version.

## Recipes

These read JSON Lines, the default format.

Every TLS endpoint a scan saw, with the versions it accepts:

```bash
jq -r 'select(.kind=="scan_host") | .data.tcp[]?
       | select(.result.tls_versions)
       | "\(.addr):\(.port) \(.result.tls_versions | join(","))"' scan.jsonl
```

Endpoints still accepting TLS 1.0 or 1.1:

```bash
jq -r 'select(.kind=="scan_host") | .data.tcp[]?
       | select(any(.result.tls_versions[]?; . == "TLS 1.0" or . == "TLS 1.1"))
       | "\(.addr):\(.port)"' scan.jsonl
```

Certificates that expire in the next 30 days, from any kind:

```bash
jq -r --arg by "$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)" '
  .. | objects | select(has("not_after") and has("subject_dn"))
     | select(.not_after < $by) | "\(.not_after)  \(.subject_dn)"' scan.jsonl | sort -u
```

(On macOS, `date -u -v+30d +%Y-%m-%dT%H:%M:%SZ`.)

Servers that accepted a hybrid post-quantum key exchange:

```bash
jq -r 'select(.kind=="scan_host") | .data.tcp[]?
       | select(.result.metadata.tls_supports_pqc_hybrid_kex == true)
       | "\(.addr):\(.port) \(.result.metadata.tls_pqc_hybrid_kex_group)"' scan.jsonl
```

TLS server names seen on the wire, with the versions negotiated:

```bash
jq -r 'select(.kind=="passive_observation" and .data.protocol=="TLS")
       | "\(.data.raw_metadata.sni_server_name // "-") \(.data.dest_ip):\(.data.port) \(.data.version)"' \
   traffic.jsonl | sort -u
```

Did the run finish cleanly?

```bash
jq -e 'select(.kind=="summary") | .data.partial == false and .data.errors == 0' scan.jsonl
```
