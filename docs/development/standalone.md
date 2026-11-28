# Standalone mode: how it is built

For people changing the agents. What standalone mode is and the rules it keeps:
[`../design/standalone-mode.md`](../design/standalone-mode.md). How to use it:
[`../standalone.md`](../standalone.md). The output format:
[`../standalone-output.md`](../standalone-output.md).

Standalone mode adds four subcommands to the two existing binaries. It reuses
the decoders, the scan engine and the collectors that managed mode runs, and
adds only the command-line front ends and one output writer. When you change
shared code, a standalone command changes with it; this page says what holds
the line.

## Where the code is

| Path | What it does |
|---|---|
| `shared/agentoutput/` | The only writer of standalone results, for both agents: the envelope, the three formats, the temporary file renamed into place at mode 0600, the CSV endpoint rows and their de-duplication, the summary on standard error, the exit status (`ExitCode`), and the removal of verdicts (`verdicts.go`). CGO-free, opens no network connection. |
| `schemas/output/v1/record.schema.json` | The JSON Schema of the envelope and of the `run`, `error` and `summary` records. |
| `internal/testsupport/outputschema/` | Test helpers that validate output against that schema. |
| `cmd/sensor/standalone.go` | `crypto-sensor` dispatch (`standaloneCommand`, `runStandaloneMain`), the shared flags, help text. |
| `cmd/sensor/standalone_capture.go` | `crypto-sensor capture`: a file through `capture.NewFileCapture` and `RunFile`, or live through `capture.NewPacketCapture`, `Start` and `Stop`; the CSV view of an observation (`endpointsOf`). |
| `cmd/sensor/standalone_scan.go` | `crypto-sensor scan`: target parsing, the one resolution of host names, the private and public address rules, the depth and pace presets, the run on `planrun.Run`, the CSV view of a host (`scanEndpoints`). |
| `internal/sensor/capture/packet_capture_file.go` | Reading a capture file: blocking instead of dropping, flushing idle TCP flows in packet time. |
| `shared/sensordispatch/planrun/guard.go` | `NamedTargetsRule` (the allow rule built from the operator's targets) and `refuseReserved`, which the managed rule uses too. |
| `cmd/device-agent/standalone.go` | `device-agent` dispatch (`runStandalone`), `collect` and `host-inventory`, credentials from a file or the environment, secret scrubbing of every message, the SSH host-key pin, the CSV view of a result. |
| `cmd/device-agent/standalone_perm_{unix,windows}.go` | The credentials-file permission check (Linux and macOS refuse a file group or others can read). |
| `internal/deviceagent/devices/standalone.go` | `InterrogateBounded` and `CredentialsFromMap`: the managed job's own steps, exported so `collect` does not keep a copy that could drift. |

## How a run goes

Both `main` functions check for a standalone subcommand **first**, before they
read a configuration file, set up logging or touch the network. With no
subcommand the binary is the managed agent, unchanged
(`TestRunStandalone_LeavesManagedInvocationsAlone`, `TestStandaloneCommandDispatch`).

Every command then:

1. parses its flags; a usage error prints one line and exits 1 **before any
   output is written and before anything is contacted**;
2. opens an `agentoutput.Writer`, which writes the `run` record;
3. does its work, writing each observation with `Write` and each failure with
   `Error`, and adding `Warn` lines for what the summary should mention;
4. calls `Close(partial, scope)`, which writes the `summary`, renames the file
   into place and prints the human summary;
5. exits with `agentoutput.ExitCode`: 0 complete, 1 nothing worked or the
   output could not be written, 2 partial.

### capture

`NewFileCapture` gives the capture a 65,536-deep discoveries channel; `RunFile`
reads packets on the calling goroutine and waits for headroom instead of
dropping, so a file is decoded completely however fast the disk is. Every 1,024
packets it flushes TCP flows idle for 30 seconds of **packet** time, so a long
file does not hold every flow in memory. Live capture uses the managed path
with the TLS enricher, the prober and the API client left out, so it sends no
packets.

`Stop` is ordered so that nothing writes to the discoveries channel after it
closes: capture goroutines, then the worker pool, then the periodic flush,
then a final flush of every assembler, then the host-observation pipeline on
its own stop signal, and only then the channels. The comment on `Stop` lists
the steps; `TestStopDrainsTheWorkerQueueBeforeClosingDiscoveries` fails with
`send on closed channel` if the worker wait is removed. Keep that order when
you add a decoder that emits from its own goroutine.

### scan

The operator's targets are the scope, and the code is arranged so nothing can
widen it:

- Host names resolve once, at the start; the scan is pinned to those addresses
  (`run.resolved`) and the name is offered as SNI only.
- `planrun.NamedTargetsRule` builds the allow rule from the targets
  themselves. Every dial the engine makes, liveness included, and every
  certificate-driven fetch (OCSP, through `Config.OutboundGuard`) passes it.
- Reserved addresses (unspecified, loopback, link-local, multicast, broadcast)
  are refused by `refuseReserved`, the same function the managed rule uses, so
  the two cannot disagree.
- A target outside private address space is a usage error unless
  `--allow-public` is given; with it, depth is capped at `standard` and the
  run record says so.
- `discovery.CheckTargetSizes` refuses an oversized target or run before any
  packet.
- OT probes are not offered.

### collect

`collect` looks the device type up in the same registry a managed job uses
(`Registry.Get`, which wraps every collector in the redaction backstop), runs
it through `devices.InterrogateBounded` with the `--timeout`, and writes the
result. Credentials come only from `--credentials FILE` or the
`VISTA_DEVICE_*` variables: there is no flag for a secret. Every message that
reaches the output or the terminal goes through `redact.Text` and then through
a replacement of the literal credential values, so a collector that echoes a
password in an error cannot leak it (`TestStandaloneCollect_SecretsNeverLeak`).
`--ssh-host-key` pins the key before any credential is sent.

### host-inventory

Runs the managed agent's one-shot host inventory and writes its report and
observations as one record.

## The rules, and the tests that hold them

| Rule | Held by |
|---|---|
| No standalone command contacts a platform, reads the managed configuration or enrolls | dispatch before configuration in both `main` functions; the dispatch tests above |
| A usage error writes nothing and contacts nothing | `TestStandaloneCollect_UsageErrorsContactNothing`, `TestStandaloneScanRefusesBadTargetsBeforeAnything`, `TestStandaloneCaptureRefusesBadFlags` |
| A scan touches only the named targets | `TestNamedTargetsRule`, `TestStandaloneScanRangeStaysInside`, `TestStandaloneScanResolvesOnceAndPins`, `TestRun_OutboundGuardJudgesTheOCSPResponder` |
| Reserved addresses are refused, even when named | `TestStandaloneScanRefusesReservedEvenWhenNamed`, `TestReservedRefusalsAreShared` |
| Public addresses need `--allow-public` | `TestStandaloneScanPublicNeedsTheFlag`, `TestTargetIsPublic` |
| No secret reaches the output, the terminal or the process list | `TestStandaloneCollect_SecretsNeverLeak`, `TestScrubSecrets_ReplacesLiteralValues`, `TestStandaloneCollect_CredentialsFileMode` |
| No verdict reaches the output | `TestWriteRemovesVerdictsAndKeepsFacts` (`shared/agentoutput/verdicts_test.go`) |
| Every record matches the schema | `shared/agentoutput/schema_test.go`, and the end-to-end tests of `capture`, `collect` and `host-inventory` validate their output against it |
| The output file is complete or absent, and private | `TestFileAppearsOnlyOnCloseWithRestrictedMode` |
| Capture stops without losing or crashing on queued packets | `TestStopDrainsTheWorkerQueueBeforeClosingDiscoveries` |
| A capture file is decoded without drops | `TestRunFileDropsNothing` |

When you add to standalone mode, add the test in the same pull request, and
check it fails when you break the thing it guards.

## Changing things

**A decoder or collector gains a field.** It appears in standalone output
automatically, under `data`. Add observations only: carry the exact protocol,
algorithm, key size or mechanism and let Platform policy judge it. Do not add a
compliance result, a weak/strong label or a score. `VerdictKeys` in
`shared/agentoutput/verdicts.go` is a defensive transition guard for retired
fields, not a route for new judgments. If a field could carry a secret, it
must not exist at all: see the projection and redaction rules in the device
interrogation code.

**A new device type.** Registering it in the collector registry makes it a
`collect --type` value; `--help` lists the registry, so nothing else changes.
Add it to the list in `standalone.md` if the guide names it.

**A new kind of record.** Add the `Kind` constant in `agentoutput`, add it to
the schema's `kind` enum, document its `data` in `standalone-output.md`, and
decide whether it has CSV endpoints. A new kind is additive within `v1`.

**A new command.** Dispatch it in the binary's standalone check, give it the
shared output flags, write only through `agentoutput`, make every refusal a
usage error before `Open`, and add its section to the design, the guide and
this page.

**A breaking change to the envelope, a kind's meaning or the CSV columns.**
That is `v2`: a new schema directory, a new `Schema` constant, and a note in
the release. Prefer an additive change.

## Building and checking

```bash
export GOWORK=off GOTOOLCHAIN=go1.26.11
go test -race ./shared/agentoutput/... ./cmd/... ./internal/sensor/capture/... ./shared/sensordispatch/planrun/...
golangci-lint run ./...
GOFLAGS=-mod=readonly go mod tidy -diff   # a new import in a test needs its go.sum lines
```

The sensor needs `libpcap-dev`; the device agent must stay CGO-free
(`make cgo-free`). To try a change by hand, build into a scratch directory and
run the command against something you own; `scan` of a public address is
refused without `--allow-public`, which is the right default for testing too.
