# Host crypto inventory

Status: being built on the branch `host-crypto-inventory`. Not released.

## What it is

The device agent learns to find the cryptographic material and configuration
on a host and describe it: certificates, private keys, keystores, SSH
material, configured protocol and cipher policy, cryptographic libraries, and
the platform protection the host relies on. It works on Linux, Windows and
macOS, in three ways:

| Way | What runs | Where the result goes |
|---|---|---|
| Local, managed | the installed agent, on a schedule or on request | to the Vista Platform, as a `host_crypto` job result |
| Remote, managed | the agent reaches another host over SSH with stored credentials | the same |
| Standalone | `device-agent host-crypto` on the command line | a file, as `vista.agent-output/v1` records |

It is off until an operator turns it on. Like the rest of the agents it only
observes: it reports what an item is, never whether that is good or bad.

## The two rules

**Posture, never key material.** A report says what an item is (algorithm,
size, whether it is encrypted, who can read it, what refers to it) and carries
a hash of its public half. It never carries a private key, a passphrase, a
keystore password or a shared secret. In remote mode no byte of a private key
file crosses the connection.

**Honest sections.** Every section reports one of `ok`, `partial`, `failed`,
`unsupported` or `skipped`, and every bound that cut a section short is
listed. An empty list means "none found" only when its section says `ok`.

## The code

Everything is in `shared/hostcrypto`, pure Go, no CGO.

| File | What it holds |
|---|---|
| `report.go` | The record: `Report` and every type in it. **The contract**; change it only with the managing reviewer's agreement. |
| `target.go` | `Target`: how the collector reaches a host, and `Identity`: what a file is from its markers. |
| `target_local.go`, `target_remote_unix.go`, `target_remote_win.go` | The three targets. (`target_remote_win.go`, not `_windows.go`: a `_windows` suffix is a build constraint, and a Linux agent collects Windows hosts.) |
| `redact.go` | The text rules every target applies: what a remote `ReadFile` returns (`publicContent`) and what `ReadText` returns (`FilterConfigText`). The remote targets carry the same rules as an awk program and as PowerShell, held byte for byte to the Go by parity tests that run the real tools. |
| `config_keep.go` | Each configuration parser's keep list: the directive names it reads and its syntax options. |
| `identify.go` | Magic numbers and PEM labels to a `Class`. |
| `parse_*.go` | Parsers. Bytes in, record types out. No I/O, no `runtime.GOOS`. |
| `config_*.go` | One configuration parser per product. Bytes in, `CryptoConfig` out. |
| `collect.go`, `pass_*.go` | The four passes and the bounds. |
| `oslinux.go`, `osdarwin.go`, `oswindows.go` | Where each platform keeps things, and its platform stores and protection. These are tables and command parsers, **not** build-tagged files: a Linux agent must be able to collect a Windows host remotely, so the names carry no `_linux`, `_darwin` or `_windows` suffix (Go reads one as a build constraint). |
| `observations.go` | The report as the managed protocol's observation. |

### Target

`Target` is host inventory's `Runner` (run a command, read a file) plus
`Local`, `Stat`, `List`, `Identify` and `ReadText`.

- The **local** target uses the Go standard library directly: `os`,
  `filepath.WalkDir`, and per-platform permission reads.
- The **remote Unix** target runs fixed `sh -c` scripts over the SSH runner
  (`find`, `stat`, `head`, `tr`, an awk program, `openssl x509`); a path is
  always a positional argument, never script text. The awk program runs
  under mawk, gawk, the BWK awk of macOS and busybox awk, and uses only
  regex literals where it runs per line: busybox compiles a regex held in a
  string again at every use, which once made a 1.2 MB file take 8.7 s of one
  core there (0.3 s under mawk) and, on a busy host, past the runner's
  90-second command bound. A "/" inside a bracket expression is written
  `\057`: busybox keeps the backslash of `\/` there, so the base64 class
  matched a backslash too.
- The **remote Windows** target runs PowerShell over the SSH runner, the
  script on stdin and its arguments as base64 JSON; every absolute path is
  sent in the `\\?\` form, so a name such as `nul.conf`, `COM1.conf` or one
  ending in a dot or a space is the file, not a device or a rewritten name,
  and a path past 260 characters is reachable.

**What crosses a remote connection.** Two calls return content, and each
decides on the host, from ONE read of the file, before anything is printed:

- `ReadFile` returns only **certificates** and **SSH public key lines**. A
  block labelled `CERTIFICATE`, `X509 CERTIFICATE` or `TRUSTED CERTIFICATE`
  is given, alone, to a certificate parser on the host (`openssl x509
  -outform PEM` on Unix; on Windows `X509Certificate2.GetCertContentType`
  must say `Cert` before anything is constructed, then `RawData`), and what
  crosses is the parser's re-encoding of the certificate, never the file's
  bytes. Before any parser sees it, the block must pass a strict DER
  envelope check, the same on every host and again in Go: one SEQUENCE with
  a definite, minimal length equal to the rest of the block, holding exactly
  the TBS SEQUENCE, the algorithm SEQUENCE and the signature BIT STRING, each
  with a minimal definite length, and nothing after them (a TRUSTED
  CERTIFICATE's trust settings are cut off first). .NET hands back its input
  as `RawData` and Go's parser takes the outer element as the certificate,
  so without the envelope check a key appended inside the SEQUENCE would
  cross. A block the check or the parser refuses is dropped and counted:
  the rest of the file still crosses, and the Report notes "N certificates
  in this file could not be read" (`PublicReader.ReadPublic`). Go checks
  what arrives block by block: an answer that is anything but canonical
  `CERTIFICATE` blocks with a strict envelope and parsing key lines is
  refused whole, while a strict-envelope block that `crypto/x509` refuses
  (the EC-ACC root in macOS's `/etc/ssl/cert.pem` has a negative serial
  number, which LibreSSL and .NET accept) is dropped and counted rather
  than sinking the bundle. No pattern over a block's
  bytes can tell a certificate from a private key written under a
  certificate's label; a parser can. Public keys, requests, revocation
  lists and parameters do not cross (no record needs them from a remote
  host); a private key label anywhere refuses the file. A Unix host without
  `openssl` answers `ErrNoHostParser` and nothing crosses, so the section can
  say partial with the reason. A key line crosses as `type blob` only
  (options and comment never), within tight length bounds per key type.
- `ReadText` returns the lines (or, for nginx, the statements) of a
  configuration file whose first word is on the parser's keep list, plus
  strict structure, under per-product syntax options (`@statements`,
  `@backslash`, `@indent`, `@cr`, `@sections`, `@anysections`, `@tags`): see
  `FilterConfigText` and `config_keep.go`. A line holding a lone carriage
  return is dropped whole; a dropped line's continuation is dropped with it;
  a dropped block opener drops its block; a section the parser does not read
  crosses nothing. PEM blocks and runs of 40 base64 characters are removed
  from what is kept.

Both refuse a file whose modification or change time is within 3 seconds of
the host's clock or later than it, and both take the file's identity (device, inode, size,
times) before and after the read and print nothing if it changed: a file
rewritten in place while it is read could otherwise join a kept word of one
version to a secret of the other. Windows also reads the file twice through
one handle and refuses the read when the two differ: it has no change time
that .NET Framework reads, and a writer can set the last-write time back. `Identify` returns only markers (size, the
first eight bytes, PEM labels, rule flags), and a remote `ReadFile` is
refused before any content command is sent unless the identity is a
certificate or SSH key file. Go checks everything that arrives.

**Batching.** A remote target also answers `Stat` and `Identify` for many
paths in one host program (`BatchTarget.StatIdentifyMany`): on Windows one
PowerShell start instead of two per path (each about 0.75 s), on Unix one
shell program that runs, per path, the single `stat` command and the single
identification script unchanged. Each path's answer is exactly the single
calls' answers, parsed by the same Go code, and no more crosses than
`Identify` returns. Batches are bounded (64 paths, 16 KiB of paths, a 40 s
host budget); a path a batch did not answer is asked for singly. Pass 1
prefetches through it on a remote target: at its start, every plain file the
location tables name and every directory it would list, so a directory the
host does not have (most of them, on any one host) costs no listing; then,
per table entry, the files the listing returned. On a Windows 11 test host (the
production SSH runner) pass 1 went from 218 commands and 125-152 s to 26
commands and about 22 s. A target without the interface, or a local one,
makes the single calls.

**Limits, stated.** These cross on purpose or are left alone:

- An SSH certificate line can carry about a kilobyte of free text in its key
  ID and principals (`*-cert-v01@openssh.com`, bounded at 4,096 characters).
- An RFC 4716 (`---- BEGIN SSH2 PUBLIC KEY ----`) file is not read remotely.
- A certificate is a certificate: a deliberately crafted one can carry any
  bytes inside its TBS (an extension), and they cross with it. The guarantee
  is for honest files, for mislabelled files (a key under a certificate's
  label), and for anything the strict envelope rejects.
- An SSH key line is checked on the host by its type, the encoded type
  prefix of its blob, the blob's length bound and the base64 alphabet, not
  by decoding it: a crafted line can carry up to the bound of bytes that are
  not a key. Go refuses such a line after it has crossed.
- On Windows a writer who controls the file and resets its times can still
  race a read: the double read narrows the window to a rewrite that changes
  nothing between two reads microseconds apart, but does not close it.
- A physical configuration line over 256 KiB makes the whole read too large.
- OpenSSL 3 takes the first certificate of a `CERTIFICATE` block that has
  bytes after it; LibreSSL, .NET and Go refuse such a block. What crosses is
  still only that certificate's encoding.
- A kept configuration line's value crosses as written (only 40-character
  runs are redacted): which directives a parser lists is the parser's
  responsibility.
- A path-shaped part of a 40-character run is not redacted, so that file
  paths such as `-Djavax.net.ssl.trustStore=/etc/elasticsearch/certs/truststore`
  cross whole: it starts at a `/` at the start of the run or right after
  `=`, holds at least two `/`, and every segment between slashes is 1 to 39
  characters; what precedes it and what follows its first longer or empty
  segment are judged as runs of their own. The same rule runs in Go, awk and
  PowerShell. A base64 secret on a kept line crosses, whole or in part, when
  its value begins with `/` and has another `/` within the next 39
  characters: for a random 32-byte key (44 characters) that is 1/64 ×
  (1 − (63/64)^39) ≈ 0.7 per cent. Hex never escapes (it has no `/`), and
  neither does a secret whose value does not begin with `/`.

### The four passes

1. **Known locations.** Each platform's table of where certificates, keys,
   keystores, SSH material, configuration and libraries live, plus the
   platform stores (Windows certificate stores and CNG; macOS keychains).
2. **Follow the configuration.** Every configuration file found is parsed; the
   files it names (`ssl_certificate_key`, `javax.net.ssl.keyStore`,
   `HostKey`, `Include`) are visited wherever they are, and become the
   `UsedBy` of what is found there.
3. **Follow the running system.** Listening sockets to processes to the
   libraries they have loaded and the key and keystore files they hold open.
   Needs root or SYSTEM for other users' processes; reports `partial`
   otherwise.
4. **Sweep.** A bounded walk of the configured roots that identifies files by
   content, not by name, so a private key called `backup.txt` is found.

In remote mode passes 1 and 2 run in full, pass 3 as far as the account's
rights allow, and pass 4 by file name and size only, on the roots asked for.

### What local mode can do that remote cannot

| | Local | Remote |
|---|---|---|
| Private key: algorithm, size, public-key hash | parsed in memory | from a command on the host that prints only a public key (`ssh-keygen -y`, `openssl pkey -pubout`); otherwise left empty with a reason |
| Private key: encrypted or not | from the file | from its PEM label and, for OpenSSH and PKCS#8, the same commands |
| Keystore contents | parsed in memory | from `keytool -list` and `openssl pkcs12 -nokeys` where installed; otherwise type and permissions only |
| Windows stores, macOS keychain | the platform's own commands | the same commands over SSH |
| Sweep | by content | by name and size; the section reads `partial` with the limit `remote_by_name` |
| known_hosts | entries counted, hashing told | recorded with its location; entries and hashing nil, `ssh` partial (its lines name other hosts and are not read) |
| authorized_keys | keys with their options | keys only; `restricted` and `certificate_authority` nil, `ssh` partial |

### Bounds

Defaults, all overridable in `Options`: 200,000 files visited per run; files
over 10 MiB are not opened; 2,000 records per section; 15 minutes per run; one
filesystem per root; pseudo-filesystems, network mounts and container layer
stores are never entered. Reads are sequential and the walk yields, so a
collection does not compete with the host's own work.

A run stops at the earlier of `MaxDuration` and the caller's deadline, or when
the caller cancels. Every section a stopped pass had not finished, and every
section of a pass that never started, reads `partial` with a `max_duration`
limit whose detail names the bound that applied; none reads `ok` with a list
it did not finish, and none reads `failed` because it was cut. A file is
charged to the file budget once, so the sweep visits what it listed.

### Coverage: when an absent item is gone

A section's state is too coarse to retire an item. An unprivileged agent (how
the Linux and macOS installers run it) always reports `certificates`,
`private_keys`, `ssh` and `processes` partial, because `/etc/ssl/private` is
unreadable and other users' processes are invisible; with a section rule a
deleted key file would never be retired and its finding never close. So the
Report also says, directory by directory, what it saw completely:

```json
"coverage": {
  "directories": ["/etc/ssh", "/srv/tls"],
  "skipped_files": [{"path": "/etc/ssh/ssh_host_ed25519_key", "reason": "permission denied"}]
}
```

A directory is in `coverage.directories` if and only if the collector listed
its direct entries completely (no permission error, no bound, no deadline; not
excluded; not a home directory without the opt-in; not a top-level directory
such as `/etc` or `C:\ProgramData`), and every regular file directly in it was
identified and, when it is something the Report records, is in the Report, or
is in `coverage.skipped_files` with the reason it was not read (over the read
bound, permission denied). Subdirectories are covered separately or not at
all; symbolic links are not followed (an item a link names lives in its
target's directory).

A platform may then retire an active file-based item (its `location.path`, or
`location.container` for a keystore entry, directly in a covered directory)
that is absent from the Report and not in `skipped_files`, whatever the
section says. Store-based items (Windows certificate stores, macOS keychains)
are not covered; their sections decide. A false "covered" retires an item that
still exists, so the collector leaves a directory uncovered whenever it is not
certain: it lists the directory again on its own, without name filters or size
bounds; a file read only in part (a keystore whose entries were not listed, a
remote file whose certificates are not read, a bundle with unreadable blocks),
a remote binary its markers cannot place, an excluded file, a listing error,
or any deadline or budget cut leaves it uncovered; and when any section
dropped records at its bound, no directory is covered (limit
`coverage`/`max_records`). At most 5,000 directories are covered per run
(limit `coverage`/`max_directories`).

Which directories are tried:

| Source | Directories | Bound |
|---|---|---|
| Pass 1 | each table row's directory and the directories its files were listed in, except configuration and NSS rows | 4,096 entries |
| Pass 2, pass 3 | the directory of each file a configuration names or a process holds or names; files first found there say `found_by: "neighbour"` | 512 entries |
| Sweep (local only) | every directory the sweep walked, with the sweep's content identities | 4,096 entries |

Remote, a directory is covered only where identification is equivalent:
`Identify` on every file through the batch call, every certificate file read
through the host's parser, every key recorded from its markers. A remote sweep
(by name) covers nothing, and a remote directory with a keystore, a file
holding a key and certificates, or an unknown binary is not covered.

### Opt-ins

Off unless the operator says otherwise:

- **Home directories**: per-user SSH keys, GnuPG homes, NSS databases,
  per-user keychains and stores.
- **Default keystore passwords**: trying the empty password, as a step of its
  own, and the well-known defaults (`changeit`, `changeme`, `password`)
  against JKS, JCEKS and PKCS#12 files. Locally the empty password is tried
  first, then the defaults; a PKCS#12 part the first password that passes
  does not open is tried with each of the others. Remotely the probe sends
  the defaults first and tries the empty password last. A store the empty
  password opens is one that needs no password: `opened: no_password`,
  `default_password: false`, contents listed. A well-known default that
  opens the store or any part of it gives `default_password: true`, and which
  one is never recorded (it would be the store's password); the empty
  password is kept apart because a store without a password is a fact to
  record, not a guessed password. A part that nothing opens keeps
  `entry_count` absent and says why in `unknown`. Locally, without the
  opt-in no password is tried. Remotely the empty password is tried either
  way (the probe lists with it), as before; the defaults only with the
  opt-in.

## Rules for anyone adding to it

1. A parser takes bytes and returns record types. It does not open files, run
   commands or read `runtime.GOOS`.
2. Every parser that touches private material has a **projection test**: feed
   it a real key, marshal the result to JSON, and fail if any run of the
   key's private bytes (raw, hex or base64) appears.
3. Test keys are **generated in the test**. No private key, however fake, is
   committed: the secret scanner cannot tell, and neither can a reader.
4. A configuration parser keeps directives on its allowlist and nothing else,
   with a test that an unlisted directive (a password, a pre-shared key) is
   dropped.
5. A section that could not be read says so. Never return an empty list for a
   failure.
6. Every guard is tested in both directions: break the rule and see the test
   fail, restore it and see it pass.
7. All of this code is written here. Other projects (osquery, cbomkit-theia)
   may be read to learn where a platform keeps something; no source is
   copied.
