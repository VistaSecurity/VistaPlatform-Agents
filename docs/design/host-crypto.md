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
  always a positional argument, never script text.
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
  cross. A block the check or the parser refuses is dropped. No pattern over a block's
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
| Sweep | by content | by name and size |

### Bounds

Defaults, all overridable in `Options`: 200,000 files visited per run; files
over 10 MiB are not opened; 2,000 records per section; 15 minutes per run; one
filesystem per root; pseudo-filesystems, network mounts and container layer
stores are never entered. Reads are sequential and the walk yields, so a
collection does not compete with the host's own work.

### Opt-ins

Off unless the operator says otherwise:

- **Home directories**: per-user SSH keys, GnuPG homes, NSS databases,
  per-user keychains and stores.
- **Default keystore passwords**: trying the well-known defaults (`changeit`,
  `changeme`, `password`, empty) against JKS, JCEKS and PKCS#12 files. Only
  the fact that one worked is recorded.

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
