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
| `target_local.go`, `target_remote_unix.go`, `target_remote_windows.go` | The three targets. |
| `identify.go` | Magic numbers and PEM labels to a `Class`. |
| `parse_*.go` | Parsers. Bytes in, record types out. No I/O, no `runtime.GOOS`. |
| `config_*.go` | One configuration parser per product. Bytes in, `CryptoConfig` out. |
| `collect.go`, `pass_*.go` | The four passes and the bounds. |
| `os_linux.go`, `os_darwin.go`, `os_windows.go` | Where each platform keeps things, and its platform stores and protection. These are tables and command parsers, **not** build-tagged files: a Linux agent must be able to collect a Windows host remotely. |
| `observations.go` | The report as the managed protocol's observation. |

### Target

`Target` is host inventory's `Runner` (run a command, read a file) plus
`Local`, `Stat`, `List` and `Identify`.

- The **local** target uses the Go standard library directly: `os`,
  `filepath.WalkDir`, and per-platform permission reads.
- The **remote Unix** target runs `find`, `stat`, `head -c 8 | od` and
  `grep -a -o` for PEM labels over the SSH runner.
- The **remote Windows** target runs PowerShell over the SSH runner, as host
  inventory does.

A remote target's `ReadFile` first identifies the path and returns
`ErrNotPublic` unless `Identity.Public()`. That refusal is the single place
the "no private key byte crosses the connection" rule is enforced, and a test
drives every collector against a recording fake target and fails if a
non-public path was read.

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
