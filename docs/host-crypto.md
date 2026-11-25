# Host crypto inventory

The device agent can describe the cryptography on a host: the certificates,
private keys, keystores and SSH material on it, the TLS and SSH policy its
configuration sets, the crypto libraries it has, and the protection the
platform gives it (disk encryption, TPM or Secure Enclave, Secure Boot, FIPS
mode, PKCS#11 tokens). It reports what each item **is** and who can read it.
It never reports key material, and it never says whether something is good or
bad.

It is off until you turn it on.

## Three ways to run it

| Way | How | Where the result goes |
|---|---|---|
| On this host, on a schedule | Turn on **Host crypto inventory** for the agent in your Vista Platform console (setting `host_crypto_enabled`) | To the platform, once a day by default |
| On this host or another, now | Ask for a collection from the console (a `host_crypto` job); another host is reached over SSH with credentials you stored | To the platform, as the job's result |
| On your own, no platform | `device-agent host-crypto` (see [`standalone.md`](standalone.md)) | A file you name |

```bash
# This machine
device-agent host-crypto --out crypto.jsonl

# Another host, over SSH, with your key; pin its host key after the first run
device-agent host-crypto --remote admin@db1.example.test --identity-file ~/.ssh/id_ed25519 --out db1.jsonl
```

## What it never collects

Posture, never key material. A report says a key's algorithm, size, format,
whether it is encrypted, who can read its file and what configuration or
process uses it, plus a SHA-256 of its **public** half (which is how a key is
paired with its certificate). It never holds:

- a private key, in any encoding;
- a passphrase, a keystore password or a pre-shared key;
- the contents of a Kerberos keytab entry;
- a configuration file's text. Each product's configuration is reduced to a
  short list of named directives (protocols, ciphers, groups, the paths of the
  certificates and keys it uses); anything not on that list, a password line
  included, is dropped before it is read.

Certificates are public and are included in full, except the members of trust
stores, which are listed by fingerprint.

The device agent checks the exact bytes it is about to send, and refuses to
send a report that contains anything shaped like a private key. Every parser
is tested against keys generated at test time: no run of a key's private
bytes, raw, hex or base64, may appear in what it returns.

## What it looks at

1. **Known locations**: where each system keeps certificates, keys, keystores
   (Java, PKCS#12, NSS, GnuPG, keytabs, macOS keychains), SSH material,
   configuration and libraries; the Windows certificate stores and CNG keys;
   the macOS keychains.
2. **The configuration**: OpenSSL, Java, OpenSSH, nginx, Apache, HAProxy,
   crypto-policies, GnuTLS, Kerberos, SChannel and others. Each file a
   configuration names (`ssl_certificate_key`, `HostKey`,
   `javax.net.ssl.keyStore`) is visited wherever it is, and recorded as used
   by that configuration.
3. **The running system**: which process listens on which port, which crypto
   libraries it has loaded and which key or keystore files it holds open.
4. **A sweep**, only when you name roots (`--root`, or `sweep_roots` in a
   job): files under them are identified by their content, so a key saved as
   `backup.txt` is found.

Every part of a report says whether it was read completely (`ok`), in part
(`partial`), not at all (`failed`), cannot be on this system (`unsupported`)
or was not asked for (`skipped`). An empty list means "none found" only when
its section says `ok`. Every bound that cut a section short is listed under
`limits`.

## Rights it needs

| System | For a complete report | Without it |
|---|---|---|
| Linux | root | Other users' processes, and key files only root may read (`/etc/ssl/private`, SSH host keys), are reported as partial: the files are listed with their owner and mode, not described. |
| Windows | an elevated Administrator (or SYSTEM, which the service runs as) | The machine's CNG keys and other users' processes are partial. |
| macOS | root, and **Full Disk Access** for the agent (System Settings → Privacy & Security → Full Disk Access) | Keychains and protected folders are partial; the report's `access.full_disk_access` says which it was. |

On Windows the installed service runs as SYSTEM and sees everything. On Linux
and macOS the installed agent runs as its own unprivileged account
(`vista-device-agent`, `_vistadeviceagent`), not as root, so its scheduled
collection reports root-only material as partial: which files exist, their
owner and mode, but not what they hold. A collection of the agent's own host
with full rights is a standalone run as root (`sudo device-agent host-crypto`),
or a remote collection with an account that has them. A standalone run has the
rights of whoever starts it.

## The two opt-ins

Both are off unless you turn them on, in the console (each asks you to
confirm) or with a flag.

- **Home directories** (`host_crypto_home_directories`,
  `--home-directories`): also describe each user's own SSH keys, GnuPG homes,
  browser key databases (NSS), keychains and certificate stores. Off, the
  report's `home_directories` section says `skipped`.
- **Default keystore passwords** (`host_crypto_default_keystore_passwords`,
  `--default-keystore-passwords`): try the well-known defaults (`changeit`,
  `changeme`, `password`, empty) against Java and PKCS#12 keystores. Only
  whether one worked is recorded; the password and the contents are not.

## Paths it never enters

`host_crypto_exclude_paths` (one absolute path per line, at most 64) lists
paths the scheduled collection never reads or walks into; a collection you ask
for carries its own list (`exclude_paths`, or `--exclude`). Whatever you set,
pseudo-filesystems (`/proc`, `/sys`), network mounts and container image
stores are never entered.

## Bounds

A collection visits at most 200,000 files, opens no file over 10 MiB, keeps at
most 2,000 items per section and stops after 15 minutes; a collection you ask
for may raise these to 1,000,000 files, 64 MiB, 10,000 items and an hour. A
report sent to the platform is at most 16 MiB: past that, certificates are
sent without their PEM first and then the longest lists are shortened, and
each section shortened says so. One collection runs at a time, and stopping
the agent stops a collection in flight (a collection you asked for then sends
what it had, marked as not finished).

## Another host, over SSH

A remote collection connects with the credentials stored for that host
(username and password, or a private key), checks the host's key against the
one pinned for it (or against `known_hosts`, or records it on first contact so
you can pin it) and never falls back to anything weaker. WinRM is not
supported; a Windows host is reached through its OpenSSH server, with
PowerShell 5.1 or later.

A remote collection is deliberately weaker than a local one, so that no byte
of a private key file crosses the connection:

- Only **certificates** and **SSH public key lines** are read from files.
  A certificate crosses as a certificate parser on the host re-encodes it,
  never as the file's bytes; a file holding a private key is refused whole.
- A private key or keystore is described from its markers (its first bytes
  and its PEM labels) and its permissions, and, where the host has the tool,
  from a command that prints only a public key (`ssh-keygen -y`,
  `openssl pkey -pubout`, `keytool -list`). Otherwise the field is left empty
  and `unknown` says why.
- Configuration is filtered **on the host** to the named directives before
  anything is sent.
- The sweep goes by file name and size only.
- Options on `authorized_keys` lines do not cross, so whether a key is
  restricted is not known remotely.

### Limits, stated

These are known and accepted:

- An SSH certificate line can carry about a kilobyte of free text in its key
  ID and principals; it crosses with the line.
- An RFC 4716 (`---- BEGIN SSH2 PUBLIC KEY ----`) file is not read remotely.
- A deliberately crafted certificate can carry arbitrary bytes inside it, and
  they cross with it. The guarantee is for honest files and for mislabelled
  ones (a key written under a certificate's label is refused).
- On Windows a writer who controls a file and resets its times can still race
  a read; reading it twice narrows the window but does not close it.
- A configuration line over 256 KiB makes the whole file too large to read.
- A kept configuration value crosses as written, apart from long base64 or hex
  runs, which are replaced by `[redacted]`. A path-shaped value is kept whole,
  so a base64 secret that begins with `/` can, rarely, cross with it.

## Supported systems

Wherever the device agent's host inventory runs, and macOS 13 Ventura or
later:

- Linux on x86-64 and ARM64;
- Windows 10 or 11, Windows Server 2016 or later, x86-64;
- macOS 13 or later, on Apple silicon and Intel.

A remote collection can be made of any of these from a device agent on any of
them.

## What the platform receives

The report's format is published with the managed protocol:
[`schemas/managed/v1/defs/host-crypto-report.json`](../schemas/managed/v1/defs/host-crypto-report.json),
carried as `host_crypto` in a job result and in the local submission
([`managed-protocol.md`](managed-protocol.md)). A standalone run writes the
same report in a `host_crypto` record
([`standalone-output.md`](standalone-output.md)). The design and the rules
for anyone changing the collector: [`design/host-crypto.md`](design/host-crypto.md).
