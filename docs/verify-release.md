# Verifying a release of the Vista Platform agents

Every file a release of this repository publishes can be checked before you
run it: its SHA-256 digest, a Sigstore signature made by this repository's
release workflow, and (for releases built after the repository became public)
a SLSA build-provenance attestation. This page shows how, with the exact
identities to check. `scripts/verify-release.sh` does all of it in one
command; the release workflows run that same script against their own assets
before and after publishing.

## What a release contains

| Asset | What it is |
|---|---|
| `vista-sensor_<version>_<os>_<arch>[.exe]` | the sensor binary |
| `vista-device-agent_<version>_<os>_<arch>[.exe]` | the device interrogation agent binary |
| `<binary>.tar.gz` (`.zip` for Windows) | the binary with its installer (where there is one), `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES`, under one top-level directory |
| `<binary>.cdx.json` | CycloneDX 1.6 SBOM of the binary, generated from the module list compiled into it |
| `install-sensor.sh`, `install-sensor.ps1`, `install-device-agent.sh` | the installers |
| `THIRD_PARTY_LICENSES` | the licence text of every third-party component linked into the binaries |
| `agents-release.json` | the release metadata (schema `schemas/release/v1/release.schema.json`): every file above with its digest, size, signature bundle, provenance, which targets were executed in the release run, and what the host must provide |
| `compatibility-agents-<version>-c<n>.json` | compatibility records (schema `schemas/compatibility/v1/record.schema.json`): which platform versions were tested with these exact bytes. The first (`c1`) ships with the release and says `pending` for every claim |
| `SHA256SUMS` | the digest of every asset above |
| `<asset>.sigstore.json` | the Sigstore signature bundle of each binary, package, installer, `agents-release.json`, compatibility record and `SHA256SUMS` |
| `provenance.intoto.jsonl` | the SLSA v1 build-provenance attestation naming every binary, package and installer |

Release kinds:

- **`vX.Y.Z`**: a stable release.
- **`vX.Y.Z-rc.N`**: a release candidate, published as a prerelease. It never
  becomes the repository's latest release.
- **`nightly-YYYYMMDD-<12 hex>`**: a nightly build of `main` at the commit the
  name ends with, version `0.0.0-nightly.YYYYMMDD.g<12 hex>`. A prerelease,
  not supported, removed after the retention period unless a compatibility
  record names it.

No URL here or in any Vista Platform product points at `releases/latest`:
always name the exact release.

## Who signs what

Signatures are keyless (Sigstore, `cosign`): each is made by a GitHub Actions
workflow of this repository with a short-lived certificate that names the
workflow and the ref it ran on. There is no long-lived signing key. Check the
certificate's identity and issuer, never only that "a" signature verifies.

Issuer, for every signature: `https://token.actions.githubusercontent.com`

| Signs | Identity (exact) |
|---|---|
| a stable release or release candidate `<tag>` | `https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/<tag>` |
| a nightly | `https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/nightly.yml@refs/heads/main` |
| compatibility records after the first | `https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/compatibility.yml@refs/heads/main` |

The same identities as regular expressions, for tools that check a channel
rather than one tag:

```text
stable          ^https://github\.com/VistaSecurity/VistaPlatform-Agents/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$
release cand.   ^https://github\.com/VistaSecurity/VistaPlatform-Agents/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$
nightly         ^https://github\.com/VistaSecurity/VistaPlatform-Agents/\.github/workflows/nightly\.yml@refs/heads/main$
compatibility   ^https://github\.com/VistaSecurity/VistaPlatform-Agents/\.github/workflows/compatibility\.yml@refs/heads/main$
```

A stable-release verifier must not accept the release-candidate or nightly
identity: they are separate on purpose. A compatibility record whose claims
are all `pending` may be signed by the release (or nightly) workflow that
published the bytes; a record that says `tested` or `withdrawn` is valid only
when signed by `compatibility.yml`, so the workflow that builds bytes can never
claim they were tested.

## The quick way

Needs `bash`, `jq`, `tar`, `unzip`, `sha256sum` (or `shasum`), `cosign` v3 and
`gh`. (The bundles are in the Sigstore bundle format cosign v3 writes; cosign
v2.4 and later read it when given `--new-bundle-format`.)

```sh
git clone --depth 1 --branch v5.3.0 https://github.com/VistaSecurity/VistaPlatform-Agents
VistaPlatform-Agents/scripts/verify-release.sh --repo VistaSecurity/VistaPlatform-Agents --tag v5.3.0
```

It downloads the release into a new temporary directory (or checks one you
downloaded, with `--dir`) and verifies, in order: the signature of
`SHA256SUMS`; every digest in it; that no asset escapes it (a renamed or added
file fails); that `agents-release.json` is signed, names this release and lists
exactly the files present with their digests, sizes, signature bundles and
SBOMs; each artefact's own signature; that every package holds, byte for byte,
the binary published beside it and the same `THIRD_PARTY_LICENSES`; the
provenance of every artefact; and every compatibility record's signer, binding
to this `agents-release.json` and digests. It prints one line per check and
exits 0 only if all pass.

`--skip-signatures` exists for rehearsals without signing identities. It says
on every line of output that nothing was verified cryptographically; do not use
it to check a download.

## Step by step

The commands below use `v5.3.0`; substitute your tag, and for a nightly the
nightly identity above. Every nightly shares that identity, so for a nightly
also pin the commit: add `--certificate-github-workflow-sha <commit>` to each
`cosign verify-blob`, where `<commit>` is `release.source_sha` in
`agents-release.json` and its first twelve characters are the ones the
nightly's name ends with. (`scripts/verify-release.sh` pins the commit for
every release.)

**1. Download** the files you need, plus `SHA256SUMS` and its bundle:

```sh
TAG=v5.3.0
gh release download "$TAG" --repo VistaSecurity/VistaPlatform-Agents --dir "$TAG"
cd "$TAG"
```

(or `curl -fLO https://github.com/VistaSecurity/VistaPlatform-Agents/releases/download/$TAG/<file>` per file).

**2. Verify the checksums file's signature**, then the digests:

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS     # macOS, with every asset downloaded: shasum -a 256 -c SHA256SUMS
```

**3. Verify one binary, package or installer on its own signature** (every one
has a bundle):

```sh
F=vista-sensor_5.3.0_linux_amd64
cosign verify-blob --bundle "$F.sigstore.json" \
  --certificate-identity "https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$F"
```

An installer is verified the same way (`install-sensor.sh` with
`install-sensor.sh.sigstore.json`). Never run an installer you have not
verified, and never one fetched from the repository's source tree instead of
the release.

**4. Verify the build provenance** (SLSA v1, from GitHub's artifact
attestations): it says which workflow run, on which commit and ref, on a
GitHub-hosted runner, produced the file:

```sh
gh attestation verify "$F" --repo VistaSecurity/VistaPlatform-Agents \
  --cert-identity "https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/$TAG" \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners
# offline, from the release asset:
gh attestation verify "$F" --bundle provenance.intoto.jsonl --repo VistaSecurity/VistaPlatform-Agents \
  --cert-identity "https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/$TAG"
```

GitHub attests build provenance only for public repositories on this plan. A
nightly or release candidate built before this repository became public says
so in `agents-release.json` (`provenance.status: "unavailable"`, with the
reason) and has no `provenance.intoto.jsonl`; a stable release always has it,
and `verify-release.sh` fails one that does not.

**5. Check what the metadata says about the file**, after verifying the
metadata's own signature like step 3:

```sh
jq --arg f "$F" '.agents[].artifacts[] | select(.file == $f)
  | {sha256, runtime_qualified, requires, native_signing}' agents-release.json
```

- `runtime_qualified: true` means the release run executed this artefact on a
  GitHub-hosted runner of its OS and architecture (today linux/amd64 and
  linux/arm64: the binary's `-version` and the installer's dependency check).
  `false` means compile-only: built, checked and signed, but not supported.
- `requires` is what the host must provide: `libpcap` (Linux, macOS) or
  `npcap` (Windows). Npcap is never bundled; install it yourself from
  https://npcap.com under its own licence, whose free tier covers up to five
  systems.
- `native_signing` is `none` for every artefact: Windows binaries are not
  Authenticode-signed and macOS binaries are not notarized. The Sigstore
  signature proves where a file came from; it does not satisfy Windows
  SmartScreen or macOS Gatekeeper.

**6. Check a compatibility record** before relying on a support claim:

```sh
R=compatibility-agents-5.3.0-c2.json
cosign verify-blob --bundle "$R.sigstore.json" \
  --certificate-identity https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/compatibility.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$R"
jq -r .agents_release.metadata.sha256 "$R"; sha256sum agents-release.json   # must be equal
jq '.platform_compatibility' "$R"
```

A platform version is supported with these agents only where a record signed
by `compatibility.yml` says `tested` for that exact version and edition. A
newer record for the same release can supersede an older one (`supersedes`);
both stay published, and records are never edited.

## Windows

With `cosign.exe` and PowerShell:

```powershell
$Tag = "v5.3.0"; $F = "vista-sensor_5.3.0_windows_amd64.exe"
cosign verify-blob --bundle "$F.sigstore.json" `
  --certificate-identity "https://github.com/VistaSecurity/VistaPlatform-Agents/.github/workflows/release.yml@refs/tags/$Tag" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com $F
(Get-FileHash $F -Algorithm SHA256).Hash.ToLower()   # compare with the line for $F in SHA256SUMS
```

## If a check fails

Do not run the file. Download it again from the release page of the exact tag;
if it still fails, report it privately as described in `SECURITY.md`.
