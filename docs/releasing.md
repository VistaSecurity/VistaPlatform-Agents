# Releasing the agents

How nightly and tagged releases of this repository are built, signed and
published, what protects them, and what to do when something goes wrong.
Customers verify releases as `docs/verify-release.md` describes.

## The three workflows

| Workflow | Trigger | Signs with | Publishes |
|---|---|---|---|
| `.github/workflows/release.yml` | push of a `vX.Y.Z` or `vX.Y.Z-rc.N` tag; or `gh workflow run release.yml --ref <tag> -f tag=<tag>` | `release.yml@refs/tags/<tag>` | a release for the tag; `vX.Y.Z-rc.N` as a prerelease; only `vX.Y.Z` may become latest |
| `.github/workflows/nightly.yml` | daily at 03:17 UTC; or `gh workflow run nightly.yml --ref main` | `nightly.yml@refs/heads/main` | a prerelease under the new tag `nightly-YYYYMMDD-<12 hex>`, never latest; skipped when the head of `main` already has a nightly |
| `.github/workflows/compatibility.yml` | push to `main` that adds `compatibility/records/<record_id>.json` | `compatibility.yml@refs/heads/main` | the signed record, attached to the release it describes |

`.github/workflows/build-agents.yml` is called by the first two and does the
building: one leg per target in `release/agents.json` on GitHub-hosted runners,
then packaging (`scripts/release/package.mjs`) and the smoke run on linux/amd64
and linux/arm64 (`scripts/release/smoke.sh`). It holds `contents: read` only.

Each trusted workflow keeps its write permissions in one job, run in its own
environment (`release`, `nightly`, `compatibility`), and `scripts/check-workflows.mjs`
fails any workflow that holds a write anywhere else, is triggered by anything
but a push to `main` or a tag, a schedule or a manual dispatch, names a secret
other than `GITHUB_TOKEN`, checks out another ref or repository, restores a
cache, or downloads another run's artefacts.

## Cutting a release

1. Merge everything for the release to `main`. `release/agents.json` names the
   targets, installers, capabilities and managed-protocol versions the metadata
   will declare; change it, and the build matrix in `build-agents.yml`, in a
   reviewed pull request (`scripts/release-metadata.test.mjs` fails when they
   disagree).
2. Create the tag on a commit of `main` and push it. Only repository
   administrators can create `v*` tags (the tag rulesets below), and no one can
   move or delete one:

   ```sh
   git tag -a v5.3.0-rc.1 -m "v5.3.0-rc.1" <commit on main> && git push origin v5.3.0-rc.1
   ```

   The agents' version tracks the platform's for now: tag the number of the
   platform release the agents are to be qualified against.
3. `release.yml` refuses a tag that is not `vX.Y.Z[-rc.N]`, that does not point
   at the commit it built, or whose commit is not on `main`; it refuses to run
   if any release (draft or published) exists for the tag. It then builds,
   smoke-runs, signs every artefact, attests provenance, writes
   `agents-release.json` and the first compatibility record (`c1`, every claim
   `pending`), writes and signs `SHA256SUMS`, and runs
   `scripts/verify-release.sh` three times: on the files it is about to upload,
   on the draft release downloaded back from GitHub, and on the published
   release.
4. A stable `vX.Y.Z` needs `LICENSE`, `NOTICE` and build provenance; a
   candidate needs `LICENSE` and `NOTICE`. The workflow fails otherwise.

## Immutability and failed runs

- A release is created as a **draft**, filled, verified, and only then
  published. A run that fails part-way leaves an unpublished draft, visible
  only to people with write access: that draft is the quarantine. Nothing
  partial is ever public.
- A re-run that finds any release for its tag fails. Inspect the draft (the
  run log says which step failed), delete it with
  `gh release delete <tag> --repo <owner>/<repo>` (without `--cleanup-tag`: the
  tag stays) and re-run the workflow. A nightly whose tag was already created
  is not re-run; the next night publishes a new identifier.
- A **published** release is never changed: no asset is replaced (no
  `--clobber` anywhere), a version is never reused with other bytes, and a fix
  is a new version. The only later additions are compatibility records, each a
  new asset with a new name.
- Builds are reproducible for a given commit: `-trimpath`, the version from
  the tag, the toolchain from `go.mod`, packages written with fixed owners,
  modes and times (the commit's time). Rebuilding a tag and comparing digests
  is how a published release is audited.

## Compatibility records

A record says which platform versions and editions were tested with one
release's exact bytes (`compatibility/records/README.md`). The platform's own
qualification produces the evidence privately; a reviewed pull request adds
`compatibility/records/agents-<version>-c<n>.json` with `supersedes` naming the
record it replaces and an opaque `qualification_ref`. On merge,
`compatibility.yml` verifies the release in full, checks the record against
it, signs it and attaches it. Records are append-only: a push that modifies,
renames or deletes one fails.

## Nightly retention

Nightly releases are kept for **30 days**, and in any case the newest **7**.
Kept past that, indefinitely:

- any nightly a compatibility record names (a platform build was tested or
  shipped against it);
- any nightly listed in `release/retained-nightlies.txt`, where the platform's
  release and recovery manifests' pins are recorded by pull request.

Pruning is never automatic. A maintainer runs the dry run, reads it, and runs
the printed commands by hand:

```sh
gh api --paginate 'repos/<owner>/<repo>/releases?per_page=100' > releases.json
node scripts/release/prune-nightlies.mjs --releases releases.json --repo <owner>/<repo>
```

Stable releases and release candidates are never pruned.

## Repository settings the workflows rely on

Applied by an administrator; GitHub, not this repository, enforces them.

- **Tag rulesets.** `v*` tags: creation by repository administrators only;
  update, deletion and non-fast-forward refused to everyone. `nightly-*` tags:
  update and non-fast-forward refused to everyone, deletion by administrators
  only (pruning). Every other tag: refused to everyone.
- **Environments.** `release` deployable from `v*` tags only; `nightly` and
  `compatibility` from `main` only. Required reviewers where the plan offers
  them. No environment holds a secret: signing is keyless.
- **Actions.** GitHub-owned and verified-creator actions only, pinned to a full
  commit SHA; default token read-only; fork pull requests need approval.
- **Branch ruleset on `main`.** Pull request with code-owner review, the
  `pr-gate` check, linear history, no force push.

## Signing identities, rotation and revocation

There is no signing key to rotate: every signature is made with a certificate
issued for one workflow run, valid for minutes, whose identity is the workflow
file and ref. What can change is the identity itself:

- **Renaming the repository, or a workflow file, changes the identity.**
  Verifiers pinned to the old one stop accepting new releases. Do neither
  without publishing the new identity next to the old one, with the date it
  takes effect, in `docs/verify-release.md`; old releases keep verifying
  against the identity they were signed with.
- **There is nothing to revoke** for a leaked key. A release that must not be
  used is withdrawn instead: a new compatibility record with `status:
  withdrawn` for every platform version it named, a notice at the top of the
  release's notes (the assets stay, so anyone can still check what they have),
  and a security advisory listing the digests.

## If a release is compromised

1. **Stop publishing.** `gh workflow disable release.yml nightly.yml
   compatibility.yml`. Cancel running workflows.
2. **Establish what was signed.** Every signature is in the public Sigstore
   transparency log (Rekor). Search it for each published digest
   (`rekor-cli search --sha <sha256>`) and compare with the releases you expect;
   check the Actions history for runs you did not start.
3. **Rebuild and compare.** Check out the release's tag and rebuild with
   `scripts/build.sh` and `scripts/release/package.mjs`; digests that differ
   from the published ones show which bytes are not what the source produces.
4. **Withdraw** as above: a `withdrawn` compatibility record, a release-notes
   notice and an advisory naming the bad digests. Delete assets only if they
   are actively harmful and the advisory records their digests.
5. **Close the hole** (a merged change, a settings change, an account) before
   enabling the workflows again, and publish a fixed release under a **new
   version**. Verifiers that need to exclude a bad build of a shared identity
   (a nightly) pin the source commit: `cosign verify-blob
   --certificate-github-workflow-sha <commit>`, which `scripts/verify-release.sh`
   always does with the commit `agents-release.json` names.
