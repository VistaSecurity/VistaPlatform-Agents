# Compatibility records

Each file here is one signed support claim: which platform versions and
editions were tested with one agents release's exact bytes. The format is
`schemas/compatibility/v1/record.schema.json`; `docs/releasing.md` explains the
lifecycle and `docs/verify-release.md` how to check a record.

- **One file per record**, named `<record_id>.json`, for example
  `agents-5.3.0-c2.json`. The first record of every release (`-c1`, every claim
  `pending`) is written by the release workflow and published with the release;
  it is not committed here.
- **Records are added, never edited or deleted.** A correction is a new record
  whose `supersedes` names the one it replaces; both stay published. The
  `compatibility.yml` workflow fails on a pull request's merge that modifies,
  renames or deletes a file here.
- **Merging is the claim.** When a record lands on `main`, `compatibility.yml`
  validates it, checks every digest it names against the published release,
  signs it with its own identity
  (`.github/workflows/compatibility.yml@refs/heads/main`) and attaches it to the
  release it describes. Only that identity may sign a `tested` or `withdrawn`
  claim.
- `qualification_ref` is an opaque identifier of the private qualification
  evidence. Nothing else about the qualification goes here.
