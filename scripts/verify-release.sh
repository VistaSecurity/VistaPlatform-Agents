#!/usr/bin/env bash
# Verify a Vista Platform agents release: every asset's digest, signature and
# provenance, and that the metadata, the packages and the compatibility records
# all describe the same bytes. docs/verify-release.md explains each step; the
# release workflows run this script against their own assets, on the draft
# before publishing and on the published release after.
#
#   scripts/verify-release.sh --repo OWNER/REPO --tag TAG [--dir DIR] [--skip-signatures]
#
#   --repo   the repository the release belongs to (VistaSecurity/VistaPlatform-Agents)
#   --tag    vX.Y.Z, vX.Y.Z-rc.N or nightly-YYYYMMDD-<12 hex>
#   --dir    assets already downloaded there; without it the release is
#            downloaded with `gh release download` into a new temporary
#            directory (kept, and printed)
#   --skip-signatures
#            do not run cosign or `gh attestation verify`. For a rehearsal
#            without signing identities only: the result is NOT a
#            verification, and the script says so on every run.
#
# Needs bash, jq, tar, unzip, sha256sum (or shasum), and unless
# --skip-signatures: cosign v3 (bundles in the new Sigstore format) and gh (for
# provenance). Exit 0 verified, 1 a check failed, 2 usage or a missing tool.
set -euo pipefail

ISSUER=https://token.actions.githubusercontent.com
repo='' tag='' dir='' skip_sig=false
usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) repo=${2:-}; shift 2 ;;
    --tag) tag=${2:-}; shift 2 ;;
    --dir) dir=${2:-}; shift 2 ;;
    --skip-signatures) skip_sig=true; shift ;;
    -h|--help) usage ;;
    *) echo "verify-release: unknown argument $1" >&2; usage ;;
  esac
done
[ -n "$repo" ] && [ -n "$tag" ] || usage
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "verify-release: --repo must be OWNER/REPO" >&2; exit 2; }

if [[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  channel=stable
elif [[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.(0|[1-9][0-9]*)$ ]]; then
  channel=prerelease
elif [[ $tag =~ ^nightly-[0-9]{8}-[0-9a-f]{12}$ ]]; then
  channel=nightly
else
  echo "verify-release: $tag is not a release tag (vX.Y.Z, vX.Y.Z-rc.N, nightly-YYYYMMDD-<12 hex>)" >&2
  exit 2
fi

# The signer identities (Fulcio certificate SAN). Exact strings for this tag;
# scripts/release/lib.mjs builds the same ones, and a test holds them equal.
base="https://github.com/${repo}/.github/workflows"
if [ "$channel" = nightly ]; then
  release_identity="${base}/nightly.yml@refs/heads/main"
  source_ref=refs/heads/main
else
  release_identity="${base}/release.yml@refs/tags/${tag}"
  source_ref="refs/tags/${tag}"
fi
compat_identity="${base}/compatibility.yml@refs/heads/main"

need() { command -v "$1" >/dev/null 2>&1 || { echo "verify-release: $1 is required" >&2; exit 2; }; }
need jq; need tar; need unzip
if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else echo "verify-release: sha256sum or shasum is required" >&2; exit 2; fi
if [ "$skip_sig" = true ]; then
  echo "################################################################################"
  echo "# --skip-signatures: cosign and provenance checks are NOT run. Digests and"
  echo "# metadata are checked, but nothing proves who produced these files. This is"
  echo "# a rehearsal mode, not a verification."
  echo "################################################################################"
else
  need cosign; need gh
fi

if [ -z "$dir" ]; then
  need gh
  dir=$(mktemp -d "${TMPDIR:-/tmp}/verify-release.XXXXXX")
  echo "downloading ${repo} ${tag} into ${dir}"
  gh release download "$tag" --repo "$repo" --dir "$dir"
fi
[ -d "$dir" ] || { echo "verify-release: no directory $dir" >&2; exit 2; }
dir=$(cd "$dir" && pwd)

work=$(mktemp -d "${TMPDIR:-/tmp}/verify-release-work.XXXXXX")
trap 'rm -rf "$work"' EXIT
: > "$work/listed"

fails=0
ok() { echo "  ok    $*"; }
bad() { echo "  FAIL  $*"; fails=$((fails + 1)); }

# The release workflow's signatures must also come from a run at the source
# commit the metadata names (the nightly identity, refs/heads/main, is shared
# by every nightly; the commit is not).
src_sha=''
cosign_verify() { # file identity
  local f=$1 id=$2
  if [ "$skip_sig" = true ]; then return 0; fi
  [ -f "$dir/$f.sigstore.json" ] || { bad "$f: no signature bundle $f.sigstore.json"; return 1; }
  if cosign verify-blob --bundle "$dir/$f.sigstore.json" \
       --certificate-identity "$id" --certificate-oidc-issuer "$ISSUER" \
       --certificate-github-workflow-repository "$repo" \
       --certificate-github-workflow-sha "$src_sha" \
       "$dir/$f" >/dev/null 2>&1; then
    ok "$f: signature by $id"
  else
    bad "$f: signature does not verify for $id"
    return 1
  fi
}

echo "verifying ${repo} ${tag} (${channel}) in ${dir}"

# 1. The checksums file and its signature.
for f in SHA256SUMS agents-release.json THIRD_PARTY_LICENSES; do
  [ -f "$dir/$f" ] || bad "$f is missing"
done
[ "$fails" -eq 0 ] || { echo "verify-release: FAILED ($fails)"; exit 1; }
src_sha=$(jq -r '.release.source_sha // ""' "$dir/agents-release.json")
[[ $src_sha =~ ^[0-9a-f]{40}$ ]] || { bad "agents-release.json: no 40-hex release.source_sha"; echo "verify-release: FAILED ($fails)"; exit 1; }
if [ "$channel" = nightly ] && [ "${tag##*-}" != "${src_sha:0:12}" ]; then
  bad "agents-release.json: source_sha $src_sha is not the commit $tag names"
fi
cosign_verify SHA256SUMS "$release_identity" || true

# 2. Every line of SHA256SUMS: well formed, unique, present, matching.
# (No associative arrays: macOS ships bash 3.2.)
while IFS= read -r line || [ -n "$line" ]; do
  if [[ ! $line =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9._+-]+)$ ]]; then
    bad "SHA256SUMS: malformed line: $line"; continue
  fi
  d=${BASH_REMATCH[1]} f=${BASH_REMATCH[2]}
  if grep -qxF -- "$f" "$work/listed"; then bad "SHA256SUMS: $f listed twice"; continue; fi
  echo "$f" >> "$work/listed"
  if [ ! -f "$dir/$f" ]; then bad "$f: listed in SHA256SUMS but not in the release"; continue; fi
  if [ "$(sha "$dir/$f")" = "$d" ]; then ok "$f: sha256"; else bad "$f: sha256 differs from SHA256SUMS"; fi
done < "$dir/SHA256SUMS"
[ -s "$work/listed" ] || bad "SHA256SUMS lists nothing"

# 3. Nothing in the release escapes SHA256SUMS: every file is listed, or is
#    the signature bundle of a file that is, or is a compatibility record
#    attached after the release (by compatibility.yml), which step 7 checks
#    on its own signature.
while IFS= read -r f; do
  case "$f" in
    SHA256SUMS) ;;
    *.sigstore.json)
      [ -f "$dir/${f%.sigstore.json}" ] || bad "$f: a signature bundle of no asset" ;;
    compatibility-agents-*.json) ;;
    *) grep -qxF -- "$f" "$work/listed" || bad "$f: not listed in SHA256SUMS (renamed or added after signing)" ;;
  esac
done < <(cd "$dir" && find . -maxdepth 1 -type f | sed 's#^\./##' | sort)

# 4. agents-release.json: names this release, and every artefact it lists is
#    here with its digest, size, signature bundle and SBOM.
meta="$dir/agents-release.json"
cosign_verify agents-release.json "$release_identity" || true
[ "$(jq -r .schema "$meta")" = vista.agents-release/v1 ] || bad "agents-release.json: not a vista.agents-release/v1 document"
[ "$(jq -r .release.tag "$meta")" = "$tag" ] || bad "agents-release.json: names tag $(jq -r .release.tag "$meta"), not $tag"
[ "$(jq -r .release.channel "$meta")" = "$channel" ] || bad "agents-release.json: channel is not $channel"
[ "$(jq -r .release.source_repo "$meta")" = "https://github.com/${repo}" ] || bad "agents-release.json: source_repo is not https://github.com/${repo}"
[ "$(jq -r .signing.identity "$meta")" = "$release_identity" ] || bad "agents-release.json: signing identity is not $release_identity"
[ "$(jq -r .notices.third_party_notices.sha256 "$meta")" = "$(sha "$dir/THIRD_PARTY_LICENSES")" ] || bad "THIRD_PARTY_LICENSES: digest differs from agents-release.json"
prov_status=$(jq -r .provenance.status "$meta")

while IFS=$'\t' read -r kind type os arch file digest size bundle_sha sbom sbom_sha; do
  if [ ! -f "$dir/$file" ]; then bad "$file: listed in agents-release.json but not in the release"; continue; fi
  [ "$(sha "$dir/$file")" = "$digest" ] || bad "$file: sha256 differs from agents-release.json"
  [ "$(wc -c < "$dir/$file" | tr -d ' ')" = "$size" ] || bad "$file: size differs from agents-release.json"
  if [ -f "$dir/$file.sigstore.json" ]; then
    [ "$(sha "$dir/$file.sigstore.json")" = "$bundle_sha" ] || bad "$file.sigstore.json: differs from agents-release.json"
  else
    bad "$file: no signature bundle"
  fi
  if [ "$sbom" != - ]; then
    if [ -f "$dir/$sbom" ] && [ "$(sha "$dir/$sbom")" = "$sbom_sha" ]; then :; else bad "$sbom: missing or differs from agents-release.json"; fi
  fi
  cosign_verify "$file" "$release_identity" || true
done < <(jq -r '.agents[] | .kind as $k | .artifacts[] |
  [$k, .type, .os, .arch, .file, .sha256, (.size|tostring), .signature.sha256,
   (if .sbom then (.sbom.url | split("/") | last) else "-" end), (if .sbom then .sbom.sha256 else "-" end)] | @tsv' "$meta")

# 5. Each package holds byte-for-byte the binary published beside it (as the
#    one entry with that digest under the package's top directory) and the
#    same THIRD_PARTY_LICENSES.
while IFS=$'\t' read -r pkg bin; do
  [ -f "$dir/$pkg" ] && [ -f "$dir/$bin" ] || continue
  rootdir=${pkg%.tar.gz}; rootdir=${rootdir%.zip}
  rm -rf "${work:?}/x"; mkdir -p "$work/x"
  case "$pkg" in
    *.tar.gz) tar -xzf "$dir/$pkg" -C "$work/x" 2>/dev/null || { bad "$pkg: not a readable tar.gz"; continue; } ;;
    *.zip) unzip -q "$dir/$pkg" -d "$work/x" 2>/dev/null || { bad "$pkg: not a readable zip"; continue; } ;;
  esac
  if [ "$(cd "$work/x" && find . -mindepth 1 -maxdepth 1 | sed 's#^\./##')" != "$rootdir" ]; then
    bad "$pkg: does not hold exactly one top directory $rootdir"; continue
  fi
  want=$(sha "$dir/$bin") found=false
  while IFS= read -r entry; do
    [ "$(sha "$entry")" = "$want" ] && found=true
  done < <(find "$work/x/$rootdir" -maxdepth 1 -type f)
  if [ "$found" = true ]; then ok "$pkg: holds $bin"; else bad "$pkg: does not hold $bin"; fi
  cmp -s "$work/x/$rootdir/THIRD_PARTY_LICENSES" "$dir/THIRD_PARTY_LICENSES" || bad "$pkg: THIRD_PARTY_LICENSES missing or different"
done < <(jq -r '.agents[] | .artifacts as $a | $a[] | select(.type == "package") | . as $p |
  ($a[] | select(.type == "binary" and .os == $p.os and .arch == $p.arch)) | [$p.file, .file] | @tsv' "$meta")

# 6. Provenance: one SLSA attestation by the same workflow naming every
#    binary, package and installer.
if [ "$prov_status" = attested ]; then
  if [ "$(jq -r .provenance.sha256 "$meta")" != "$(sha "$dir/provenance.intoto.jsonl" 2>/dev/null || echo none)" ]; then
    bad "provenance.intoto.jsonl: missing or differs from agents-release.json"
  elif [ "$skip_sig" = false ]; then
    while IFS= read -r file; do
      if gh attestation verify "$dir/$file" --bundle "$dir/provenance.intoto.jsonl" --repo "$repo" \
           --cert-identity "$release_identity" --cert-oidc-issuer "$ISSUER" \
           --source-ref "$source_ref" --source-digest "$src_sha" --deny-self-hosted-runners >/dev/null 2>&1; then
        ok "$file: provenance"
      else
        bad "$file: provenance does not verify"
      fi
    done < <(jq -r '.agents[].artifacts[].file' "$meta")
  fi
else
  reason=$(jq -r '.provenance.reason // "no reason given"' "$meta")
  if [ "$channel" = stable ]; then
    bad "provenance: a stable release must carry provenance ($reason)"
  else
    echo "  note  provenance: not available for this ${channel} release: ${reason}"
  fi
fi

# 7. Compatibility records: signed by a signer allowed to make their claims,
#    bound to this agents-release.json, naming exactly these digests.
meta_sha=$(sha "$meta")
nrec=0
while IFS= read -r rec; do
  nrec=$((nrec + 1))
  [ "$(jq -r .schema "$dir/$rec")" = vista.agent-compatibility/v1 ] || { bad "$rec: not a vista.agent-compatibility/v1 document"; continue; }
  [ "$rec" = "compatibility-$(jq -r .record_id "$dir/$rec").json" ] || bad "$rec: file name does not match its record_id"
  [ "$(jq -r .agents_release.metadata.sha256 "$dir/$rec")" = "$meta_sha" ] || bad "$rec: bound to a different agents-release.json"
  [ "$(jq -r .agents_release.tag "$dir/$rec")" = "$tag" ] || bad "$rec: names another release"
  if jq -e '[.platform_compatibility[].status] | all(. == "pending")' "$dir/$rec" >/dev/null; then
    allowed=("$release_identity" "$compat_identity")
  else
    allowed=("$compat_identity")
  fi
  [[ " ${allowed[*]} " == *" $(jq -r .signer.identity "$dir/$rec") "* ]] || bad "$rec: signer.identity may not make these claims"
  while IFS=$'\t' read -r file digest; do
    if [ -f "$dir/$file" ] && [ "$(sha "$dir/$file")" = "$digest" ]; then :; else bad "$rec: names $file with a digest this release does not have"; fi
  done < <(jq -r '.agents[].artifacts[] | [.file, .sha256] | @tsv' "$dir/$rec")
  if [ "$skip_sig" = false ]; then
    signed=false
    for id in "${allowed[@]}"; do
      if cosign verify-blob --bundle "$dir/$rec.sigstore.json" --certificate-identity "$id" \
           --certificate-oidc-issuer "$ISSUER" "$dir/$rec" >/dev/null 2>&1; then
        ok "$rec: signature by $id"; signed=true; break
      fi
    done
    [ "$signed" = true ] || bad "$rec: no signature by an identity allowed to make its claims"
  fi
done < <(cd "$dir" && find . -maxdepth 1 -type f -name 'compatibility-*.json' ! -name '*.sigstore.json' | sed 's#^\./##' | sort)
[ "$nrec" -gt 0 ] || bad "no compatibility record in the release"

if [ "$fails" -gt 0 ]; then
  echo "verify-release: FAILED ($fails check(s))"
  exit 1
fi
if [ "$skip_sig" = true ]; then
  echo "verify-release: digests and metadata consistent; SIGNATURES AND PROVENANCE NOT VERIFIED (--skip-signatures)"
else
  echo "verify-release: ${repo} ${tag} verified"
fi
