#!/usr/bin/env bash
# Sign the container images a release pushed, by digest, with cosign keyless
# (the job's GitHub OIDC identity: the same identity that signs every other
# file of the release), and verify each signature against that identity before
# moving on. The signature is stored in the registry beside the image, which is
# where an admission controller looks for it.
#
#   scripts/release/sign-images.sh IDENTITY STATE_DIR
#
# Reads the images from STATE_DIR/package.json. An image is signed as
# repository@digest, never by tag: the signature is of those bytes whatever a
# tag is later made to say. Needs cosign v3 on PATH, registry credentials
# (cosign login) and, in Actions, `id-token: write`.
set -euo pipefail
identity=${1:?usage: sign-images.sh IDENTITY STATE_DIR}; state=${2:?}
issuer=https://token.actions.githubusercontent.com
n=0
while IFS=$'\t' read -r repository digest; do
  [[ $repository =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$ ]] || { echo "sign-images.sh: refusing repository $repository" >&2; exit 1; }
  [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "sign-images.sh: refusing digest $digest" >&2; exit 1; }
  ref="$repository@$digest"
  cosign sign --yes "$ref" >/dev/null
  cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$ref" >/dev/null
  echo "signed and verified: $ref"
  n=$((n + 1))
done < <(jq -r '(.images // [])[] | select(.repository != null) | [.repository, .digest] | @tsv' "$state/package.json")
[ "$n" -gt 0 ] || { echo "sign-images.sh: no pushed image in $state/package.json" >&2; exit 1; }
