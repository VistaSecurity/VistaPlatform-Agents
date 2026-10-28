#!/usr/bin/env bash
# Sign files with cosign keyless (the job's GitHub OIDC identity), one
# Sigstore bundle per file (<file>.sigstore.json), and verify each bundle
# against the identity the release documents before moving on. A bundle that
# already exists is an error: nothing is ever re-signed in place.
#
#   scripts/release/sign.sh IDENTITY DIR FILE...
#
# Needs cosign v3 on PATH and, in Actions, `id-token: write`.
set -euo pipefail
identity=${1:?usage: sign.sh IDENTITY DIR FILE...}; dir=${2:?}; shift 2
[ $# -gt 0 ] || { echo "sign.sh: no files" >&2; exit 2; }
issuer=https://token.actions.githubusercontent.com
for f in "$@"; do
  [ -f "$dir/$f" ] || { echo "sign.sh: no file $dir/$f" >&2; exit 1; }
  [ ! -e "$dir/$f.sigstore.json" ] || { echo "sign.sh: $f.sigstore.json already exists" >&2; exit 1; }
  cosign sign-blob --yes --bundle "$dir/$f.sigstore.json" "$dir/$f" >/dev/null
  cosign verify-blob --bundle "$dir/$f.sigstore.json" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$dir/$f" >/dev/null
  echo "signed and verified: $f"
done
