#!/usr/bin/env bash
# Write DIR/SHA256SUMS: the SHA-256 of every file in DIR except the signature
# bundles (*.sigstore.json) and SHA256SUMS itself, sorted by name, in the
# format `sha256sum -c` reads. Refuses a name outside [A-Za-z0-9._+-], which
# is all a release asset may be called.
#
#   scripts/release/sums.sh DIR
set -euo pipefail
dir=${1:?usage: sums.sh DIR}
cd "$dir"
[ ! -e SHA256SUMS ] || { echo "sums.sh: SHA256SUMS already exists in $dir" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum -- "$1"; }; else sum() { shasum -a 256 -- "$1"; }; fi
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
n=0
while IFS= read -r f; do
  [[ $f =~ ^[A-Za-z0-9._+-]+$ ]] || { echo "sums.sh: refusing asset name $f" >&2; exit 1; }
  sum "$f" >> "$tmp"
  n=$((n + 1))
done < <(find . -maxdepth 1 -type f ! -name '*.sigstore.json' ! -name SHA256SUMS | sed 's#^\./##' | LC_ALL=C sort)
[ "$n" -gt 0 ] || { echo "sums.sh: nothing to list in $dir" >&2; exit 1; }
mv "$tmp" SHA256SUMS
trap - EXIT
echo "sums.sh: $n file(s) in $dir/SHA256SUMS"
