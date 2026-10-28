#!/usr/bin/env bash
# Install cosign from its GitHub release, pinned by version AND by the SHA-256
# of the binary, into DIR (added to GITHUB_PATH when run in Actions). No
# third-party action is involved, so the Actions policy (GitHub-owned and
# verified creators only) does not need an exception, and a moved release
# asset fails here instead of signing.
#
#   scripts/release/install-cosign.sh DIR
#
# A version bump changes both lines below, read from the release's
# cosign_checksums.txt, in a reviewed pull request.
set -euo pipefail
dir=${1:?usage: install-cosign.sh DIR}
version=v3.1.3
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) asset=cosign-linux-amd64; want=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
  Linux-aarch64) asset=cosign-linux-arm64; want=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
  *) echo "install-cosign.sh: no pinned cosign for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
mkdir -p "$dir"
curl -fsSL --proto '=https' --tlsv1.2 -o "$dir/cosign" "https://github.com/sigstore/cosign/releases/download/${version}/${asset}"
got=$(sha256sum "$dir/cosign" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
  rm -f "$dir/cosign"
  echo "install-cosign.sh: ${asset} ${version} has sha256 ${got}, pinned ${want}" >&2
  exit 1
fi
chmod 0755 "$dir/cosign"
[ -z "${GITHUB_PATH:-}" ] || echo "$dir" >> "$GITHUB_PATH"
"$dir/cosign" version 2>/dev/null | grep -E '^GitVersion' || true
