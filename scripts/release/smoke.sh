#!/usr/bin/env bash
# Smoke-run the packaged agents on the machine this runs on, which must be a
# GitHub-hosted runner of the OS and architecture under test. What passes here
# is what release metadata may call runtime_qualified; nothing else is.
#
#   scripts/release/smoke.sh ASSETS VERSION OUT.json
#
# For every agent in release/agents.json with a target for this machine's
# OS/architecture (read from uname, never from an argument, so a mislabelled
# runner cannot qualify a target it is not):
#   1. unpack the package; it must hold, byte for byte, the binary published
#      beside it, and the OS's installer identical to the published one;
#   2. run the binary's -version: it must report this release's version and
#      this machine's OS/architecture (the sensor loads libpcap to get there);
#   3. run the installer's --check-dependencies from the unpacked directory,
#      which runs the binary again through the installer's own check and
#      changes nothing on the host.
# No capture, no registration, no network. OUT.json lists the files executed.
set -euo pipefail
assets=${1:?usage: smoke.sh ASSETS VERSION OUT.json}; version=${2:?}; out=${3:?}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
surface="$root/release/agents.json"
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) echo "smoke.sh: unsupported OS $(uname -s)" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "smoke.sh: unsupported machine $(uname -m)" >&2; exit 1 ;; esac
[ "$os" = linux ] || { echo "smoke.sh: packages are tar.gz with Linux installers; this script runs on Linux" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
executed=()
checks=()
n=0
while IFS=$'\t' read -r kind prefix exe installer; do
  base="${prefix}_${version}_${os}_${arch}"
  pkg="$base.tar.gz"
  [ -f "$assets/$pkg" ] || { echo "smoke.sh: $pkg is missing" >&2; exit 1; }
  [ -f "$assets/$base" ] || { echo "smoke.sh: $base is missing" >&2; exit 1; }
  mkdir -p "$work/$kind"
  tar -xzf "$assets/$pkg" -C "$work/$kind"
  dir="$work/$kind/$base"
  [ -x "$dir/$exe" ] || { echo "smoke.sh: $pkg has no executable $exe" >&2; exit 1; }
  cmp -s "$dir/$exe" "$assets/$base" || { echo "smoke.sh: $pkg/$exe differs from $base" >&2; exit 1; }
  report=$(cd "$dir" && LC_ALL=C "./$exe" -version 2>&1) || { echo "smoke.sh: $exe -version failed:" >&2; echo "$report" >&2; exit 1; }
  echo "$report"
  head -n1 <<<"$report" | grep -qE " v${version//./\\.}\$" || { echo "smoke.sh: $exe does not report v$version" >&2; exit 1; }
  grep -qxF "Platform: ${os}/${arch}" <<<"$report" || { echo "smoke.sh: $exe does not report ${os}/${arch}" >&2; exit 1; }
  checks+=("$kind: -version reports v$version on ${os}/${arch}")
  executed+=("$pkg" "$base")
  if [ "$installer" != - ]; then
    cmp -s "$dir/$installer" "$assets/$installer" || { echo "smoke.sh: $pkg/$installer differs from the published $installer" >&2; exit 1; }
    (cd "$dir" && bash "./$installer" --check-dependencies) || { echo "smoke.sh: $installer --check-dependencies failed" >&2; exit 1; }
    checks+=("$kind: $installer --check-dependencies")
    executed+=("$installer")
  fi
  n=$((n + 1))
done < <(jq -r --arg os "$os" --arg arch "$arch" '.agents[] | select(any(.targets[]; .os == $os and .arch == $arch)) |
  [.kind, .asset_prefix, .executable, (.installers[$os] // "-")] | @tsv' "$surface")
[ "$n" -gt 0 ] || { echo "smoke.sh: release/agents.json has no target for ${os}/${arch}" >&2; exit 1; }

jq -n --arg os "$os" --arg arch "$arch" --arg version "$version" --arg machine "$(uname -m)" \
  --arg runner "${RUNNER_NAME:-local}" --arg image "${ImageOS:-}-${ImageVersion:-}" \
  --args '{os: $os, arch: $arch, version: $version, machine: $machine, runner: $runner, image: $image,
          result: "passed", executed: ($ARGS.positional | unique)}' "${executed[@]}" > "$out"
printf '%s\n' "${checks[@]}"
echo "smoke.sh: ${os}/${arch} passed -> $out"
