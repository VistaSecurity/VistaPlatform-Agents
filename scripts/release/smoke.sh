#!/usr/bin/env bash
# Smoke-run the packaged agents on the machine this runs on, which must be a
# GitHub-hosted runner of the OS and architecture under test: Linux, macOS, or
# Windows under Git Bash. What passes here is what release metadata may call
# runtime_qualified; nothing else is.
#
#   scripts/release/smoke.sh ASSETS VERSION OUT.json
#
# For every agent in release/agents.json with a target for this machine's
# OS/architecture (read from uname, never from an argument, so a mislabelled
# runner cannot qualify a target it is not):
#   1. unpack the package; it must hold, byte for byte, the binary published
#      beside it, and the OS's installer identical to the published one;
#   2. run the binary's -version: it must report this release's version and
#      this machine's OS/architecture (on Linux and macOS the sensor loads
#      libpcap to get there);
#   3. run the installer's dependency check from the unpacked directory, which
#      runs the binary again through the installer's own check and changes
#      nothing on the host.
# No capture, no registration, no network, no service installed. OUT.json
# lists the files executed.
#
# Windows differs in three ways, each stated where the proof is reported:
#   - The sensor imports nothing from Npcap: only kernel32.dll is in its import
#     table, and the pcap library's init tries wpcap.dll, keeps no error and
#     resolves nothing when it is absent. So a hosted runner, which has no
#     Npcap, can start it, and -version proves that the published bytes start
#     and nothing about loading Npcap. This script fails if it finds Npcap,
#     because that sentence would then be untrue.
#   - install-sensor.ps1 has no dependency-check switch; its dependency check
#     is the Npcap refusal it reaches before changing anything. On this machine
#     the check must refuse, with a key that is never used.
#   - The smoke entry's also_started architectures run here too (the x86 sensor,
#     under WoW64 on x64): same unpacking and -version, a failure fails the leg,
#     but this machine is not that architecture, so they are listed in OUT.json
#     as started_not_qualified, never as executed.
#
# One script for every system: the steps and the rules are the same, and
# Linux and macOS packages are both .tar.gz with the system's installer
# inside. It runs under the bash macOS ships (3.2), so it uses nothing newer;
# scripts/release-tools.test.mjs runs it as macOS and as Windows against
# stand-ins.
set -euo pipefail
assets=${1:?usage: smoke.sh ASSETS VERSION OUT.json}; version=${2:?}; out=${3:?}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
surface="$root/release/agents.json"
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW*|MSYS*) os=windows ;;
  *) echo "smoke.sh: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "smoke.sh: unsupported machine $(uname -m)" >&2; exit 1 ;; esac

suffix=''; pkg_suffix=.tar.gz
if [ "$os" = windows ]; then
  suffix=.exe; pkg_suffix=.zip
  assets=$(cygpath -u "$assets") # unzip reads a backslash as an escape
  for lib in System32/Npcap/wpcap.dll System32/wpcap.dll SysWOW64/Npcap/wpcap.dll SysWOW64/wpcap.dll; do
    [ ! -e "${SYSTEMROOT:-}/$lib" ] || { echo "smoke.sh: $lib is on this runner; this leg states that it ran without Npcap" >&2; exit 1; }
  done
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
executed=()
started=()
checks=()
n=0

# The agents with a target for OS/ARCH, one tab-separated line each. Windows
# jq writes CRLF.
agents_for() {
  jq -r --arg os "$os" --arg arch "$1" '.agents[] | select(any(.targets[]; .os == $os and .arch == $arch)) |
    [.kind, .asset_prefix, .executable, (.installers[$os] // "-"),
     (first(.targets[] | select(.os == $os and .arch == $arch)).requires | join(",") | if . == "" then "-" else . end)] | @tsv' "$surface" | tr -d '\r'
}

# Steps 1 and 2 for one agent at architecture $1. Leaves pkg, published and dir.
start_package() {
  local at=$1 base report
  base="${prefix}_${version}_${os}_${at}"
  pkg="$base$pkg_suffix"
  published="$base$suffix"
  [ -f "$assets/$pkg" ] || { echo "smoke.sh: $pkg is missing" >&2; exit 1; }
  [ -f "$assets/$published" ] || { echo "smoke.sh: $published is missing" >&2; exit 1; }
  mkdir -p "$work/$kind-$at"
  if [ "$os" = windows ]; then
    unzip -q "$assets/$pkg" -d "$work/$kind-$at"
  else
    tar -xzf "$assets/$pkg" -C "$work/$kind-$at"
  fi
  dir="$work/$kind-$at/$base"
  [ -x "$dir/$exe$suffix" ] || { echo "smoke.sh: $pkg has no executable $exe$suffix" >&2; exit 1; }
  cmp -s "$dir/$exe$suffix" "$assets/$published" || { echo "smoke.sh: $pkg/$exe$suffix differs from $published" >&2; exit 1; }
  report=$(cd "$dir" && LC_ALL=C "./$exe$suffix" -version 2>&1) || { echo "smoke.sh: $exe -version failed:" >&2; echo "$report" >&2; exit 1; }
  echo "$report"
  head -n1 <<<"$report" | grep -qE " v${version//./\\.}\$" || { echo "smoke.sh: $exe does not report v$version" >&2; exit 1; }
  grep -qxF "Platform: ${os}/${at}" <<<"$report" || { echo "smoke.sh: $exe does not report ${os}/${at}" >&2; exit 1; }
  if [ "$installer" != - ]; then
    cmp -s "$dir/$installer" "$assets/$installer" || { echo "smoke.sh: $pkg/$installer differs from the published $installer" >&2; exit 1; }
  fi
}

# Windows PowerShell, which every customer host has and the installers target.
powershell_file() {
  (cd "$dir" && powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w "$dir/$installer")" "$@" 2>&1)
}

while IFS=$'\t' read -r kind prefix exe installer requires; do
  start_package "$arch"
  if [ "$requires" = npcap ]; then
    checks+=("$kind: -version reports v$version on ${os}/${arch} without Npcap (capture library not loaded)")
  else
    checks+=("$kind: -version reports v$version on ${os}/${arch}")
  fi
  executed+=("$pkg" "$published")
  if [ "$installer" != - ]; then
    if [ "$os" != windows ]; then
      (cd "$dir" && bash "./$installer" --check-dependencies) || { echo "smoke.sh: $installer --check-dependencies failed" >&2; exit 1; }
      checks+=("$kind: $installer --check-dependencies")
    elif [ "$requires" = npcap ]; then
      if refusal=$(powershell_file -IP 192.0.2.1 -Key REG-SMOKE-NEVER-SENT); then
        echo "$refusal" >&2; echo "smoke.sh: $installer did not refuse a host without Npcap" >&2; exit 1
      fi
      echo "$refusal"
      grep -q 'Npcap is not installed' <<<"$refusal" || { echo "smoke.sh: $installer stopped, but not at its Npcap check" >&2; exit 1; }
      checks+=("$kind: $installer stops at its Npcap check before changing anything")
    else
      powershell_file -CheckDependencies || { echo "smoke.sh: $installer -CheckDependencies failed" >&2; exit 1; }
      checks+=("$kind: $installer -CheckDependencies")
    fi
    executed+=("$installer")
  fi
  n=$((n + 1))
done < <(agents_for "$arch")
[ "$n" -gt 0 ] || { echo "smoke.sh: release/agents.json has no target for ${os}/${arch}" >&2; exit 1; }

also_started=$(jq -r --arg os "$os" --arg arch "$arch" '.smoke[] | select(.os == $os and .arch == $arch) | (.also_started // [])[]' "$surface" | tr -d '\r')
for at in $also_started; do
  while IFS=$'\t' read -r kind prefix exe installer requires; do
    start_package "$at"
    checks+=("$kind: -version reports v$version as ${os}/${at} on this ${arch} machine (started, not qualified)")
    started+=("$pkg" "$published")
  done < <(agents_for "$at")
done

jq -n --arg os "$os" --arg arch "$arch" --arg version "$version" --arg machine "$(uname -m)" \
  --arg runner "${RUNNER_NAME:-local}" --arg image "${ImageOS:-}-${ImageVersion:-}" \
  --arg started "$(printf '%s\n' ${started[@]+"${started[@]}"})" \
  --args '{os: $os, arch: $arch, version: $version, machine: $machine, runner: $runner, image: $image,
          result: "passed", executed: ($ARGS.positional | unique),
          started_not_qualified: ($started | split("\n") | map(select(length > 0)) | unique)}' "${executed[@]}" > "$out"
printf '%s\n' "${checks[@]}"
echo "smoke.sh: ${os}/${arch} passed -> $out"
