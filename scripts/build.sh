#!/usr/bin/env bash
#
# Builds one customer agent for one target.
#
#   scripts/build.sh <sensor|device-agent> native         -> bin/<binary>
#   scripts/build.sh <sensor|device-agent> <os>-<arch>    -> dist/<agent>/<os>-<arch>/<binary>
#   scripts/build.sh <sensor|device-agent> linux-<arch> container
#                                                         -> dist/<agent>-container/linux-<arch>/<binary>
#
# The version stamped into main.Version is AGENT_VERSION (default "dev"),
# with a leading "v" stripped: the platform stores the bare version and shows
# it as v{version}.
#
# CGO: the sensor links libpcap through cgo on Linux and macOS (a cross-build
# needs the target's C toolchain and libpcap) and loads Npcap at run time on
# Windows, so it builds with CGO_ENABLED=0 there. The device agent is pure Go
# and always builds with CGO_ENABLED=0, so its binaries are statically linked.
#
# The installer for the target is copied beside the binary in dist/.
#
# container: the executable that goes into the agent's container image
# (scripts/release/image.mjs). Always CGO_ENABLED=0, so it is static and the
# image needs nothing else, and built with the tags release/agents.json names
# for the image: "container" embeds the root certificates an image without an
# operating system would otherwise lack, and the sensor's "nocapture" leaves
# out packet capture (and with it libpcap), because the sensor in a container
# runs scans only. No installer goes with it.
set -euo pipefail

usage() { echo "usage: scripts/build.sh <sensor|device-agent> <native|<os>-<arch>> [container]" >&2; exit 2; }
agent=${1:-}; target=${2:-}; variant=${3:-}
[ -n "$agent" ] && [ -n "$target" ] || usage
case "$variant" in ''|container) ;; *) usage ;; esac
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

go_version=$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' go.mod)
[ -n "$go_version" ] || { echo "build.sh: no go directive in go.mod" >&2; exit 1; }
export GOTOOLCHAIN="go$go_version" GOWORK=off
version=${AGENT_VERSION:-dev}
ldflags=${AGENT_LDFLAGS:-"-X main.Version=${version#v}"}

case "$agent" in
  sensor) pkg=./cmd/sensor; binary=crypto-sensor ;;
  device-agent) pkg=./cmd/device-agent; binary=device-agent ;;
  *) usage ;;
esac

if [ "$target" = native ]; then
  goos=$(go env GOOS); out=bin/$binary
else
  case "$target" in */*|*' '*) usage ;; esac
  goos=${target%-*}; goarch=${target#*-}
  [ "$goos" != "$target" ] && [ -n "$goarch" ] || usage
  export GOOS=$goos GOARCH=$goarch
  out=dist/$agent/$target/$binary
fi
[ "$goos" != windows ] || out=$out.exe

tags=''
if [ "$variant" = container ]; then
  [ "$goos" = linux ] && [ "$target" != native ] || { echo "build.sh: a container build is linux-<arch>" >&2; exit 2; }
  # The tags of each image, as release/agents.json declares them
  # (scripts/release-images.test.mjs holds the two together).
  case "$agent" in
    sensor) tags=container,nocapture ;;
    device-agent) tags=container ;;
  esac
  out=dist/$agent-container/$target/$binary
  export CGO_ENABLED=0
elif [ "$agent" = sensor ] && [ "$goos" != windows ]; then
  export CGO_ENABLED=1
else
  export CGO_ENABLED=0
fi

mkdir -p "$(dirname "$out")"
echo "building $agent for ${target}${variant:+ ($variant)} (GOOS=${GOOS:-$goos} CGO_ENABLED=$CGO_ENABLED, version ${version#v}) -> $out" >&2
if [ -n "$tags" ]; then
  go build -trimpath -tags "$tags" -ldflags "$ldflags" -o "$out" "$pkg"
else
  go build -trimpath -ldflags "$ldflags" -o "$out" "$pkg"
fi

if [ "$target" != native ] && [ -z "$variant" ]; then
  case "$agent:$goos" in
    sensor:linux) cp scripts/install-sensor.sh "$(dirname "$out")/" ;;
    sensor:darwin) cp scripts/install-sensor-macos.sh "$(dirname "$out")/" ;;
    sensor:windows) cp scripts/install-sensor.ps1 "$(dirname "$out")/" ;;
    device-agent:linux) cp scripts/install-device-agent.sh "$(dirname "$out")/" ;;
    device-agent:darwin) cp scripts/install-device-agent-macos.sh "$(dirname "$out")/" ;;
    device-agent:windows) cp scripts/install-device-agent.ps1 "$(dirname "$out")/" ;;
  esac
fi
