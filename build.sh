#!/bin/sh
# Builds cvewatch and cvewatch-tui.
#
#   ./build.sh                local build into the project root, version dev-<commit>[-dirty]
#   ./build.sh local          the same
#   ./build.sh tag            release build of the tag on HEAD into dist/ (fails if HEAD has no tag)
#   ./build.sh tag v1.3.0     release build of that tag into dist/ (the tag must exist)
set -eu

root=$(cd "$(dirname "$0")" && pwd)
mode=${1:-local}

case "$mode" in
local)
	version=dev-$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
	if [ -n "$(git -C "$root" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
		version=$version-dirty
	fi
	out=$root
	;;
tag)
	if [ -n "${2:-}" ]; then
		version=$2
		git -C "$root" rev-parse -q --verify "refs/tags/$version" >/dev/null || { echo "no such tag: $version" >&2; exit 1; }
		if [ "$(git -C "$root" rev-parse "$version^{commit}")" != "$(git -C "$root" rev-parse HEAD)" ]; then
			echo "HEAD is not at $version; check it out first" >&2
			exit 1
		fi
	else
		version=$(git -C "$root" describe --tags --exact-match 2>/dev/null) || { echo "HEAD has no tag; tag it or pass a tag name" >&2; exit 1; }
	fi
	if [ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]; then
		echo "working tree has uncommitted changes; a tagged build must be clean" >&2
		exit 1
	fi
	out=$root/dist
	mkdir -p "$out"
	;;
*)
	echo "usage: $0 [local | tag [vX.Y.Z]]" >&2
	exit 2
	;;
esac

cd "$root/app"
for name in cvewatch cvewatch-tui; do
	echo "building $name ($version) -> $out/$name"
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out/$name" "./src/cmd/$name"
done
