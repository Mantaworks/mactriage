#!/bin/sh
set -eu

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT HUP INT TERM
commit="$(git rev-parse HEAD)"
date="$(git show -s --format=%cI HEAD)"
flags="-s -w -X main.version=dev -X main.commit=$commit -X main.date=$date -buildid="

for arch in arm64 amd64; do
  GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$flags" -o "$work/$arch-a" ./cmd/mactriage
  GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$flags" -o "$work/$arch-b" ./cmd/mactriage
  cmp "$work/$arch-a" "$work/$arch-b"
done
