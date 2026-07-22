#!/bin/sh

set -eu

REPOSITORY="Mantaworks/mactriage"
PROGRAM="mactriage"

fail() {
  printf 'mactriage installer: %s\n' "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v shasum >/dev/null 2>&1 || fail "shasum is required"

[ "$(uname -s)" = "Darwin" ] || fail "mactriage supports macOS only"

case "$(uname -m)" in
  arm64 | aarch64) ARCH="arm64" ;;
  x86_64 | amd64) ARCH="x86_64" ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

if [ -n "${VERSION:-}" ]; then
  TAG="v${VERSION#v}"
else
  LATEST_URL=$(curl --proto '=https' --tlsv1.2 -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPOSITORY}/releases/latest")
  TAG=${LATEST_URL##*/}
  [ -n "$TAG" ] && [ "$TAG" != "latest" ] || fail "no release is available"
fi

RELEASE_VERSION=${TAG#v}
ARCHIVE="${PROGRAM}_${RELEASE_VERSION}_darwin_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPOSITORY}/releases/download/${TAG}"

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mactriage-install.XXXXXX")
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

printf 'Downloading mactriage %s for %s…\n' "$RELEASE_VERSION" "$ARCH"
curl --proto '=https' --tlsv1.2 -fsSL "$BASE_URL/$ARCHIVE" -o "$TEMP_DIR/$ARCHIVE"
curl --proto '=https' --tlsv1.2 -fsSL "$BASE_URL/checksums.txt" -o "$TEMP_DIR/checksums.txt"

EXPECTED=$(awk -v file="$ARCHIVE" '$2 == file { print $1; exit }' "$TEMP_DIR/checksums.txt")
[ -n "$EXPECTED" ] || fail "release checksum is missing for $ARCHIVE"
ACTUAL=$(shasum -a 256 "$TEMP_DIR/$ARCHIVE" | awk '{ print $1 }')
[ "$ACTUAL" = "$EXPECTED" ] || fail "checksum verification failed"

tar -xzf "$TEMP_DIR/$ARCHIVE" -C "$TEMP_DIR"
[ -f "$TEMP_DIR/$PROGRAM" ] || fail "release archive does not contain $PROGRAM"

if [ -n "${INSTALL_DIR:-}" ]; then
  DESTINATION=$INSTALL_DIR
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  DESTINATION=/usr/local/bin
else
  DESTINATION="${HOME}/.local/bin"
fi

mkdir -p "$DESTINATION"
[ -w "$DESTINATION" ] || fail "$DESTINATION is not writable; set INSTALL_DIR to a writable directory"
install -m 0755 "$TEMP_DIR/$PROGRAM" "$DESTINATION/$PROGRAM"

printf 'Installed mactriage to %s\n' "$DESTINATION/$PROGRAM"
case ":$PATH:" in
  *":$DESTINATION:"*) ;;
  *) printf 'Add %s to PATH to run mactriage from any shell.\n' "$DESTINATION" ;;
esac
