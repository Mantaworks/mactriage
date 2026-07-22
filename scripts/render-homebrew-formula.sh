#!/bin/sh

set -eu

tag=${1:-}
output_path=${2:-}

if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  printf 'error: expected a stable semantic version tag such as v0.1.0\n' >&2
  exit 2
fi

if [ -z "$output_path" ]; then
  printf 'usage: %s <tag> <output-path>\n' "$0" >&2
  exit 2
fi

source_url=${MACTRIAGE_SOURCE_URL:-"https://github.com/Mantaworks/mactriage/archive/refs/tags/$tag.tar.gz"}

case "$source_url" in
  https://github.com/Mantaworks/mactriage/*) ;;
  *)
    printf 'error: source URL must be hosted by Mantaworks/mactriage on GitHub\n' >&2
    exit 2
    ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
template_path="$script_dir/../packaging/homebrew/mactriage.rb.tmpl"
output_dir=$(dirname -- "$output_path")
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mactriage-formula.XXXXXX")
archive_path="$tmp_dir/source.tar.gz"
rendered_path="$tmp_dir/mactriage.rb"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

curl --proto '=https' --tlsv1.2 --fail --location --retry 5 --silent --show-error \
  "$source_url" --output "$archive_path"

if command -v sha256sum >/dev/null 2>&1; then
  checksum=$(sha256sum "$archive_path" | awk '{print $1}')
else
  checksum=$(shasum -a 256 "$archive_path" | awk '{print $1}')
fi

sed \
  -e "s|@SOURCE_URL@|$source_url|g" \
  -e "s|@SHA256@|$checksum|g" \
  "$template_path" >"$rendered_path"

mkdir -p "$output_dir"
chmod 0644 "$rendered_path"
mv "$rendered_path" "$output_path"
printf 'Rendered Homebrew formula for %s at %s\n' "$tag" "$output_path"
