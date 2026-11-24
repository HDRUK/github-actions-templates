#!/usr/bin/env bash
# Install pinned Syft and Grype from their GitHub releases, verifying the
# published checksums. Deliberately avoids third-party marketplace actions.
set -euo pipefail

SYFT_VERSION="${SYFT_VERSION:?SYFT_VERSION required}"
GRYPE_VERSION="${GRYPE_VERSION:-}"
DEST="${SBOM_BIN_DIR:-$HOME/.local/sbom-bin}"
mkdir -p "$DEST"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

install_tool() {
  local tool="$1" version="$2"
  local base="https://github.com/anchore/${tool}/releases/download/v${version}"
  local archive="${tool}_${version}_linux_amd64.tar.gz"
  local sums="${tool}_${version}_checksums.txt"
  curl -fsSL --retry 3 -o "$tmp/$archive" "$base/$archive"
  curl -fsSL --retry 3 -o "$tmp/$sums" "$base/$sums"
  (cd "$tmp" && grep " ${archive}\$" "$sums" | sha256sum -c -)
  tar -xzf "$tmp/$archive" -C "$DEST" "$tool"
}

install_tool syft "$SYFT_VERSION"
[ -n "$GRYPE_VERSION" ] && install_tool grype "$GRYPE_VERSION"
echo "$DEST" >> "${GITHUB_PATH:-/dev/null}"
"$DEST/syft" --version
[ -n "$GRYPE_VERSION" ] && "$DEST/grype" --version
exit 0
