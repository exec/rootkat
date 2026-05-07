#!/usr/bin/env bash
# Download an Ubuntu cloud image for QEMU tests.
#   $UBUNTU_VERSION (env, default 26.04) selects the release.
#   First positional arg overrides $UBUNTU_VERSION.
# Outputs the absolute path of the cached image on stdout.
set -euo pipefail

VERSION="${1:-${UBUNTU_VERSION:-26.04}}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG_DIR="$ROOT/tests/qemu/images"
mkdir -p "$IMG_DIR"

IMG_URL="https://cloud-images.ubuntu.com/releases/${VERSION}/release/ubuntu-${VERSION}-server-cloudimg-amd64.img"
IMG_PATH="$IMG_DIR/ubuntu-${VERSION}.img"

if [ ! -f "$IMG_PATH" ]; then
    echo "[fetch] Downloading Ubuntu ${VERSION} cloud image..." >&2
    curl -fL --retry 3 -o "$IMG_PATH.tmp" "$IMG_URL"
    mv "$IMG_PATH.tmp" "$IMG_PATH"
fi
echo "$IMG_PATH"
