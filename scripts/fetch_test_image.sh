#!/usr/bin/env bash
# Download Ubuntu 26.04 cloud image (kernel 7.0) for QEMU tests.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG_DIR="$ROOT/tests/qemu/images"
mkdir -p "$IMG_DIR"

IMG_URL="https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img"
IMG_PATH="$IMG_DIR/ubuntu-26.04.img"

if [ ! -f "$IMG_PATH" ]; then
    echo "[fetch] Downloading Ubuntu 26.04 cloud image..."
    curl -L -o "$IMG_PATH" "$IMG_URL"
fi
echo "[fetch] image at $IMG_PATH"
