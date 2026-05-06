#!/usr/bin/env bash
# Build everything inside the rootkat Docker build container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="rootkat-build:latest"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[build] Building Docker image $IMAGE..."
    docker build -t "$IMAGE" "$ROOT/build"
fi

TARGET="${1:-all}"

docker run --rm \
    -v "$ROOT":/work \
    -w /work \
    "$IMAGE" \
    bash -c "make -C lkm $TARGET && make -C ebpf $TARGET"
