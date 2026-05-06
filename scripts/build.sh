#!/usr/bin/env bash
# Build everything inside the rootkat Docker build container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="rootkat-build:latest"

if [ "${BUILD_IMAGE_FORCE:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[build] Building Docker image $IMAGE..."
    # buildx + --load is required so Colima honors --platform.
    docker buildx build --platform linux/amd64 --load \
        -t "$IMAGE" "$ROOT/build"
fi

TARGET="${1:-all}"

docker run --rm --platform linux/amd64 \
    -v "$ROOT":/work \
    -w /work \
    "$IMAGE" \
    bash -c "make -C lkm $TARGET && make -C ebpf $TARGET"
