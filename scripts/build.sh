#!/usr/bin/env bash
# Build everything inside the rootkat Docker build container.
#
#   $UBUNTU_VERSION (env, default 26.04) selects the build env's Ubuntu
#   release. The container's kernel headers come from that release, so
#   the LKM ABI matches the QEMU cloud image at the same UBUNTU_VERSION.
#   $BUILD_IMAGE_FORCE=1 forces a container rebuild.
#   $ROOTKAT_COMPONENTS (space-separated, default "lkm ebpf rust tests")
#   restricts which component subdirs are built. Set to "lkm" for a
#   fast release build that only produces rootkat.ko.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UBUNTU_VERSION="${UBUNTU_VERSION:-26.04}"
KERNEL_RUST="${KERNEL_RUST:-enabled}"
IMAGE="rootkat-build:ubuntu-${UBUNTU_VERSION}-rust-${KERNEL_RUST}"

if [ "${BUILD_IMAGE_FORCE:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[build] Building Docker image $IMAGE..."
    # buildx + --load is required so Colima honors --platform.
    docker buildx build --platform linux/amd64 --load \
        --build-arg "UBUNTU_VERSION=${UBUNTU_VERSION}" \
        --build-arg "KERNEL_RUST=${KERNEL_RUST}" \
        -t "$IMAGE" "$ROOT/build"
fi

TARGET="${1:-all}"
COMPONENTS="${ROOTKAT_COMPONENTS:-lkm ebpf rust tests}"

BTF_MOUNT=()
if [ -e /sys/kernel/btf/vmlinux ]; then
    BTF_MOUNT=(-v /sys/kernel/btf:/sys/kernel/btf:ro)
fi

BUILD_CMD=""
for comp in $COMPONENTS; do
    BUILD_CMD="${BUILD_CMD}make -C ${comp} ${TARGET} && "
done
BUILD_CMD="${BUILD_CMD%&& }"

docker run --rm --platform linux/amd64 \
    -e ROOTKAT_I_UNDERSTAND=1 \
    ${BTF_MOUNT[@]+"${BTF_MOUNT[@]}"} \
    -v "$ROOT":/work \
    -w /work \
    "$IMAGE" \
    bash -c "$BUILD_CMD"
